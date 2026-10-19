//go:build linux

package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/multica-ai/multica/server/internal/r2dgit"
	"github.com/multica-ai/multica/server/internal/testutil"
)

// This image-provider fixture runs before TestMain. It exercises the production
// entrypoint binary's real subprocess protocol without initializing DB fixtures.
func init() {
	if os.Getenv("MULTICA_SYNTHETIC_IMAGE_PROVIDER") != "1" {
		return
	}
	if len(os.Args) != 2 || os.Args[1] != "--multica-protected-v1" {
		os.Exit(91)
	}
	var input r2dgit.ProtectedProviderInput
	if json.NewDecoder(io.LimitReader(os.Stdin, 32768)).Decode(&input) != nil || input.Version != 1 || input.Assignment.Title == "" {
		os.Exit(92)
	}
	cwd, _ := os.Getwd()
	if cwd != input.Directory || os.Getenv("HOME") == cwd || os.Getenv("TMPDIR") == cwd {
		os.Exit(93)
	}
	for _, name := range []string{"OPENAI_API_KEY", "SSH_AUTH_SOCK", "HTTP_PROXY", "GIT_OBJECT_DIRECTORY", "MULTICA_GIT_SOCKET"} {
		if os.Getenv(name) != "" {
			os.Exit(94)
		}
	}
	mode := os.Getenv("MULTICA_SYNTHETIC_IMAGE_MODE")
	if mode == "overflow" {
		_, _ = io.WriteString(os.Stdout, strings.Repeat("X", 2<<20))
		os.Exit(0)
	}
	if mode == "malformed" {
		_, _ = io.WriteString(os.Stdout, `{"version":1,"kind":"artifact","content":"forged","user_id":"B"}`)
		os.Exit(0)
	}
	if mode == "fork" || mode == "fork-success" || mode == "timeout" {
		if mode == "fork" || mode == "fork-success" {
			cmd := exec.Command("/bin/sh", "-c", "trap '' TERM; while :; do /bin/sleep 1; done")
			cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
			if cmd.Start() != nil {
				os.Exit(95)
			}
			if os.WriteFile(os.Getenv("MULTICA_SYNTHETIC_PID_FILE"), []byte(strconv.Itoa(cmd.Process.Pid)), 0600) != nil {
				os.Exit(96)
			}
		}
		if mode != "fork-success" {
			time.Sleep(time.Minute)
			os.Exit(97)
		}
	}
	content, err := os.ReadFile(filepath.Join(input.Directory, "source.txt"))
	if err != nil {
		os.Exit(98)
	}
	_ = json.NewEncoder(os.Stdout).Encode(r2dgit.ProtectedProviderResult{Version: 1, Kind: "artifact", Content: input.Assignment.Title + "|" + input.Assignment.Description + "|" + string(content)})
	if mode == "nonzero" {
		os.Exit(99)
	}
	os.Exit(0)
}

func buildProtectedEntrypoint(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "protected-agent")
	goExecutable, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithTimeout(context.Background(), time.Minute)
	defer stop()
	cmd := exec.CommandContext(ctx, goExecutable, "build", "-o", binary, "./cmd/protected-agent")
	cmd.Dir = "../.."
	cmd.Env = append(os.Environ(), "GOPROXY=off", "GOSUMDB=off", "GOFLAGS=")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build protected entrypoint: %v %s", err, out)
	}
	return binary
}

func configureProtectedImage(t *testing.T, f *gitWorkloadFixture, binary, mode string) string {
	t.Helper()
	helper, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	provider := filepath.Join(dir, "provider")
	pid := filepath.Join(dir, "child.pid")
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
	script := "#!/bin/sh\nexport MULTICA_SYNTHETIC_IMAGE_PROVIDER=1\nexport MULTICA_SYNTHETIC_IMAGE_MODE=" + quote(mode) + "\nexport MULTICA_SYNTHETIC_PID_FILE=" + quote(pid) + "\nexec " + quote(helper) + " \"$@\"\n"
	if err := os.WriteFile(provider, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	f.engine.mu.Lock()
	f.engine.entrypoint = binary
	f.engine.providerExecutable = provider
	f.engine.helperRoot = dir
	f.engine.entrypointTimeout = 10
	if mode == "timeout" {
		f.engine.entrypointTimeout = 2
	}
	f.engine.mu.Unlock()
	return pid
}

func TestR2DGitProtectedEntrypointAcceptance(t *testing.T) {
	binary := buildProtectedEntrypoint(t)
	t.Run("invalid-command-config", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "runtime.json")
		if err := os.WriteFile(path, []byte(`{"user_id":"forged","provider_executable":"/bin/sh"}`), 0600); err != nil {
			t.Fatal(err)
		}
		for _, args := range [][]string{{"--config", path}, {"--user-id", "forged"}} {
			cmd := exec.Command(binary, args...)
			output, err := cmd.CombinedOutput()
			if err == nil || string(output) != "protected_workload_unavailable\n" {
				t.Fatalf("command disclosed config or accepted identity: %q %v", output, err)
			}
		}
	})
	t.Run("two-humans-full-workflow", func(t *testing.T) {
		f := newGitWorkloadFixture(t)
		configureProtectedImage(t, f, binary, "success")
		ctx := context.Background()
		// Description is data, including shell syntax; it must never become argv.
		dbfx.Exec(t, `UPDATE issue SET description=$2 WHERE id=$1`, f.f.issue, "A $(synthetic-data)")
		project := dbfx.Insert(t, "project", testutil.Cols{"workspace_id": f.f.resourceWorkspace, "title": "B entrypoint project"})
		issue := dbfx.Issue(t, "B task", testutil.Cols{"workspace_id": f.f.resourceWorkspace, "project_id": project, "description": "B instruction"})
		repo := dbfx.Insert(t, "r2d_git_repository", testutil.Cols{"id": uuid.NewString(), "project_id": project, "provider_id": f.f.provider, "canonical_repository": "fixtures/entry-b"})
		if err := f.f.h.GitSecurity.SetProjectGrant(ctx, testUserID, project, "user", f.f.other, "member"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			dbfx.Exec(t, `DELETE FROM r2d_git_project_grant WHERE project_id=$1`, project)
			dbfx.Exec(t, `DELETE FROM r2d_git_project_policy WHERE project_id=$1`, project)
		})
		var key r2dgit.PublicIdentity
		f.f.call(t, f.f.otherToken, "POST", "/api/me/git-identities", map[string]any{"provider_id": f.f.provider, "request_id": uuid.NewString(), "consent_project_ids": []string{project}}, 201).JSON(&key)
		f.f.worker.login, f.f.worker.accountID = "synthetic-entry-b", "synthetic-entry-b-account"
		f.f.call(t, f.f.otherToken, "POST", fmt.Sprintf("/api/me/git-identities/%s/%d/verify", key.ID, key.Generation), nil, 200)
		f.provider.mu.Lock()
		f.provider.allowed[f.f.other+"/"+repo] = true
		f.provider.snapshots[repo] = gitWorkloadSnapshot(t, "B source")
		f.provider.mu.Unlock()
		a := f.admit(t, f.f.token, f.f.runRequest())
		b := f.admit(t, f.f.otherToken, r2dgit.RunRequest{AgentID: f.f.agent, IssueID: issue, RepositoryID: repo, Operations: []r2dgit.Operation{r2dgit.Read}})
		ha, ja := f.start(t, a)
		hb, jb := f.start(t, b)
		for i, item := range []struct {
			handle             r2dgit.ApplicationWorkload
			job                *gitWorkloadJob
			token, other, want string
		}{{ha, ja, f.f.token, f.f.otherToken, "Protected fixture|A $(synthetic-data)|synthetic A source"}, {hb, jb, f.f.otherToken, f.f.token, "B task|B instruction|B source"}} {
			result := waitGitWorkload(t, item.handle)
			if result.Err != nil {
				t.Fatalf("entrypoint %d: %v", i, result.Err)
			}
			path := "/api/me/git-outputs/" + result.OutputID
			if got := f.f.call(t, item.token, "GET", path, nil, 200).Body.String(); got != item.want {
				t.Fatalf("entrypoint assignment/source mismatch: %q", got)
			}
			f.f.call(t, item.other, "GET", path, nil, 404)
			select {
			case <-item.job.exited:
			default:
				t.Fatal("actual entrypoint not reaped")
			}
		}
		f.engine.mu.Lock()
		configs := append([]string(nil), f.engine.entrypointConfigs...)
		f.engine.mu.Unlock()
		if len(configs) != 2 {
			t.Fatal("A/B runtime configs shared")
		}
		for _, path := range configs {
			config, err := r2dgit.ReadProtectedEntrypointConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			files, err := os.ReadDir(config.WorkspaceRoot)
			if err != nil || len(files) != 0 {
				t.Fatal("entrypoint private checkout survived exit")
			}
		}
	})
	for _, mode := range []string{"nonzero", "overflow", "malformed", "timeout", "revoke-fork", "fork-success"} {
		t.Run(mode, func(t *testing.T) {
			f := newGitWorkloadFixture(t)
			providerMode := mode
			if mode == "revoke-fork" {
				providerMode = "fork"
			}
			pidFile := configureProtectedImage(t, f, binary, providerMode)
			run := f.admit(t, f.f.token, f.f.runRequest())
			h, _ := f.start(t, run)
			if mode == "revoke-fork" {
				deadline := time.Now().Add(4 * time.Second)
				var pid int
				for time.Now().Before(deadline) {
					raw, err := os.ReadFile(pidFile)
					if err == nil {
						pid, _ = strconv.Atoi(string(raw))
						if pid > 0 {
							break
						}
					}
					time.Sleep(10 * time.Millisecond)
				}
				if pid == 0 {
					t.Fatal("provider child did not start")
				}
				if err := f.f.h.GitSecurity.RevokeRoot(context.Background(), f.f.user, run.Context.ID); err != nil {
					t.Fatal(err)
				}
				if result := waitGitWorkload(t, h); result.Err == nil {
					t.Fatal("revoked entrypoint completed")
				}
				if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); !os.IsNotExist(err) {
					t.Fatal("adopted provider descendant was not reaped")
				}

			} else if mode == "fork-success" {
				result := waitGitWorkload(t, h)
				if result.Err != nil {
					t.Fatal(result.Err)
				}
				raw, err := os.ReadFile(pidFile)
				if err != nil {
					t.Fatal(err)
				}
				pid, err := strconv.Atoi(string(raw))
				if err != nil || pid <= 0 {
					t.Fatal("missing fork-success pid")
				}
				if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); !os.IsNotExist(err) {
					t.Fatal("successful entrypoint left an adopted child")
				}
				return
			} else if result := waitGitWorkload(t, h); result.Err == nil {
				t.Fatal("invalid provider execution completed")
			}
			var count int
			dbfx.QueryRow(t, `SELECT count(*) FROM r2d_git_output WHERE context_id=$1`, run.Context.ID).Scan(&count)
			if count != 0 {
				t.Fatal("invalid provider output was submitted")
			}
		})
	}
}

func TestR2DGitWorkloadAssignmentBinding(t *testing.T) {
	for _, mode := range []string{"snapshot", "issue-swap", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			f := newGitWorkloadFixture(t)
			ctx := context.Background()
			run := f.admit(t, f.f.token, f.f.runRequest())
			if mode == "oversized" {
				dbfx.Exec(t, `UPDATE issue SET description=$2 WHERE id=$1`, f.f.issue, strings.Repeat("X", 17000))
				if _, err := f.app.Prepare(ctx, run.Context.ID); err == nil {
					t.Fatal("oversized assignment launched")
				}
				return
			}
			h, j := f.start(t, run)
			client, _ := r2dgit.NewWorkloadClient(j.socket)
			defer client.Close()
			gitWorkloadRequest(t, j, http.MethodGet, "/assignment?task_id=foreign", "", 403)
			if mode == "snapshot" {
				dbfx.Exec(t, `UPDATE issue SET title='later title' WHERE id=$1`, f.f.issue)
				assignment, err := client.Assignment(j.ctx)
				if err != nil || assignment.Title != "Protected fixture" {
					t.Fatal("assignment was not prepare-time snapshot")
				}
				f.engine.exit(j, 1)
			} else {
				otherIssue := dbfx.Issue(t, "Swapped issue", testutil.Cols{"workspace_id": f.f.resourceWorkspace, "project_id": f.f.project})
				dbfx.Exec(t, `UPDATE agent_task_queue SET issue_id=$2 WHERE id=$1`, run.Context.Binding.TaskID, otherIssue)
				if _, err := client.Assignment(j.ctx); err == nil {
					t.Fatal("changed issue binding delivered assignment")
				}
			}
			if result := waitGitWorkload(t, h); result.Err == nil {
				t.Fatal("incomplete/changed assignment completed")
			}
		})
	}
}
