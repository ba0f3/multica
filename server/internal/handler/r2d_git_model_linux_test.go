//go:build linux

package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/multica-ai/multica/server/internal/r2dgit"
)

func TestR2DGitCompiledProviderThroughModelGateway(t *testing.T) {
	entrypoint := buildProtectedEntrypoint(t)
	provider := filepath.Join(t.TempDir(), "provider")
	goExecutable, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	build := exec.Command(goExecutable, "build", "-o", provider, "./cmd/protected-provider")
	build.Dir = "../.."
	build.Env = append(os.Environ(), "GOPROXY=off", "GOSUMDB=off", "GOFLAGS=")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("provider build: %v %s", err, out)
	}
	for _, mode := range []string{"success", "missing-model-account", "revocation", "forged-selector", "write-success", "write-readonly", "write-uncertain"} {
		t.Run(mode, func(t *testing.T) {
			f := newGitWorkloadFixture(t)
			write := strings.HasPrefix(mode, "write-")
			if write && mode != "write-readonly" {
				dbfx.Exec(t, `UPDATE r2d_git_repository SET allow_write=true,write_refs='["refs/heads/task/a"]' WHERE id=$1`, f.f.repo)
				f.provider.refs = map[string]string{f.f.repo + "/refs/heads/task/a": f.provider.snapshots[f.f.repo].Head}
				f.provider.uncertainWrite = mode == "write-uncertain"
			}
			var calls atomic.Int32
			entered := make(chan struct{}, 1)
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				var request map[string]any
				if json.NewDecoder(r.Body).Decode(&request) != nil || request["model"] != "synthetic-coding-model" || r.Header.Get("Authorization") != "Bearer synthetic-A-only" || request["store"] != false || len(request) != 5 {
					t.Error("wrong model scope")
				}
				input, _ := request["input"].(string)
				if !strings.Contains(input, "synthetic A source") || strings.Contains(input, "synthetic-poison") {
					t.Error("wrong source or ambient credential reached model")
				}
				entered <- struct{}{}
				if mode == "revocation" {
					<-r.Context().Done()
					return
				}
				w.Header().Set("Content-Type", "application/json")
				text := `{"content":"synthetic model A answer","changes":[]}`
				if write {
					text = `{"content":"synthetic model A answer","changes":[{"path":"source.txt","content":"synthetic model edit"}]}`
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"status": "completed", "output": []any{map[string]any{"type": "message", "role": "assistant", "content": []any{map[string]any{"type": "output_text", "text": text}}}}})
			}))
			defer upstream.Close()
			user := f.f.user
			if mode == "missing-model-account" {
				user = f.f.other
			}
			model, err := r2dgit.NewResponsesGateway(upstream.URL+"/v1/responses", upstream.Client(), []r2dgit.ModelAccount{{UserID: user, Model: "synthetic-coding-model", Token: "synthetic-A-only", ProjectIDs: []string{f.f.project}, ExpiresAt: time.Now().Add(time.Hour)}}, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.app.Close(); err != nil {
				t.Fatal(err)
			}
			f.config.Model = model
			f.config.Quarantine = r2dgit.GitQuarantine{GitExecutable: "/usr/bin/git", Root: t.TempDir()}
			app, err := r2dgit.NewWorkloadApplication(f.f.h.GitSecurity, f.config)
			if err != nil {
				t.Fatal(err)
			}
			f.app = app
			*f.brokerApp = app
			if err := app.Recover(context.Background()); err != nil {
				t.Fatal(err)
			}
			if mode != "forged-selector" {
				f.engine.mu.Lock()
				f.engine.entrypoint = entrypoint
				f.engine.providerBinary = provider
				f.engine.helperRoot = t.TempDir()
				f.engine.entrypointTimeout = 15
				f.engine.mu.Unlock()
			}
			request := f.f.runRequest()
			if write && mode != "write-readonly" {
				request.Operations = []r2dgit.Operation{r2dgit.Read, r2dgit.Write}
				request.WriteRefs = []string{"refs/heads/task/a"}
			}
			run := f.admit(t, f.f.token, request)
			h, j := f.start(t, run)
			if mode == "forged-selector" {
				gitWorkloadRequest(t, j, http.MethodPost, "/model", `{"input":"source","user_id":"forged"}`, 403)
				gitWorkloadRequest(t, j, http.MethodPost, "/model?user_id=forged", `{"input":"source"}`, 403)
				f.engine.exit(j, 1)
			}
			if mode == "revocation" {
				select {
				case <-entered:
				case <-time.After(10 * time.Second):
					t.Fatal("model never entered")
				}
				if err := f.f.h.GitSecurity.RevokeRoot(context.Background(), f.f.user, run.Context.ID); err != nil {
					t.Fatal(err)
				}
			}
			result := waitGitWorkload(t, h)
			if mode == "success" || mode == "write-success" {
				if result.Err != nil {
					t.Fatal(result.Err)
				}
				path := "/api/me/git-outputs/" + result.OutputID
				if got := f.f.call(t, f.f.token, "GET", path, nil, 200).Body.String(); got != "synthetic model A answer" {
					t.Fatalf("wrong restricted model output: %q", got)
				}
				f.f.call(t, f.f.otherToken, "GET", path, nil, 404)
			} else if result.Err == nil {
				t.Fatal("unauthorized model workload completed")
			}
			if mode == "write-success" || mode == "write-uncertain" {
				f.provider.mu.Lock()
				pushes := f.provider.pushes
				tip := f.provider.refs[f.f.repo+"/refs/heads/task/a"]
				f.provider.mu.Unlock()
				if pushes != 1 || tip == f.provider.snapshots[f.f.repo].Head {
					t.Fatal("write did not perform exactly one canonical CAS")
				}
			}
			if (mode == "missing-model-account" || mode == "forged-selector") && calls.Load() != 0 {
				t.Fatal("unauthorized workload reached upstream")
			}
		})
	}
}
