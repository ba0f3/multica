package daemon

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestWorkerGitTransportRewritesHTTPSAndUsesTaskHostTrust(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "http.extraHeader")
	t.Setenv("GIT_CONFIG_VALUE_0", "HOST_AUTH_MUST_NOT_ESCAPE")
	_, private, err := generateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0700); err != nil {
		t.Fatal(err)
	}
	hostKey := "[git.r2d.dev]:2222 " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))) + "\n"
	if err := os.WriteFile(filepath.Join(home, ".ssh", "known_hosts"), []byte(hostKey), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "id_ed25519"), []byte("PRIVATE_KEY_MUST_NOT_ESCAPE"), 0600); err != nil {
		t.Fatal(err)
	}
	env := newSandboxTestEnv(t)
	task := Task{Repos: []RepoData{{URL: "https://git.r2d.dev/R2D/project.git"}}, GitIdentities: []GitIdentityBinding{{Host: "git.r2d.dev", Port: 2222}}}
	values, err := taskWorkerGitEnvironment(task, "/task/signing.sock", env)
	if err != nil {
		t.Fatal(err)
	}
	if values["SSH_AUTH_SOCK"] != "/task/signing.sock" {
		t.Fatal("worker lost its task signing socket")
	}
	cmd := exec.Command("git", "ls-remote", "--get-url", task.Repos[0].URL)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir()}
	for key, value := range values {
		if strings.Contains(value, "MUST_NOT_ESCAPE") {
			t.Fatal("host secret leaked into worker environment")
		}
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	out, err := cmd.CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "ssh://git@git.r2d.dev:2222/R2D/project.git" {
		t.Fatalf("worker Git transport=%q err=%v", out, err)
	}
	for _, setting := range []string{"BatchMode=yes", "StrictHostKeyChecking=yes", "IdentityFile=none", "UserKnownHostsFile="} {
		if !strings.Contains(values["GIT_SSH_COMMAND"], setting) {
			t.Errorf("missing SSH setting %s", setting)
		}
	}
	data, err := os.ReadFile(filepath.Join(env.RootDir, "git-known-hosts"))
	if err != nil || !strings.Contains(string(data), strings.TrimSpace(hostKey)) || strings.Contains(string(data), "PRIVATE_KEY") {
		t.Fatalf("task host trust missing or includes private data: %v", err)
	}
}

func TestWorkerGitWithoutGrantDoesNotBorrowHostAgent(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "/host/agent.sock")
	values, err := taskWorkerGitEnvironment(Task{}, "", newSandboxTestEnv(t))
	if err != nil {
		t.Fatal(err)
	}
	if socket, ok := values["SSH_AUTH_SOCK"]; !ok || socket != "" {
		t.Fatal("missing credential must explicitly remove an inherited host agent")
	}
}
