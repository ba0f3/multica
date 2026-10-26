package daemon

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestTaskRepoGitEnvironmentScopesGitHubSSHRewrite(t *testing.T) {
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "custom.setting")
	t.Setenv("GIT_CONFIG_VALUE_0", "preserved")
	t.Setenv("SSH_AUTH_SOCK", "/host/agent.sock")
	for _, tc := range []struct {
		name, host, socket, url, want string
		port                          int
	}{
		{"verified GitHub", "github.com", "/task/agent.sock", "https://github.com/ba0f3/xpfarm.git", "ssh://git@github.com/ba0f3/xpfarm.git", 22},
		{"no signing socket", "github.com", "", "https://github.com/ba0f3/xpfarm.git", "https://github.com/ba0f3/xpfarm.git", 22},
		{"unrelated credential", "git.example.com", "/task/agent.sock", "https://github.com/ba0f3/xpfarm.git", "https://github.com/ba0f3/xpfarm.git", 22},
		{"explicit Gitea port", "git.r2d.dev", "/task/agent.sock", "ssh://git@git.r2d.dev:2222/r2d/repo.git", "ssh://git@git.r2d.dev:2222/r2d/repo.git", 2222},
		{"Gitea HTTPS", "git.r2d.dev", "/task/agent.sock", "https://git.r2d.dev/hai-tac/gms.git", "ssh://git@git.r2d.dev:2222/hai-tac/gms.git", 2222},
		{"Gitea web port", "git.r2d.dev", "/task/agent.sock", "http://git.r2d.dev:3000/hai-tac/gms.git", "ssh://git@git.r2d.dev:2222/hai-tac/gms.git", 2222},
		{"older server default port", "git.example.com", "/task/agent.sock", "https://git.example.com/team/repo.git", "ssh://git@git.example.com/team/repo.git", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			task := Task{Repos: []RepoData{{URL: tc.url}}, GitIdentities: []GitIdentityBinding{{Host: tc.host, Port: tc.port}}}
			env := taskRepoGitEnvironment(task, tc.socket)
			cmd := exec.Command("git", "ls-remote", "--get-url", tc.url)
			cmd.Env = env
			out, err := cmd.Output()
			if err != nil || strings.TrimSpace(string(out)) != tc.want {
				t.Fatalf("transport URL = %q, error %v; want %q", out, err, tc.want)
			}
			cmd = exec.Command("git", "config", "--get", "custom.setting")
			cmd.Env = env
			if out, err := cmd.Output(); err != nil || strings.TrimSpace(string(out)) != "preserved" {
				t.Fatalf("existing Git configuration was lost: %q, %v", out, err)
			}
			lastSocket := ""
			for _, entry := range env {
				if value, ok := strings.CutPrefix(entry, "SSH_AUTH_SOCK="); ok {
					lastSocket = value
				}
			}
			if lastSocket != tc.socket {
				t.Fatalf("SSH_AUTH_SOCK = %q, want %q", lastSocket, tc.socket)
			}
		})
	}
	if os.Getenv("SSH_AUTH_SOCK") != "/host/agent.sock" || os.Getenv("GIT_CONFIG_COUNT") != "1" {
		t.Fatal("task authentication changed the daemon environment")
	}
}

func TestPickGitIdentityMatchesTheRepositoryHost(t *testing.T) {
	task := Task{
		Repos: []RepoData{
			{URL: "git@github.com:acme/api.git"},
			{URL: "ssh://git@git.example.com/acme/web.git"},
		},
		GitIdentities: []GitIdentityBinding{
			{ProviderID: "provider-gitea", Host: "git.example.com", IdentityID: "identity-2"},
			{ProviderID: "provider-github", Host: "github.com", IdentityID: "identity-1"},
		},
	}

	binding := pickGitIdentity(task)
	if binding == nil {
		t.Fatal("no identity was picked for a task whose repository has a matching provider")
	}
	// The first repository is on github.com, so the GitHub credential wins.
	if binding.ProviderID != "provider-github" {
		t.Fatalf("provider id = %q, want %q", binding.ProviderID, "provider-github")
	}
}

func TestPickGitIdentityReturnsNilWhenNoProviderMatches(t *testing.T) {
	task := Task{
		Repos:         []RepoData{{URL: "git@git.other.example:acme/api.git"}},
		GitIdentities: []GitIdentityBinding{{ProviderID: "provider-github", Host: "github.com"}},
	}

	if binding := pickGitIdentity(task); binding != nil {
		t.Fatalf("an unrelated provider was picked: %+v", binding)
	}
}

func TestPickGitIdentityReturnsNilWithoutCredentials(t *testing.T) {
	task := Task{Repos: []RepoData{{URL: "git@github.com:acme/api.git"}}}
	if binding := pickGitIdentity(task); binding != nil {
		t.Fatalf("an identity was picked for a task with no credentials: %+v", binding)
	}
}

func TestValidateGitCredentialForTaskAllowsMissingCredential(t *testing.T) {
	task := Task{
		Repos: []RepoData{{URL: "git@github.com:acme/api.git"}},
	}
	if err := validateGitCredentialForTask(task, ""); err != nil {
		t.Fatalf("missing credentials must not block task startup: %v", err)
	}
}

func TestValidateGitCredentialForTaskAllowsUnmatchedRepository(t *testing.T) {
	task := Task{
		Repos: []RepoData{
			{URL: "git@github.com:acme/api.git"},
			{URL: "ssh://git@git.r2d.dev:2222/r2d/sveltia-test.git"},
		},
		GitIdentities: []GitIdentityBinding{{ProviderID: "provider-gitea", Host: "git.r2d.dev"}},
	}
	if err := validateGitCredentialForTask(task, "/tmp/fake.sock"); err != nil {
		t.Fatalf("an unrelated repository must not block task startup: %v", err)
	}
}

func TestValidateGitCredentialForTaskRejectsUnavailableSigning(t *testing.T) {
	task := Task{
		Repos:         []RepoData{{URL: "git@github.com:acme/api.git"}},
		GitIdentities: []GitIdentityBinding{{ProviderID: "provider-github", Host: "github.com"}},
	}
	err := validateGitCredentialForTask(task, "")
	if err == nil || !strings.Contains(err.Error(), "git signing is unavailable") {
		t.Fatalf("expected unavailable signing error, got %v", err)
	}
}

func TestMissingGitSupervisorAuthorizationExplainsUpgrade(t *testing.T) {
	task := gitAgentTestTask()
	task.GitSigningDaemonToken = ""
	err := validateGitCredentialForTask(task, "")
	if err == nil || !strings.Contains(err.Error(), "update the backend and daemon") || strings.Contains(err.Error(), "Check connection") {
		t.Fatalf("missing supervisor authorization must identify deployment recovery: %v", err)
	}
}

func TestValidateGitCredentialForTaskAllowsReadyCredential(t *testing.T) {
	task := Task{
		Repos: []RepoData{{URL: "git@github.com:acme/api.git"}},
		GitIdentities: []GitIdentityBinding{
			{ProviderID: "provider-github", Host: "github.com"},
		},
	}
	if err := validateGitCredentialForTask(task, "/tmp/fake.sock"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRepositoryHostParsesBothURLForms(t *testing.T) {
	cases := map[string]string{
		"git@github.com:acme/api.git":             "github.com",
		"ssh://git@git.example.com/acme/web.git":  "git.example.com",
		"https://github.com/acme/api.git":         "github.com",
		"https://gitea.example.com:3000/acme/api": "gitea.example.com",
		"":          "",
		"not a url": "",
	}
	for raw, want := range cases {
		if got := repositoryHost(raw); got != want {
			t.Errorf("repositoryHost(%q) = %q, want %q", raw, got, want)
		}
	}
}
