package daemon

import (
	"strings"
	"testing"
)

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
