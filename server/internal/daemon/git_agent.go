package daemon

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/multica-ai/multica/server/internal/daemon/gitagent"
	"github.com/multica-ai/multica/server/internal/daemon/repocache"
)

// taskRepoGitEnvironment supplies cache Git calls with the task's signing
// lease and maps HTTP clone URLs to the provider's SSH endpoint.
func taskRepoGitEnvironment(task Task, socketPath string) []string {
	env := repocache.GitEnv()
	// Never borrow the daemon owner's SSH agent for a task.
	env = append(env, "SSH_AUTH_SOCK="+socketPath)
	binding := pickGitIdentity(task)
	if socketPath == "" || binding == nil {
		return env
	}
	count := 0
	for _, entry := range env {
		if value, ok := strings.CutPrefix(entry, "GIT_CONFIG_COUNT="); ok {
			count, _ = strconv.Atoi(value)
		}
	}
	endpoint := url.URL{Scheme: "ssh", User: url.User("git"), Host: binding.Host, Path: "/"}
	// Older servers omit the port; SSH's standard port remains the default.
	if binding.Port != 0 && binding.Port != 22 {
		endpoint.Host = net.JoinHostPort(binding.Host, strconv.Itoa(binding.Port))
	}
	seen := make(map[string]bool)
	for _, repo := range task.Repos {
		parsed, err := url.Parse(repo.URL)
		if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Hostname() != binding.Host {
			continue
		}
		prefix := parsed.Scheme + "://" + parsed.Host + "/"
		if seen[prefix] {
			continue
		}
		seen[prefix] = true
		env = append(env,
			"GIT_CONFIG_KEY_"+strconv.Itoa(count)+"=url."+endpoint.String()+".insteadOf",
			"GIT_CONFIG_VALUE_"+strconv.Itoa(count)+"="+prefix,
		)
		count++
	}
	return append(env, "GIT_CONFIG_COUNT="+strconv.Itoa(count))
}

// serverGitSigner forwards signature requests to the server.
//
// The daemon never holds the private key: it presents the lease id and the
// bytes, and receives the signature. That is what keeps a compromised runner
// from reading a key out of the socket it was given.
type serverGitSigner struct {
	client    *Client
	leaseID   string
	publicKey string
}

func (s *serverGitSigner) PublicKey() string { return s.publicKey }

func (s *serverGitSigner) Sign(ctx context.Context, data []byte) ([]byte, error) {
	return s.client.SignGitData(ctx, s.leaseID, data)
}

// validateGitCredentialForTask requires a signing socket only when a matching
// verified credential was supplied. Missing credentials do not block startup.
func validateGitCredentialForTask(task Task, gitSocketPath string) error {
	if binding := pickGitIdentity(task); binding != nil && gitSocketPath == "" {
		return fmt.Errorf(
			"git signing is unavailable for %s; Check connection on your Git credential or retry the task",
			binding.Host,
		)
	}
	return nil
}

// pickGitIdentity chooses the credential whose provider matches one of the
// run's repositories.
//
// A run with no matching repository gets no credential: signing a request to
// a host the user has no key for would fail at the provider anyway, and
// guessing would be worse than starting without Git.
func pickGitIdentity(task Task) *GitIdentityBinding {
	if len(task.GitIdentities) == 0 {
		return nil
	}
	// Walk the repositories in the order the run will work on them: the
	// first repository that has a credential decides which key signs.
	for _, repo := range task.Repos {
		host := repositoryHost(repo.URL)
		if host == "" {
			continue
		}
		for index := range task.GitIdentities {
			if task.GitIdentities[index].Host == host {
				return &task.GitIdentities[index]
			}
		}
	}
	return nil
}

// repositoryHost extracts the host of a clone URL, tolerating both the SSH
// shorthand (git@host:path) and a normal URL.
func repositoryHost(raw string) string {
	if raw == "" {
		return ""
	}
	if parsed, err := url.Parse(raw); err == nil && parsed.Host != "" {
		return parsed.Hostname()
	}
	// scp-like syntax: git@github.com:owner/repo.git
	if at := strings.LastIndexByte(raw, '@'); at >= 0 {
		rest := raw[at+1:]
		if colon := strings.IndexByte(rest, ':'); colon > 0 {
			return rest[:colon]
		}
	}
	return ""
}

// startGitAgentSocket opens a signing lease for the run and starts the
// per-attempt agent socket.
//
// The returned path is what the runner's SSH client reads from
// SSH_AUTH_SOCK. An empty path means the run has no Git credential, which is
// the correct outcome for a run with no provable human originator, no
// verified key or no matching provider.
func (d *Daemon) startGitAgentSocket(ctx context.Context, task Task, profileRoot string, attemptID string) (string, func()) {
	binding := pickGitIdentity(task)
	if binding == nil || d.client == nil {
		return "", func() {}
	}
	lease, err := d.client.OpenGitSigningLease(ctx, task.ID, attemptID, binding.ProviderID)
	if err != nil {
		d.logger.Warn("git: could not open a signing lease", "task_id", task.ID, "error", err)
		return "", func() {}
	}

	if strings.TrimSpace(attemptID) == "" {
		attemptID = task.ID
	}
	// Two full UUIDs exceed the Unix socket path limit under a normal home.
	// Hash both IDs to retain attempt isolation in a shorter directory name.
	socketID := sha256.Sum256([]byte(task.ID + "\x00" + attemptID))
	socketDir := filepath.Join(profileRoot, "git-agent", fmt.Sprintf("%x", socketID[:16]))
	// A crash during an earlier attempt can leave the directory behind, and
	// Serve refuses an existing path. Clearing it here keeps a re-delivered
	// task from being unable to sign forever.
	if removeErr := os.RemoveAll(socketDir); removeErr != nil {
		d.logger.Warn("git: could not clear a stale signing directory", "task_id", task.ID, "error", removeErr)
	}
	socket, err := gitagent.Serve(ctx, gitagent.Options{
		SocketPath: filepath.Join(socketDir, "agent.sock"),
		PublicKey:  lease.PublicKey,
		Signer: &serverGitSigner{
			client:    d.client,
			leaseID:   lease.LeaseID,
			publicKey: lease.PublicKey,
		},
	})
	if err != nil {
		d.logger.Warn("git: could not start the per-task signing socket", "task_id", task.ID, "error", err)
		return "", func() {}
	}
	return socket.Path(), func() {
		_ = socket.Close()
		_ = os.RemoveAll(socketDir)
	}
}
