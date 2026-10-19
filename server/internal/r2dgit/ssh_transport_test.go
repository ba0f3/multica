package r2dgit

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type syntheticSigners map[string]ssh.Signer

func (s syntheticSigners) WithSigner(_ context.Context, ref string, fn func(ssh.Signer) error) error {
	key, ok := s[ref]
	if !ok {
		return ErrIdentity
	}
	return fn(key)
}
func syntheticSigner(t *testing.T, seed byte) ssh.Signer {
	t.Helper()
	s, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type syntheticRegistry struct {
	targets   map[string]TransportTarget
	owners    map[string]string
	protected map[string]bool
}

func (r syntheticRegistry) CheckGitWritePolicy(ctx context.Context, op BoundOperation) error {
	if _, err := r.ResolveGitOperation(ctx, op); err != nil {
		return err
	}
	if r.protected[op.Ref] {
		return ErrScope
	}
	return nil
}

func (r syntheticRegistry) ResolveGitVerification(_ context.Context, provider, id string, generation uint64, ref string) (string, error) {
	if generation != 2 {
		return "", ErrIdentity
	}
	for key, target := range r.targets {
		if strings.HasPrefix(key, id+":") && target.Provider.ID == provider && target.SecretRef == ref {
			return target.Fingerprint, nil
		}
	}
	return "", ErrIdentity
}

func (r syntheticRegistry) ResolveGitOperation(_ context.Context, op BoundOperation) (TransportTarget, error) {
	t, ok := r.targets[op.IdentityID+":"+op.RepositoryID]
	if !ok || r.owners[op.IdentityID] != op.UserID || op.Generation != 2 {
		return TransportTarget{}, ErrScope
	}
	return t, nil
}

type localSSHProvider struct {
	mu          sync.Mutex
	allowed     map[string]map[string]string
	logins      map[string]string
	seen        []string
	listener    net.Listener
	provider    Provider
	git         string
	kind        string
	connections map[net.Conn]bool
	wg          sync.WaitGroup
	beforeGit   func(string, ssh.Channel)
	afterGit    func(string, ssh.Channel)
}

func fixtureGit(t *testing.T, dir string, args ...string) []byte {
	t.Helper()
	git, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(git, args...)
	cmd.Dir = dir
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + dir, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0", "LC_ALL=C"}
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("synthetic git fixture: %v %s", err, b)
	}
	return b
}
func localRepository(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	fixtureGit(t, dir, "init", "-b", "main")
	if err := os.WriteFile(filepath.Join(dir, "synthetic.txt"), []byte("synthetic source only\n"), 0600); err != nil {
		t.Fatal(err)
	}
	fixtureGit(t, dir, "add", "synthetic.txt")
	fixtureGit(t, dir, "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid", "commit", "--no-gpg-sign", "-m", "synthetic")
	return dir
}
func newLocalSSHProvider(t *testing.T, a, b ssh.Signer, repo string) *localSSHProvider {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	host := syntheticSigner(t, 99)
	git, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	f := &localSSHProvider{listener: listener, git: git, connections: map[net.Conn]bool{}, allowed: map[string]map[string]string{}, logins: map[string]string{ssh.FingerprintSHA256(a.PublicKey()): "alice", ssh.FingerprintSHA256(b.PublicKey()): "bob"}}
	f.allowed["alice"] = map[string]string{"owner/only-a": repo, "owner/shared": repo}
	f.allowed["bob"] = map[string]string{"owner/shared": repo}
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	n, _ := strconv.Atoi(port)
	f.provider = Provider{ID: "provider-a", Kind: "github", Host: "127.0.0.1", Port: n, HostPins: []string{ssh.FingerprintSHA256(host.PublicKey())}}
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		login := f.logins[ssh.FingerprintSHA256(key)]
		if login == "" {
			return nil, fmt.Errorf("synthetic key denied")
		}
		return &ssh.Permissions{Extensions: map[string]string{"login": login}}, nil
	}}
	cfg.AddHostKey(host)
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			f.mu.Lock()
			f.connections[c] = true
			f.mu.Unlock()
			f.wg.Add(1)
			go func() {
				defer f.wg.Done()
				defer c.Close()
				conn, ch, req, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				defer conn.Close()
				go ssh.DiscardRequests(req)
				for channel := range ch {
					f.serve(channel, conn.Permissions.Extensions["login"])
				}
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		f.mu.Lock()
		for c := range f.connections {
			_ = c.Close()
		}
		f.mu.Unlock()
		f.wg.Wait()
	})
	return f
}
func (f *localSSHProvider) serve(in ssh.NewChannel, login string) {
	if in.ChannelType() != "session" {
		_ = in.Reject(ssh.UnknownChannelType, "session required")
		return
	}
	ch, requests, err := in.Accept()
	if err != nil {
		return
	}
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		defer ch.Close()
		for req := range requests {
			switch req.Type {
			case "shell":
				_ = req.Reply(true, nil)
				f.mu.Lock()
				kind := f.kind
				f.mu.Unlock()
				code := uint32(1)
				if kind == "gitea" {
					code = 0
					_, _ = fmt.Fprintf(ch.Stderr(), "Hi there, %s! You've successfully authenticated with the SSH key named synthetic.\nGitea does not provide shell access. If this is unexpected, please setup Gitea under another SSH user or use container to deploy.", login)
				} else {
					_, _ = fmt.Fprintf(ch.Stderr(), "Hi %s! You've successfully authenticated, but GitHub does not provide shell access.\n", login)
				}
				_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{code}))
				return
			case "exec":
				var command struct{ Command string }
				if ssh.Unmarshal(req.Payload, &command) != nil {
					_ = req.Reply(false, nil)
					return
				}
				f.mu.Lock()
				f.seen = append(f.seen, login+":"+command.Command)
				var dir string
				service := "upload-pack"
				for repo, path := range f.allowed[login] {
					if command.Command == "git-upload-pack '"+repo+".git'" || command.Command == "git-receive-pack '"+repo+".git'" {
						if strings.HasPrefix(command.Command, "git-receive-pack ") {
							service = "receive-pack"
						}
						dir = path
					}
				}
				before, after := f.beforeGit, f.afterGit
				f.mu.Unlock()
				_ = req.Reply(true, nil)
				if dir == "" {
					_, _ = ch.Stderr().Write([]byte("synthetic repository denied"))
					_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{1}))
					return
				}
				if before != nil {
					before(service, ch)
				}
				cmd := exec.Command(f.git, service, dir)
				cmd.Env = []string{"HOME=" + dir, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "LC_ALL=C"}
				cmd.Stdin, cmd.Stdout, cmd.Stderr = ch, ch, ch.Stderr()
				code := uint32(0)
				if cmd.Run() != nil {
					code = 1
				}
				if after != nil {
					after(service, ch)
				}
				_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{code}))
				return
			default:
				_ = req.Reply(false, nil)
			}
		}
	}()
}

func TestSSHWorkerPinnedIdentityAndRealGitPack(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("pack validation worker requires Linux resource controls")
	}
	a, b := syntheticSigner(t, 1), syntheticSigner(t, 2)
	repo := localRepository(t)
	remote := newLocalSSHProvider(t, a, b, repo)
	registry := syntheticRegistry{targets: map[string]TransportTarget{}, owners: map[string]string{"identity-a": "human-a", "identity-b": "human-b"}}
	for id, key := range map[string]ssh.Signer{"identity-a": a, "identity-b": b} {
		for rid, path := range map[string]string{"repo-a": "owner/only-a", "shared": "owner/shared"} {
			registry.targets[id+":"+rid] = TransportTarget{Provider: remote.provider, Repository: path, SecretRef: id, Fingerprint: ssh.FingerprintSHA256(key.PublicKey())}
		}
	}
	git, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	w, err := NewSSHWorker(registry, syntheticSigners{"identity-a": a, "identity-b": b}, map[string][]netip.Prefix{"provider-a": {netip.MustParsePrefix("127.0.0.1/32")}}, GitQuarantine{GitExecutable: git, Root: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for id, login := range map[string]string{"identity-a": "alice", "identity-b": "bob"} {
		proof, err := w.Verify(ctx, remote.provider, id, id, 2)
		if err != nil || proof.Login != login || !proof.HostPinned {
			t.Fatalf("SSH enrollment %s: %+v %v", id, proof, err)
		}
	}
	wrongKeyWorker, err := NewSSHWorker(registry, syntheticSigners{"identity-a": b}, map[string][]netip.Prefix{"provider-a": {netip.MustParsePrefix("127.0.0.1/32")}}, w.validator)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongKeyWorker.Verify(ctx, remote.provider, "identity-a", "identity-a", 2); err == nil {
		t.Fatal("custody returned another identity key and verification accepted it")
	}
	op := BoundOperation{UserID: "human-a", IdentityID: "identity-a", Generation: 2, ProviderID: "provider-a", RepositoryID: "repo-a", ContextID: "context-a", TaskID: "task-a", AttemptID: "attempt-a", Operation: Read}
	broker, lease, _, _, _ := brokerFixture(t)
	broker.Transport = w
	w.validator = &deadlinePackValidator{t: t, inner: w.validator}
	for _, warm := range []bool{false, true} {
		if err := w.ProveRepository(ctx, op); err != nil {
			t.Fatalf("repository proof warm=%t: %v", warm, err)
		}
		snapshot, err := broker.ReadSnapshot(ctx, lease, "channel-a", fmt.Sprintf("local-ssh-%t", warm))
		pack := snapshot.Pack
		if !objectID(snapshot.Head) || snapshot.Head == zeroObject {
			t.Fatalf("snapshot lost authenticated HEAD: %q", snapshot.Head)
		}
		if err != nil || !bytes.HasPrefix(pack, []byte("PACK")) {
			t.Fatalf("read warm=%t: len=%d err=%v", warm, len(pack), err)
		}
	}
	op.UserID, op.IdentityID = "human-b", "identity-b"
	if err := w.ProveRepository(ctx, op); err == nil {
		t.Fatal("B obtained proof for A-only repository")
	}
	if data, err := w.Read(ctx, op); len(data) != 0 || err == nil {
		t.Fatal("B read A-only pack")
	}
	op.RepositoryID = "shared"
	if data, err := w.Read(ctx, op); len(data) == 0 || err != nil {
		t.Fatalf("B shared repository control failed: %v", err)
	}
	op.UserID = "human-a"
	if _, err := w.Read(ctx, op); err == nil {
		t.Fatal("identity owner substitution accepted")
	}
	op.UserID = "human-b"
	op.Generation = 1
	if _, err := w.Read(ctx, op); err == nil {
		t.Fatal("old generation accepted")
	}
	bad := remote.provider
	bad.HostPins = []string{ssh.FingerprintSHA256(a.PublicKey())}
	if _, err := w.Verify(ctx, bad, "identity-a", "identity-a", 2); err == nil {
		t.Fatal("wrong server pin accepted")
	}
	bad = remote.provider
	bad.Kind = "unsupported"
	if _, err := w.Verify(ctx, bad, "identity-a", "identity-a", 2); err == nil {
		t.Fatal("unsupported provider silently verified")
	}
	remote.mu.Lock()
	remote.kind = "gitea"
	remote.mu.Unlock()
	gitea := remote.provider
	gitea.Kind = "gitea"
	for id, login := range map[string]string{"identity-a": "alice", "identity-b": "bob"} {
		proof, err := w.Verify(ctx, gitea, id, id, 2)
		if err != nil || proof.Login != login {
			t.Fatalf("Gitea account verification: %+v %v", proof, err)
		}
	}
	remote.mu.Lock()
	delete(remote.allowed["alice"], "owner/only-a")
	remote.mu.Unlock()
	op.UserID, op.IdentityID, op.Generation, op.RepositoryID = "human-a", "identity-a", 2, "repo-a"
	if err := w.ProveRepository(ctx, op); err == nil {
		t.Fatal("external ACL revocation did not deny warm proof")
	}
}

type deadlinePackValidator struct {
	t     *testing.T
	inner PackValidator
}

func (v *deadlinePackValidator) Validate(ctx context.Context, pack []byte, head string) error {
	v.t.Helper()
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > 10*time.Second {
		v.t.Error("SSH operation deadline did not reach validator")
		return ErrUnavailable
	}
	return v.inner.Validate(ctx, pack, head)
}

func TestGiteaSSHRequiresAccountKeyResponse(t *testing.T) {
	footer := "\nGitea does not provide shell access. If this is unexpected, please setup Gitea under another SSH user or use container to deploy."
	account := "Hi there, alice! You've successfully authenticated with the SSH key named synthetic." + footer
	if login, err := verifyGiteaSSH("", account, 0, true); err != nil || login != "alice" {
		t.Fatal("account key positive control failed")
	}
	for _, response := range []string{"", "Hi there! You've successfully authenticated with an SSH deploy key." + footer, "Hi there! You've successfully authenticated with the SSH principal alice." + footer, account + "\nextra", strings.Replace(account, "synthetic.", "synthetic.\nforged", 1)} {
		if _, err := verifyGiteaSSH("", response, 0, true); err == nil {
			t.Fatal("non-account/ambiguous proof accepted")
		}
	}
	if _, err := verifyGiteaSSH("", account, 1, true); err == nil {
		t.Fatal("wrong provider exit semantics accepted")
	}
	if _, err := verifyGiteaSSH("", account, 0, false); err == nil {
		t.Fatal("unpinned response accepted")
	}
}

func TestSSHWorkerRejectsAuthorityAndProtocolSubstitution(t *testing.T) {
	a := syntheticSigner(t, 1)
	registry := syntheticRegistry{targets: map[string]TransportTarget{"identity:repo-a": {Provider: Provider{ID: "provider-a"}, SecretRef: "key", Fingerprint: ssh.FingerprintSHA256(a.PublicKey())}}}
	w, err := NewSSHWorker(registry, syntheticSigners{"key": a}, map[string][]netip.Prefix{"provider-a": {netip.MustParsePrefix("192.0.2.1/32")}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	p := Provider{ID: "provider-a", Kind: "github", Host: "127.0.0.1", Port: 22, HostPins: []string{"pin"}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := w.Verify(ctx, p, "key", "identity", 2); err == nil {
		t.Fatal("unlisted loopback authority reached")
	}
	for _, text := range []string{"0000", "0003", "ffff", "0008notgit", "zzzz"} {
		if _, err := readAdvertisement(bufioReader(text)); err == nil {
			t.Fatal("malformed advertisement accepted", text)
		}
	}
}

func bufioReader(s string) *bufio.Reader { return bufio.NewReader(strings.NewReader(s)) }

func TestGitQuarantineRejectsCorruptionAndExternalSources(t *testing.T) {
	repo := localRepository(t)
	git, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	q := GitQuarantine{GitExecutable: git, Root: t.TempDir()}
	if err := q.Validate(context.Background(), []byte("PACKbad"), strings.Repeat("a", 40)); err == nil {
		t.Fatal("invalid pack accepted")
	}
	if err := os.WriteFile(filepath.Join(repo, ".gitmodules"), []byte("synthetic unsupported submodule\n"), 0600); err != nil {
		t.Fatal(err)
	}
	fixtureGit(t, repo, "add", ".gitmodules")
	fixtureGit(t, repo, "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid", "commit", "--no-gpg-sign", "-m", "unsupported")
	head := strings.TrimSpace(string(fixtureGit(t, repo, "rev-parse", "HEAD")))
	cmd := exec.Command(git, "-C", repo, "pack-objects", "--stdout", "--all")
	cmd.Env = []string{"HOME=" + repo, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null"}
	pack, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Validate(context.Background(), pack, head); err == nil {
		t.Fatal("unsupported submodule metadata accepted")
	}
	if binary.BigEndian.Uint32(pack[4:8]) != 2 {
		t.Fatal("fixture did not produce a real version2 pack")
	}
}
