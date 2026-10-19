package r2dgit

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// All authority mutations use this lock; the real watchdog runs concurrently.
type pushAuthority struct {
	mu     sync.Mutex
	rights CurrentRights
	outage bool
}

func (a *pushAuthority) Current(ctx context.Context, _ ContextSpec, _ GrantSpec) (CurrentRights, error) {
	a.mu.Lock()
	r, down := a.rights, a.outage
	a.mu.Unlock()
	if down {
		<-ctx.Done()
		return CurrentRights{}, ctx.Err()
	}
	return r, nil
}
func (a *pushAuthority) change(f func(*CurrentRights)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	f(&a.rights)
}

func pushFixture(t *testing.T) (Broker, Lease, *pushAuthority, *localSSHProvider, string, *fixtureJournal) {
	t.Helper()
	a, b := syntheticSigner(t, 1), syntheticSigner(t, 2)
	repo := localRepository(t)
	remote := newLocalSSHProvider(t, a, b, repo)
	registry := syntheticRegistry{targets: map[string]TransportTarget{"identity-a:repo-a": {Provider: remote.provider, Repository: "owner/only-a", SecretRef: "identity-a", Fingerprint: ssh.FingerprintSHA256(a.PublicKey())}}, owners: map[string]string{"identity-a": "human-a"}}
	git, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	q := GitQuarantine{GitExecutable: git, Root: t.TempDir()}
	worker, err := NewSSHWorker(registry, syntheticSigners{"identity-a": a}, map[string][]netip.Prefix{"provider-a": {netip.MustParsePrefix("127.0.0.1/32")}}, q)
	if err != nil {
		t.Fatal(err)
	}
	r, g, old := fixture(t)
	authority := &pushAuthority{rights: old.rights}
	lease, err := IssueLease(context.Background(), Authorizer{authority}, r, g, "channel-a", Write, "refs/heads/task/a", fixtureNow, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	j := &fixtureJournal{}
	return Broker{Authorizer: Authorizer{authority}, Transport: worker, Journal: j, Now: func() time.Time { return fixtureNow }, Quarantine: q}, lease, authority, remote, repo, j
}

func fullPack(t *testing.T, repo string) ([]byte, string) {
	t.Helper()
	return fixtureGit(t, repo, "pack-objects", "--all", "--stdout"), strings.TrimSpace(string(fixtureGit(t, repo, "rev-parse", "HEAD")))
}
func commitSynthetic(t *testing.T, repo, name string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(repo, name), []byte("synthetic "+name), 0600); err != nil {
		t.Fatal(err)
	}
	fixtureGit(t, repo, "add", name)
	fixtureGit(t, repo, "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid", "commit", "--no-gpg-sign", "-m", name)
}

// These files authenticate only the synthetic workload HTTP channel. They are
// never Git provider keys; those stay inside syntheticSigners.WithSigner.
type certificateChannel struct {
	lease  Lease
	public []byte
}

func (a certificateChannel) Authenticate(r *http.Request) (Lease, string, error) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) != 1 || !bytes.Equal(r.TLS.PeerCertificates[0].RawSubjectPublicKeyInfo, a.public) {
		return Lease{}, "", ErrPrincipal
	}
	return a.lease, "channel-a", nil
}
func pushHTTPFixture(t *testing.T, b Broker, l Lease) (string, []string, *http.Client) {
	t.Helper()
	dir := t.TempDir()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{11}, 32))
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic-workload"}, NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	server := httptest.NewUnstartedServer(PushHandler{Broker: b, Channel: certificateChannel{l, cert.RawSubjectPublicKeyInfo}})
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, block *pem.Block) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, pem.EncodeToMemory(block), 0600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ca := write("server.pem", &pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	cp := write("client.pem", &pem.Block{Type: "CERTIFICATE", Bytes: der})
	kp := write("client-key.pem", &pem.Block{Type: "PRIVATE KEY", Bytes: encoded})
	pair, err := tls.LoadX509KeyPair(cp, kp)
	if err != nil {
		t.Fatal(err)
	}
	client := server.Client()
	client.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{pair}
	return server.URL, []string{"-c", "protocol.version=0", "-c", "http.sslCAInfo=" + ca, "-c", "http.sslCert=" + cp, "-c", "http.sslKey=" + kp}, client
}
func runSyntheticPush(t *testing.T, repo, url string, options []string, refspecs ...string) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	args := append(append([]string{}, options...), "push", "--porcelain", "--no-verify", url)
	args = append(args, refspecs...)
	cmd := exec.CommandContext(ctx, "/usr/bin/git", args...)
	cmd.Dir = repo
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + repo, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0", "LC_ALL=C"}
	return cmd.CombinedOutput()
}

func TestPushSmartHTTPRealGitCreateAndIncremental(t *testing.T) {
	b, l, _, remote, repo, j := pushFixture(t)
	url, options, client := pushHTTPFixture(t, b, l)
	source := t.TempDir()
	fixtureGit(t, source, "clone", "--no-local", repo, ".")
	commitSynthetic(t, source, "create.txt")
	for _, name := range []string{"create", "incremental"} {
		if name == "incremental" {
			commitSynthetic(t, source, "incremental.txt")
		}
		out, err := runSyntheticPush(t, source, url, options, "HEAD:"+l.ref)
		if err != nil {
			t.Fatalf("real Git %s: %v %s", name, err, out)
		}
		want := strings.TrimSpace(string(fixtureGit(t, source, "rev-parse", "HEAD")))
		got := strings.TrimSpace(string(fixtureGit(t, repo, "rev-parse", l.ref)))
		if got != want {
			t.Fatalf("remote ref mismatch %s %s", got, want)
		}
	}
	response, err := client.Get(url + "/info/refs?service=git-receive-pack")
	if err != nil {
		t.Fatal(err)
	}
	refs, caps, err := advertisement(bufioReaderAfterService(t, response))
	response.Body.Close()
	if err != nil || len(refs) != 1 || refs[l.ref] == "" || !caps["report-status"] {
		t.Fatalf("ref disclosure %v %v", refs, err)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	writes := 0
	for id, op := range j.intents {
		if op.NewObject != "" {
			writes++
			if op.Ref != l.ref || op.UserID != "human-a" || op.IdentityID != "identity-a" || op.Generation != 2 || len(op.PackDigest) != 64 || j.outcomes[id] != "succeeded" {
				t.Fatalf("bad intent %+v %s", op, j.outcomes[id])
			}
		}
	}
	if writes != 2 {
		t.Fatalf("missing mutation intents %d", writes)
	}
	remote.mu.Lock()
	defer remote.mu.Unlock()
	for _, seen := range remote.seen {
		if !strings.HasPrefix(seen, "alice:git-") {
			t.Fatalf("wrong provider identity %s", seen)
		}
	}
}

func bufioReaderAfterService(t *testing.T, r *http.Response) *bufio.Reader {
	t.Helper()
	br := bufio.NewReader(r.Body)
	p, err := pkt(br)
	if err != nil || string(p) != "# service=git-receive-pack\n" {
		t.Fatalf("bad service %q %v", p, err)
	}
	p, err = pkt(br)
	if err != nil || p != nil {
		t.Fatal("missing service flush")
	}
	return br
}

func TestPushRejectsFramingAndUnsafeRefs(t *testing.T) {
	pack := fixtureGit(t, localRepository(t), "pack-objects", "--all", "--stdout")
	oid := strings.Repeat("a", 40)
	wire := func(command, cap string, tail []byte) []byte {
		var b bytes.Buffer
		_ = writePkt(&b, command+"\x00"+cap+"\n")
		b.WriteString("0000")
		b.Write(tail)
		return b.Bytes()
	}
	good := zeroObject + " " + oid + " refs/heads/task/a"
	valid := wire(good, "report-status", pack)
	if _, _, err := parsePush(bytes.NewReader(valid)); err != nil {
		t.Fatal("positive protocol control", err)
	}
	if _, _, err := parsePush(bytes.NewReader(wire(good, " report-status ", pack))); err != nil {
		t.Fatal("Git capability spacing rejected", err)
	}
	for name, data := range map[string][]byte{
		"delete":        wire(oid+" "+zeroObject+" refs/heads/task/a", "report-status", pack),
		"tag":           wire(zeroObject+" "+oid+" refs/tags/task/a", "report-status", pack),
		"default":       wire(zeroObject+" "+oid+" refs/heads/main", "report-status", pack),
		"newline":       wire(zeroObject+" "+oid+" refs/heads/task/a\nrefs/heads/main", "report-status", pack),
		"revision":      wire(zeroObject+" "+oid+" refs/heads/task/a~1", "report-status", pack),
		"options":       wire(good, "report-status push-options", pack),
		"v2status":      wire(good, "report-status-v2", pack),
		"duplicatecaps": wire(good, "report-status report-status", pack),
		"delimiter":     []byte("0001"), "badhex": []byte("zzzz"), "truncated": valid[:len(valid)-1],
		"trailing":  append(bytes.Clone(valid), []byte("0000")...),
		"multi":     wire(good, "report-status", wire(good, "report-status", pack)),
		"traversal": wire(zeroObject+" "+oid+" refs/heads/task/../main", "report-status", pack),
		"lock":      wire(zeroObject+" "+oid+" refs/heads/task/x.lock", "report-status", pack),
		"overlong":  wire(zeroObject+" "+oid+" refs/heads/task/"+strings.Repeat("x", 256), "report-status", pack),
	} {
		t.Run(name, func(t *testing.T) {
			_, got, err := parsePush(bytes.NewReader(data))
			clear(got)
			if err == nil {
				t.Fatal("accepted malicious request")
			}
		})
	}
}

func TestPushWriteAuthorizationAndHistory(t *testing.T) {
	for _, name := range []string{"channel", "user", "key-generation", "policy-epoch", "grant-epoch", "root", "write-right", "read-only-project", "foreign-ref", "force", "missing-object", "hidden-submodule-history", "provider-reject", "audit-outage", "changed-remote", "replay", "payload-copy"} {
		t.Run(name, func(t *testing.T) {
			b, l, a, _, repo, j := pushFixture(t)
			source := t.TempDir()
			fixtureGit(t, source, "clone", "--no-local", repo, ".")
			base := strings.TrimSpace(string(fixtureGit(t, source, "rev-parse", "HEAD")))
			fixtureGit(t, repo, "update-ref", l.ref, base)
			commitSynthetic(t, source, "new.txt")
			pack, next := fullPack(t, source)
			u := RefUpdate{Old: base, New: next, Ref: l.ref}
			channel := "channel-a"
			switch name {
			case "channel":
				channel = "channel-b"
			case "user":
				a.change(func(c *CurrentRights) { c.Binding.OriginatorUserID = "human-b" })
			case "key-generation":
				a.change(func(c *CurrentRights) { c.CredentialGeneration++ })
			case "policy-epoch":
				a.change(func(c *CurrentRights) { c.PolicyEpoch++ })
			case "grant-epoch":
				a.change(func(c *CurrentRights) { c.GrantEpoch++ })
			case "root":
				a.change(func(c *CurrentRights) { c.RootActive = false })
			case "write-right":
				a.change(func(c *CurrentRights) { c.RepositoryWrite = false })
			case "read-only-project":
				a.change(func(c *CurrentRights) { c.ProjectContribute = false })
			case "foreign-ref":
				u.Ref = "refs/heads/task/b"
			case "force":
				other := localRepository(t)
				fixtureGit(t, other, "checkout", "--orphan", "unrelated")
				fixtureGit(t, other, "rm", "-rf", ".")
				commitSynthetic(t, other, "unrelated.txt")
				pack, u.New = fullPack(t, other)
			case "missing-object":
				u.New = strings.Repeat("f", 40)
			case "hidden-submodule-history":
				commitSynthetic(t, source, ".gitmodules")
				fixtureGit(t, source, "rm", ".gitmodules")
				fixtureGit(t, source, "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid", "commit", "--no-gpg-sign", "-m", "removed")
				pack, u.New = fullPack(t, source)
			case "provider-reject":
				hook := filepath.Join(repo, ".git", "hooks", "pre-receive")
				if err := os.WriteFile(hook, []byte("#!/bin/sh\nexit 1\n"), 0700); err != nil {
					t.Fatal(err)
				}
			case "audit-outage":
				j.failBegin = true
			case "changed-remote":
				j.beginHook = func() { fixtureGit(t, repo, "update-ref", l.ref, zeroObject, base) }
			case "payload-copy":
				j.beginHook = func() { clear(pack) }
			}
			err := b.Write(context.Background(), l, channel, "mutation", u, pack)
			wantSuccess := name == "replay" || name == "payload-copy"
			if (err == nil) != wantSuccess {
				t.Fatalf("authorization result %v", err)
			}
			if name == "replay" {
				if err = b.Write(context.Background(), l, channel, "mutation", u, pack); err == nil {
					t.Fatal("replayed mutation")
				}
			}
			current := strings.TrimSpace(string(fixtureGit(t, repo, "for-each-ref", "--format=%(objectname)", l.ref)))
			want := base
			if wantSuccess {
				want = u.New
			}
			if name == "changed-remote" {
				want = ""
			}
			if current != want {
				t.Fatalf("unexpected mutation: %s want %s", current, want)
			}
			if name == "provider-reject" && !errors.Is(err, ErrIndeterminate) {
				t.Fatalf("post-send failure should be uncertain: %v", err)
			}
		})
	}
}

func TestPushProviderIdentityCannotBeSubstituted(t *testing.T) {
	b, l, _, remote, repo, _ := pushFixture(t)
	w := b.Transport.(*SSHWorker)
	registry := w.registry.(syntheticRegistry)
	other := syntheticSigner(t, 2)
	target := registry.targets["identity-a:repo-a"]
	target.SecretRef = "identity-b"
	target.Fingerprint = ssh.FingerprintSHA256(other.PublicKey())
	registry.targets["identity-a:repo-a"] = target
	w.custody = syntheticSigners{"identity-b": other}
	pack, next := fullPack(t, repo)
	err := b.Write(context.Background(), l, "channel-a", "foreign-provider", RefUpdate{Old: zeroObject, New: next, Ref: l.ref}, pack)
	if err == nil {
		t.Fatal("Bob wrote Alice-only repository")
	}
	remote.mu.Lock()
	defer remote.mu.Unlock()
	if len(remote.seen) == 0 {
		t.Fatal("negative control never reached same-key provider ACL")
	}
}

func TestPushActiveCancellationBeforeAndAfterSend(t *testing.T) {
	for _, phase := range []string{"before-advertisement", "after-remote-commit", "policy-outage"} {
		t.Run(phase, func(t *testing.T) {
			b, l, a, remote, repo, j := pushFixture(t)
			pack, next := fullPack(t, repo)
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			if phase == "after-remote-commit" {
				remote.afterGit = func(service string, _ ssh.Channel) {
					if service == "receive-pack" { // discovery sends no update; check the synthetic ref.
						out := fixtureGit(t, repo, "for-each-ref", "--format=%(objectname)", l.ref)
						if strings.TrimSpace(string(out)) == next {
							once.Do(func() { close(entered) })
							<-release
						}
					}
				}
			} else {
				remote.beforeGit = func(_ string, _ ssh.Channel) { once.Do(func() { close(entered) }); <-release }
			}
			done := make(chan error, 1)
			go func() {
				done <- b.Write(context.Background(), l, "channel-a", "blocked", RefUpdate{Old: zeroObject, New: next, Ref: l.ref}, pack)
			}()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				close(release)
				t.Fatal("provider block not reached")
			}
			start := time.Now()
			if phase == "policy-outage" {
				a.mu.Lock()
				a.outage = true
				a.mu.Unlock()
			} else {
				a.change(func(c *CurrentRights) { c.RootActive = false })
			}
			select {
			case err := <-done:
				if err == nil {
					t.Error("cancelled push succeeded")
				}
				if phase == "after-remote-commit" && !errors.Is(err, ErrIndeterminate) {
					t.Errorf("lost response classified %v", err)
				}
				t.Logf("%s cutoff %s", phase, time.Since(start))
			case <-time.After(3 * time.Second):
				close(release)
				t.Fatal("active SSH connection not cancelled")
			}
			close(release)
			if phase == "after-remote-commit" {
				j.mu.Lock()
				outcome := j.outcomes["blocked"]
				j.mu.Unlock()
				if outcome != "indeterminate" {
					t.Fatalf("uncertain mutation audit %s", outcome)
				}
				got := strings.TrimSpace(string(fixtureGit(t, repo, "rev-parse", l.ref)))
				if got != next {
					t.Fatal("fixture did not actually commit before cancellation")
				}
			}
		})
	}
}

func TestPushHTTPRejectsOtherServicesAndClientIdentity(t *testing.T) {
	b, l, _, _, _, _ := pushFixture(t)
	url, _, client := pushHTTPFixture(t, b, l)
	for _, path := range []string{"/info/refs?service=git-upload-pack", "/git-upload-pack", "/info/refs?service=git-receive-pack&user=human-b", "/other/info/refs?service=git-receive-pack"} {
		r, err := client.Get(url + path)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode != http.StatusForbidden {
			t.Fatalf("accepted %s", path)
		}
	}
	req, _ := http.NewRequest(http.MethodGet, url+"/info/refs?service=git-receive-pack", nil)
	req.Header.Set("Git-Protocol", "version=2")
	r, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != http.StatusForbidden {
		t.Fatal("protocol upgrade accepted")
	}
	// Supplying an originator/channel header cannot replace a verified TLS peer.
	recorder := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/info/refs?service=git-receive-pack", nil)
	req.Header.Set("X-User-ID", "human-a")
	req.Header.Set("X-Channel-ID", "channel-a")
	PushHandler{Broker: b, Channel: certificateChannel{l, nil}}.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Fatal("header identity accepted")
	}
}

func (j *fixtureJournal) Lookup(_ context.Context, id string) (BoundOperation, string, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	op, ok := j.intents[id]
	if !ok {
		return BoundOperation{}, "", ErrAudit
	}
	outcome := j.outcomes[id]
	if outcome == "" {
		outcome = "pending"
	}
	return op, outcome, nil
}

func TestPushReconciliationObservesWithoutRetry(t *testing.T) {
	for _, state := range []string{"matches_old", "matches_new", "diverged", "other-user", "other-attempt", "revoked"} {
		t.Run(state, func(t *testing.T) {
			b, l, a, _, repo, j := pushFixture(t)
			_, old := fullPack(t, repo)
			commitSynthetic(t, repo, "next.txt")
			_, next := fullPack(t, repo)
			op := b.writeOperation(l)
			op.OldObject, op.NewObject, op.PackDigest = old, next, strings.Repeat("a", 64)
			if state == "other-user" {
				op.UserID = "human-b"
			}
			if state == "other-attempt" {
				op.AttemptID = "attempt-b"
			}
			if _, err := j.Begin(context.Background(), "uncertain", op); err != nil {
				t.Fatal(err)
			}
			_ = j.Complete(context.Background(), "uncertain", "indeterminate")
			observed := old
			if state == "matches_new" {
				observed = next
			}
			if state == "diverged" {
				commitSynthetic(t, repo, "third.txt")
				_, observed = fullPack(t, repo)
			}
			fixtureGit(t, repo, "update-ref", l.ref, observed)
			if state == "revoked" {
				a.change(func(c *CurrentRights) { c.RootActive = false })
			}
			result, err := b.ReconcileWrite(context.Background(), l, "channel-a", "uncertain")
			if state == "other-user" || state == "other-attempt" || state == "revoked" {
				if err == nil || result != "" {
					t.Fatalf("foreign observation %s %v", result, err)
				}
			} else if err != nil || result != state {
				t.Fatalf("observation %s %v", result, err)
			}
			got := strings.TrimSpace(string(fixtureGit(t, repo, "rev-parse", l.ref)))
			if got != observed {
				t.Fatal("reconciliation changed remote ref")
			}
			j.mu.Lock()
			defer j.mu.Unlock()
			if j.outcomes["uncertain"] != "indeterminate" {
				t.Fatal("original uncertainty overwritten")
			}
			if err == nil {
				found := false
				for _, entry := range j.intents {
					if entry.Reconciles == "uncertain" && entry.ObservedObject == observed {
						found = true
					}
				}
				if !found {
					t.Fatal("observation was not durably audited")
				}
			}
		})
	}
}

func TestPushQuarantineDropsUnreachableObjectsAndAllowsNewOrphan(t *testing.T) {
	b, l, _, _, repo, _ := pushFixture(t)
	// A new task ref may start a closed orphan history; existing refs still require
	// ancestry. An unadvertised second branch must never hitchhike in its pack.
	source := localRepository(t)
	fixtureGit(t, source, "checkout", "--orphan", "orphan")
	fixtureGit(t, source, "rm", "-rf", ".")
	commitSynthetic(t, source, "orphan.txt")
	next := strings.TrimSpace(string(fixtureGit(t, source, "rev-parse", "HEAD")))
	fixtureGit(t, source, "checkout", "-b", "unreachable")
	commitSynthetic(t, source, ".gitmodules")
	incoming := fixtureGit(t, source, "pack-objects", "--all", "--stdout")
	u := RefUpdate{Old: zeroObject, New: next, Ref: l.ref}
	canonical, err := b.Quarantine.Prepare(context.Background(), nil, incoming, u)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(canonical)
	if len(canonical) >= len(incoming) {
		t.Fatal("unreachable objects were forwarded")
	}
	if err = b.Write(context.Background(), l, "channel-a", "new-orphan", u, incoming); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(fixtureGit(t, repo, "rev-parse", l.ref))); got != next {
		t.Fatal("orphan positive control failed")
	}
}

func TestPushAuditFailureAfterCommitRemainsUncertain(t *testing.T) {
	b, l, _, _, repo, j := pushFixture(t)
	pack, next := fullPack(t, repo)
	u := RefUpdate{Old: zeroObject, New: next, Ref: l.ref}
	j.failComplete = true
	if err := b.Write(context.Background(), l, "channel-a", "lost-audit", u, pack); !errors.Is(err, ErrIndeterminate) {
		t.Fatalf("lost audit %v", err)
	}
	if got := strings.TrimSpace(string(fixtureGit(t, repo, "rev-parse", l.ref))); got != next {
		t.Fatal("positive remote mutation did not happen")
	}
	j.failComplete = false
	if state, err := b.ReconcileWrite(context.Background(), l, "channel-a", "lost-audit"); err != nil || state != "matches_new" {
		t.Fatalf("observe committed uncertain mutation %s %v", state, err)
	}
	if err := b.Write(context.Background(), l, "channel-a", "lost-audit", u, pack); err == nil {
		t.Fatal("uncertain operation retried")
	}
	_, outcome, err := j.Lookup(context.Background(), "lost-audit")
	if err != nil || outcome != "pending" {
		t.Fatal("observation erased original pending record")
	}
}

func TestPushRejectsProviderAdvertisementAmbiguity(t *testing.T) {
	oid := strings.Repeat("a", 40)
	encoded := func(lines ...string) []byte {
		var b bytes.Buffer
		for _, line := range lines {
			_ = writePkt(&b, line)
		}
		b.WriteString("0000")
		return b.Bytes()
	}
	first := oid + " refs/heads/task/a\x00report-status object-format=sha1\n"
	if refs, _, err := advertisement(bytes.NewReader(encoded(first))); err != nil || refs["refs/heads/task/a"] != oid {
		t.Fatal("advertisement positive control", err)
	}
	for name, data := range map[string][]byte{
		"duplicate": encoded(first, oid+" refs/heads/task/a\n"), "capability-in-second": encoded(first, oid+" refs/heads/task/b\x00report-status\n"),
		"sha256":         encoded(oid + " refs/heads/task/a\x00report-status object-format=sha256\n"),
		"empty-plus-ref": encoded(zeroObject+" capabilities^{}\x00report-status\n", oid+" refs/heads/task/a\n"),
		"control":        encoded(oid + " refs/heads/task/a\nmain\x00report-status\n"), "missing-caps": encoded(oid + " refs/heads/task/a\n"),
		"protocol-delimiter": []byte("0001"), "uppercase-frame": []byte("00AF"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := advertisement(bytes.NewReader(data)); err == nil {
				t.Fatal("ambiguous provider advertisement accepted")
			}
		})
	}
}

type delayedWriteTransport struct {
	ProviderTransport
	WriteTransport
	delay time.Duration
}

func (w delayedWriteTransport) WriteReference(ctx context.Context, op BoundOperation) (string, error) {
	select {
	case <-time.After(w.delay):
		return w.WriteTransport.WriteReference(ctx, op)
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func TestPushHTTP2AllowsSlowValidProviderWork(t *testing.T) {
	b, l, _, _, _, _ := pushFixture(t)
	b.Transport = delayedWriteTransport{b.Transport, b.Transport.(WriteTransport), 1200 * time.Millisecond}
	url, _, client := pushHTTPFixture(t, b, l)
	start := time.Now()
	r, err := client.Get(url + "/info/refs?service=git-receive-pack")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	if r.StatusCode != 200 || r.ProtoMajor != 2 || time.Since(start) < time.Second {
		t.Fatalf("slow HTTP2 proof failed: %d %s %s", r.StatusCode, r.Proto, time.Since(start))
	}
	if _, _, err := advertisement(bufioReaderAfterService(t, r)); err != nil {
		t.Fatal(err)
	}
}

type uncertainWriteTransport struct {
	ProviderTransport
	WriteTransport
	mu     sync.Mutex
	pushes int
}

func (w *uncertainWriteTransport) Push(context.Context, BoundOperation, RefUpdate, []byte, func(context.Context) error) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.pushes++
	return ErrIndeterminate
}
func TestPushHTTPRetriesCannotObtainNewMutationIdentity(t *testing.T) {
	b, l, _, _, repo, j := pushFixture(t)
	tr := &uncertainWriteTransport{ProviderTransport: b.Transport, WriteTransport: b.Transport.(WriteTransport)}
	b.Transport = tr
	source := t.TempDir()
	fixtureGit(t, source, "clone", "--no-local", repo, ".")
	commitSynthetic(t, source, "retry.txt")
	for attempt := 0; attempt < 2; attempt++ { // reconstruct handler/broker around persisted journal state.
		restarted := b
		restarted.Journal = j
		url, options, _ := pushHTTPFixture(t, restarted, l)
		if out, err := runSyntheticPush(t, source, url, options, "HEAD:"+l.ref); err == nil {
			t.Fatalf("uncertain HTTP mutation succeeded: %s", out)
		}
	}
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if tr.pushes != 1 {
		t.Fatalf("wire retry bypassed durable intent: %d sends", tr.pushes)
	}
}

func TestPushDeniesDefaultProtectedAndMissingProviderPolicy(t *testing.T) {
	for _, name := range []string{"default-task-ref", "protected-task-ref", "no-policy-adapter"} {
		t.Run(name, func(t *testing.T) {
			b, l, _, _, repo, _ := pushFixture(t)
			worker := b.Transport.(*SSHWorker)
			pack, next := fullPack(t, repo)
			switch name {
			case "default-task-ref":
				fixtureGit(t, repo, "update-ref", l.ref, next)
				fixtureGit(t, repo, "symbolic-ref", "HEAD", l.ref)
			case "protected-task-ref":
				registry := worker.registry.(syntheticRegistry)
				registry.protected = map[string]bool{l.ref: true}
				worker.registry = registry
			case "no-policy-adapter":
				worker.registry = struct{ TransportRegistry }{worker.registry}
			}
			if _, err := worker.WriteReference(context.Background(), b.writeOperation(l)); err == nil {
				t.Fatal("provider policy proof bypass")
			}
			if err := b.Write(context.Background(), l, "channel-a", "blocked-policy", RefUpdate{Old: zeroObject, New: next, Ref: l.ref}, pack); err == nil {
				t.Fatal("blocked policy wrote")
			}
		})
	}
}

func TestPushConfirmedMutationRemainsInspectableAfterDeliveryRevoke(t *testing.T) {
	b, l, a, _, repo, j := pushFixture(t)
	pack, next := fullPack(t, repo)
	j.completeHook = func() { a.change(func(c *CurrentRights) { c.RootActive = false }) }
	err := b.Write(context.Background(), l, "channel-a", "confirmed", RefUpdate{Old: zeroObject, New: next, Ref: l.ref}, pack)
	if !errors.Is(err, ErrCommitted) {
		t.Fatalf("confirmed mutation misclassified: %v", err)
	}
	_, outcome, err := j.Lookup(context.Background(), "confirmed")
	if err != nil || outcome != "succeeded" {
		t.Fatal("confirmed mutation audit lost")
	}
	j.completeHook = nil
	a.change(func(c *CurrentRights) { c.RootActive = true })
	if state, err := b.ReconcileWrite(context.Background(), l, "channel-a", "confirmed"); err != nil || state != "matches_new" {
		t.Fatalf("confirmed mutation stranded: %s %v", state, err)
	}
}
