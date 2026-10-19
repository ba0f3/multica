//go:build linux

package r2dgit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The fake engine executes only this test-created helper process. It does not
// call Docker, create namespaces or demonstrate filesystem/kernel containment.
func TestWorkloadFakeCLIProcess(t *testing.T) {
	if os.Getenv("MULTICA_SYNTHETIC_WORKLOAD_CLI") != "1" {
		return
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", os.Getenv("MULTICA_SYNTHETIC_WORKLOAD_SOCKET"))
	}}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	request, _ := http.NewRequest(http.MethodGet, "http://local/info/refs?service=git-receive-pack", nil)
	// Deliberately hostile workload input. It must never select B's authority.
	request.Header.Set("X-User-ID", "human-b")
	request.Header.Set("X-Channel-ID", "channel-b")
	request.Header.Set("X-Task-ID", "task-b")
	request.Header.Set("Authorization", "Bearer synthetic-forgery")
	response, err := client.Do(request)
	if err != nil {
		os.Exit(10)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != 200 {
		os.Exit(11)
	}
	// Remain live until the fake engine's Remove cancels and reaps the helper.
	<-time.After(30 * time.Second)
	os.Exit(12)
}

type workloadAuthority struct {
	mu     sync.Mutex
	rights map[string]CurrentRights
	outage string
}

func (a *workloadAuthority) Current(ctx context.Context, run ContextSpec, _ GrantSpec) (CurrentRights, error) {
	a.mu.Lock()
	rights, found := a.rights[run.ID]
	outage := a.outage == run.ID
	a.mu.Unlock()
	if outage {
		<-ctx.Done()
		return CurrentRights{}, ctx.Err()
	}
	if !found {
		return CurrentRights{}, ErrPrincipal
	}
	return rights, nil
}
func (a *workloadAuthority) change(id string, change func(*CurrentRights)) {
	a.mu.Lock()
	r := a.rights[id]
	change(&r)
	a.rights[id] = r
	a.mu.Unlock()
}

type workloadTransport struct {
	mu         sync.Mutex
	operations []BoundOperation
	observed   chan BoundOperation
	block      atomic.Bool
	entered    chan struct{}
	cancelled  chan struct{}
	delay      atomic.Int64
}

func (w *workloadTransport) ProveRepository(ctx context.Context, op BoundOperation) error {
	w.mu.Lock()
	w.operations = append(w.operations, op)
	w.mu.Unlock()
	if delay := w.delay.Load(); delay != 0 {
		select {
		case <-time.After(time.Duration(delay)):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if w.block.Load() {
		select {
		case w.entered <- struct{}{}:
		default:
		}
		<-ctx.Done()
		select {
		case w.cancelled <- struct{}{}:
		default:
		}
		return ctx.Err()
	}
	w.observed <- op
	return nil
}
func (*workloadTransport) Read(context.Context, BoundOperation) ([]byte, error) { return nil, ErrScope }
func (w *workloadTransport) WriteReference(ctx context.Context, op BoundOperation) (string, error) {
	return zeroObject, w.ProveRepository(ctx, op)
}
func (*workloadTransport) ReadReference(context.Context, BoundOperation, string) ([]byte, error) {
	return nil, ErrScope
}
func (*workloadTransport) Push(context.Context, BoundOperation, RefUpdate, []byte, func(context.Context) error) error {
	return ErrScope
}

type fakeWorkloadContainer struct {
	inspection DockerInspection
	cancel     context.CancelFunc
	exited     chan struct{}
}
type fakeWorkloadDocker struct {
	mu                       sync.Mutex
	containers               map[string]*fakeWorkloadContainer
	creates, starts, removes int
	mutate                   func(*DockerInspection)
	onCreate                 func()
	createEntered            chan struct{}
	createRelease            <-chan struct{}
	removeFailure            bool
}

func cloneWorkload[T any](value T) T {
	data, _ := json.Marshal(value)
	var out T
	_ = json.Unmarshal(data, &out)
	return out
}
func (d *fakeWorkloadDocker) find(name string) (string, *fakeWorkloadContainer) {
	if c := d.containers[name]; c != nil {
		return name, c
	}
	for key, c := range d.containers {
		if c.inspection.ID == name {
			return key, c
		}
	}
	return "", nil
}
func (d *fakeWorkloadDocker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1.47")
	if path == "/containers/create" && r.Method == http.MethodPost {
		var spec DockerWorkload
		if json.NewDecoder(r.Body).Decode(&spec) != nil {
			http.Error(w, "bad", 400)
			return
		}
		name := r.URL.Query().Get("name")
		d.mu.Lock()
		release, entered, hook := d.createRelease, d.createEntered, d.onCreate
		d.mu.Unlock()
		if entered != nil {
			select {
			case entered <- struct{}{}:
			default:
			}
		}
		if release != nil {
			<-release
		} // deliberately models create succeeding after cancellation.
		id := sha256.Sum256([]byte(name))
		actual := DockerInspection{ID: hex.EncodeToString(id[:]), Name: "/" + name, Config: spec, HostConfig: spec.HostConfig, AppArmorProfile: "synthetic-profile", Mounts: []DockerMount{{Type: "bind", Source: strings.Split(spec.HostConfig.Binds[0], ":")[0], Destination: "/run/multica", RW: false}}}
		d.mu.Lock()
		d.creates++
		if d.mutate != nil {
			d.mutate(&actual)
		}
		d.containers[name] = &fakeWorkloadContainer{inspection: actual}
		d.mu.Unlock()
		if hook != nil {
			hook()
		}
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]string{"Id": actual.ID})
		return
	}
	if path == "/containers/json" {
		d.mu.Lock()
		var list []DockerContainer
		// Intentionally return foreign resources too: ownership must be checked.
		for _, c := range d.containers {
			list = append(list, DockerContainer{ID: c.inspection.ID, Names: []string{c.inspection.Name}, Labels: cloneWorkload(c.inspection.Config.Labels)})
		}
		d.mu.Unlock()
		_ = json.NewEncoder(w).Encode(list)
		return
	}
	name := strings.TrimPrefix(path, "/containers/")
	name = strings.TrimSuffix(strings.TrimSuffix(name, "/json"), "/start")
	d.mu.Lock()
	key, c := d.find(name)
	if c == nil {
		d.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	if r.Method == http.MethodGet {
		actual := cloneWorkload(c.inspection)
		d.mu.Unlock()
		_ = json.NewEncoder(w).Encode(actual)
		return
	}
	if r.Method == http.MethodDelete {
		if d.removeFailure {
			d.mu.Unlock()
			http.Error(w, "synthetic removal outage", 500)
			return
		}
		if r.URL.Query().Get("force") != "true" || r.URL.Query().Get("v") != "true" {
			d.mu.Unlock()
			http.Error(w, "unsafe remove", 400)
			return
		}
		d.removes++
		delete(d.containers, key)
		cancel, exited := c.cancel, c.exited
		d.mu.Unlock()
		if cancel != nil {
			cancel()
			<-exited
		}
		w.WriteHeader(204)
		return
	}
	if strings.HasSuffix(path, "/start") {
		d.starts++
		c.inspection.State.Running = true
		ctx, cancel := context.WithCancel(context.Background())
		c.cancel = cancel
		c.exited = make(chan struct{})
		socket := strings.Split(c.inspection.HostConfig.Binds[0], ":")[0] + "/broker.sock"
		executable, err := os.Executable()
		if err != nil {
			d.mu.Unlock()
			http.Error(w, "helper", 500)
			return
		}
		cmd := exec.CommandContext(ctx, executable, "-test.run=^TestWorkloadFakeCLIProcess$")
		cmd.Env = []string{"MULTICA_SYNTHETIC_WORKLOAD_CLI=1", "MULTICA_SYNTHETIC_WORKLOAD_SOCKET=" + socket}
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		if err = cmd.Start(); err != nil {
			d.mu.Unlock()
			http.Error(w, "helper", 500)
			return
		}
		d.mu.Unlock()
		go func() {
			_ = cmd.Wait()
			d.mu.Lock()
			c.inspection.State.Running = false
			close(c.exited)
			d.mu.Unlock()
		}()
		w.WriteHeader(204)
		return
	}
	d.mu.Unlock()
	http.Error(w, "unknown", 400)
}

type workloadFixture struct {
	s          *WorkloadSupervisor
	engine     *fakeWorkloadDocker
	engineHTTP *httptest.Server
	authority  *workloadAuthority
	channels   atomic.Pointer[WorkloadChannels]
	transport  *workloadTransport
	broker     *httptest.Server
	roots      *x509.CertPool
	runs       [2]RunSecurityContext
	grants     [2]RepositoryGrant
	pairs      [2]tls.Certificate
	clock      atomic.Int64
}

func workloadPair(t *testing.T, seed byte) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	template := &x509.Certificate{SerialNumber: big.NewInt(int64(seed)), Subject: pkix.Name{CommonName: "synthetic"}, NotBefore: fixtureNow.Add(-time.Hour), NotAfter: fixtureNow.Add(365 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(nil, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}, cert
}
func newWorkloadFixture(t *testing.T) *workloadFixture {
	t.Helper()
	f := &workloadFixture{}
	f.clock.Store(fixtureNow.UnixNano())
	ra, ga, a := fixture(t)
	f.runs[0], f.grants[0] = ra, ga
	b := ra.spec.Binding
	b.TaskID = "task-b"
	b.OriginatorUserID = "human-b"
	rb, err := NewHumanRoot("context-b", "attempt-b", "human-b", b, 7, fixtureNow, fixtureNow.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	f.runs[1] = rb
	gb := ga.Spec()
	gb.ID = "grant-b"
	gb.ContextID = rb.spec.ID
	gb.IdentityID = "identity-b"
	gb.RepositoryID = "repo-b"
	gb.WriteRefs = []string{"refs/heads/task/b"}
	f.grants[1], err = NewGrant(rb, gb, fixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	rightsB := a.rights
	rightsB.Binding = b
	rightsB.IdentityID = gb.IdentityID
	rightsB.RepositoryID = gb.RepositoryID
	rightsB.AllowedWriteRefs = gb.WriteRefs
	rightsB.Runtime.ChannelID = "channel-b"
	f.authority = &workloadAuthority{rights: map[string]CurrentRights{ra.spec.ID: a.rights, rb.spec.ID: rightsB}}
	channels := NewWorkloadChannels(Authorizer{f.authority}, func() time.Time { return time.Unix(0, f.clock.Load()) })
	f.channels.Store(channels)
	f.transport = &workloadTransport{observed: make(chan BoundOperation, 128), entered: make(chan struct{}, 1), cancelled: make(chan struct{}, 1)}
	journal := &fixtureJournal{}
	broker := Broker{Authorizer: Authorizer{f.authority}, Transport: f.transport, Journal: journal, Now: channels.now}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-User-ID") != "" || r.Header.Get("X-Channel-ID") != "" {
			http.Error(w, "untrusted forwarded identity", 400)
			return
		}
		PushHandler{Broker: broker, Channel: f.channels.Load()}.ServeHTTP(w, r)
	}))
	clientRoots := x509.NewCertPool()
	for n := range f.pairs {
		pair, cert := workloadPair(t, byte(n+1))
		f.pairs[n] = pair
		clientRoots.AddCert(cert)
	}
	server.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientRoots, MinVersion: tls.VersionTLS13, Time: channels.now}
	server.StartTLS()
	f.broker = server
	t.Cleanup(server.Close)
	f.roots = x509.NewCertPool()
	f.roots.AddCert(server.Certificate())
	f.engine = &fakeWorkloadDocker{containers: make(map[string]*fakeWorkloadContainer)}
	f.engineHTTP = httptest.NewServer(f.engine)
	t.Cleanup(f.engineHTTP.Close)
	root, err := os.MkdirTemp("", "s4-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	policy := WorkloadPolicy{RuntimeID: "runner-a", Root: root, Image: "synthetic/agent@sha256:" + strings.Repeat("a", 64), AppArmor: "synthetic-profile", Seccomp: json.RawMessage(`{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"names":["read","write","exit"],"action":"SCMP_ACT_ALLOW"}]}`), ContainerUID: 65534, ContainerGID: 65534, SocketUID: os.Getuid(), SocketGID: os.Getgid(), Memory: 64 << 20, NanoCPUs: 500000000, PIDs: 32, WorkspaceBytes: 8 << 20, HomeBytes: 8 << 20, TmpBytes: 8 << 20, MaxRuns: 2}
	f.s, err = NewWorkloadSupervisor(DockerEngine{Client: f.engineHTTP.Client(), Endpoint: f.engineHTTP.URL}, channels, policy, server.URL, f.roots)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.s.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.s.Close() })
	return f
}
func (f *workloadFixture) launch(t *testing.T, n int) WorkloadHandle {
	t.Helper()
	h, err := f.s.Launch(context.Background(), f.runs[n], f.grants[n], fmt.Sprintf("channel-%c", 'a'+n), Write, f.grants[n].spec.WriteRefs[0], time.Minute, f.pairs[n])
	if err != nil {
		t.Fatal(err)
	}
	return h
}
func waitWorkload(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(4 * time.Second):
		t.Fatal("workload cleanup exceeded bound")
	}
}
func observedWorkload(t *testing.T, f *workloadFixture) BoundOperation {
	t.Helper()
	select {
	case op := <-f.transport.observed:
		return op
	case <-time.After(4 * time.Second):
		t.Fatal("fake CLI did not reach authenticated broker")
		return BoundOperation{}
	}
}

func TestWorkloadTwoUsersLaunchChannelRevokeCleanup(t *testing.T) {
	f := newWorkloadFixture(t)
	a := f.launch(t, 0)
	opA := observedWorkload(t, f)
	b := f.launch(t, 1)
	opB := observedWorkload(t, f)
	if opA.UserID != "human-a" || opA.IdentityID != "identity-a" || opA.TaskID != "task-a" || opA.Ref != "refs/heads/task/a" || opB.UserID != "human-b" || opB.IdentityID != "identity-b" {
		t.Fatalf("workload headers selected identity: %v %v", opA, opB)
	}
	f.engine.mu.Lock()
	var specs []DockerWorkload
	for _, c := range f.engine.containers {
		specs = append(specs, cloneWorkload(c.inspection.Config))
	}
	f.engine.mu.Unlock()
	if len(specs) != 2 || specs[0].Labels["io.multica.git-cache"] == specs[1].Labels["io.multica.git-cache"] || specs[0].Labels["io.multica.git-session"] == specs[1].Labels["io.multica.git-session"] || specs[0].HostConfig.Binds[0] == specs[1].HostConfig.Binds[0] {
		t.Fatal("A/B storage/channel partitions shared")
	}
	for _, spec := range specs {
		if len(spec.Volumes) != 0 || len(spec.HostConfig.Tmpfs) != 3 || spec.HostConfig.NetworkMode != "none" || spec.HostConfig.LogConfig.Type != "none" || len(spec.HostConfig.Binds) != 1 {
			t.Fatal("ambient storage/network/log sink")
		}
	}
	f.authority.change("context-a", func(r *CurrentRights) { r.RootActive = false })
	waitWorkload(t, a.Done)
	select {
	case <-b.Done:
		t.Fatal("A revoke stopped B")
	default:
	}
	if err := f.s.Revoke(b.ID); err != nil {
		t.Fatal(err)
	}
	waitWorkload(t, b.Done)
	f.engine.mu.Lock()
	remaining := len(f.engine.containers)
	f.engine.mu.Unlock()
	if remaining != 0 {
		t.Fatal("containers survived cleanup")
	}
	if _, err := os.Stat(f.s.directory(a.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("source/socket state retained")
	}
}

func TestWorkloadAdmissionCannotWidenOrSelfApprove(t *testing.T) {
	for _, mode := range []string{"read-with-ref", "foreign-ref", "oversize-ttl", "foreign-user", "unapproved-runtime", "wrong-channel", "foreign-grant"} {
		t.Run(mode, func(t *testing.T) {
			f := newWorkloadFixture(t)
			run, grant := f.runs[0], f.grants[0]
			channel, op, ref, ttl := "channel-a", Write, "refs/heads/task/a", time.Minute
			switch mode {
			case "read-with-ref":
				op, ref = Read, "refs/heads/task/a"
			case "foreign-ref":
				ref = "refs/heads/task/b"
			case "oversize-ttl":
				ttl = MaxLeaseTTL + time.Second
			case "foreign-user":
				f.authority.change(run.spec.ID, func(r *CurrentRights) { r.Binding.OriginatorUserID = "human-b" })
			case "unapproved-runtime":
				f.authority.change(run.spec.ID, func(r *CurrentRights) { r.Runtime = RuntimeEvidence{} })
			case "wrong-channel":
				channel = "channel-b"
			case "foreign-grant":
				grant = f.grants[1]
			}
			if _, err := f.s.Launch(context.Background(), run, grant, channel, op, ref, ttl, f.pairs[0]); err == nil {
				t.Fatal("invalid launch admitted")
			}
			f.engine.mu.Lock()
			count := f.engine.creates
			f.engine.mu.Unlock()
			if count != 0 {
				t.Fatal("denied admission created container")
			}
		})
	}
}

func TestWorkloadExpiredLeaseNeverStarts(t *testing.T) {
	f := newWorkloadFixture(t)
	f.engine.onCreate = func() { f.clock.Add(int64(2 * time.Second)) }
	if _, err := f.s.Launch(context.Background(), f.runs[0], f.grants[0], "channel-a", Write, "refs/heads/task/a", time.Second, f.pairs[0]); !errors.Is(err, ErrRevoked) {
		t.Fatalf("expired launch: %v", err)
	}
	f.engine.mu.Lock()
	defer f.engine.mu.Unlock()
	if f.engine.starts != 0 || len(f.engine.containers) != 0 {
		t.Fatal("expired lease executed or leaked")
	}
}

func TestWorkloadInspectionMismatchNeverExecutes(t *testing.T) {
	for _, mode := range []string{"privileged", "host-network", "extra-mount", "writable-root", "profile", "user", "added-cap", "engine-log", "unbounded-memory"} {
		t.Run(mode, func(t *testing.T) {
			f := newWorkloadFixture(t)
			f.engine.mutate = func(i *DockerInspection) {
				switch mode {
				case "privileged":
					i.HostConfig.Privileged = true
				case "host-network":
					i.HostConfig.NetworkMode = "host"
				case "extra-mount":
					i.Mounts = append(i.Mounts, DockerMount{Type: "bind", Source: "/", Destination: "/host"})
				case "writable-root":
					i.HostConfig.ReadonlyRootfs = false
				case "profile":
					i.AppArmorProfile = "unconfined"
				case "user":
					i.Config.User = "0:0"
				case "added-cap":
					i.HostConfig.CapAdd = []string{"SYS_ADMIN"}
				case "engine-log":
					i.HostConfig.LogConfig.Type = "json-file"
				case "unbounded-memory":
					i.HostConfig.Memory = 0
				}
			}
			if _, err := f.s.Launch(context.Background(), f.runs[0], f.grants[0], "channel-a", Write, "refs/heads/task/a", time.Minute, f.pairs[0]); err == nil {
				t.Fatal("unsafe inspection accepted")
			}
			f.engine.mu.Lock()
			defer f.engine.mu.Unlock()
			if f.engine.starts != 0 || len(f.engine.containers) != 0 {
				t.Fatal("unsafe container executed/leaked")
			}
		})
	}
}

func TestWorkloadRevokeCancelsBrokerBeforeEngineCleanup(t *testing.T) {
	f := newWorkloadFixture(t)
	f.transport.block.Store(true)
	h := f.launch(t, 0)
	select {
	case <-f.transport.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("broker operation not started")
	}
	f.engine.mu.Lock()
	f.engine.removeFailure = true
	f.engine.mu.Unlock()
	if err := f.s.Revoke(h.ID); err == nil {
		t.Fatal("remove failure hidden")
	}
	select {
	case <-f.transport.cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("in-flight broker request survived revoke")
	}
	select {
	case <-h.Done:
		t.Fatal("cleanup acknowledged before engine removal")
	default:
	}
	if _, err := os.Stat(filepath.Join(f.s.directory(h.ID), "intent.json")); err != nil {
		t.Fatal("failed cleanup intent lost")
	}
	if _, err := f.s.Launch(context.Background(), f.runs[1], f.grants[1], "channel-b", Write, "refs/heads/task/b", time.Minute, f.pairs[1]); err == nil {
		t.Fatal("cleanup outage allowed new work")
	}
	f.engine.mu.Lock()
	f.engine.removeFailure = false
	f.engine.mu.Unlock()
	if err := f.s.Revoke(h.ID); err != nil {
		t.Fatal(err)
	}
	waitWorkload(t, h.Done)
}

func TestWorkloadRevocationDoesNotWaitForOtherLaunch(t *testing.T) {
	f := newWorkloadFixture(t)
	a := f.launch(t, 0)
	observedWorkload(t, f)
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	f.engine.mu.Lock()
	f.engine.createRelease = release
	f.engine.createEntered = entered
	f.engine.mu.Unlock()
	launched := make(chan error, 1)
	go func() {
		_, err := f.s.Launch(context.Background(), f.runs[1], f.grants[1], "channel-b", Write, "refs/heads/task/b", time.Minute, f.pairs[1])
		launched <- err
	}()
	<-entered
	start := time.Now()
	if err := f.s.Revoke(a.ID); err != nil {
		t.Fatal(err)
	}
	waitWorkload(t, a.Done)
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("cross-run admission delayed revoke")
	}
	close(release)
	<-launched
}

func simulateWorkloadSupervisorCrash(s *WorkloadSupervisor) {
	s.admission.Lock()
	defer s.admission.Unlock()
	s.mu.Lock()
	s.closed = true
	close(s.closeDone)
	runs := make([]*supervisedWorkload, 0, len(s.runs))
	for _, w := range s.runs {
		runs = append(runs, w)
	}
	s.mu.Unlock()
	for _, w := range runs {
		w.mu.Lock()
		if !w.stopped {
			w.stopped = true
			close(w.watchStop)
		}
		w.mu.Unlock()
		<-w.watchDone // a simulated dead process has no remaining watchdog.
		s.channels.revoke(w.cert, w.lease)
		if w.server != nil {
			_ = w.server.Close()
		}
	}
	_ = unix.Flock(int(s.lock.Fd()), unix.LOCK_UN)
	_ = s.lock.Close()
}
func restartWorkloadSupervisor(t *testing.T, f *workloadFixture) {
	t.Helper()
	channels := NewWorkloadChannels(Authorizer{f.authority}, func() time.Time { return time.Unix(0, f.clock.Load()) })
	f.channels.Store(channels)
	s, err := NewWorkloadSupervisor(DockerEngine{Client: f.engineHTTP.Client(), Endpoint: f.engineHTTP.URL}, channels, f.s.policy, f.broker.URL, f.roots)
	if err != nil {
		t.Fatal(err)
	}
	f.s = s
}

func TestWorkloadCrashRecoveryPurgesAndNeverRebindsCertificate(t *testing.T) {
	f := newWorkloadFixture(t)
	h := f.launch(t, 0)
	observedWorkload(t, f)
	simulateWorkloadSupervisorCrash(f.s)
	f.engine.mu.Lock()
	orphans := len(f.engine.containers)
	f.engine.mu.Unlock()
	if orphans != 1 {
		t.Fatal("crash fixture cleaned engine before recovery")
	}
	if _, err := os.Stat(filepath.Join(f.s.directory(h.ID), "intent.json")); err != nil {
		t.Fatal("crash fixture lost launch intent")
	}
	restartWorkloadSupervisor(t, f)
	if err := f.s.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.engine.mu.Lock()
	remaining := len(f.engine.containers)
	f.engine.mu.Unlock()
	if remaining != 0 {
		t.Fatal("crash orphan adopted")
	}
	if _, err := os.Stat(f.s.directory(h.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("old native state retained")
	}
	if _, err := f.s.Launch(context.Background(), f.runs[1], f.grants[1], "channel-b", Write, "refs/heads/task/b", time.Minute, f.pairs[0]); err == nil {
		t.Fatal("old TLS identity rebound to B")
	}
	if _, err := f.s.Launch(context.Background(), f.runs[0], f.grants[0], "channel-a", Write, "refs/heads/task/a", time.Minute, f.pairs[1]); err == nil {
		t.Fatal("old channel rebound to fresh TLS identity")
	}
}

func TestWorkloadLateCreateRetainsIntentUntilResourceObserved(t *testing.T) {
	f := newWorkloadFixture(t)
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	f.engine.createRelease = release
	f.engine.createEntered = entered
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := f.s.Launch(ctx, f.runs[0], f.grants[0], "channel-a", Write, "refs/heads/task/a", time.Minute, f.pairs[0])
		done <- err
	}()
	<-entered
	cancel()
	if err := <-done; err == nil {
		t.Fatal("cancelled create succeeded")
	}
	if err := f.s.Close(); err == nil {
		t.Fatal("uncertain absent create acknowledged clean")
	}
	restartWorkloadSupervisor(t, f)
	if err := f.s.Recover(context.Background()); err == nil {
		t.Fatal("404 erased uncertain launch intent")
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for {
		f.engine.mu.Lock()
		count := f.engine.creates
		f.engine.mu.Unlock()
		if count == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("late fake create missing")
		}
		time.Sleep(time.Millisecond)
	}
	if err := f.s.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.engine.mu.Lock()
	defer f.engine.mu.Unlock()
	if f.engine.starts != 0 || len(f.engine.containers) != 0 {
		t.Fatal("late orphan executed or survived")
	}
}

func TestWorkloadCurrentPolicyAndLeaseExpiryStopExecution(t *testing.T) {
	for _, mode := range []string{"key-rotation", "policy-epoch", "offboard", "policy-outage", "lease-expiry"} {
		t.Run(mode, func(t *testing.T) {
			f := newWorkloadFixture(t)
			h := f.launch(t, 0)
			observedWorkload(t, f)
			start := time.Now()
			switch mode {
			case "key-rotation":
				f.authority.change("context-a", func(r *CurrentRights) { r.CredentialGeneration++ })
			case "policy-epoch":
				f.authority.change("context-a", func(r *CurrentRights) { r.PolicyEpoch++ })
			case "offboard":
				f.authority.change("context-a", func(r *CurrentRights) { r.ActiveHuman = false })
			case "policy-outage":
				f.authority.mu.Lock()
				f.authority.outage = "context-a"
				f.authority.mu.Unlock()
			case "lease-expiry":
				f.clock.Add(int64(2 * time.Minute))
			}
			waitWorkload(t, h.Done)
			t.Logf("synthetic %s cleanup %s", mode, time.Since(start))
			f.engine.mu.Lock()
			count := len(f.engine.containers)
			f.engine.mu.Unlock()
			if count != 0 {
				t.Fatal("revoked process left running")
			}
		})
	}
}

func TestWorkloadGrantExpiryClampsLeaseAndRetryHasFreshSession(t *testing.T) {
	f := newWorkloadFixture(t)
	g := f.grants[0].Spec()
	g.ExpiresAt = fixtureNow.Add(10 * time.Second)
	narrow, err := NewGrant(f.runs[0], g, fixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	h, err := f.s.Launch(context.Background(), f.runs[0], narrow, "channel-a", Write, "refs/heads/task/a", time.Minute, f.pairs[0])
	if err != nil {
		t.Fatal(err)
	}
	observedWorkload(t, f)
	f.s.mu.Lock()
	lease := f.s.runs[h.ID].lease
	oldSession := f.s.runs[h.ID].intent.Session
	oldCache := f.s.runs[h.ID].intent.Cache
	f.s.mu.Unlock()
	if lease.expires != g.ExpiresAt || lease.operation != Write || lease.ref != "refs/heads/task/a" {
		t.Fatal("lease widened originator grant")
	}
	if err = f.s.Revoke(h.ID); err != nil {
		t.Fatal(err)
	}
	child, err := Derive(f.runs[0], "retry-context", "retry-attempt", f.runs[0].spec.Binding, Retry, fixtureNow, fixtureNow.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	childSpec := f.grants[0].Spec()
	childSpec.ContextID = child.spec.ID
	childSpec.ID = "retry-grant"
	childGrant, err := NarrowGrant(f.grants[0], child, childSpec, fixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	f.authority.mu.Lock()
	rights := f.authority.rights["context-a"]
	rights.Runtime.ChannelID = "retry-channel"
	f.authority.rights[child.spec.ID] = rights
	f.authority.mu.Unlock()
	retry, err := f.s.Launch(context.Background(), child, childGrant, "retry-channel", Write, "refs/heads/task/a", time.Minute, f.pairs[1])
	if err != nil {
		t.Fatal(err)
	}
	observedWorkload(t, f)
	f.s.mu.Lock()
	record := f.s.runs[retry.ID].intent
	f.s.mu.Unlock()
	if record.Cache != oldCache || record.Session == oldSession || retry.ID == h.ID {
		t.Fatal("retry reused native state or changed authorization domain")
	}
	if _, err = os.Stat(f.s.directory(h.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("prior attempt source remained")
	}
}

func TestWorkloadRecoveryPreservesForeignSupervisorAndRejectsDoubleOwner(t *testing.T) {
	f := newWorkloadFixture(t)
	h := f.launch(t, 0)
	observedWorkload(t, f)
	if _, err := NewWorkloadSupervisor(f.s.engine, f.channels.Load(), f.s.policy, f.broker.URL, f.roots); !errors.Is(err, ErrConflict) {
		t.Fatalf("concurrent root owner accepted: %v", err)
	}
	root, err := os.MkdirTemp("", "s4-foreign-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	policy := f.s.policy
	policy.Root = root
	other, err := NewWorkloadSupervisor(f.s.engine, NewWorkloadChannels(Authorizer{f.authority}, f.channels.Load().now), policy, f.broker.URL, f.roots)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err = other.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.engine.mu.Lock()
	count := len(f.engine.containers)
	f.engine.mu.Unlock()
	if count != 1 {
		t.Fatal("foreign supervisor purged live workload")
	}
	select {
	case <-h.Done:
		t.Fatal("foreign recovery stopped owner workload")
	default:
	}
}

func TestWorkloadChannelRejectsMissingTLSAndUnregisteredCertificate(t *testing.T) {
	f := newWorkloadFixture(t)
	h := f.launch(t, 0)
	observedWorkload(t, f)
	request := httptest.NewRequest(http.MethodGet, "https://local/info/refs?service=git-receive-pack", nil)
	request.Header.Set("X-Channel-ID", "channel-a")
	request.Header.Set("Authorization", "Bearer synthetic-forgery")
	if _, _, err := f.channels.Load().Authenticate(request); err == nil {
		t.Fatal("headers supplied identity without mTLS")
	}
	client := f.broker.Client()
	transport := client.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.Certificates = []tls.Certificate{f.pairs[1]}
	client.Transport = transport
	defer transport.CloseIdleConnections()
	request, _ = http.NewRequest(http.MethodGet, f.broker.URL+"/info/refs?service=git-receive-pack", nil)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatalf("unregistered B certificate selected A: %d", response.StatusCode)
	}
	activeTransport := f.broker.Client().Transport.(*http.Transport).Clone()
	activeTransport.TLSClientConfig.Certificates = []tls.Certificate{f.pairs[0]}
	defer activeTransport.CloseIdleConnections()
	activeClient := &http.Client{Transport: activeTransport, Timeout: 2 * time.Second}
	response, err = activeClient.Get(f.broker.URL + "/info/refs?service=git-receive-pack")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("ordinary current A channel denied")
	}
	observedWorkload(t, f)
	if err = f.s.Revoke(h.ID); err != nil {
		t.Fatal(err)
	}
	// Reuse the same established mTLS connection after revocation.
	response, err = activeClient.Get(f.broker.URL + "/info/refs?service=git-receive-pack")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatal("old TLS channel survived cleanup")
	}
}

func TestWorkloadCloseRefusesChannelsBeforeBlockedAdmissionDrains(t *testing.T) {
	f := newWorkloadFixture(t)
	a := f.launch(t, 0)
	observedWorkload(t, f)
	release := make(chan struct{})
	defer close(release)
	entered := make(chan struct{}, 1)
	f.engine.mu.Lock()
	f.engine.createRelease = release
	f.engine.createEntered = entered
	f.engine.mu.Unlock()
	launched := make(chan error, 1)
	go func() {
		_, err := f.s.Launch(context.Background(), f.runs[1], f.grants[1], "channel-b", Write, "refs/heads/task/b", time.Minute, f.pairs[1])
		launched <- err
	}()
	<-entered
	closed := make(chan error, 1)
	go func() { closed <- f.s.Close() }()
	select {
	case <-f.s.lifetime.Done():
	case <-time.After(500 * time.Millisecond):
		t.Fatal("shutdown waited for blocked admission")
	}
	client := f.broker.Client()
	transport := client.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.Certificates = []tls.Certificate{f.pairs[0]}
	client.Transport = transport
	defer transport.CloseIdleConnections()
	response, err := client.Get(f.broker.URL + "/info/refs?service=git-receive-pack")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatal("A channel remained active during blocked B shutdown")
	}
	if err = <-launched; err == nil {
		t.Fatal("shutdown launch returned success")
	}
	if err = <-closed; err == nil {
		t.Fatal("uncertain B create was falsely acknowledged cleaned")
	}
	waitWorkload(t, a.Done)
}

func TestWorkloadProxyAllowsBoundedSlowProviderWork(t *testing.T) {
	f := newWorkloadFixture(t)
	f.transport.delay.Store(int64(1200 * time.Millisecond))
	h := f.launch(t, 0)
	observedWorkload(t, f)
	// The provider callback has returned, but the fake CLI must also receive
	// the successful response. It exits immediately on HTTP/transport failure.
	time.Sleep(150 * time.Millisecond)
	f.engine.mu.Lock()
	live := false
	for _, c := range f.engine.containers {
		live = c.inspection.State.Running
	}
	f.engine.mu.Unlock()
	if !live {
		t.Fatal("valid provider work longer than1s was aborted by proxy")
	}
	if err := f.s.Revoke(h.ID); err != nil {
		t.Fatal(err)
	}
}

func TestWorkloadSpentAttemptCannotRelaunchWithFreshChannel(t *testing.T) {
	for _, restart := range []bool{false, true} {
		t.Run(fmt.Sprintf("restart-%v", restart), func(t *testing.T) {
			f := newWorkloadFixture(t)
			h := f.launch(t, 0)
			observedWorkload(t, f)
			if err := f.s.Revoke(h.ID); err != nil {
				t.Fatal(err)
			}
			if restart {
				if err := f.s.Close(); err != nil {
					t.Fatal(err)
				}
				restartWorkloadSupervisor(t, f)
				if err := f.s.Recover(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			f.authority.change("context-a", func(r *CurrentRights) { r.Runtime.ChannelID = "channel-b" })
			if _, err := f.s.Launch(context.Background(), f.runs[0], f.grants[0], "channel-b", Write, "refs/heads/task/a", time.Minute, f.pairs[1]); !errors.Is(err, ErrConflict) {
				t.Fatalf("spent execution attempt relaunched: %v", err)
			}
			f.engine.mu.Lock()
			starts := f.engine.starts
			f.engine.mu.Unlock()
			if starts != 1 {
				t.Fatal("attempt executed twice")
			}
		})
	}
}

func TestWorkloadMalformedEngineIDRetainsCleanupIntent(t *testing.T) {
	f := newWorkloadFixture(t)
	f.engine.mutate = func(i *DockerInspection) { i.ID = "../../foreign" }
	if _, err := f.s.Launch(context.Background(), f.runs[0], f.grants[0], "channel-a", Write, "refs/heads/task/a", time.Minute, f.pairs[0]); err == nil {
		t.Fatal("malformed container ID accepted")
	}
	f.engine.mu.Lock()
	starts := f.engine.starts
	count := len(f.engine.containers)
	// Repair only the fake engine so test teardown can reap its reserved object.
	for name, c := range f.engine.containers {
		id := sha256.Sum256([]byte(name))
		c.inspection.ID = hex.EncodeToString(id[:])
	}
	f.engine.mu.Unlock()
	if starts != 0 || count != 1 {
		t.Fatal("malformed ID executed or unsafe deletion attempted")
	}
	f.s.mu.Lock()
	ready := f.s.ready
	pending := len(f.s.runs)
	f.s.mu.Unlock()
	if ready || pending != 1 {
		t.Fatal("unclean ownership was hidden")
	}
}

func TestWorkloadLostProxyStopsRunAndRefusesPreStart(t *testing.T) {
	for _, beforeStart := range []bool{false, true} {
		t.Run(fmt.Sprintf("before-start-%v", beforeStart), func(t *testing.T) {
			f := newWorkloadFixture(t)
			if beforeStart {
				var cancelled atomic.Bool
				f.engine.onCreate = func() {
					f.s.mu.Lock()
					var run *supervisedWorkload
					for _, w := range f.s.runs {
						run = w
					}
					f.s.mu.Unlock()
					_ = run.server.Close()
					select {
					case <-run.lifetime.Done():
						cancelled.Store(true)
					case <-time.After(500 * time.Millisecond):
					}
				}
				if _, err := f.s.Launch(context.Background(), f.runs[0], f.grants[0], "channel-a", Write, "refs/heads/task/a", time.Minute, f.pairs[0]); err == nil {
					t.Fatal("lost pre-start proxy allowed execution")
				}
				f.engine.mu.Lock()
				starts := f.engine.starts
				f.engine.mu.Unlock()
				if !cancelled.Load() || starts != 0 {
					t.Fatal("proxy failure did not cancel pending launch")
				}
				return
			}
			h := f.launch(t, 0)
			observedWorkload(t, f)
			f.s.mu.Lock()
			run := f.s.runs[h.ID]
			f.s.mu.Unlock()
			if err := run.server.Close(); err != nil {
				t.Fatal(err)
			}
			waitWorkload(t, h.Done)
			f.engine.mu.Lock()
			remaining := len(f.engine.containers)
			f.engine.mu.Unlock()
			if remaining != 0 {
				t.Fatal("dead proxy left workload active")
			}
		})
	}
}
