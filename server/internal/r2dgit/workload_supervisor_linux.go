//go:build linux

package r2dgit

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/uuid"
	"golang.org/x/net/netutil"
	"golang.org/x/sys/unix"
)

const workloadCallBound = time.Second

// WorkloadPolicy is operator-owned launch policy, not proof of containment.
// Docker Inspect validates the requested configuration; kernel/VM containment
// still requires the deployment acceptance suite. No production caller enables
// protected execution from these fields.
type WorkloadPolicy struct {
	RuntimeID, Root, Image, AppArmor                            string
	Seccomp                                                     json.RawMessage
	ContainerUID, ContainerGID, SocketUID, SocketGID            int
	Memory, NanoCPUs, PIDs, WorkspaceBytes, HomeBytes, TmpBytes int64
	MaxRuns                                                     int
}

type WorkloadSupervisor struct {
	admission     sync.Mutex
	mu            sync.Mutex
	engine        WorkloadEngine
	channels      *WorkloadChannels
	policy        WorkloadPolicy
	broker        *url.URL
	roots         *x509.CertPool
	lock          *os.File
	ready, closed bool
	runs          map[string]*supervisedWorkload
	lifetime      context.Context
	cancel        context.CancelFunc
	closeDone     chan struct{}
	closeErr      error
}

type workloadIntent struct {
	Nonce, Name, RuntimeID, ContextID, TaskID, AttemptID, Cache, Session, Phase string
}

type supervisedWorkload struct {
	mu              sync.Mutex
	finished        bool
	cleanExit       atomic.Bool
	revoked         atomic.Bool
	intent          workloadIntent
	lease           Lease
	cert            *x509.Certificate
	cancel          context.CancelFunc
	lifetime        context.Context
	server          *http.Server
	transport       *http.Transport
	done            chan struct{}
	watchStop       chan struct{}
	watchDone       chan struct{}
	stopped         bool
	createAttempted bool
}

type WorkloadHandle struct {
	ID       string
	Done     <-chan struct{}
	workload *supervisedWorkload
}

var pinnedWorkloadImage = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:/-]*@sha256:[a-f0-9]{64}$`)
var workloadProfile = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$`)

func NewWorkloadSupervisor(engine WorkloadEngine, channels *WorkloadChannels, p WorkloadPolicy, broker string, roots *x509.CertPool) (*WorkloadSupervisor, error) {
	u, err := url.Parse(broker)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || roots == nil || engine == nil || channels == nil || channels.now == nil || !nonempty(p.RuntimeID) || !pinnedWorkloadImage.MatchString(p.Image) || !workloadProfile.MatchString(p.AppArmor) || p.AppArmor == "unconfined" || !filepath.IsAbs(p.Root) || strings.ContainsAny(p.Root, ":,\x00\r\n") || p.ContainerUID <= 0 || p.ContainerGID <= 0 || p.SocketUID < 0 || p.SocketGID < 0 || p.Memory <= 0 || p.NanoCPUs <= 0 || p.PIDs <= 0 || p.WorkspaceBytes <= 0 || p.HomeBytes <= 0 || p.TmpBytes <= 0 || p.WorkspaceBytes > p.Memory || p.HomeBytes > p.Memory-p.WorkspaceBytes || p.TmpBytes > p.Memory-p.WorkspaceBytes-p.HomeBytes {
		return nil, ErrRuntime
	}
	var profile struct {
		DefaultAction string
		Syscalls      []json.RawMessage
	}
	if len(p.Seccomp) > 64<<10 || json.Unmarshal(p.Seccomp, &profile) != nil || profile.DefaultAction != "SCMP_ACT_ERRNO" || len(profile.Syscalls) == 0 {
		return nil, ErrRuntime
	}
	p.Seccomp = append(json.RawMessage(nil), p.Seccomp...)
	// A pre-created private supervisor directory is required. It must never be
	// a workload mount; only individual socket directories are exposed.
	info, err := os.Lstat(p.Root)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return nil, ErrRuntime
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || p.MaxRuns <= 0 || p.MaxRuns > 32 {
		return nil, ErrRuntime
	}
	lock, err := os.OpenFile(filepath.Join(p.Root, "lock"), os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, ErrRuntime
	}
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		return nil, ErrConflict
	}
	lifetime, cancel := context.WithCancel(context.Background())
	return &WorkloadSupervisor{engine: engine, channels: channels, policy: p, broker: u, roots: roots.Clone(), lock: lock, runs: make(map[string]*supervisedWorkload), lifetime: lifetime, cancel: cancel, closeDone: make(chan struct{})}, nil
}

func (s *WorkloadSupervisor) name(nonce string) string {
	h := sha256.Sum256([]byte(s.policy.RuntimeID))
	return "r2d-" + hex.EncodeToString(h[:8]) + "-" + nonce
}
func (s *WorkloadSupervisor) owner() string {
	h := sha256.Sum256([]byte(filepath.Clean(s.policy.Root)))
	return s.policy.RuntimeID + "-" + hex.EncodeToString(h[:16])
}
func (s *WorkloadSupervisor) directory(nonce string) string {
	return filepath.Join(s.policy.Root, nonce)
}

func (s *WorkloadSupervisor) persist(i workloadIntent) error {
	dir := s.directory(i.Nonce)
	if err := os.Mkdir(dir, 0700); err != nil {
		return ErrRuntime
	}
	return s.updateIntent(i)
}
func (s *WorkloadSupervisor) updateIntent(i workloadIntent) error {
	data, err := json.Marshal(i)
	if err != nil {
		return ErrRuntime
	}
	dir := s.directory(i.Nonce)
	f, err := os.OpenFile(filepath.Join(dir, "intent.tmp"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return ErrRuntime
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err == nil {
		err = os.Rename(filepath.Join(dir, "intent.tmp"), filepath.Join(dir, "intent.json"))
	}
	if err == nil {
		err = syncWorkloadDirectory(dir)
	}
	if err == nil {
		err = syncWorkloadDirectory(s.policy.Root)
	}
	return err
}
func syncWorkloadDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}

func (s *WorkloadSupervisor) specification(i workloadIntent) DockerWorkload {
	p := s.policy
	owner := fmt.Sprintf(",uid=%d,gid=%d,mode=0700", p.ContainerUID, p.ContainerGID)
	host := DockerWorkloadHost{NetworkMode: "none", IpcMode: "private", CgroupnsMode: "private", ReadonlyRootfs: true, CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges=true", "apparmor=" + p.AppArmor, "seccomp=" + string(p.Seccomp)}, Memory: p.Memory, MemorySwap: p.Memory, NanoCpus: p.NanoCPUs, PidsLimit: p.PIDs, Binds: []string{filepath.Join(s.directory(i.Nonce), "channel") + ":/run/multica:ro,rprivate"}, Tmpfs: map[string]string{
		"/workspace":  "rw,nosuid,nodev,size=" + strconv.FormatInt(p.WorkspaceBytes, 10) + owner,
		"/home/agent": "rw,noexec,nosuid,nodev,size=" + strconv.FormatInt(p.HomeBytes, 10) + owner,
		"/tmp":        "rw,noexec,nosuid,nodev,size=" + strconv.FormatInt(p.TmpBytes, 10) + owner,
	}}
	host.LogConfig.Type = "none" // stdout/source must not enter the ambient engine log sink.
	host.RestartPolicy.Name = "no"
	return DockerWorkload{Image: p.Image, User: fmt.Sprintf("%d:%d", p.ContainerUID, p.ContainerGID), WorkingDir: "/workspace", Entrypoint: []string{"/opt/multica/agent"}, Cmd: []string{}, Env: []string{"HOME=/home/agent", "PATH=/usr/local/bin:/usr/bin:/bin", "MULTICA_GIT_SOCKET=/run/multica/broker.sock"}, Labels: map[string]string{workloadOwnerLabel: s.owner(), workloadNonceLabel: i.Nonce, "io.multica.git-cache": i.Cache, "io.multica.git-session": i.Session}, HostConfig: host}
}

func (s *WorkloadSupervisor) inspect(ctx context.Context, name string) (DockerInspection, error) {
	ctx, cancel := context.WithTimeout(ctx, workloadCallBound)
	defer cancel()
	return s.engine.Inspect(ctx, name)
}
func (s *WorkloadSupervisor) remove(ctx context.Context, name string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, workloadCallBound)
	defer cancel()
	actual, err := s.engine.Inspect(ctx, name)
	if errors.Is(err, errWorkloadAbsent) {
		return false, nil
	}
	if err != nil || actual.Name != "/"+name || actual.Config.Labels[workloadOwnerLabel] != s.owner() || name != s.name(actual.Config.Labels[workloadNonceLabel]) || len(actual.ID) != 64 || strings.Trim(actual.ID, "0123456789abcdef") != "" {
		return false, ErrRuntime
	}
	return true, s.engine.Remove(ctx, actual.ID)
}

func sameWorkloadHost(a, b DockerWorkloadHost) bool {
	// Engine JSON uses [] and null interchangeably for empty options.
	normalize := func(h DockerWorkloadHost) DockerWorkloadHost {
		v := reflect.ValueOf(&h).Elem()
		for n := 0; n < v.NumField(); n++ {
			f := v.Field(n)
			if (f.Kind() == reflect.Slice || f.Kind() == reflect.Map) && f.Len() == 0 {
				f.SetZero()
			}
		}
		return h
	}
	return reflect.DeepEqual(normalize(a), normalize(b))
}

func (s *WorkloadSupervisor) validateInspection(i workloadIntent, actual DockerInspection) error {
	want := s.specification(i)
	if len(actual.ID) != 64 || strings.Trim(actual.ID, "0123456789abcdef") != "" || actual.Name != "/"+i.Name || len(actual.Config.Cmd) != 0 || !reflect.DeepEqual(actual.Config.Env, want.Env) || !reflect.DeepEqual(actual.Config.Entrypoint, want.Entrypoint) || actual.Config.Image != want.Image || actual.Config.User != want.User || actual.Config.WorkingDir != want.WorkingDir || len(actual.Config.Volumes) != 0 || !reflect.DeepEqual(actual.Config.Labels, want.Labels) || !sameWorkloadHost(actual.HostConfig, want.HostConfig) || actual.AppArmorProfile != s.policy.AppArmor {
		return ErrRuntime
	}
	bind := false
	for _, mount := range actual.Mounts {
		if mount.Type == "bind" && mount.Source == filepath.Join(s.directory(i.Nonce), "channel") && mount.Destination == "/run/multica" && !mount.RW {
			if bind {
				return ErrRuntime
			}
			bind = true
			continue
		}
		if mount.Type == "tmpfs" && want.HostConfig.Tmpfs[mount.Destination] != "" {
			continue
		}
		return ErrRuntime
	}
	if !bind {
		return ErrRuntime
	}
	return nil
}

// Launch accepts sealed identity/grants plus an already-enrolled outside-run
// proxy certificate. RuntimeEvidence must independently authorize this exact
// channel. This component never manufactures OperatorApproved/Isolated flags.
func (s *WorkloadSupervisor) Launch(ctx context.Context, run RunSecurityContext, grant RepositoryGrant, channel string, op Operation, ref string, ttl time.Duration, pair tls.Certificate) (WorkloadHandle, error) {
	s.admission.Lock()
	defer s.admission.Unlock()
	ctx, cancelLaunch := context.WithCancel(ctx)
	stopClose := context.AfterFunc(s.lifetime, cancelLaunch)
	defer cancelLaunch()
	defer stopClose()
	s.mu.Lock()
	available := !s.closed && s.ready
	s.mu.Unlock()
	if !available || (op != Write && op != Read) || run.spec.Binding.RuntimeID != s.policy.RuntimeID || len(pair.Certificate) != 1 {
		return WorkloadHandle{}, ErrRuntime
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return WorkloadHandle{}, ErrPrincipal
	}
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return WorkloadHandle{}, ErrPrincipal
	}
	public, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || !reflect.DeepEqual(public, cert.RawSubjectPublicKeyInfo) {
		return WorkloadHandle{}, ErrPrincipal
	}
	authCtx, cancel := context.WithTimeout(ctx, workloadCallBound)
	leaseNow := s.channels.now()
	if remaining := cert.NotAfter.Sub(leaseNow); ttl > remaining {
		ttl = remaining
	}
	lease, err := IssueLease(authCtx, s.channels.authorizer, run, grant, channel, op, ref, leaseNow, ttl)
	cancel()
	if err != nil {
		return WorkloadHandle{}, err
	}
	cache, err := CachePartition(run, grant)
	if err != nil {
		return WorkloadHandle{}, err
	}
	session, err := SessionPartition(run, grant)
	if err != nil {
		return WorkloadHandle{}, err
	}
	s.mu.Lock()
	if len(s.runs) >= s.policy.MaxRuns {
		s.mu.Unlock()
		return WorkloadHandle{}, ErrRuntime
	}
	for _, active := range s.runs {
		if active.intent.Session == session {
			s.mu.Unlock()
			return WorkloadHandle{}, ErrConflict
		}
	}
	s.mu.Unlock()
	i := workloadIntent{Nonce: uuid.NewString(), RuntimeID: s.policy.RuntimeID, ContextID: run.spec.ID, TaskID: run.spec.Binding.TaskID, AttemptID: run.spec.AttemptID, Cache: cache, Session: session, Phase: "reserved"}
	i.Name = s.name(i.Nonce)
	if err = s.persist(i); err != nil {
		s.notReady()
		return WorkloadHandle{}, ErrRuntime
	}
	lifetime, revoke := context.WithCancel(s.lifetime)
	w := &supervisedWorkload{intent: i, lease: lease, cert: cert, cancel: revoke, lifetime: lifetime, done: make(chan struct{}), watchStop: make(chan struct{}), watchDone: make(chan struct{})}
	stopRun := context.AfterFunc(lifetime, cancelLaunch)
	defer stopRun()
	s.mu.Lock()
	s.runs[i.Nonce] = w
	s.mu.Unlock()
	fail := func(cause error) (WorkloadHandle, error) {
		return WorkloadHandle{}, errors.Join(cause, s.cleanupWorkload(w))
	}
	// Spent identities survive restart. They are non-secret tombstones, not
	// reusable bearer credentials or native session state.
	for _, value := range []string{"sess-" + hexDigest([]byte(session)), "cert-" + hexDigest(cert.Raw), "chan-" + hexDigest([]byte(channel))} {
		f, err := os.OpenFile(filepath.Join(s.policy.Root, value), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return fail(ErrConflict)
		}
		err = errors.Join(f.Sync(), f.Close(), syncWorkloadDirectory(s.policy.Root))
		if err != nil {
			s.notReady()
			return fail(ErrRuntime)
		}
	}
	if err = s.channels.register(cert, lease, lifetime); err != nil {
		return fail(err)
	}
	if err = s.serve(w, lifetime, pair); err != nil {
		return fail(err)
	}
	w.intent.Phase = "creating"
	if err = s.updateIntent(w.intent); err != nil {
		return fail(ErrRuntime)
	}
	w.createAttempted = true
	createCtx, stop := context.WithTimeout(ctx, workloadCallBound)
	err = s.engine.Create(createCtx, i.Name, s.specification(i))
	stop()
	if err != nil {
		return fail(ErrRuntime)
	}
	w.intent.Phase = "created"
	if err = s.updateIntent(w.intent); err != nil {
		return fail(ErrRuntime)
	}
	actual, err := s.inspect(ctx, i.Name)
	if err != nil || s.validateInspection(i, actual) != nil {
		return fail(ErrRuntime)
	}
	// Recheck after create/inspect before an executable can run.
	authCtx, cancel = context.WithTimeout(ctx, workloadCallBound)
	err = s.channels.authorizer.Authorize(authCtx, run, grant, channel, op, ref, s.channels.now())
	cancel()
	if err != nil {
		return fail(err)
	}
	if ctx.Err() != nil || lifetime.Err() != nil || !s.launchAllowed() || !s.channels.now().Before(lease.expires) {
		return fail(ErrRevoked)
	}
	startCtx, stop := context.WithTimeout(ctx, workloadCallBound)
	err = s.engine.Start(startCtx, actual.ID)
	stop()
	if err != nil {
		return fail(ErrRuntime)
	}
	if ctx.Err() != nil || lifetime.Err() != nil || !s.launchAllowed() || !s.channels.now().Before(lease.expires) {
		return fail(ErrRevoked)
	}
	go s.watch(w)
	return WorkloadHandle{ID: i.Nonce, Done: w.done, workload: w}, nil
}

func (s *WorkloadSupervisor) serve(w *supervisedWorkload, lifetime context.Context, pair tls.Certificate) error {
	dir := filepath.Join(s.directory(w.intent.Nonce), "channel")
	if err := os.Mkdir(dir, 0700); err != nil {
		return ErrRuntime
	}
	listener, err := net.Listen("unix", filepath.Join(dir, "broker.sock"))
	if err != nil {
		return ErrRuntime
	}
	if err = os.Chown(filepath.Join(dir, "broker.sock"), s.policy.SocketUID, s.policy.SocketGID); err == nil {
		err = os.Chmod(filepath.Join(dir, "broker.sock"), 0600)
	}
	if err == nil {
		err = os.Chown(dir, s.policy.SocketUID, s.policy.SocketGID)
	}
	if err != nil {
		listener.Close()
		return ErrRuntime
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: s.roots, Certificates: []tls.Certificate{pair}}, ResponseHeaderTimeout: 30 * time.Second, TLSHandshakeTimeout: time.Second, IdleConnTimeout: time.Second, MaxIdleConnsPerHost: 1, MaxConnsPerHost: 2}
	w.transport = transport
	proxy := &httputil.ReverseProxy{Transport: transport, Rewrite: func(p *httputil.ProxyRequest) {
		p.SetURL(s.broker)
		p.Out.Header = http.Header{}
		for _, key := range []string{"Content-Type", "Git-Protocol"} {
			if value := p.In.Header.Get(key); value != "" {
				p.Out.Header.Set(key, value)
			}
		}
	}, ErrorHandler: func(rw http.ResponseWriter, _ *http.Request, _ error) {
		w.cancel()
		http.Error(rw, "git_workload_unavailable", http.StatusServiceUnavailable)
	}}
	slots := make(chan struct{}, 2)
	w.server = &http.Server{ReadHeaderTimeout: workloadCallBound, ReadTimeout: 5 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: workloadCallBound, MaxHeaderBytes: 8192, Handler: http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		writeRoute := w.lease.operation == Write && ((r.Method == http.MethodGet && r.URL.Path == "/info/refs" && r.URL.RawQuery == "service=git-receive-pack") || (r.Method == http.MethodPost && r.URL.Path == "/git-receive-pack" && r.URL.RawQuery == ""))
		readRoute := w.lease.operation == Read && r.URL.RawQuery == "" && ((r.Method == http.MethodGet && (r.URL.Path == "/snapshot" || r.URL.Path == "/assignment" || r.URL.Path == "/write-reference")) || (r.Method == http.MethodPost && (r.URL.Path == "/outputs" || r.URL.Path == "/acknowledge" || r.URL.Path == "/model" || r.URL.Path == "/finalize" || r.URL.Path == "/children")))
		if lifetime.Err() != nil || !(writeRoute || readRoute) {
			http.Error(rw, "git_workload_unavailable", http.StatusForbidden)
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			http.Error(rw, "git_workload_busy", http.StatusServiceUnavailable)
			return
		}
		r.Body = http.MaxBytesReader(rw, r.Body, maxPackBytes+2048)
		requestCtx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		stop := context.AfterFunc(lifetime, cancel)
		defer stop()
		proxy.ServeHTTP(rw, r.WithContext(requestCtx))
	})}
	go func() {
		_ = w.server.Serve(netutil.LimitListener(listener, 4))
		if lifetime.Err() == nil {
			w.cancel()
		}
	}()
	return nil
}

func (s *WorkloadSupervisor) watch(w *supervisedWorkload) {
	defer close(w.watchDone)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-w.watchStop:
			return
		case <-w.lifetime.Done():
			_ = s.cleanupWorkload(w)
			return
		case <-ticker.C:
		}
		ctx, cancel := context.WithTimeout(context.Background(), workloadCallBound)
		err := s.channels.authorizer.Authorize(ctx, w.lease.run, w.lease.grant, w.lease.channelID, w.lease.operation, w.lease.ref, s.channels.now())
		cancel()
		if !s.channels.now().Before(w.lease.expires) {
			err = ErrRevoked
		}
		clean := false
		if err == nil {
			actual, inspectErr := s.inspect(context.Background(), w.intent.Name)
			if inspectErr == nil && !actual.State.Running && actual.State.ExitCode == 0 && s.validateInspection(w.intent, actual) == nil {
				clean = true
			}
			if inspectErr != nil || !actual.State.Running || s.validateInspection(w.intent, actual) != nil {
				err = ErrRuntime
			}
		}
		if err != nil {
			_ = s.cleanupWorkloadResult(w, clean)
			return
		}
	}
}

// Cleanup first refuses/cancels broker traffic, then force-removes the exact
// journalled container and its anonymous volumes. Failed cleanup retains its
// intent and blocks new launches until recovery succeeds.
func (s *WorkloadSupervisor) cleanupWorkload(w *supervisedWorkload) error {
	w.revoked.Store(true)
	return s.cleanupWorkloadResult(w, false)
}

func (s *WorkloadSupervisor) cleanupWorkloadResult(w *supervisedWorkload, clean bool) error {
	live := w.lifetime.Err() == nil
	w.cancel()
	s.channels.revoke(w.cert, w.lease)
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.finished {
		return nil
	}
	if w.server != nil {
		_ = w.server.Close()
	}
	if w.transport != nil {
		w.transport.CloseIdleConnections()
	}
	if !w.stopped {
		w.stopped = true
		close(w.watchStop)
	}
	found, err := s.remove(context.Background(), w.intent.Name)
	if err != nil || (w.createAttempted && w.intent.Phase == "creating" && !found) {
		s.notReady()
		return ErrRuntime
	}
	if err := os.RemoveAll(s.directory(w.intent.Nonce)); err != nil {
		s.notReady()
		return ErrRuntime
	}
	if err := syncWorkloadDirectory(s.policy.Root); err != nil {
		s.notReady()
		return ErrRuntime
	}
	s.mu.Lock()
	delete(s.runs, w.intent.Nonce)
	s.mu.Unlock()
	w.finished = true
	w.cleanExit.Store(clean && live && !w.revoked.Load())
	close(w.done)
	return nil
}

func (s *WorkloadSupervisor) Revoke(id string) error {
	s.mu.Lock()
	w, ok := s.runs[id]
	s.mu.Unlock()
	if !ok {
		return ErrRevoked
	}
	return s.cleanupWorkload(w)
}

// Recover is mandatory before launch, and never adopts/resumes a container.
// Exact runtime+nonce labels and deterministic names scope engine cleanup.
func (s *WorkloadSupervisor) Recover(ctx context.Context) error {
	s.admission.Lock()
	defer s.admission.Unlock()
	s.mu.Lock()
	s.ready = false
	allowed := !s.closed && len(s.runs) == 0
	s.mu.Unlock()
	if !allowed {
		return ErrConflict
	}
	listCtx, cancel := context.WithTimeout(ctx, workloadCallBound)
	containers, err := s.engine.List(listCtx, s.owner())
	cancel()
	if err != nil {
		return ErrRuntime
	}
	removed := map[string]bool{}
	for _, c := range containers {
		if c.Labels[workloadOwnerLabel] != s.owner() {
			continue
		}
		nonce := c.Labels[workloadNonceLabel]
		if _, err := uuid.Parse(nonce); err != nil || len(c.Names) != 1 || c.Names[0] != "/"+s.name(nonce) {
			return ErrRuntime
		}
		if _, err := s.remove(ctx, s.name(nonce)); err != nil {
			return ErrRuntime
		}
		removed[nonce] = true
	}
	files, err := os.ReadDir(s.policy.Root)
	if err != nil {
		return ErrRuntime
	}
	for _, file := range files {
		if applicationJournalName(file.Name()) && file.Type().IsRegular() {
			continue
		}
		if file.Name() == "lock" {
			continue
		}
		if (strings.HasPrefix(file.Name(), "cert-") || strings.HasPrefix(file.Name(), "chan-") || strings.HasPrefix(file.Name(), "sess-")) && len(file.Name()) == 69 && strings.Trim(file.Name()[5:], "0123456789abcdef") == "" && file.Type().IsRegular() {
			continue
		}
		if _, err := uuid.Parse(file.Name()); err != nil || !file.IsDir() {
			return ErrRuntime
		}
		data, err := os.ReadFile(filepath.Join(s.directory(file.Name()), "intent.json"))
		if err != nil || len(data) > 8192 {
			return ErrRuntime
		}
		var intent workloadIntent
		if json.Unmarshal(data, &intent) != nil || intent.Nonce != file.Name() || intent.RuntimeID != s.policy.RuntimeID || intent.Name != s.name(file.Name()) || (intent.Phase != "reserved" && intent.Phase != "creating" && intent.Phase != "created") {
			return ErrRuntime
		}
		found, err := s.remove(ctx, intent.Name)
		// A timed-out create may finish AFTER a 404. Keep its intent and deny
		// admission until the reserved resource is observed and removed.
		if err != nil || (intent.Phase == "creating" && !found && !removed[file.Name()]) {
			return ErrRuntime
		}
		if err := os.RemoveAll(s.directory(file.Name())); err != nil {
			return ErrRuntime
		}
	}
	if err := syncWorkloadDirectory(s.policy.Root); err != nil {
		return ErrRuntime
	}
	s.mu.Lock()
	s.ready = !s.closed
	s.mu.Unlock()
	return nil
}

func (s *WorkloadSupervisor) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		<-s.closeDone
		return s.closeErr
	}
	s.closed = true
	s.ready = false
	s.mu.Unlock()
	// Refuse every channel, including a launch still doing I/O, before waiting
	// for admission or filesystem/engine cleanup. Per-run watchers cancel too.
	s.cancel()
	s.admission.Lock()
	defer s.admission.Unlock()
	s.mu.Lock()
	runs := make([]*supervisedWorkload, 0, len(s.runs))
	for _, w := range s.runs {
		runs = append(runs, w)
	}
	s.mu.Unlock()
	var err error
	for _, w := range runs {
		err = errors.Join(err, s.cleanupWorkload(w))
	}
	err = errors.Join(err, unix.Flock(int(s.lock.Fd()), unix.LOCK_UN), s.lock.Close())
	s.closeErr = err
	close(s.closeDone)
	return err
}

func (s *WorkloadSupervisor) notReady() { s.mu.Lock(); s.ready = false; s.mu.Unlock() }
func (s *WorkloadSupervisor) launchAllowed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ready && !s.closed
}
