//go:build linux

package handler

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
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/multica-ai/multica/server/internal/r2dgit"
	"github.com/multica-ai/multica/server/internal/service"
	"github.com/multica-ai/multica/server/internal/testutil"
	"github.com/multica-ai/multica/server/internal/util"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
)

// A test-created child enters before TestMain so the handler's shared database
// fixtures are never initialized twice. This mode runs no installed agent CLI.
func init() {
	if os.Getenv("MULTICA_SYNTHETIC_PROTECTED_HELPER") != "1" {
		return
	}
	ctx, stop := context.WithTimeout(context.Background(), 15*time.Second)
	client, err := r2dgit.NewWorkloadClient(os.Getenv("MULTICA_SYNTHETIC_SOCKET"))
	if err != nil {
		os.Exit(81)
	}
	directory, _, err := client.Prepare(ctx, "/usr/bin/git", os.Getenv("MULTICA_SYNTHETIC_ROOT"))
	if err != nil {
		os.Exit(82)
	}
	content, err := os.ReadFile(filepath.Join(directory, "source.txt"))
	if err != nil {
		os.Exit(83)
	}
	if os.Getenv("MULTICA_SYNTHETIC_MODE") != "missing-receipt" {
		if _, err := client.Submit(ctx, "artifact", string(content)); err != nil {
			os.Exit(84)
		}
	}
	client.Close()
	stop()
	if os.Getenv("MULTICA_SYNTHETIC_MODE") == "nonzero" {
		os.Exit(85)
	}
	os.Exit(0)
}

// All keys, enrollment claims, Git repositories and runtime observations here
// are synthetic. The fake Engine never creates a container or claims containment.
type gitWorkloadEnrollment struct {
	operator ed25519.PrivateKey
	ca       *x509.Certificate
	caKey    ed25519.PrivateKey
	mode     string
	hook     func()
}

func (e *gitWorkloadEnrollment) Enroll(_ context.Context, request r2dgit.WorkloadEnrollmentRequest) (r2dgit.WorkloadEnrollment, error) {
	if e.hook != nil {
		e.hook()
	}
	seed := sha256.Sum256([]byte(request.ChannelID))
	key := ed25519.NewKeyFromSeed(seed[:])
	cert := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "synthetic-workload"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(2 * time.Minute), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(bytes.NewReader(make([]byte, 256)), cert, e.ca, key.Public(), e.caKey)
	if err != nil {
		return r2dgit.WorkloadEnrollment{}, err
	}
	out := r2dgit.WorkloadEnrollment{Certificate: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, AcceptanceID: "synthetic-only-no-containment-claim"}
	signed := request
	switch e.mode {
	case "attempt":
		signed.Context.AttemptID = uuid.NewString()
	case "policy":
		signed.PolicyDigest = strings.Repeat("0", 64)
	case "channel":
		signed.ChannelID = uuid.NewString()
	case "issue":
		signed.IssueID = uuid.NewString()
	case "assignment":
		signed.AssignmentDigest = strings.Repeat("0", 64)
	case "expiry":
		signed.ExpiresAt = signed.ExpiresAt.Add(-time.Hour)
	}
	message, err := r2dgit.WorkloadRegistrationBytes(signed, der, out.AcceptanceID)
	if err != nil {
		return out, err
	}
	out.Signature = ed25519.Sign(e.operator, message)
	if e.mode == "unsigned" {
		out.Signature = nil
	}
	if e.mode == "certificate" {
		out.Certificate.Certificate[0] = []byte("substituted")
	}
	return out, nil
}

type gitWorkloadProvider struct {
	service        *r2dgit.Service
	mu             sync.Mutex
	allowed        map[string]bool
	snapshots      map[string]r2dgit.RepositorySnapshot
	ops            []r2dgit.BoundOperation
	block          atomic.Bool
	outage         atomic.Bool
	entered        chan struct{}
	cancelled      chan struct{}
	refs           map[string]string
	packs          map[string][]byte
	pushes         int
	uncertainWrite bool
}

func (p *gitWorkloadProvider) WriteReference(ctx context.Context, op r2dgit.BoundOperation) (string, error) {
	if err := p.ProveRepository(ctx, op); err != nil {
		return "", err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if value := p.refs[op.RepositoryID+"/"+op.Ref]; value != "" {
		return value, nil
	}
	return strings.Repeat("0", 40), nil
}

func (p *gitWorkloadProvider) ReadReference(ctx context.Context, op r2dgit.BoundOperation, old string) ([]byte, error) {
	if err := p.ProveRepository(ctx, op); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if snapshot := p.snapshots[op.RepositoryID]; snapshot.Head == old {
		return bytes.Clone(snapshot.Pack), nil
	}
	if pack := p.packs[old]; pack != nil {
		return bytes.Clone(pack), nil
	}
	return nil, r2dgit.ErrProvider
}

func (p *gitWorkloadProvider) Push(ctx context.Context, op r2dgit.BoundOperation, update r2dgit.RefUpdate, pack []byte, authorize func(context.Context) error) error {
	if err := p.ProveRepository(ctx, op); err != nil {
		return err
	}
	if err := authorize(ctx); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	key := op.RepositoryID + "/" + op.Ref
	old := p.refs[key]
	if old == "" {
		old = strings.Repeat("0", 40)
	}
	if old != update.Old {
		return r2dgit.ErrRejected
	}
	if p.refs == nil {
		p.refs = map[string]string{}
	}
	if p.packs == nil {
		p.packs = map[string][]byte{}
	}
	p.refs[key] = update.New
	p.packs[update.New] = bytes.Clone(pack)
	p.pushes++
	if p.uncertainWrite {
		return r2dgit.ErrIndeterminate
	}
	return nil
}

func (p *gitWorkloadProvider) ProveRepository(ctx context.Context, op r2dgit.BoundOperation) error {
	if _, err := p.service.ResolveGitOperation(ctx, op); err != nil {
		return err
	}
	p.mu.Lock()
	p.ops = append(p.ops, op)
	allowed := p.allowed[op.UserID+"/"+op.RepositoryID]
	p.mu.Unlock()
	if p.block.Load() {
		select {
		case p.entered <- struct{}{}:
		default:
		}
		<-ctx.Done()
		select {
		case p.cancelled <- struct{}{}:
		default:
		}
		return ctx.Err()
	}
	if !allowed || p.outage.Load() {
		return r2dgit.ErrProvider
	}
	return nil
}
func (p *gitWorkloadProvider) Read(ctx context.Context, op r2dgit.BoundOperation) ([]byte, error) {
	s, e := p.ReadSnapshot(ctx, op)
	return s.Pack, e
}
func (p *gitWorkloadProvider) ReadSnapshot(ctx context.Context, op r2dgit.BoundOperation) (r2dgit.RepositorySnapshot, error) {
	if err := p.ProveRepository(ctx, op); err != nil {
		return r2dgit.RepositorySnapshot{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	s, ok := p.snapshots[op.RepositoryID]
	if !ok {
		return s, r2dgit.ErrProvider
	}
	s.Pack = bytes.Clone(s.Pack)
	return s, nil
}

type gitWorkloadJob struct {
	inspection r2dgit.DockerInspection
	ctx        context.Context
	cancel     context.CancelFunc
	socket     string
	exited     chan struct{}
}
type gitWorkloadEngine struct {
	mu                 sync.Mutex
	jobs               map[string]*gitWorkloadJob
	started            chan *gitWorkloadJob
	creates            int
	removeFailure      atomic.Bool
	helperMode         string
	helperRoot         string
	entrypoint         string
	providerExecutable string
	providerBinary     string
	entrypointTimeout  int
	entrypointConfigs  []string
}

func (e *gitWorkloadEngine) exit(j *gitWorkloadJob, code int) {
	e.mu.Lock()
	j.inspection.State.Running = false
	j.inspection.State.ExitCode = code
	e.mu.Unlock()
}
func (e *gitWorkloadEngine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1.47")
	e.mu.Lock()
	defer e.mu.Unlock()
	if path == "/containers/json" {
		var list []r2dgit.DockerContainer
		for _, j := range e.jobs {
			list = append(list, r2dgit.DockerContainer{ID: j.inspection.ID, Names: []string{j.inspection.Name}, Labels: j.inspection.Config.Labels})
		}
		_ = json.NewEncoder(w).Encode(list)
		return
	}
	if path == "/containers/create" {
		var spec r2dgit.DockerWorkload
		if json.NewDecoder(r.Body).Decode(&spec) != nil {
			http.Error(w, "bad", 400)
			return
		}
		name := r.URL.Query().Get("name")
		hash := sha256.Sum256([]byte(name))
		id := hex.EncodeToString(hash[:])
		source := strings.Split(spec.HostConfig.Binds[0], ":")[0]
		ctx, cancel := context.WithCancel(context.Background())
		e.jobs[name] = &gitWorkloadJob{inspection: r2dgit.DockerInspection{ID: id, Name: "/" + name, Config: spec, HostConfig: spec.HostConfig, AppArmorProfile: "synthetic-profile", Mounts: []r2dgit.DockerMount{{Type: "bind", Source: source, Destination: "/run/multica"}}}, ctx: ctx, cancel: cancel, socket: filepath.Join(source, "broker.sock")}
		e.creates++
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]string{"Id": id})
		return
	}
	name := strings.TrimSuffix(strings.TrimSuffix(strings.TrimPrefix(path, "/containers/"), "/json"), "/start")
	j := e.jobs[name]
	if j == nil {
		for k, c := range e.jobs {
			if c.inspection.ID == name {
				name, j = k, c
				break
			}
		}
	}
	if j == nil {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		_ = json.NewEncoder(w).Encode(j.inspection)
	case http.MethodDelete:
		if e.removeFailure.Load() {
			http.Error(w, "synthetic cleanup outage", 503)
			return
		}
		j.cancel()
		delete(e.jobs, name)
		if j.exited != nil {
			e.mu.Unlock()
			<-j.exited
			e.mu.Lock()
		}
		w.WriteHeader(204)
	case http.MethodPost:
		j.inspection.State.Running = true
		if e.helperMode != "" || e.entrypoint != "" {
			executable, err := os.Executable()
			if err != nil {
				http.Error(w, "helper", 500)
				return
			}
			cmd := exec.CommandContext(j.ctx, executable)
			cmd.Env = []string{"MULTICA_SYNTHETIC_PROTECTED_HELPER=1", "MULTICA_SYNTHETIC_SOCKET=" + j.socket, "MULTICA_SYNTHETIC_ROOT=" + e.helperRoot, "MULTICA_SYNTHETIC_MODE=" + e.helperMode}
			signal := syscall.SIGKILL
			if e.entrypoint != "" {
				root, err := os.MkdirTemp(e.helperRoot, "entry-")
				if err != nil {
					http.Error(w, "runtime", 500)
					return
				}
				config := r2dgit.ProtectedEntrypointConfig{SocketPath: j.socket, GitExecutable: "/usr/bin/git", ProviderExecutable: e.providerExecutable, WorkspaceRoot: filepath.Join(root, "workspace"), HomeRoot: filepath.Join(root, "home"), TmpRoot: filepath.Join(root, "tmp"), TimeoutSeconds: e.entrypointTimeout}
				for _, dir := range []string{config.WorkspaceRoot, config.HomeRoot, config.TmpRoot} {
					if err := os.Mkdir(dir, 0700); err != nil {
						http.Error(w, "runtime", 500)
						return
					}
				}
				path := filepath.Join(root, "runtime.json")
				if e.providerBinary != "" {
					config.ProviderExecutable = filepath.Join(root, "provider")
					quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
					wrapper := "#!/bin/sh\nexec " + quote(e.providerBinary) + " --multica-protected-v1 --config " + quote(path) + "\n"
					if err := os.WriteFile(config.ProviderExecutable, []byte(wrapper), 0700); err != nil {
						http.Error(w, "provider", 500)
						return
					}
				}
				raw, _ := json.Marshal(config)
				if err := os.WriteFile(path, raw, 0600); err != nil {
					http.Error(w, "runtime", 500)
					return
				}
				e.entrypointConfigs = append(e.entrypointConfigs, path)
				cmd = exec.CommandContext(j.ctx, e.entrypoint, "--config", path)
				cmd.Env = []string{"OPENAI_API_KEY=synthetic-poison", "SSH_AUTH_SOCK=/synthetic-poison", "HTTP_PROXY=http://synthetic.invalid", "GIT_OBJECT_DIRECTORY=/synthetic-poison"}
				signal = syscall.SIGTERM
			}
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			cmd.Cancel = func() error {
				err := syscall.Kill(-cmd.Process.Pid, signal)
				if err == syscall.ESRCH {
					return os.ErrProcessDone
				}
				return err
			}
			cmd.WaitDelay = 500 * time.Millisecond
			cmd.Stdout = io.Discard
			cmd.Stderr = io.Discard
			if err := cmd.Start(); err != nil {
				http.Error(w, "helper", 500)
				return
			}
			j.exited = make(chan struct{})
			go func() {
				err := cmd.Wait()
				close(j.exited)
				code := 0
				if err != nil {
					code = 1
				}
				e.exit(j, code)
			}()
		}
		e.started <- j
		w.WriteHeader(204)
	default:
		http.Error(w, "bad", 400)
	}
}

type gitWorkloadFixture struct {
	f                *gitHTTPFixture
	app              *r2dgit.WorkloadApplication
	engine           *gitWorkloadEngine
	provider         *gitWorkloadProvider
	enroller         *gitWorkloadEnrollment
	root             string
	config           r2dgit.WorkloadApplicationConfig
	brokerApp        **r2dgit.WorkloadApplication
	settlementOutage *atomic.Bool
	terminalGate     *gitWorkloadTerminalGate
}

type gitWorkloadTerminalGate struct {
	mu      sync.Mutex
	entered chan struct{}
	release <-chan struct{}
}

func (g *gitWorkloadTerminalGate) wait(ctx context.Context) error {
	g.mu.Lock()
	entered, release := g.entered, g.release
	g.mu.Unlock()
	if entered == nil {
		return nil
	}
	select {
	case entered <- struct{}{}:
	default:
	}
	select {
	case <-release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func gitWorkloadSnapshot(t *testing.T, content string) r2dgit.RepositorySnapshot {
	t.Helper()
	dir := t.TempDir()
	run := func(input string, args ...string) []byte {
		t.Helper()
		cmd := exec.Command("/usr/bin/git", append([]string{"-C", dir, "-c", "core.hooksPath=/dev/null", "-c", "protocol.allow=never"}, args...)...)
		cmd.Env = []string{"HOME=" + dir, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_AUTHOR_NAME=Synthetic", "GIT_AUTHOR_EMAIL=fixture@invalid", "GIT_COMMITTER_NAME=Synthetic", "GIT_COMMITTER_EMAIL=fixture@invalid"}
		cmd.Stdin = strings.NewReader(input)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("synthetic git: %v %s", err, out)
		}
		return out
	}
	run("", "init", "--template=")
	if err := os.WriteFile(filepath.Join(dir, "source.txt"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	run("", "add", "source.txt")
	run("", "commit", "-m", "synthetic")
	head := strings.TrimSpace(string(run("", "rev-parse", "HEAD")))
	return r2dgit.RepositorySnapshot{Head: head, Pack: run(head+"\n", "pack-objects", "--stdout", "--revs")}
}
func newGitWorkloadFixture(t *testing.T) *gitWorkloadFixture {
	t.Helper()
	f := newGitHTTPFixture(t)
	f.ready(t)
	provider := &gitWorkloadProvider{service: f.h.GitSecurity, allowed: map[string]bool{f.user + "/" + f.repo: true}, snapshots: map[string]r2dgit.RepositorySnapshot{f.repo: gitWorkloadSnapshot(t, "synthetic A source")}, entered: make(chan struct{}, 1), cancelled: make(chan struct{}, 1)}
	f.h.GitSecurity.OutputProof = provider
	caKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{71}, 32))
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic-workload-ca"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(bytes.NewReader(make([]byte, 256)), template, template, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	clientRoots := x509.NewCertPool()
	clientRoots.AddCert(ca)
	enroller := &gitWorkloadEnrollment{operator: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{72}, 32)), ca: ca, caKey: caKey}
	engine := &gitWorkloadEngine{jobs: map[string]*gitWorkloadJob{}, started: make(chan *gitWorkloadJob, 8)}
	engineHTTP := httptest.NewServer(engine)
	t.Cleanup(engineHTTP.Close)
	var app *r2dgit.WorkloadApplication
	broker := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { app.ServeHTTP(w, r) }))
	broker.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientRoots, MinVersion: tls.VersionTLS13}
	broker.StartTLS()
	t.Cleanup(broker.Close)
	roots := x509.NewCertPool()
	roots.AddCert(broker.Certificate())
	root, err := os.MkdirTemp("/tmp", "gwa-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	policy := r2dgit.WorkloadPolicy{RuntimeID: f.runtime, Root: root, Image: "synthetic/image@sha256:" + strings.Repeat("a", 64), AppArmor: "synthetic-profile", Seccomp: json.RawMessage(`{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"names":["read"],"action":"SCMP_ACT_ALLOW"}]}`), ContainerUID: 1234, ContainerGID: 1234, SocketUID: os.Geteuid(), SocketGID: os.Getegid(), Memory: 256 << 20, NanoCPUs: 1000000000, PIDs: 32, WorkspaceBytes: 64 << 20, HomeBytes: 16 << 20, TmpBytes: 16 << 20, MaxRuns: 4}
	settlementOutage := &atomic.Bool{}
	terminalGate := &gitWorkloadTerminalGate{}
	config := r2dgit.WorkloadApplicationConfig{Policy: policy, Engine: r2dgit.DockerEngine{Client: &http.Client{Transport: &http.Transport{}}, Endpoint: engineHTTP.URL}, BrokerURL: broker.URL, BrokerRoots: roots, OperatorKey: enroller.operator.Public().(ed25519.PublicKey), Enroller: enroller, Transport: provider, Journal: r2dgit.SQLJournal{DB: testPool}, SettleTerminal: func(ctx context.Context, tx pgx.Tx, id string) error {
		if settlementOutage.Load() {
			return r2dgit.ErrUnavailable
		}
		if err := terminalGate.wait(ctx); err != nil {
			return err
		}
		q := db.New(tx)
		task, err := q.GetAgentTask(ctx, util.MustParseUUID(id))
		if err != nil {
			return err
		}
		return service.SettleTerminalTaskState(ctx, q, task)
	}}
	app, err = r2dgit.NewWorkloadApplication(f.h.GitSecurity, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := app.Close(); err != nil {
			t.Errorf("application cleanup: %v", err)
		}
	})
	if err := app.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		dbfx.Exec(t, `DELETE FROM r2d_git_operation WHERE spec->>'UserID' IN ($1,$2)`, f.user, f.other)
	})
	fixture := &gitWorkloadFixture{f: f, app: app, engine: engine, provider: provider, enroller: enroller, root: root, config: config, brokerApp: &app, settlementOutage: settlementOutage, terminalGate: terminalGate}
	fixture.classifyAssignment(t, f.runRequest())
	return fixture
}
func (f *gitWorkloadFixture) classifyAssignment(t *testing.T, request r2dgit.RunRequest) {
	t.Helper()
	var assignment r2dgit.WorkloadAssignment
	var project, provider string
	if err := testPool.QueryRow(context.Background(), `SELECT i.title,COALESCE(i.description,''),i.project_id::text,r.provider_id::text FROM issue i JOIN r2d_git_repository r ON r.id=$2 AND r.project_id=i.project_id WHERE i.id=$1`, request.IssueID, request.RepositoryID).Scan(&assignment.Title, &assignment.Description, &project, &provider); err != nil {
		t.Fatal(err)
	}
	a := r2dgit.AssignmentClassification{ID: uuid.NewString(), ActorID: f.f.user, IssueID: request.IssueID, ProjectID: project, ProviderID: provider, RepositoryID: request.RepositoryID, Digest: r2dgit.WorkloadAssignmentDigest(assignment), ExpiresAt: time.Now().Add(time.Hour)}
	a.Signature = ed25519.Sign(f.enroller.operator, r2dgit.AssignmentClassificationBytes(a))
	if err := f.f.h.GitSecurity.RecordAssignmentClassification(context.Background(), a, f.enroller.operator.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
}
func (f *gitWorkloadFixture) admit(t *testing.T, token string, request r2dgit.RunRequest) r2dgit.RunInfo {
	t.Helper()
	f.classifyAssignment(t, request)
	var run r2dgit.RunInfo
	f.f.call(t, token, http.MethodPost, "/api/me/git-runs", request, 201).JSON(&run)
	if run.ExecutionAvailable {
		t.Fatal("production admission advertised execution")
	}
	return run
}
func (f *gitWorkloadFixture) start(t *testing.T, run r2dgit.RunInfo) (r2dgit.ApplicationWorkload, *gitWorkloadJob) {
	t.Helper()
	h, err := f.app.Prepare(context.Background(), run.Context.ID)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case j := <-f.engine.started:
		return h, j
	case <-time.After(2 * time.Second):
		t.Fatal("fake runtime did not start")
	}
	return h, nil
}
func waitGitWorkload(t *testing.T, h r2dgit.ApplicationWorkload) r2dgit.WorkloadResult {
	t.Helper()
	select {
	case <-h.Done:
		return h.Result()
	case <-time.After(5 * time.Second):
		t.Fatal("workload lifecycle did not settle")
	}
	return r2dgit.WorkloadResult{}
}

func gitWorkloadPendingReceipts(t *testing.T, f *gitWorkloadFixture, run r2dgit.RunInfo) func() {
	t.Helper()
	comment := dbfx.Comment(t, f.f.issue, "synthetic receipt metadata", testutil.Cols{"workspace_id": f.f.resourceWorkspace, "author_type": "system", "type": "progress_update", "source_task_id": run.Context.Binding.TaskID})
	dbfx.Exec(t, `UPDATE agent_task_queue SET delivered_comment_ids=ARRAY[$2]::uuid[] WHERE id=$1`, run.Context.Binding.TaskID, comment)
	dbfx.Exec(t, `INSERT INTO task_supplement(task_id,workspace_id,issue_id,comment_id,author_id,client_request_id,status) VALUES($1,$2,$3,$4,$5,$6,'pending')`, run.Context.Binding.TaskID, f.f.workspace, f.f.issue, comment, f.f.user, uuid.NewString())
	t.Cleanup(func() { dbfx.Exec(t, `DELETE FROM task_supplement WHERE task_id=$1`, run.Context.Binding.TaskID) })
	return func() {
		t.Helper()
		var status string
		var settled bool
		dbfx.QueryRow(t, `SELECT status FROM task_supplement WHERE task_id=$1`, run.Context.Binding.TaskID).Scan(&status)
		dbfx.QueryRow(t, `SELECT recovery_settled_at IS NOT NULL FROM comment WHERE id=$1`, comment).Scan(&settled)
		if status != "failed" || !settled {
			t.Fatalf("terminal receipts stranded: supplement=%s recovery=%v", status, settled)
		}
	}
}

func TestR2DGitWorkloadApplicationObservedHelperExit(t *testing.T) {
	for _, mode := range []string{"success", "nonzero", "missing-receipt"} {
		t.Run(mode, func(t *testing.T) {
			f := newGitWorkloadFixture(t)
			run := f.admit(t, f.f.token, f.f.runRequest())
			assertReceipts := gitWorkloadPendingReceipts(t, f, run)
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			f.engine.mu.Lock()
			f.engine.helperRoot = root
			f.engine.helperMode = mode
			f.engine.mu.Unlock()
			h, j := f.start(t, run)
			result := waitGitWorkload(t, h)
			if mode == "success" {
				if result.Err != nil || result.OutputID == "" {
					t.Fatalf("observed child success failed: %+v", result)
				}
				if got := f.f.call(t, f.f.token, "GET", "/api/me/git-outputs/"+result.OutputID, nil, 200).Body.String(); got != "synthetic A source" {
					t.Fatal("child output mismatch")
				}
			} else if result.Err == nil {
				t.Fatal("unsuccessful child completed")
			}
			select {
			case <-j.exited:
			default:
				t.Fatal("child was not reaped before lifecycle settled")
			}
			assertReceipts()
		})
	}
}

func TestR2DGitWorkloadApplicationCrashRecovery(t *testing.T) {
	for _, mode := range []string{"before-claim", "running-orphan", "settlement-outage", "forged-attempt"} {
		t.Run(mode, func(t *testing.T) {
			f := newGitWorkloadFixture(t)
			run := f.admit(t, f.f.token, f.f.runRequest())
			assertReceipts := gitWorkloadPendingReceipts(t, f, run)
			if err := f.app.Close(); err != nil {
				t.Fatal(err)
			}
			spec := run.Context
			if mode != "before-claim" {
				dbfx.Exec(t, `UPDATE agent_task_queue SET status='running' WHERE id=$1`, run.Context.Binding.TaskID)
			}
			if mode == "forged-attempt" {
				spec.AttemptID = uuid.NewString()
			}
			journal := filepath.Join(f.root, "app-"+spec.ID+".json")
			raw, _ := json.Marshal(spec)
			file, err := os.OpenFile(journal, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = file.Write(raw); err != nil {
				t.Fatal(err)
			}
			if err = file.Sync(); err != nil {
				t.Fatal(err)
			}
			if err = file.Close(); err != nil {
				t.Fatal(err)
			}
			if mode == "running-orphan" {
				nonce := uuid.NewString()
				rootHash := sha256.Sum256([]byte(filepath.Clean(f.root)))
				runtimeHash := sha256.Sum256([]byte(f.f.runtime))
				name := "r2d-" + hex.EncodeToString(runtimeHash[:8]) + "-" + nonce
				spec := r2dgit.DockerWorkload{Labels: map[string]string{"io.multica.git-supervisor": f.f.runtime + "-" + hex.EncodeToString(rootHash[:16]), "io.multica.git-run": nonce}, HostConfig: r2dgit.DockerWorkloadHost{Binds: []string{filepath.Join(f.root, nonce, "channel") + ":/run/multica:ro"}}}
				if err := f.config.Engine.Create(context.Background(), name, spec); err != nil {
					t.Fatal(err)
				}
			}
			restarted, err := r2dgit.NewWorkloadApplication(f.f.h.GitSecurity, f.config)
			if err != nil {
				t.Fatal(err)
			}
			f.app = restarted
			*f.brokerApp = restarted
			if mode == "settlement-outage" {
				f.settlementOutage.Store(true)
			}
			err = restarted.Recover(context.Background())
			if mode == "forged-attempt" {
				if err == nil {
					t.Fatal("forged journal settled another attempt")
				}
				if _, statErr := os.Stat(journal); statErr != nil {
					t.Fatal("forged evidence removed")
				}
				return
			}
			if mode == "settlement-outage" {
				if err == nil {
					t.Fatal("settlement outage recovered")
				}
				var status string
				dbfx.QueryRow(t, `SELECT status FROM agent_task_queue WHERE id=$1`, run.Context.Binding.TaskID).Scan(&status)
				if status != "running" {
					t.Fatal("terminal write escaped failed settlement transaction")
				}
				if _, err := os.Stat(journal); err != nil {
					t.Fatal("uncertain recovery evidence removed")
				}
				if _, err := restarted.Prepare(context.Background(), run.Context.ID); err == nil {
					t.Fatal("uncertain recovery admitted execution")
				}
				f.settlementOutage.Store(false)
				err = restarted.Recover(context.Background())
			}
			if err != nil {
				t.Fatal(err)
			}
			assertReceipts()
			if _, err := os.Stat(journal); !os.IsNotExist(err) {
				t.Fatal("settled journal retained")
			}
			var status string
			dbfx.QueryRow(t, `SELECT status FROM agent_task_queue WHERE id=$1`, run.Context.Binding.TaskID).Scan(&status)
			if status != "failed" {
				t.Fatalf("orphan was adopted: %s", status)
			}
			f.engine.mu.Lock()
			remaining := len(f.engine.jobs)
			f.engine.mu.Unlock()
			if remaining != 0 {
				t.Fatal("orphan container retained")
			}
			if _, err := restarted.Prepare(context.Background(), run.Context.ID); err == nil {
				t.Fatal("recovered attempt replayed")
			}
		})
	}
}

func TestR2DGitWorkloadCompletionSerializesChildAdmission(t *testing.T) {
	f := newGitWorkloadFixture(t)
	ctx := context.Background()
	run := f.admit(t, f.f.token, f.f.runRequest())
	h, j := f.start(t, run)
	request := f.f.runRequest()
	request.AgentID = f.f.child
	child, err := f.f.h.GitSecurity.EnqueueChild(ctx, run.Context.ID, run.Context.Binding.TaskID, f.f.agent, f.f.workspace, request)
	if err != nil {
		t.Fatal(err)
	}
	client, _ := r2dgit.NewWorkloadClient(j.socket)
	defer client.Close()
	root := t.TempDir()
	_ = os.Chmod(root, 0700)
	if _, _, err := client.Prepare(j.ctx, "/usr/bin/git", root); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Submit(j.ctx, "artifact", "synthetic completion"); err != nil {
		t.Fatal(err)
	}
	// Child admission holds context SHARE before acquiring the parent queue row.
	// Keep that context lock held until private completion has committed.
	lock, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback(ctx)
	if _, err := lock.Exec(ctx, `SELECT id FROM r2d_git_run_context WHERE root_id=$1 ORDER BY id FOR SHARE`, run.Context.ID); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}, 1), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	f.terminalGate.mu.Lock()
	f.terminalGate.entered = entered
	f.terminalGate.release = release
	f.terminalGate.mu.Unlock()
	f.engine.exit(j, 0)
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("completion did not acquire terminal queue lock")
	}
	childResult := make(chan error, 1)
	go func() {
		_, err := f.f.h.GitSecurity.EnqueueChild(ctx, run.Context.ID, run.Context.Binding.TaskID, f.f.agent, f.f.workspace, request)
		childResult <- err
	}()
	deadline := time.Now().Add(500 * time.Millisecond)
	waiting := false
	for time.Now().Before(deadline) {
		if err := testPool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query='SELECT id FROM agent_task_queue WHERE id=$1 FOR SHARE')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !waiting {
		t.Fatal("child admission did not wait on completion's queue lock")
	}
	close(release)
	if result := waitGitWorkload(t, h); result.Err != nil {
		t.Fatalf("context SHARE blocked private completion: %v", result.Err)
	}
	select {
	case err := <-childResult:
		if err == nil {
			t.Fatal("completed parent admitted a fresh child")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("child admission deadlocked with completion")
	}
	current, err := f.f.h.GitSecurity.Current(ctx, child.Context, child.Grant)
	if err != nil || !current.ContextActive {
		t.Fatalf("already-issued child lost normally completed parent: %+v %v", current, err)
	}
	current, err = f.f.h.GitSecurity.Current(ctx, run.Context, run.Grant)
	if err != nil || current.ContextActive {
		t.Fatalf("completed parent remained executable: %+v %v", current, err)
	}
}
func gitWorkloadRequest(t *testing.T, j *gitWorkloadJob, method, path, body string, status int) {
	t.Helper()
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", j.socket)
	}}
	defer transport.CloseIdleConnections()
	r, _ := http.NewRequestWithContext(j.ctx, method, "http://workload"+path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-User-ID", "forged B")
	r.Header.Set("X-Task-ID", "forged B task")
	r.Header.Set("Authorization", "Bearer forged")
	response, err := (&http.Client{Transport: transport, Timeout: 3 * time.Second}).Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	if response.StatusCode != status {
		t.Fatalf("%s %s: %d wanted %d", method, path, response.StatusCode, status)
	}
}

func TestR2DGitWorkloadApplicationReadOutputAndCurrentReader(t *testing.T) {
	f := newGitWorkloadFixture(t)
	ctx := context.Background()
	bProject := dbfx.Insert(t, "project", testutil.Cols{"workspace_id": f.f.resourceWorkspace, "title": "B protected project"})
	bIssue := dbfx.Issue(t, "B source", testutil.Cols{"workspace_id": f.f.resourceWorkspace, "project_id": bProject})
	bRepo := dbfx.Insert(t, "r2d_git_repository", testutil.Cols{"id": uuid.NewString(), "project_id": bProject, "provider_id": f.f.provider, "canonical_repository": "fixtures/b"})
	if err := f.f.h.GitSecurity.SetProjectGrant(ctx, testUserID, bProject, "user", f.f.other, "member"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		dbfx.Exec(t, `DELETE FROM r2d_git_project_grant WHERE project_id=$1`, bProject)
		dbfx.Exec(t, `DELETE FROM r2d_git_project_policy WHERE project_id=$1`, bProject)
	})
	// Give B consent to both sources, then remove A's project grant before runs.
	if err := f.f.h.GitSecurity.SetProjectGrant(ctx, testUserID, f.f.project, "user", f.f.other, "member"); err != nil {
		t.Fatal(err)
	}
	var bKey r2dgit.PublicIdentity
	f.f.call(t, f.f.otherToken, "POST", "/api/me/git-identities", map[string]any{"provider_id": f.f.provider, "request_id": uuid.NewString(), "consent_project_ids": []string{bProject, f.f.project}}, 201).JSON(&bKey)
	f.f.worker.login, f.f.worker.accountID = "synthetic-b", "synthetic-b-account"
	f.f.call(t, f.f.otherToken, "POST", fmt.Sprintf("/api/me/git-identities/%s/%d/verify", bKey.ID, bKey.Generation), nil, 200)
	if err := f.f.h.GitSecurity.SetProjectGrant(ctx, testUserID, f.f.project, "user", f.f.other, ""); err != nil {
		t.Fatal(err)
	}
	f.provider.mu.Lock()
	f.provider.allowed[f.f.other+"/"+bRepo] = true
	f.provider.snapshots[bRepo] = gitWorkloadSnapshot(t, "synthetic B source")
	f.provider.mu.Unlock()
	a := f.admit(t, f.f.token, f.f.runRequest())
	b := f.admit(t, f.f.otherToken, r2dgit.RunRequest{AgentID: f.f.agent, IssueID: bIssue, RepositoryID: bRepo, Operations: []r2dgit.Operation{r2dgit.Read}})
	f.f.call(t, f.f.otherToken, "POST", "/api/me/git-runs", f.f.runRequest(), 404)
	ha, ja := f.start(t, a)
	current, err := f.f.h.GitSecurity.Current(ctx, a.Context, a.Grant)
	if err != nil || current.Runtime.OperatorApproved || current.Runtime.Isolated {
		t.Fatal("application registration enabled production authority")
	}
	hb, jb := f.start(t, b)
	if ja.socket == jb.socket {
		t.Fatal("A/B shared channel")
	}
	for _, j := range []*gitWorkloadJob{ja, jb} {
		gitWorkloadRequest(t, j, "GET", "/info/refs?service=git-receive-pack", "", 403)
		gitWorkloadRequest(t, j, "POST", "/git-receive-pack", "", 403)
		gitWorkloadRequest(t, j, "GET", "/snapshot?repository_id="+bRepo, "", 403)
		gitWorkloadRequest(t, j, "POST", "/outputs", `{"kind":"artifact","content":"early"}`, 403)
	}
	for index, item := range []struct {
		run    r2dgit.RunInfo
		job    *gitWorkloadJob
		handle r2dgit.ApplicationWorkload
		source string
	}{{a, ja, ha, "synthetic A source"}, {b, jb, hb, "synthetic B source"}} {
		client, err := r2dgit.NewWorkloadClient(item.job.socket)
		if err != nil {
			t.Fatal(err)
		}
		root := t.TempDir()
		_ = os.Chmod(root, 0700)
		directory, _, err := client.Prepare(item.job.ctx, "/usr/bin/git", root)
		if err != nil {
			t.Fatal(err)
		}
		content, err := os.ReadFile(filepath.Join(directory, "source.txt"))
		if err != nil || string(content) != item.source {
			t.Fatalf("A/B snapshot confused: %q %v", content, err)
		}
		gitWorkloadRequest(t, item.job, "POST", "/outputs", `{"kind":"artifact","content":"forged","context_id":"`+b.Context.ID+`"}`, 403)
		gitWorkloadRequest(t, item.job, "POST", "/acknowledge", `{"output_id":"`+uuid.NewString()+`"}`, 403)
		id, err := client.Submit(item.job.ctx, "artifact", string(content))
		client.Close()
		if err != nil {
			t.Fatal(err)
		}
		f.engine.exit(item.job, 0)
		result := waitGitWorkload(t, item.handle)
		if result.Err != nil || result.OutputID != id {
			t.Fatalf("private completion: %+v", result)
		}
		var status string
		var leaked bool
		dbfx.QueryRow(t, `SELECT status,session_id IS NOT NULL OR work_dir IS NOT NULL OR result IS NOT NULL OR error IS NOT NULL FROM agent_task_queue WHERE id=$1`, item.run.Context.Binding.TaskID).Scan(&status, &leaked)
		if status != "completed" || leaked {
			t.Fatalf("unsafe terminal row %s leaked=%v", status, leaked)
		}
		token, other := f.f.token, f.f.otherToken
		if index == 1 {
			token, other = other, token
		}
		path := "/api/me/git-outputs/" + id
		if got := f.f.call(t, token, "GET", path, nil, 200).Body.String(); got != item.source {
			t.Fatal("restricted read content mismatch")
		}
		f.f.call(t, other, "GET", path, nil, 404)
		if _, err := f.app.Prepare(ctx, item.run.Context.ID); err == nil {
			t.Fatal("completed attempt relaunched")
		}
		if index == 0 {
			if err := f.f.h.GitSecurity.SetProjectGrant(ctx, testUserID, f.f.project, "user", f.f.other, "viewer"); err != nil {
				t.Fatal(err)
			}
			f.f.call(t, f.f.otherToken, "GET", path, nil, 503)
			f.provider.mu.Lock()
			f.provider.allowed[f.f.other+"/"+f.f.repo] = true
			f.provider.mu.Unlock()
			f.f.call(t, f.f.otherToken, "GET", path, nil, 200)
			f.provider.mu.Lock()
			op := f.provider.ops[len(f.provider.ops)-1]
			f.provider.mu.Unlock()
			if op.UserID != f.f.other || op.IdentityID != bKey.ID {
				t.Fatal("B reader borrowed A's key")
			}
			if err := f.f.h.GitSecurity.RevokeRoot(ctx, f.f.user, a.Context.ID); err != nil {
				t.Fatal(err)
			}
			f.f.call(t, f.f.token, "GET", path, nil, 409)
			f.f.call(t, f.f.otherToken, "GET", path, nil, 409)
		}
	}
	if _, err := r2dgit.NewWorkloadApplication(f.f.h.GitSecurity, r2dgit.WorkloadApplicationConfig{}); err == nil {
		t.Fatal("default production dependencies enabled runtime")
	}
}

func TestR2DGitWorkloadRegistrationAndLifecycleDeny(t *testing.T) {
	for _, mode := range []string{"unsigned", "attempt", "policy", "channel", "expiry", "certificate", "issue", "assignment", "project-revoke-during-enrollment", "terminal-before-prepare", "provider-outage", "missing-receipt", "missing-ack", "nonzero-exit", "revoke-stalled-read"} {
		t.Run(mode, func(t *testing.T) {
			f := newGitWorkloadFixture(t)
			run := f.admit(t, f.f.token, f.f.runRequest())
			ctx := context.Background()
			if mode == "project-revoke-during-enrollment" {
				f.enroller.hook = func() {
					if err := f.f.h.GitSecurity.SetProjectGrant(ctx, testUserID, f.f.project, "user", f.f.user, ""); err != nil {
						t.Error(err)
					}
				}
			} else {
				f.enroller.mode = mode
			}
			if mode == "terminal-before-prepare" {
				dbfx.Exec(t, `UPDATE agent_task_queue SET status='completed' WHERE id=$1`, run.Context.Binding.TaskID)
			}
			denyBefore := mode == "issue" || mode == "assignment" || mode == "unsigned" || mode == "attempt" || mode == "policy" || mode == "channel" || mode == "expiry" || mode == "certificate" || mode == "project-revoke-during-enrollment" || mode == "terminal-before-prepare"
			if denyBefore {
				if _, err := f.app.Prepare(ctx, run.Context.ID); err == nil {
					t.Fatal("invalid registration/admission launched")
				}
				f.engine.mu.Lock()
				creates := f.engine.creates
				f.engine.mu.Unlock()
				if creates != 0 {
					t.Fatal("invalid run reached engine")
				}
				return
			}
			h, j := f.start(t, run)
			client, _ := r2dgit.NewWorkloadClient(j.socket)
			defer client.Close()
			privateRoot := t.TempDir()
			if err := os.Chmod(privateRoot, 0700); err != nil {
				t.Fatal(err)
			}
			if mode == "provider-outage" {
				f.provider.outage.Store(true)
				if _, _, err := client.Prepare(j.ctx, "/usr/bin/git", privateRoot); err == nil {
					t.Fatal("provider outage delivered source")
				}
				f.engine.exit(j, 1)
			} else if mode == "revoke-stalled-read" {
				f.provider.block.Store(true)
				done := make(chan error, 1)
				go func() { _, _, err := client.Prepare(j.ctx, "/usr/bin/git", privateRoot); done <- err }()
				select {
				case <-f.provider.entered:
				case <-time.After(2 * time.Second):
					t.Fatal("provider did not stall")
				}
				if err := f.f.h.GitSecurity.RevokeRoot(ctx, f.f.user, run.Context.ID); err != nil {
					t.Fatal(err)
				}
				select {
				case <-f.provider.cancelled:
				case <-time.After(3 * time.Second):
					t.Fatal("revocation did not cancel provider")
				}
				select {
				case err := <-done:
					if err == nil {
						t.Fatal("revoked source delivered")
					}
				case <-time.After(3 * time.Second):
					t.Fatal("CLI read survived revoke")
				}
			} else {
				root := t.TempDir()
				_ = os.Chmod(root, 0700)
				if _, _, err := client.Prepare(j.ctx, "/usr/bin/git", root); err != nil {
					t.Fatal(err)
				}
				if mode == "missing-ack" {
					gitWorkloadRequest(t, j, "POST", "/outputs", `{"kind":"artifact","content":"unacknowledged source"}`, 200)
				} else if mode == "nonzero-exit" {
					if _, err := client.Submit(j.ctx, "artifact", "source with failed exit"); err != nil {
						t.Fatal(err)
					}
				}
				code := 0
				if mode == "nonzero-exit" {
					code = 1
				}
				f.engine.exit(j, code)
			}
			if result := waitGitWorkload(t, h); result.Err == nil {
				t.Fatal("incomplete/revoked execution completed")
			}
			var status string
			dbfx.QueryRow(t, `SELECT status FROM agent_task_queue WHERE id=$1`, run.Context.Binding.TaskID).Scan(&status)
			if status != "failed" {
				t.Fatalf("unsafe failure status %s", status)
			}
		})
	}
}
