//go:build linux

package r2dgit

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// WorkloadApplicationConfig has no environment/default credential discovery.
// Production does not construct this application or mount its handler. Synthetic
// enrollment validates the integration, not the operator's containment claim.
type WorkloadApplicationConfig struct {
	Policy         WorkloadPolicy
	Engine         WorkloadEngine
	BrokerURL      string
	BrokerRoots    *x509.CertPool
	OperatorKey    ed25519.PublicKey
	Enroller       WorkloadEnroller
	Transport      ProviderTransport
	Journal        AuditJournal
	SettleTerminal WorkloadTerminalSettlement
	Model          *ResponsesGateway
	// AcceptanceID is mandatory in the protected deployment factory. Empty is
	// retained only for the preexisting synthetic application fixtures.
	AcceptanceID string
	Quarantine   WriteQuarantine
}

type WorkloadApplication struct {
	admission    sync.Mutex
	settle       WorkloadTerminalSettlement
	ready        bool
	mu           sync.Mutex
	service      *Service
	registry     *registeredWorkloads
	channels     *WorkloadChannels
	supervisor   *WorkloadSupervisor
	broker       Broker
	enroller     WorkloadEnroller
	model        *ResponsesGateway
	policyDigest string
	runs         map[string]*applicationRun
	closed       bool
}

type applicationRun struct {
	mu                sync.Mutex
	run               RunSecurityContext
	grant             RepositoryGrant
	assignment        WorkloadAssignment
	prepared          bool
	outputID          string
	acknowledged      bool
	modelUsed         bool
	finalizeUsed      bool
	finalizeSucceeded bool
	writeOld          string
	children          int
	done              chan struct{}
	err               error
}

type WorkloadResult struct {
	OutputID string
	Err      error
}
type ApplicationWorkload struct {
	ID    string
	Done  <-chan struct{}
	state *applicationRun
}

// Result is available after Done closes. It contains a restricted output ID,
// never source/narrative content, session paths or provider credentials.
func (w ApplicationWorkload) Result() WorkloadResult {
	if w.state == nil {
		return WorkloadResult{Err: ErrUnavailable}
	}
	select {
	case <-w.Done:
	default:
		return WorkloadResult{Err: ErrConflict}
	}
	w.state.mu.Lock()
	defer w.state.mu.Unlock()
	return WorkloadResult{w.state.outputID, w.state.err}
}

func NewWorkloadApplication(s *Service, c WorkloadApplicationConfig) (*WorkloadApplication, error) {
	if s == nil || s.Store == nil || s.Store.DB == nil || s.Now == nil || len(c.OperatorKey) != ed25519.PublicKeySize || c.Enroller == nil || c.Transport == nil || c.Journal == nil || c.SettleTerminal == nil {
		return nil, ErrUnavailable
	}
	if _, ok := c.Transport.(SnapshotTransport); !ok {
		return nil, ErrUnavailable
	}
	registry := &registeredWorkloads{service: s, now: s.Now, key: append(ed25519.PublicKey(nil), c.OperatorKey...), entries: make(map[string]WorkloadEnrollmentRequest), acceptanceID: c.AcceptanceID}
	authorizer := Authorizer{Authority: registry}
	channels := NewWorkloadChannels(authorizer, s.Now)
	supervisor, err := NewWorkloadSupervisor(c.Engine, channels, c.Policy, c.BrokerURL, c.BrokerRoots)
	if err != nil {
		return nil, err
	}
	policy, err := json.Marshal(supervisor.policy)
	if err != nil {
		_ = supervisor.Close()
		return nil, ErrRuntime
	}
	return &WorkloadApplication{settle: c.SettleTerminal, service: s, registry: registry, channels: channels, supervisor: supervisor, broker: Broker{Authorizer: authorizer, Transport: c.Transport, Journal: c.Journal, Now: s.Now, Quarantine: c.Quarantine}, enroller: c.Enroller, model: c.Model, policyDigest: hexDigest(policy), runs: make(map[string]*applicationRun)}, nil
}

// Recover refuses adoption. Application journals survive engine cleanup until
// the exact durable attempt and its dependent receipts are privately settled.
func (a *WorkloadApplication) Recover(ctx context.Context) error {
	ctx, stopRecovery := context.WithTimeout(ctx, 5*time.Second)
	defer stopRecovery()
	a.admission.Lock()
	defer a.admission.Unlock()
	a.mu.Lock()
	allowed := !a.closed && len(a.runs) == 0
	a.ready = false
	a.mu.Unlock()
	if !allowed {
		return ErrConflict
	}
	if err := a.supervisor.Recover(ctx); err != nil {
		return err
	}
	files, err := os.ReadDir(a.supervisor.policy.Root)
	if err != nil {
		return ErrRuntime
	}
	for _, file := range files {
		if !applicationJournalName(file.Name()) {
			continue
		}
		if !file.Type().IsRegular() {
			return ErrRuntime
		}
		raw, err := os.ReadFile(filepath.Join(a.supervisor.policy.Root, file.Name()))
		if err != nil || len(raw) > 16384 {
			return ErrRuntime
		}
		var spec ContextSpec
		if json.Unmarshal(raw, &spec) != nil || spec.ID+".json" != file.Name()[4:] || spec.Binding.RuntimeID != a.supervisor.policy.RuntimeID {
			return ErrPrincipal
		}
		settleCtx, stop := context.WithTimeout(ctx, workloadCallBound)
		settleErr := a.service.failWorkload(settleCtx, RunSecurityContext{spec: spec}, a.settle)
		stop()
		if settleErr != nil {
			return settleErr
		}
		if err := a.removeJournal(spec.ID); err != nil {
			return err
		}
	}
	a.mu.Lock()
	a.ready = !a.closed
	a.mu.Unlock()
	return nil
}

func applicationJournalName(name string) bool {
	if len(name) != 45 || name[:4] != "app-" || name[40:] != ".json" {
		return false
	}
	id, err := uuid.Parse(name[4:40])
	return err == nil && id.String() == name[4:40]
}
func (a *WorkloadApplication) journal(run RunSecurityContext) error {
	raw, err := json.Marshal(run.spec)
	if err != nil {
		return ErrScope
	}
	file, err := os.OpenFile(filepath.Join(a.supervisor.policy.Root, "app-"+run.spec.ID+".json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return ErrConflict
	}
	_, err = file.Write(raw)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return ErrRuntime
	}
	return syncWorkloadDirectory(a.supervisor.policy.Root)
}
func (a *WorkloadApplication) removeJournal(id string) error {
	if err := os.Remove(filepath.Join(a.supervisor.policy.Root, "app-"+id+".json")); err != nil {
		return ErrRuntime
	}
	return syncWorkloadDirectory(a.supervisor.policy.Root)
}
func (a *WorkloadApplication) notReady() { a.mu.Lock(); a.ready = false; a.mu.Unlock() }

func (a *WorkloadApplication) Close() error {
	a.mu.Lock()
	a.closed = true
	a.mu.Unlock()
	err := a.supervisor.Close()
	a.mu.Lock()
	pending := make([]*applicationRun, 0, len(a.runs))
	for _, run := range a.runs {
		pending = append(pending, run)
	}
	a.mu.Unlock()
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	for _, run := range pending {
		select {
		case <-run.done:
		case <-timer.C:
			return ErrUnavailable
		}
	}
	return err
}

// Prepare is a trusted application seam, not an HTTP admission API. The only
// input is an already-admitted context ID; all authority is reloaded from DB.
func (a *WorkloadApplication) Prepare(ctx context.Context, contextID string) (ApplicationWorkload, error) {
	a.admission.Lock()
	defer a.admission.Unlock()
	a.mu.Lock()
	allowed := a.ready && !a.closed
	a.mu.Unlock()
	if !allowed {
		return ApplicationWorkload{}, ErrRuntime
	}
	ctx, stopPrepare := context.WithTimeout(ctx, 5*time.Second)
	defer stopPrepare()
	var run RunSecurityContext
	var grant RepositoryGrant
	var assignment WorkloadAssignment
	var issueID string
	err := a.service.Store.transaction(ctx, func(tx pgx.Tx) error {
		var err error
		run, grant, err = loadRun(ctx, tx, contextID, a.service.Now())
		if err != nil {
			return err
		}
		assignment, issueID, err = loadWorkloadAssignment(ctx, tx, run)
		if err != nil {
			return err
		}
		return a.service.assignmentClassified(ctx, tx, issueID, run.spec.Binding.ProjectID, assignment, grant.spec, a.registry.key)
	})
	if err != nil {
		return ApplicationWorkload{}, err
	}
	if run.spec.Binding.RuntimeID != a.supervisor.policy.RuntimeID || !hasOp(grant.spec, Read) {
		return ApplicationWorkload{}, ErrScope
	}
	assignmentRaw, _ := json.Marshal(assignment)
	// X.509 encodes whole seconds. The lease must not outlive its leaf by a
	// fractional second when the issuer encodes this exact expiry.
	request := WorkloadEnrollmentRequest{Context: run.Spec(), Grant: grant.Spec(), ChannelID: uuid.NewString(), PolicyDigest: a.policyDigest, IssueID: issueID, AssignmentDigest: hexDigest(assignmentRaw), ExpiresAt: a.service.Now().Add(time.Minute).Truncate(time.Second)}
	if grant.spec.ExpiresAt.Before(request.ExpiresAt) {
		request.ExpiresAt = grant.spec.ExpiresAt.Truncate(time.Second)
	}
	enrollCtx, cancel := context.WithTimeout(ctx, workloadCallBound)
	enrollment, err := a.enroller.Enroll(enrollCtx, request)
	cancel()
	if err != nil {
		return ApplicationWorkload{}, ErrRuntime
	}
	if err = a.registry.register(request, enrollment); err != nil {
		return ApplicationWorkload{}, err
	}
	state := &applicationRun{run: run, grant: grant, assignment: assignment, done: make(chan struct{})}
	a.mu.Lock()
	if a.closed || a.runs[contextID] != nil {
		a.mu.Unlock()
		a.registry.revoke(contextID)
		return ApplicationWorkload{}, ErrConflict
	}
	a.runs[contextID] = state
	a.mu.Unlock()
	forget := func() { a.registry.revoke(contextID); a.mu.Lock(); delete(a.runs, contextID); a.mu.Unlock() }
	if err = a.journal(run); err != nil {
		a.notReady()
		forget()
		close(state.done)
		return ApplicationWorkload{}, err
	}
	if err = a.service.transitionWorkload(ctx, run, grant, issueID, "", a.settle); err != nil {
		failCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), workloadCallBound)
		failErr := a.service.failWorkload(failCtx, run, a.settle)
		stop()
		if failErr != nil || a.removeJournal(run.spec.ID) != nil {
			a.notReady()
		}
		forget()
		close(state.done)
		return ApplicationWorkload{}, err
	}
	handle, err := a.supervisor.Launch(ctx, run, grant, request.ChannelID, Read, "", request.ExpiresAt.Sub(a.service.Now()), enrollment.Certificate)
	if err != nil {
		failCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), workloadCallBound)
		failErr := a.service.failWorkload(failCtx, run, a.settle)
		stop()
		if failErr != nil || a.removeJournal(run.spec.ID) != nil {
			a.notReady()
		}
		forget()
		close(state.done)
		if failErr != nil {
			return ApplicationWorkload{}, ErrAudit
		}
		return ApplicationWorkload{}, err
	}
	go func() {
		<-handle.Done // only successful exact-resource cleanup closes this channel
		state.mu.Lock()
		defer state.mu.Unlock()
		finishCtx, stop := context.WithTimeout(context.Background(), workloadCallBound)
		defer stop()
		if handle.workload.cleanExit.Load() && state.prepared && state.outputID != "" && state.acknowledged && (!state.finalizeUsed || state.finalizeSucceeded) {
			state.err = a.service.transitionWorkload(finishCtx, run, grant, issueID, state.outputID, a.settle)
		} else {
			state.err = ErrRuntime
		}
		if state.err != nil {
			failCtx, cancel := context.WithTimeout(context.Background(), workloadCallBound)
			if a.service.failWorkload(failCtx, run, a.settle) != nil {
				state.err = ErrAudit
			}
			cancel()
		}
		if state.err == ErrAudit {
			a.notReady()
		} else if a.removeJournal(run.spec.ID) != nil {
			a.notReady()
			state.err = ErrRuntime
		}
		forget()
		close(state.done)
	}()
	return ApplicationWorkload{ID: handle.ID, Done: state.done, state: state}, nil
}

// ServeHTTP is the internal mTLS broker endpoint. The verified channel supplies
// every identity, scope and output classification; the URL never selects them.
func (a *WorkloadApplication) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	control := http.NewResponseController(w)
	fail := func() {
		_ = control.SetWriteDeadline(time.Now().Add(time.Second))
		http.Error(w, "git workload unavailable", http.StatusForbidden)
	}
	if r.URL.RawQuery != "" || r.Header.Get("Content-Encoding") != "" || r.Header.Get("Git-Protocol") != "" {
		fail()
		return
	}
	lease, channel, err := a.channels.Authenticate(r)
	if err != nil || lease.operation != Read {
		fail()
		return
	}
	a.mu.Lock()
	state := a.runs[lease.run.spec.ID]
	a.mu.Unlock()
	if state == nil || state.run.spec != lease.run.spec || !reflect.DeepEqual(state.grant.spec, lease.grant.spec) {
		fail()
		return
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	if control.SetWriteDeadline(time.Time{}) != nil {
		fail()
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/assignment" && state.outputID == "":
		raw, err := json.Marshal(state.assignment)
		if err != nil || len(raw) > maxAssignmentBytes {
			fail()
			return
		}
		if err = a.deliverAssignment(ctx, lease, raw, w, control, r); err != nil {
			panic(http.ErrAbortHandler)
		}
	case r.Method == http.MethodGet && r.URL.Path == "/snapshot" && !state.prepared && state.outputID == "":
		snapshot, err := a.broker.ReadSnapshot(ctx, lease, channel, uuid.NewString())
		if err != nil {
			fail()
			return
		}
		defer clear(snapshot.Pack)
		if err = a.deliverSnapshot(ctx, lease, channel, snapshot, w, control, r); err != nil {
			panic(http.ErrAbortHandler)
		}
		state.prepared = true
	case r.Method == http.MethodPost && r.URL.Path == "/children" && state.prepared && state.outputID == "" && state.children < 8 && r.Header.Get("Content-Type") == "application/json":
		var request RunRequest
		if workloadJSON(w, r, control, &request) != nil {
			fail()
			return
		}
		state.children++
		binding := state.run.spec.Binding
		child, err := a.service.EnqueueChild(ctx, state.run.spec.ID, binding.TaskID, binding.AgentID, binding.ExecutionWorkspaceID, request)
		if err != nil {
			fail()
			return
		}
		if control.SetWriteDeadline(time.Now().Add(time.Second)) != nil {
			fail()
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if json.NewEncoder(w).Encode(struct {
			ContextID string `json:"context_id"`
		}{child.Context.ID}) != nil {
			panic(http.ErrAbortHandler)
		}
	case r.Method == http.MethodPost && r.URL.Path == "/model" && state.prepared && state.outputID == "" && !state.modelUsed && r.Header.Get("Content-Type") == "application/json":
		var payload struct {
			Input string `json:"input"`
		}
		if workloadJSON(w, r, control, &payload) != nil {
			fail()
			return
		}
		state.modelUsed = true
		text, err := a.generateModel(ctx, lease, channel, payload.Input)
		if err != nil {
			fail()
			return
		}
		raw, err := json.Marshal(struct {
			Content string `json:"content"`
		}{text})
		defer clear(raw)
		if err != nil || a.deliverSourceJSON(ctx, lease, raw, w, control, r, "model") != nil {
			panic(http.ErrAbortHandler)
		}
	case r.Method == http.MethodGet && r.URL.Path == "/write-reference" && state.prepared && state.outputID == "" && state.writeOld == "":
		old, err := a.writeReference(ctx, lease, channel)
		if err != nil {
			fail()
			return
		}
		state.writeOld = old
		if control.SetWriteDeadline(time.Now().Add(time.Second)) != nil {
			fail()
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if json.NewEncoder(w).Encode(struct {
			Old string `json:"old"`
		}{old}) != nil {
			panic(http.ErrAbortHandler)
		}
	case r.Method == http.MethodPost && r.URL.Path == "/finalize" && state.prepared && state.outputID == "" && !state.finalizeUsed && state.writeOld != "" && r.Header.Get("Content-Type") == "application/json":
		var payload FinalizeRequest
		if workloadJSON(w, r, control, &payload) != nil || len(payload.Pack) > 512<<10 || payload.Old != state.writeOld {
			fail()
			return
		}
		defer clear(payload.Pack)
		state.finalizeUsed = true
		if a.finalize(ctx, lease, channel, payload) != nil {
			fail()
			return
		}
		state.finalizeSucceeded = true
		if control.SetWriteDeadline(time.Now().Add(time.Second)) != nil {
			fail()
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPost && r.URL.Path == "/outputs" && state.prepared && state.outputID == "" && r.Header.Get("Content-Type") == "application/json":
		var payload struct {
			Kind    string `json:"kind"`
			Content string `json:"content"`
		}
		if err := workloadJSON(w, r, control, &payload); err != nil {
			fail()
			return
		}
		checkCtx, stop := context.WithTimeout(ctx, workloadCallBound)
		err = a.broker.Authorizer.Authorize(checkCtx, lease.run, lease.grant, channel, Read, "", a.service.Now())
		stop()
		if err != nil {
			fail()
			return
		}
		b := lease.run.spec.Binding
		storeCtx, stop := context.WithTimeout(ctx, workloadCallBound)
		state.outputID, err = a.service.StoreOutput(storeCtx, lease.run.spec.ID, b.TaskID, b.AgentID, b.ExecutionWorkspaceID, payload.Kind, []byte(payload.Content))
		stop()
		if err != nil {
			state.outputID = ""
			fail()
			return
		}
		if control.SetWriteDeadline(time.Now().Add(time.Second)) != nil {
			fail()
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			OutputID string `json:"output_id"`
		}{state.outputID})
		_ = control.Flush()
	case r.Method == http.MethodPost && r.URL.Path == "/acknowledge" && state.outputID != "" && !state.acknowledged && r.Header.Get("Content-Type") == "application/json":
		var receipt struct {
			OutputID string `json:"output_id"`
		}
		if workloadJSON(w, r, control, &receipt) != nil || receipt.OutputID != state.outputID {
			fail()
			return
		}
		checkCtx, stop := context.WithTimeout(ctx, workloadCallBound)
		err = a.broker.Authorizer.Authorize(checkCtx, lease.run, lease.grant, channel, Read, "", a.service.Now())
		if err == nil {
			err = event(checkCtx, a.service.Store.DB, lease.run.spec.Binding.OriginatorUserID, state.outputID, "restricted_workload_output_acknowledged")
		}
		stop()
		if err != nil {
			fail()
			return
		}
		state.acknowledged = true
		_ = control.SetWriteDeadline(time.Now().Add(time.Second))
		w.WriteHeader(http.StatusNoContent)
	default:
		fail()
	}
}

func workloadJSON(w http.ResponseWriter, r *http.Request, c *http.ResponseController, out any) error {
	if c.SetReadDeadline(time.Now().Add(time.Second)) != nil {
		return ErrUnavailable
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, (1<<20)+1024))
	d.DisallowUnknownFields()
	err := d.Decode(out)
	if err == nil {
		var trailing any
		if d.Decode(&trailing) != io.EOF {
			err = ErrScope
		}
	}
	if err != nil {
		return err
	}
	if c.SetReadDeadline(time.Time{}) != nil {
		return ErrUnavailable
	}
	return err
}

func (a *WorkloadApplication) deliverSnapshot(ctx context.Context, l Lease, channel string, snapshot RepositorySnapshot, w http.ResponseWriter, control *http.ResponseController, request *http.Request) (err error) {
	details := outputDeliveryDetails{DeliveryID: uuid.NewString(), ContextID: l.run.spec.ID, RootID: l.run.spec.RootID, OriginatorUserID: l.run.spec.Binding.OriginatorUserID, AgentID: l.run.spec.Binding.AgentID}
	details.Sources = []outputDeliverySource{{Operation: BoundOperation{UserID: l.run.spec.Binding.OriginatorUserID, ContextID: l.run.spec.ID, TaskID: l.run.spec.Binding.TaskID, AttemptID: l.run.spec.AttemptID, RootID: l.run.spec.RootID, GrantID: l.grant.spec.ID, ProviderID: l.grant.spec.ProviderID, RepositoryID: l.grant.spec.RepositoryID, IdentityID: l.grant.spec.IdentityID, Generation: l.grant.spec.CredentialGeneration, Operation: Read}}}
	if a.service.outputDeliveryEvent(ctx, l.run.spec.Binding.OriginatorUserID, l.run.spec.ID, "restricted_source_delivery_intent", details) != nil {
		return ErrAudit
	}
	defer func() {
		action := "restricted_source_delivery_completed"
		if err != nil {
			action = "restricted_source_delivery_aborted"
		}
		if a.service.outputDeliveryEvent(context.WithoutCancel(ctx), l.run.spec.Binding.OriginatorUserID, l.run.spec.ID, action, details) != nil {
			err = ErrAudit
		}
	}()
	if control.SetWriteDeadline(time.Now().Add(time.Second)) != nil {
		return ErrUnavailable
	}
	w.Header().Set("Content-Type", "application/x-git-packed-objects")
	w.Header().Set("Multica-Git-Head", snapshot.Head)
	for offset := 0; offset < len(snapshot.Pack); {
		checkCtx, stop := context.WithTimeout(ctx, workloadCallBound)
		_, currentChannel, err := a.channels.Authenticate(request.WithContext(checkCtx))
		if currentChannel != channel {
			err = ErrPrincipal
		}
		stop()
		if err != nil || !a.service.Now().Before(l.expires) {
			return ErrRevoked
		}
		if control.SetWriteDeadline(time.Now().Add(time.Second)) != nil {
			return ErrUnavailable
		}
		end := min(offset+outputChunkSize, len(snapshot.Pack))
		n, err := w.Write(snapshot.Pack[offset:end])
		if n > 0 && n <= end-offset {
			details.AcceptedBytes += n
		}
		if err != nil || n != end-offset {
			return io.ErrShortWrite
		}
		if control.Flush() != nil {
			return ErrUnavailable
		}
		offset = end
	}
	return nil
}

func (a *WorkloadApplication) deliverAssignment(ctx context.Context, l Lease, raw []byte, w http.ResponseWriter, control *http.ResponseController, request *http.Request) (err error) {
	return a.deliverSourceJSON(ctx, l, raw, w, control, request, "assignment")
}

func (a *WorkloadApplication) deliverSourceJSON(ctx context.Context, l Lease, raw []byte, w http.ResponseWriter, control *http.ResponseController, request *http.Request, source string) (err error) {
	details := outputDeliveryDetails{DeliveryID: uuid.NewString(), ContextID: l.run.spec.ID, RootID: l.run.spec.RootID, OriginatorUserID: l.run.spec.Binding.OriginatorUserID, AgentID: l.run.spec.Binding.AgentID}
	if a.service.outputDeliveryEvent(ctx, l.run.spec.Binding.OriginatorUserID, l.run.spec.ID, "restricted_"+source+"_delivery_intent", details) != nil {
		return ErrAudit
	}
	defer func() {
		action := "restricted_" + source + "_delivered"
		if err != nil {
			action = "restricted_" + source + "_delivery_aborted"
		}
		if a.service.outputDeliveryEvent(context.WithoutCancel(ctx), l.run.spec.Binding.OriginatorUserID, l.run.spec.ID, action, details) != nil {
			err = ErrAudit
		}
	}()
	w.Header().Set("Content-Type", "application/json")
	for offset := 0; offset < len(raw); {
		if _, _, err = a.channels.Authenticate(request.WithContext(ctx)); err != nil {
			return err
		}
		if control.SetWriteDeadline(time.Now().Add(time.Second)) != nil {
			return ErrUnavailable
		}
		end := min(offset+outputChunkSize, len(raw))
		n, writeErr := w.Write(raw[offset:end])
		if n > 0 && n <= end-offset {
			details.AcceptedBytes += n
		}
		if writeErr != nil || n != end-offset {
			return io.ErrShortWrite
		}
		if control.Flush() != nil {
			return ErrUnavailable
		}
		offset = end
	}
	return nil
}
