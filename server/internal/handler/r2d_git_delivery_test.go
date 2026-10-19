package handler

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	obsmetrics "github.com/multica-ai/multica/server/internal/metrics"
	"github.com/multica-ai/multica/server/internal/middleware"
	"github.com/multica-ai/multica/server/internal/r2dgit"
	"github.com/multica-ai/multica/server/internal/testutil"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func gitProductionOutputHandler(next http.Handler) http.Handler {
	return middleware.RequestLogger(obsmetrics.NewHTTPMetrics().Middleware(chimw.Recoverer(next)))
}

type gitDeliveryFixture struct {
	*gitHTTPFixture
	run      r2dgit.RunInfo
	a, b     r2dgit.PublicIdentity
	outputID string
	body     []byte
}

func newGitDeliveryFixture(t *testing.T) *gitDeliveryFixture {
	t.Helper()
	f := newGitHTTPFixture(t)
	ctx := context.Background()
	a := f.ready(t)
	if err := f.h.GitSecurity.SetProjectGrant(ctx, testUserID, f.project, "user", f.other, "member"); err != nil {
		t.Fatal(err)
	}
	b, err := f.h.GitSecurity.Generate(ctx, f.other, f.provider, uuid.NewString(), []string{f.project})
	if err != nil {
		t.Fatal(err)
	}
	f.worker.login, f.worker.accountID = "synthetic-b", "synthetic-account-b"
	b, err = f.h.GitSecurity.Verify(ctx, f.other, b.ID, b.Generation)
	if err != nil {
		t.Fatal(err)
	}
	f.worker.login, f.worker.accountID = "synthetic-account", "synthetic-immutable-id"
	run, err := f.h.GitSecurity.EnqueueHuman(ctx, f.user, f.workspace, f.runRequest())
	if err != nil {
		t.Fatal(err)
	}
	// Fixture-only running task. Production admission/start remains unavailable.
	dbfx.Exec(t, `UPDATE agent_task_queue SET status='running' WHERE id=$1`, run.Context.Binding.TaskID)
	body := bytes.Repeat([]byte("synthetic-output!"), 1<<16)[:1<<20]
	id, err := f.h.GitSecurity.StoreOutput(ctx, run.Context.ID, run.Context.Binding.TaskID, f.agent, f.workspace, "artifact", body)
	if err != nil {
		t.Fatal(err)
	}
	f.h.GitSecurity.OutputProof = &outputFixtureProof{allowed: map[string]bool{f.user: true, f.other: true}}
	return &gitDeliveryFixture{gitHTTPFixture: f, run: run, a: a, b: b, outputID: id, body: body}
}
func (f *gitDeliveryFixture) path() string { return "/api/me/git-outputs/" + f.outputID }
func (f *gitDeliveryFixture) request(t *testing.T, base, token string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodGet, base+f.path(), nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("X-Workspace-ID", f.workspace)
	r.Close = true
	return r
}

func TestR2DGitDownloadRequiresDeadlineAndDurableIntent(t *testing.T) {
	f := newGitDeliveryFixture(t)
	// An unsupported response writer cannot silently select an unbounded path.
	r := testutil.WithHeaders(testutil.JSONRequest(http.MethodGet, f.path(), nil), "Authorization", "Bearer "+f.otherToken)
	w := testutil.Call(t, f.router.ServeHTTP, r).Want(503)
	if strings.Contains(w.Body.String(), "synthetic-output!") {
		t.Fatal("unsupported writer received source")
	}
	f.h.GitSecurity.Store.DB = outputAuditDatabase{Database: testPool, fail: "restricted_output_delivery_intent"}
	f.call(t, f.otherToken, http.MethodGet, f.path(), nil, 503)
	var prepared int
	dbfx.QueryRow(t, `SELECT count(*) FROM r2d_git_security_event WHERE subject_id=$1 AND action='restricted_output_delivery_completed'`, f.outputID).Scan(&prepared)
	if prepared != 0 {
		t.Fatal("delivery completed without deadline or durable intent")
	}
}

func TestR2DGitDownloadActualHTTPAndReaderKeyAudit(t *testing.T) {
	for _, http2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("http2=%t", http2), func(t *testing.T) {
			f := newGitDeliveryFixture(t)
			server := httptest.NewUnstartedServer(gitProductionOutputHandler(f.router))
			server.EnableHTTP2 = http2
			if http2 {
				server.StartTLS()
			} else {
				server.Start()
			}
			defer server.Close()
			response, err := server.Client().Do(f.request(t, server.URL, f.otherToken))
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil || response.StatusCode != 200 || !bytes.Equal(body, f.body) || response.Header.Get("Cache-Control") != "no-store" {
				t.Fatalf("authorized real HTTP download failed: status=%d bytes=%d err=%v", response.StatusCode, len(body), err)
			}
			if http2 && response.ProtoMajor != 2 {
				t.Fatal("HTTP2 positive control did not negotiate HTTP2")
			}
			var details []byte
			// The client can drain queued bytes just before the terminal audit commits.
			until := time.Now().Add(2 * time.Second)
			for {
				err = testPool.QueryRow(context.Background(), `SELECT details FROM r2d_git_security_event WHERE subject_id=$1 AND action='restricted_output_delivery_completed'`, f.outputID).Scan(&details)
				if err == nil {
					break
				}
				if time.Now().After(until) {
					t.Fatal("missing completion audit")
				}
				time.Sleep(5 * time.Millisecond)
			}
			var audit struct {
				Accepted int    `json:"accepted_bytes"`
				Root     string `json:"root_id"`
				Sources  []struct {
					Operation   r2dgit.BoundOperation `json:"operation"`
					Fingerprint string                `json:"fingerprint"`
				} `json:"sources"`
			}
			if json.Unmarshal(details, &audit) != nil || audit.Accepted != len(f.body) || audit.Root != f.run.Context.ID || len(audit.Sources) != 1 {
				t.Fatalf("invalid delivery audit: accepted=%d sources=%d", audit.Accepted, len(audit.Sources))
			}
			op := audit.Sources[0].Operation
			if op.UserID != f.other || op.IdentityID != f.b.ID || op.Generation != f.b.Generation || op.TaskID != f.run.Context.Binding.TaskID || audit.Sources[0].Fingerprint != f.b.Fingerprint {
				t.Fatal("delivery audit substituted originator/owner credentials")
			}
			if bytes.Contains(details, []byte("synthetic-output!")) {
				t.Fatal("source in routine delivery audit")
			}
		})
	}
}

type gitDeliveryTransactions struct {
	r2dgit.Transactions
	offline atomic.Bool
}

func (t *gitDeliveryTransactions) Begin(ctx context.Context) (pgx.Tx, error) {
	if t.offline.Load() {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return t.Transactions.Begin(ctx)
}

type gitDeliveryConnection struct {
	net.Conn
	mu                    sync.Mutex
	writing               bool
	started, lastAccepted time.Time
	closedAt              time.Time
	accepted              int
	closed                chan struct{}
	closeOnce             sync.Once
}

func (c *gitDeliveryConnection) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.writing = true
	c.started = time.Now()
	c.mu.Unlock()
	n, err := c.Conn.Write(p)
	c.mu.Lock()
	c.writing = false
	if n > 0 {
		c.lastAccepted = time.Now()
		c.accepted += n
	}
	c.mu.Unlock()
	return n, err
}
func (c *gitDeliveryConnection) Close() error {
	err := c.Conn.Close()
	c.closeOnce.Do(func() { c.mu.Lock(); c.closedAt = time.Now(); c.mu.Unlock(); close(c.closed) })
	return err
}
func (c *gitDeliveryConnection) blocked() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writing && time.Since(c.started) > 25*time.Millisecond
}

type gitDeliveryListener struct {
	net.Listener
	accepted chan *gitDeliveryConnection
}

func (l gitDeliveryListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		conn.Close()
		return nil, errors.New("synthetic TCP listener required")
	}
	if err := tcp.SetWriteBuffer(1024); err != nil {
		conn.Close()
		return nil, err
	}
	observed := &gitDeliveryConnection{Conn: conn, closed: make(chan struct{})}
	l.accepted <- observed
	return observed, nil
}

func TestR2DGitDownloadLocalRevocationStopsBlockedSocket(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("measured TCP backpressure acceptance runs on Linux")
	}
	for _, change := range []string{"root_cancel", "key_revoke", "key_rotate", "offboard", "policy_outage"} {
		t.Run(change, func(t *testing.T) {
			f := newGitDeliveryFixture(t)
			ctx := context.Background()
			transactions := &gitDeliveryTransactions{Transactions: testPool}
			f.h.GitSecurity.Store.Transactions = transactions
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			observed := make(chan *gitDeliveryConnection, 1)
			finished := make(chan struct{})
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { defer close(finished); f.router.ServeHTTP(w, r) }))
			server.Listener.Close()
			server.Listener = gitDeliveryListener{Listener: listener, accepted: observed}
			server.Start()
			defer server.Close()
			conn, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := conn.(*net.TCPConn).SetReadBuffer(1024); err != nil {
				t.Fatal(err)
			}
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: fixture.invalid\r\nAuthorization: Bearer %s\r\nConnection: close\r\n\r\n", f.path(), f.otherToken); err != nil {
				t.Fatal(err)
			}
			response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != 200 {
				t.Fatalf("authorized stream never started: %d", response.StatusCode)
			}
			tracked := <-observed
			until := time.NewTimer(700 * time.Millisecond)
			defer until.Stop()
			tick := time.NewTicker(5 * time.Millisecond)
			defer tick.Stop()
			for !tracked.blocked() {
				select {
				case <-tick.C:
				case <-until.C:
					t.Fatal("fixture failed to create a blocked socket write")
				case <-tracked.closed:
					t.Fatal("stream ended before revocation trigger")
				}
			}
			select {
			case <-tracked.closed:
				t.Fatal("stream ended before local change started")
			default:
			}
			switch change {
			case "root_cancel":
				err = f.h.GitSecurity.RevokeRoot(ctx, f.user, f.run.Context.ID)
			case "key_revoke":
				err = f.h.GitSecurity.Revoke(ctx, f.user, f.a.ID)
			case "key_rotate":
				var next r2dgit.PublicIdentity
				next, err = f.h.GitSecurity.Generate(ctx, f.user, f.provider, uuid.NewString(), []string{f.project})
				if err == nil {
					_, err = f.h.GitSecurity.Verify(ctx, f.user, next.ID, next.Generation)
				}
				if err == nil {
					_, err = f.h.GitSecurity.Activate(ctx, f.user, next.ID, next.Generation)
				}
			case "offboard":
				_, err = testPool.Exec(ctx, `DELETE FROM member WHERE user_id=$1 AND workspace_id=$2`, f.user, f.workspace)
			case "policy_outage":
				transactions.offline.Store(true)
			}
			if err != nil {
				t.Fatal(err)
			}
			committed := time.Now()
			select {
			case <-tracked.closed:
			case <-time.After(5 * time.Second):
				t.Fatal("server did not stop blocked delivery within5s of local change")
			}
			select {
			case <-finished:
			case <-time.After(2 * time.Second):
				t.Fatal("delivery audit/handler outlived bounded response")
			}
			tracked.mu.Lock()
			last, accepted, closedAt := tracked.lastAccepted, tracked.accepted, tracked.closedAt
			tracked.mu.Unlock()
			elapsed := max(time.Duration(0), closedAt.Sub(committed))
			if accepted >= len(f.body) || last.After(committed.Add(5*time.Second)) || elapsed > 5*time.Second {
				t.Fatal("source delivery continued after cutoff or completed despite backpressure")
			}
			var audit []byte
			if err := testPool.QueryRow(ctx, `SELECT details FROM r2d_git_security_event WHERE subject_id=$1 AND action='restricted_output_delivery_aborted' ORDER BY created_at DESC LIMIT 1`, f.outputID).Scan(&audit); err != nil {
				t.Fatalf("missing aborted audit: %v", err)
			}
			var detail struct {
				Accepted int    `json:"accepted_bytes"`
				Reason   string `json:"reason"`
			}
			if json.Unmarshal(audit, &detail) != nil || detail.Accepted >= len(f.body) || detail.Reason == "" {
				t.Fatal("invalid partial delivery audit")
			}
			t.Logf("%s: server closed in %s after committed local change; accepted wire bytes=%d/%d", change, elapsed, accepted, len(f.body))
			want := 409
			if change == "policy_outage" {
				want = 503
			}
			f.call(t, f.otherToken, http.MethodGet, f.path(), nil, want)
		})
	}
}

type gitDeliveryMemorySink struct {
	bytes.Buffer
	afterFirst func()
	calls      int
}

func (*gitDeliveryMemorySink) SetWriteDeadline(time.Time) error { return nil }
func (*gitDeliveryMemorySink) Begin(int)                        {}
func (s *gitDeliveryMemorySink) Write(body []byte) (int, error) {
	n, err := s.Buffer.Write(body)
	s.calls++
	if s.calls == 1 && s.afterFirst != nil {
		s.afterFirst()
	}
	return n, err
}

func TestR2DGitDeliveryRechecksDuringProgressAndRecordsAuditOutage(t *testing.T) {
	for _, mode := range []string{"query_timeout", "query_lock", "periodic_provider", "reader_rotation", "terminal_audit"} {
		t.Run(mode, func(t *testing.T) {
			f := newGitDeliveryFixture(t)
			ctx := context.Background()
			sink := &gitDeliveryMemorySink{}
			switch mode {
			case "query_timeout":
				transactions := &gitDeliveryTransactions{Transactions: testPool}
				f.h.GitSecurity.Store.Transactions = transactions
				sink.afterFirst = func() { transactions.offline.Store(true) }
			case "query_lock":
				sink.afterFirst = func() {
					tx, err := testPool.Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
					if _, err = tx.Exec(ctx, `LOCK TABLE r2d_git_output IN ACCESS EXCLUSIVE MODE`); err != nil {
						t.Fatal(err)
					}
				}
			case "periodic_provider":
				base := time.Now()
				var advance atomic.Int64
				f.h.GitSecurity.Now = func() time.Time { return base.Add(time.Duration(advance.Load())) }
				sink.afterFirst = func() {
					advance.Store(int64(31 * time.Second))
					f.h.GitSecurity.OutputProof.(*outputFixtureProof).allowed[f.other] = false
				}
			case "reader_rotation":
				sink.afterFirst = func() {
					f.worker.login, f.worker.accountID = "synthetic-b", "synthetic-account-b"
					next, err := f.h.GitSecurity.Generate(ctx, f.other, f.provider, uuid.NewString(), []string{f.project})
					if err != nil {
						t.Fatal(err)
					}
					if _, err = f.h.GitSecurity.Verify(ctx, f.other, next.ID, next.Generation); err != nil {
						t.Fatal(err)
					}
					if _, err = f.h.GitSecurity.Activate(ctx, f.other, next.ID, next.Generation); err != nil {
						t.Fatal(err)
					}
				}
			case "terminal_audit":
				f.h.GitSecurity.Store.DB = outputAuditDatabase{Database: testPool, fail: "restricted_output_delivery_completed"}
			}
			start := time.Now()
			err := f.h.GitSecurity.DeliverOutput(ctx, f.other, f.outputID, sink)
			if err == nil {
				t.Fatalf("continued delivery after %s", mode)
			}
			if mode == "terminal_audit" {
				if !errors.Is(err, r2dgit.ErrAudit) || sink.Len() != len(f.body) {
					t.Fatal("terminal audit outage did not report already accepted outcome uncertainty")
				}
				var intents, completed int
				dbfx.QueryRow(t, `SELECT count(*) FILTER(WHERE action='restricted_output_delivery_intent'),count(*) FILTER(WHERE action='restricted_output_delivery_completed') FROM r2d_git_security_event WHERE subject_id=$1`, f.outputID).Scan(&intents, &completed)
				if intents != 1 || completed != 0 {
					t.Fatal("missing pending audit intent or false completed outcome")
				}
			} else {
				if sink.calls != 1 || sink.Len() != 16<<10 {
					t.Fatalf("source continued past first authorized chunk: calls=%d bytes=%d", sink.calls, sink.Len())
				}
				if time.Since(start) > 3*time.Second {
					t.Fatal("current rights/proof check did not obey bounded deadline")
				}
			}
		})
	}
}

type gitDeadlineWithoutFlush struct{ http.ResponseWriter }

func (gitDeadlineWithoutFlush) SetWriteDeadline(time.Time) error { return nil }

type gitFlushFailureWriter struct{ *httptest.ResponseRecorder }

func (*gitFlushFailureWriter) SetWriteDeadline(time.Time) error { return nil }
func (*gitFlushFailureWriter) FlushError() error {
	return errors.New("synthetic transport flush failed")
}

func TestR2DGitDeliveryRejectsMissingFlushAndPreservesMiddlewareErrors(t *testing.T) {
	f := newGitDeliveryFixture(t)
	request := func() *http.Request {
		return testutil.WithHeaders(testutil.JSONRequest(http.MethodGet, f.path(), nil), "Authorization", "Bearer "+f.otherToken)
	}
	testutil.Call(t, func(w http.ResponseWriter, r *http.Request) { f.router.ServeHTTP(gitDeadlineWithoutFlush{w}, r) }, request()).Want(503)
	recorder := httptest.NewRecorder()
	writer := &gitFlushFailureWriter{recorder}
	aborted := false
	func() {
		defer func() {
			if p := recover(); p != nil {
				if p != http.ErrAbortHandler {
					panic(p)
				}
				aborted = true
			}
		}()
		gitProductionOutputHandler(f.router).ServeHTTP(writer, request())
	}()
	if !aborted || recorder.Code != 200 || recorder.Body.Len() != 16<<10 {
		t.Fatal("middleware swallowed a partial response flush failure")
	}
	var completed, partial int
	dbfx.QueryRow(t, `SELECT count(*) FILTER(WHERE action='restricted_output_delivery_completed'),count(*) FILTER(WHERE action='restricted_output_delivery_aborted' AND (details->>'accepted_bytes')::int=16384) FROM r2d_git_security_event WHERE subject_id=$1`, f.outputID).Scan(&completed, &partial)
	if completed != 0 || partial != 1 {
		t.Fatal("flush failure acquired a false completed audit outcome")
	}
}

func TestR2DGitDownloadHTTP2RevocationStopsFlowControlledStream(t *testing.T) {
	f := newGitDeliveryFixture(t)
	finished := make(chan struct{})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(finished)
		gitProductionOutputHandler(f.router).ServeHTTP(w, r)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	conn, err := tls.Dial("tcp", server.Listener.Addr().String(), &tls.Config{RootCAs: roots, NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if conn.ConnectionState().NegotiatedProtocol != "h2" {
		t.Fatal("fixture did not negotiate HTTP2")
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, http2.ClientPreface); err != nil {
		t.Fatal(err)
	}
	frames := http2.NewFramer(conn, conn)
	frames.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	if err := frames.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1024}); err != nil {
		t.Fatal(err)
	}
	var headers bytes.Buffer
	encoder := hpack.NewEncoder(&headers)
	for _, field := range []hpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"}, {Name: ":authority", Value: server.Listener.Addr().String()}, {Name: ":path", Value: f.path()}, {Name: "authorization", Value: "Bearer " + f.otherToken}} {
		if err := encoder.WriteField(field); err != nil {
			t.Fatal(err)
		}
	}
	if err := frames.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: headers.Bytes(), EndHeaders: true, EndStream: true}); err != nil {
		t.Fatal(err)
	}
	accepted := 0
	authorized := false
	var committed time.Time
	for {
		frame, err := frames.ReadFrame()
		if err != nil {
			t.Fatalf("HTTP2 stream ended without measured reset: %v", err)
		}
		switch frame := frame.(type) {
		case *http2.SettingsFrame:
			if !frame.IsAck() {
				if err := frames.WriteSettingsAck(); err != nil {
					t.Fatal(err)
				}
			}
		case *http2.MetaHeadersFrame:
			if frame.StreamID == 1 {
				authorized = frame.PseudoValue("status") == "200"
				if !authorized {
					t.Fatal("authorized HTTP2 stream did not start")
				}
			}
		case *http2.DataFrame:
			if frame.StreamID != 1 || !authorized || frame.StreamEnded() {
				t.Fatal("HTTP2 fixture did not exercise a partial authorized response")
			}
			accepted += len(frame.Data())
			if accepted > 1024 {
				t.Fatal("HTTP2 fixture accidentally replenished response flow control")
			}
			if committed.IsZero() {
				if err := f.h.GitSecurity.RevokeRoot(context.Background(), f.user, f.run.Context.ID); err != nil {
					t.Fatal(err)
				}
				committed = time.Now()
				_ = conn.SetReadDeadline(committed.Add(5 * time.Second))
			}
			// Deliberately send no WINDOW_UPDATE. Default clients buffer too much data
			// to prove that a blocked HTTP2 stream obeys the server write deadline.
		case *http2.RSTStreamFrame:
			if frame.StreamID != 1 || committed.IsZero() || time.Since(committed) > 5*time.Second {
				t.Fatal("HTTP2 reset did not follow committed local revocation within5s")
			}
			elapsed := time.Since(committed)
			select {
			case <-finished:
			case <-time.After(2 * time.Second):
				t.Fatal("HTTP2 handler/audit outlived stream reset")
			}
			var aborted int
			dbfx.QueryRow(t, `SELECT count(*) FROM r2d_git_security_event WHERE subject_id=$1 AND action='restricted_output_delivery_aborted'`, f.outputID).Scan(&aborted)
			if aborted != 1 {
				t.Fatal("HTTP2 stalled delivery acquired no aborted audit")
			}
			t.Logf("HTTP2 root cancel: reset in %s; received source bytes=%d/%d", elapsed, accepted, len(f.body))
			return
		}
	}
}
