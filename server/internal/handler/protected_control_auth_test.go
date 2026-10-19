//go:build linux

package handler

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/multica-ai/multica/server/internal/auth"
	"github.com/multica-ai/multica/server/internal/middleware"
	"github.com/multica-ai/multica/server/internal/r2dgit"
)

type controlMailFixture struct {
	mu         sync.Mutex
	codes      map[string]string
	deliveries int
}

func (m *controlMailFixture) DeliverCode(ctx context.Context, email, code string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.codes[email] = code
	m.deliveries++
	return nil
}
func (m *controlMailFixture) code(email string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.codes[email]
}

type controlAuthFixture struct {
	f         *gitHTTPFixture
	authority *middleware.ProtectedControlAuth
	mail      *controlMailFixture
	router    http.Handler
	email     string
	clock     atomic.Int64
}

const controlFixtureOrigin = "https://control.fixture.invalid"

func newControlAuthFixture(t *testing.T) *controlAuthFixture {
	t.Helper()
	f := newGitHTTPFixture(t)
	_ = gitRestoreFixture(t, f)
	c := &controlAuthFixture{f: f, mail: &controlMailFixture{codes: map[string]string{}}}
	c.clock.Store(time.Now().Unix())
	if err := testPool.QueryRow(context.Background(), `SELECT email FROM "user" WHERE id=$1`, f.user).Scan(&c.email); err != nil {
		t.Fatal(err)
	}
	a, err := middleware.NewProtectedControlAuth(middleware.ProtectedControlAuthConfig{Source: f.h.GitSecurity, Delivery: c.mail, Origin: controlFixtureOrigin, Now: func() time.Time { return time.Unix(c.clock.Load(), 0) }})
	if err != nil {
		t.Fatal(err)
	}
	c.authority = a
	t.Cleanup(a.Close)
	r := chi.NewRouter()
	r.Post("/auth/code", a.RequestCode)
	r.Post("/auth/session", a.VerifyCode)
	r.Group(func(r chi.Router) {
		r.Use(a.Authenticate)
		r.Get("/auth/session", func(http.ResponseWriter, *http.Request) {})
		r.Delete("/auth/session", func(http.ResponseWriter, *http.Request) {})
		f.h.MountGitAccountRoutes(r)
		r.Get("/origin", func(w http.ResponseWriter, r *http.Request) {
			s, ok := middleware.HumanSessionFromContext(r.Context())
			if !ok {
				t.Error("missing authoritative human")
			}
			writeJSON(w, 200, map[string]string{"user": s.UserID, "header": r.Header.Get("X-User-ID"), "task": r.Header.Get("X-Task-ID")})
		})
	})
	c.router = r
	return c
}
func (c *controlAuthFixture) call(method, path string, body any, cookie *http.Cookie, csrf string, headers map[string]string) *httptest.ResponseRecorder {
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	r := httptest.NewRequest(method, controlFixtureOrigin+path, bytes.NewReader(raw))
	r.RemoteAddr = "127.0.0.1:30000"
	r.Header.Set("Origin", controlFixtureOrigin)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if csrf != "" {
		r.Header.Set("X-CSRF-Token", csrf)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	out := httptest.NewRecorder()
	c.router.ServeHTTP(out, r)
	return out
}
func controlCookie(t *testing.T, out *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range out.Result().Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	t.Fatalf("missing cookie %s: %d %s", name, out.Code, out.Body)
	return nil
}
func (c *controlAuthFixture) challenge(t *testing.T) (string, *http.Cookie) {
	t.Helper()
	out := c.call("POST", "/auth/code", map[string]string{"email": c.email}, nil, "", nil)
	if out.Code != 202 {
		t.Fatalf("request code: %d %s", out.Code, out.Body)
	}
	var receipt struct {
		ChallengeID string `json:"challenge_id"`
	}
	if json.Unmarshal(out.Body.Bytes(), &receipt) != nil || receipt.ChallengeID == "" {
		t.Fatal("missing challenge")
	}
	return receipt.ChallengeID, controlCookie(t, out, "__Host-multica_control_challenge")
}
func (c *controlAuthFixture) login(t *testing.T) (*http.Cookie, string) {
	t.Helper()
	id, cookie := c.challenge(t)
	out := c.call("POST", "/auth/session", map[string]string{"challenge_id": id, "code": c.mail.code(c.email)}, cookie, "", nil)
	if out.Code != 200 {
		t.Fatalf("verify code: %d %s", out.Code, out.Body)
	}
	var receipt struct {
		CSRF string `json:"csrf_token"`
	}
	if json.Unmarshal(out.Body.Bytes(), &receipt) != nil || receipt.CSRF == "" {
		t.Fatal("missing session CSRF")
	}
	for _, issued := range out.Result().Cookies() {
		if issued.Name == auth.AuthCookieName || strings.HasPrefix(issued.Name, "CloudFront-") {
			t.Fatal("legacy authority minted")
		}
	}
	return controlCookie(t, out, middleware.ControlCookie), receipt.CSRF
}

func TestR2DGitControlAuthenticationIsolationAndLogout(t *testing.T) {
	c := newControlAuthFixture(t)
	cookie, csrf := c.login(t)
	if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Domain != "" || cookie.Path != "/" || cookie.MaxAge != 900 {
		t.Fatal("unsafe protected cookie")
	}
	out := c.call("GET", "/origin", nil, cookie, "", map[string]string{"X-User-ID": c.f.other, "X-Task-ID": "forged", "X-Actor-Source": "task_token"})
	if out.Code != 200 || !strings.Contains(out.Body.String(), c.f.user) || strings.Contains(out.Body.String(), c.f.other) || strings.Contains(out.Body.String(), "forged") {
		t.Fatal("identity substitution", out.Code, out.Body)
	}
	checkpoint, err := c.f.h.GitSecurity.Store.Restore.Witness.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	out = c.call("GET", "/api/me/git-identities", nil, cookie, "", nil)
	if out.Code != 200 {
		t.Fatal("profile unavailable", out.Code, out.Body)
	}
	after, err := c.f.h.GitSecurity.Store.Restore.Witness.Current(context.Background())
	if err != nil || after != checkpoint {
		t.Fatal("read authentication advanced the witness", err)
	}
	for _, token := range []string{c.f.token, "mul_synthetic", "mat_synthetic", "mcn_synthetic", "mdt_synthetic"} {
		out = c.call("GET", "/auth/session", nil, cookie, "", map[string]string{"Authorization": "Bearer " + token})
		if out.Code != 401 {
			t.Fatal("ambient credential was promoted", token, out.Code)
		}
	}
	out = c.call("GET", "/auth/session", nil, cookie, "", nil)
	if out.Code != 200 || strings.Contains(out.Body.String(), "name") || strings.Contains(out.Body.String(), "email") || strings.Contains(out.Body.String(), "profile") || strings.Contains(out.Body.String(), "questionnaire") {
		t.Fatal("broad profile disclosure", out.Code, out.Body)
	}
	for _, headers := range []map[string]string{{"Origin": "https://foreign.invalid"}, {"Origin": ""}} {
		out = c.call("DELETE", "/auth/session", nil, cookie, csrf, headers)
		if out.Code != 403 {
			t.Fatal("cross-origin logout accepted")
		}
	}
	if out = c.call("DELETE", "/auth/session", nil, cookie, "", nil); out.Code != 403 {
		t.Fatal("missing CSRF accepted")
	}
	if out = c.call("DELETE", "/auth/session", nil, cookie, csrf, nil); out.Code != 200 {
		t.Fatal("logout", out.Code, out.Body)
	}
	if out = c.call("GET", "/api/me/git-identities", nil, cookie, "", nil); out.Code != 401 {
		t.Fatal("logged-out session replayed")
	}
}

func TestR2DGitControlProofSingleUseExpiryAndCurrentAccount(t *testing.T) {
	t.Run("concurrent_consume", func(t *testing.T) {
		c := newControlAuthFixture(t)
		id, cookie := c.challenge(t)
		code := c.mail.code(c.email)
		var success atomic.Int32
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				out := c.call("POST", "/auth/session", map[string]string{"challenge_id": id, "code": code}, cookie, "", nil)
				if out.Code == 200 {
					success.Add(1)
				} else if out.Code != 401 {
					t.Errorf("unexpected consume response %d %s", out.Code, out.Body)
				}
			}()
		}
		wg.Wait()
		if success.Load() != 1 {
			t.Fatal("proof was replayed", success.Load())
		}
	})
	t.Run("expiry_and_no_dev_override", func(t *testing.T) {
		t.Setenv("MULTICA_DEV_VERIFICATION_CODE", "123456")
		c := newControlAuthFixture(t)
		id, cookie := c.challenge(t)
		wrong := "123456"
		if wrong == c.mail.code(c.email) {
			wrong = "654321"
		}
		out := c.call("POST", "/auth/session", map[string]string{"challenge_id": id, "code": wrong}, cookie, "", nil)
		if out.Code != 401 {
			t.Fatal("dev override accepted")
		}
		c.clock.Add(181)
		out = c.call("POST", "/auth/session", map[string]string{"challenge_id": id, "code": c.mail.code(c.email)}, cookie, "", nil)
		if out.Code != 401 {
			t.Fatal("expired challenge accepted")
		}
		cookie, _ = c.login(t)
		c.clock.Add(901)
		if out = c.call("GET", "/auth/session", nil, cookie, "", nil); out.Code != 401 {
			t.Fatal("expired session accepted")
		}
	})
	t.Run("changed_email", func(t *testing.T) {
		c := newControlAuthFixture(t)
		id, cookie := c.challenge(t)
		if err := c.f.h.GitSecurity.MutateAuthority(context.Background(), func(db r2dgit.Database) error {
			_, err := db.Exec(context.Background(), `UPDATE "user" SET email=$2 WHERE id=$1`, c.f.user, "changed-"+c.email)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if out := c.call("POST", "/auth/session", map[string]string{"challenge_id": id, "code": c.mail.code(c.email)}, cookie, "", nil); out.Code != 401 {
			t.Fatal("changed account accepted")
		}
	})
	t.Run("unknown_account_receipt_and_attempt_bound", func(t *testing.T) {
		c := newControlAuthFixture(t)
		out := c.call("POST", "/auth/code", map[string]string{"email": "unknown@fixture.invalid"}, nil, "", nil)
		if out.Code != 202 || c.mail.deliveries != 0 {
			t.Fatal("unknown account enumerated or mailed")
		}
		id, cookie := c.challenge(t)
		code := c.mail.code(c.email)
		wrong := "000000"
		if wrong == code {
			wrong = "111111"
		}
		for range 5 {
			if out = c.call("POST", "/auth/session", map[string]string{"challenge_id": id, "code": wrong}, cookie, "", nil); out.Code != 401 {
				t.Fatal("wrong proof accepted")
			}
		}
		if out = c.call("POST", "/auth/session", map[string]string{"challenge_id": id, "code": code}, cookie, "", nil); out.Code != 401 {
			t.Fatal("attempt bound bypassed")
		}
	})
}

func TestR2DGitControlRestoreInvalidatesPendingAndExistingSessions(t *testing.T) {
	c := newControlAuthFixture(t)
	cookie, _ := c.login(t)
	id, pending := c.challenge(t)
	oldCode := c.mail.code(c.email)
	if err := c.f.h.GitSecurity.ReconcileRestoredDatabase(context.Background()); err != nil {
		t.Fatal(err)
	}
	if out := c.call("GET", "/auth/session", nil, cookie, "", nil); out.Code != 401 {
		t.Fatal("restored session accepted", out.Code, out.Body)
	}
	if out := c.call("POST", "/auth/session", map[string]string{"challenge_id": id, "code": oldCode}, pending, "", nil); out.Code != 401 {
		t.Fatal("pre-restore proof refreshed authority", out.Code, out.Body)
	}
	fresh, _ := c.login(t)
	if out := c.call("GET", "/auth/session", nil, fresh, "", nil); out.Code != 200 {
		t.Fatal("fresh authentication unavailable after reconciliation", out.Code, out.Body)
	}
	// Forgetting the in-memory registry cannot reconstruct a session from its DB event.
	c.authority.Close()
	if out := c.call("GET", "/auth/session", nil, fresh, "", nil); out.Code != 401 {
		t.Fatal("closed registry reused")
	}
}

func TestR2DGitControlRequiresTLSOriginAndBoundedReceipts(t *testing.T) {
	c := newControlAuthFixture(t)
	for _, origin := range []string{"http://control.fixture.invalid", "https://control.fixture.invalid/path", "https://user@control.fixture.invalid", "https://control.fixture.invalid?query"} {
		if a, err := middleware.NewProtectedControlAuth(middleware.ProtectedControlAuthConfig{Source: c.f.h.GitSecurity, Delivery: c.mail, Origin: origin}); err == nil || a != nil {
			t.Fatal("unsafe origin accepted", origin)
		}
	}
	req := httptest.NewRequest("POST", controlFixtureOrigin+"/auth/code", strings.NewReader(`{"email":"synthetic@fixture.invalid"}`))
	req.TLS = nil
	req.Header.Set("Origin", controlFixtureOrigin)
	out := httptest.NewRecorder()
	c.authority.RequestCode(out, req)
	if out.Code != 403 {
		t.Fatal("plaintext auth accepted")
	}
	req = httptest.NewRequest("POST", controlFixtureOrigin+"/auth/code", strings.NewReader(`{"email":"synthetic@fixture.invalid"}`))
	req.TLS = &tls.ConnectionState{}
	req.Host = "foreign.invalid"
	req.Header.Set("Origin", controlFixtureOrigin)
	out = httptest.NewRecorder()
	c.authority.RequestCode(out, req)
	if out.Code != 403 {
		t.Fatal("forwarded/foreign host accepted")
	}
	for n := 0; n < 3; n++ {
		out = c.call("POST", "/auth/code", map[string]string{"email": c.email}, nil, "", nil)
		if out.Code != 202 {
			t.Fatal("rate positive", n, out.Code)
		}
	}
	out = c.call("POST", "/auth/code", map[string]string{"email": c.email}, nil, "", nil)
	if out.Code != 429 {
		t.Fatal("email rate bound missing", out.Code)
	}
}

type controlRevokingWriter struct {
	*httptest.ResponseRecorder
	after func()
	once  sync.Once
}

func (w *controlRevokingWriter) Write(raw []byte) (int, error) {
	n, err := w.ResponseRecorder.Write(raw)
	w.once.Do(w.after)
	return n, err
}
func TestR2DGitControlSessionStopsCapturedResponseAndConcurrentLogout(t *testing.T) {
	t.Run("bounded_response", func(t *testing.T) {
		c := newControlAuthFixture(t)
		cookie, _ := c.login(t)
		body := bytes.Repeat([]byte("synthetic-session-content"), 2000)
		var accepted int
		var writeErr error
		c.router = c.authority.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { accepted, writeErr = w.Write(body) }))
		r := httptest.NewRequest("GET", controlFixtureOrigin+"/stream", nil)
		r.AddCookie(cookie)
		writer := &controlRevokingWriter{ResponseRecorder: httptest.NewRecorder(), after: c.authority.Close}
		c.router.ServeHTTP(writer, r)
		if writeErr == nil || accepted != 16384 || writer.Body.Len() != 16384 {
			t.Fatal("closed session continued response", accepted, writer.Body.Len(), writeErr)
		}
	})
	t.Run("read_snapshot_vs_durable_logout", func(t *testing.T) {
		c := newControlAuthFixture(t)
		cookie, _ := c.login(t)
		guard := c.f.h.GitSecurity.Store.Restore
		base := guard.Witness
		paused := &pausedReadFinalization{RestoreWitness: base, paused: make(chan struct{}), release: make(chan struct{})}
		paused.calls.Store(1)
		guard.Witness = paused
		defer func() { guard.Witness = base }()
		done := make(chan *httptest.ResponseRecorder, 1)
		go func() { done <- c.call("GET", "/auth/session", nil, cookie, "", nil) }()
		select {
		case <-paused.paused:
		case <-time.After(time.Second):
			t.Fatal("session read did not reach witnessed finalization")
		}
		if err := c.f.h.GitSecurity.MutateAuthority(context.Background(), func(db r2dgit.Database) error {
			_, err := db.Exec(context.Background(), `UPDATE r2d_git_security_event SET action='control_logged_out' WHERE user_id=$1 AND action='control_authenticated'`, c.f.user)
			return err
		}); err != nil {
			close(paused.release)
			t.Fatal(err)
		}
		close(paused.release)
		select {
		case out := <-done:
			if out.Code != 401 {
				t.Fatal("stale session survived committed logout", out.Code, out.Body)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("session finalization hung")
		}
	})
}
