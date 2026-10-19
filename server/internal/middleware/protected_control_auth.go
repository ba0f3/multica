package middleware

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/multica-ai/multica/server/internal/auth"
	"github.com/multica-ai/multica/server/internal/r2dgit"
)

const ControlCookie = "__Host-multica_control"
const controlChallengeCookie = "__Host-multica_control_challenge"
const controlSessionTTL = 15 * time.Minute
const controlChallengeTTL = 3 * time.Minute

// ProtectedControlAuthConfig is explicit, existing-account authentication. It
// imports no legacy JWT, dev verification code, signup, CDN or email-service path.
type ProtectedControlAuthConfig struct {
	Source   *r2dgit.Service
	Delivery auth.CodeDelivery
	Origin   string
	Now      func() time.Time
}

type controlChallenge struct {
	id, user, email string
	cookie, code    [32]byte
	expires         time.Time
	attempts        int
}
type controlSession struct {
	id, user, email        string
	authenticated, expires time.Time
}
type controlRate struct {
	until time.Time
	count int
}

// ProtectedControlAuth owns bounded ephemeral challenges and opaque sessions.
// Restart forgets all credentials. Only non-secret event IDs persist, so neither
// restoring the DB nor replaying an event can recreate an authenticated session.
type ProtectedControlAuth struct {
	mu         sync.Mutex
	source     *r2dgit.Service
	delivery   auth.CodeDelivery
	origin     *url.URL
	now        func() time.Time
	key        [32]byte
	closed     bool
	challenges map[string]controlChallenge
	sessions   map[[32]byte]controlSession
	rates      map[[32]byte]controlRate
}

func NewProtectedControlAuth(c ProtectedControlAuthConfig) (*ProtectedControlAuth, error) {
	u, err := url.Parse(c.Origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || c.Source == nil || c.Source.Store == nil || c.Source.Store.DB == nil || c.Source.Store.Transactions == nil || c.Source.Store.Restore == nil || c.Delivery == nil {
		return nil, r2dgit.ErrUnavailable
	}
	if validator, ok := c.Delivery.(interface{ Validate() error }); ok && validator.Validate() != nil {
		return nil, r2dgit.ErrUnavailable
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	a := &ProtectedControlAuth{source: c.Source, delivery: c.Delivery, origin: u, now: c.Now, challenges: map[string]controlChallenge{}, sessions: map[[32]byte]controlSession{}, rates: map[[32]byte]controlRate{}}
	if _, err = rand.Read(a.key[:]); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *ProtectedControlAuth) Close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closed = true
	clear(a.challenges)
	clear(a.sessions)
	clear(a.rates)
	clear(a.key[:])
}

func controlJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func controlError(w http.ResponseWriter, status int) {
	controlJSON(w, status, map[string]string{"error": "protected_control_unavailable"})
}

func controlBody(w http.ResponseWriter, r *http.Request, value any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 2048)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	return d.Decode(value) == nil && d.Decode(new(any)) == io.EOF
}

func (a *ProtectedControlAuth) SameOrigin(r *http.Request) bool {
	return r.TLS != nil && r.Host == a.origin.Host && r.URL.RawQuery == "" &&
		(auth.IsSafeMethod(r.Method) || r.Header.Get("Origin") == a.origin.String())
}

func (a *ProtectedControlAuth) digest(value string) [32]byte {
	mac := hmac.New(sha256.New, a.key[:])
	mac.Write([]byte(value))
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}
func controlSecret() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}
func controlEmail(raw string) (string, bool) {
	if len(raw) > 254 || strings.ContainsAny(raw, "\r\n") {
		return "", false
	}
	raw = strings.ToLower(strings.TrimSpace(raw))
	address, err := mail.ParseAddress(raw)
	return raw, err == nil && address.Address == raw
}

func (a *ProtectedControlAuth) prune(now time.Time) {
	for id, c := range a.challenges {
		if !now.Before(c.expires) {
			delete(a.challenges, id)
		}
	}
	for id, s := range a.sessions {
		if !now.Before(s.expires) {
			delete(a.sessions, id)
		}
	}
	for id, r := range a.rates {
		if !now.Before(r.until) {
			delete(a.rates, id)
		}
	}
}
func (a *ProtectedControlAuth) takeRate(key string, limit int, now time.Time) bool {
	id := a.digest(key)
	rate := a.rates[id]
	if rate.until.IsZero() {
		rate.until = now.Add(15 * time.Minute)
	}
	if rate.count >= limit {
		return false
	}
	rate.count++
	a.rates[id] = rate
	return true
}

// RequestCode emits an identical receipt for known and unknown accounts. Only a
// freshly looked-up existing account can receive the fixed authentication message.
func (a *ProtectedControlAuth) RequestCode(w http.ResponseWriter, r *http.Request) {
	if !a.SameOrigin(r) {
		controlError(w, 403)
		return
	}
	var input struct{ Email string }
	if !controlBody(w, r, &input) {
		controlError(w, 400)
		return
	}
	email, ok := controlEmail(input.Email)
	if !ok {
		controlError(w, 400)
		return
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	now := a.now()
	a.mu.Lock()
	a.prune(now)
	if a.closed || len(a.challenges) >= 1000 || len(a.rates) >= 3000 || !a.takeRate("ip:"+ip, 10, now) || !a.takeRate("email:"+email, 3, now) || !a.takeRate("global", 1000, now) {
		a.mu.Unlock()
		controlError(w, 429)
		return
	}
	a.mu.Unlock()
	cookie, err := controlSecret()
	if err != nil {
		controlError(w, 503)
		return
	}
	// Rejection sampling avoids modulo bias in the six-digit proof.
	var code string
	for {
		var raw [3]byte
		if _, err = rand.Read(raw[:]); err != nil {
			controlError(w, 503)
			return
		}
		n := int(raw[0])<<16 | int(raw[1])<<8 | int(raw[2])
		if n < 16000000 {
			code = leftPadCode(n % 1000000)
			break
		}
	}
	challenge := controlChallenge{id: uuid.NewString(), email: email, expires: now.Add(controlChallengeTTL)}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	err = a.source.MutateAuthority(ctx, func(db r2dgit.Database) error {
		var count int
		if err := db.QueryRow(ctx, `SELECT COALESCE(min(id::text),''),count(*) FROM "user" WHERE lower(email)=$1`, email).Scan(&challenge.user, &count); err != nil {
			return err
		}
		if count != 1 || auth.IsTemporarilyDisabledUser(challenge.user, email) {
			challenge.user = ""
			return nil
		}
		if err := db.QueryRow(ctx, `SELECT email FROM "user" WHERE id=$1`, challenge.user).Scan(&challenge.email); err != nil {
			return err
		}
		_, err := db.Exec(ctx, `INSERT INTO r2d_git_security_event(id,user_id,subject_id,action) VALUES($1,$2,$1,'control_challenge')`, challenge.id, challenge.user)
		return err
	})
	if err != nil {
		controlError(w, 503)
		return
	}
	a.mu.Lock()
	if a.closed || len(a.challenges) >= 1000 {
		a.mu.Unlock()
		controlError(w, 503)
		return
	}
	challenge.cookie = a.digest("browser:" + cookie)
	challenge.code = a.digest(challenge.id + ":" + code)
	a.challenges[challenge.id] = challenge
	a.mu.Unlock()
	if challenge.user != "" {
		deliveryCtx, stop := context.WithTimeout(r.Context(), 5*time.Second)
		err = a.delivery.DeliverCode(deliveryCtx, challenge.email, code)
		stop()
		if err != nil {
			a.mu.Lock()
			delete(a.challenges, challenge.id)
			a.mu.Unlock()
		}
	}
	http.SetCookie(w, &http.Cookie{Name: controlChallengeCookie, Value: cookie, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: int(controlChallengeTTL.Seconds())})
	controlJSON(w, http.StatusAccepted, map[string]any{"challenge_id": challenge.id, "expires_in_seconds": int(controlChallengeTTL.Seconds())})
}
func leftPadCode(n int) string {
	var b [6]byte
	for i := 5; i >= 0; i-- {
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[:])
}

// VerifyCode consumes proof before any potentially uncertain transaction. Failure
// never reinstates it, and concurrent valid submissions can create at most one session.
func (a *ProtectedControlAuth) VerifyCode(w http.ResponseWriter, r *http.Request) {
	if !a.SameOrigin(r) {
		controlError(w, 403)
		return
	}
	var input struct {
		ChallengeID string `json:"challenge_id"`
		Code        string `json:"code"`
	}
	if !controlBody(w, r, &input) {
		controlError(w, 400)
		return
	}
	cookie, err := r.Cookie(controlChallengeCookie)
	if err != nil {
		controlError(w, 401)
		return
	}
	now := a.now()
	a.mu.Lock()
	a.prune(now)
	challenge, ok := a.challenges[input.ChallengeID]
	browser := a.digest("browser:" + cookie.Value)
	proof := a.digest(input.ChallengeID + ":" + input.Code)
	valid := !a.closed && ok && challenge.user != "" && len(input.Code) == 6 && subtle.ConstantTimeCompare(browser[:], challenge.cookie[:]) == 1 && subtle.ConstantTimeCompare(proof[:], challenge.code[:]) == 1 && len(a.sessions) < 1000
	if valid {
		delete(a.challenges, input.ChallengeID)
	} else if ok {
		challenge.attempts++
		if challenge.attempts >= 5 {
			delete(a.challenges, input.ChallengeID)
		} else {
			a.challenges[input.ChallengeID] = challenge
		}
	}
	a.mu.Unlock()
	if !valid {
		controlError(w, 401)
		return
	}
	secret, err := controlSecret()
	if err != nil {
		controlError(w, 503)
		return
	}
	session := controlSession{id: uuid.NewString(), user: challenge.user, email: challenge.email, authenticated: now, expires: now.Add(controlSessionTTL)}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	err = a.source.MutateAuthority(ctx, func(db r2dgit.Database) error {
		var email string
		if err := db.QueryRow(ctx, `SELECT email FROM "user" WHERE id=$1`, session.user).Scan(&email); err != nil {
			return err
		}
		if email != session.email || auth.IsTemporarilyDisabledUser(session.user, email) {
			return r2dgit.ErrPrincipal
		}
		tag, err := db.Exec(ctx, `UPDATE r2d_git_security_event SET action='control_challenge_consumed' WHERE id=$1 AND subject_id=$1 AND user_id=$2 AND action='control_challenge'`, challenge.id, session.user)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return r2dgit.ErrPrincipal
		}
		_, err = db.Exec(ctx, `INSERT INTO r2d_git_security_event(id,user_id,subject_id,action) VALUES($1,$2,$1,'control_authenticated')`, session.id, session.user)
		return err
	})
	if err != nil {
		controlError(w, 401)
		return
	}
	a.mu.Lock()
	if a.closed || len(a.sessions) >= 1000 {
		a.mu.Unlock()
		controlError(w, 503)
		return
	}
	a.sessions[sha256.Sum256([]byte(secret))] = session
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: ControlCookie, Value: secret, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: int(controlSessionTTL.Seconds())})
	http.SetCookie(w, &http.Cookie{Name: controlChallengeCookie, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	a.sessionResponse(w, session)
}

func (a *ProtectedControlAuth) csrf(s controlSession) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := a.digest("csrf:" + s.id)
	return hex.EncodeToString(out[:])
}
func (a *ProtectedControlAuth) sessionResponse(w http.ResponseWriter, s controlSession) {
	controlJSON(w, 200, map[string]any{"user_id": s.user, "authenticated_at": s.authenticated.UTC(), "expires_at": s.expires.UTC(), "csrf_token": a.csrf(s)})
}
func (a *ProtectedControlAuth) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, header := range []string{"X-User-ID", "X-User-Email", "X-Agent-ID", "X-Task-ID", "X-Actor-Source"} {
			r.Header.Del(header)
		}
		if !a.SameOrigin(r) {
			controlError(w, 403)
			return
		}
		if r.Header.Get("Authorization") != "" {
			controlError(w, 401)
			return
		}
		cookie, err := r.Cookie(ControlCookie)
		if err != nil {
			controlError(w, 401)
			return
		}
		key := sha256.Sum256([]byte(cookie.Value))
		a.mu.Lock()
		a.prune(a.now())
		session, ok := a.sessions[key]
		closed := a.closed
		a.mu.Unlock()
		if !ok || closed {
			controlError(w, 401)
			return
		}
		if !auth.IsSafeMethod(r.Method) && !hmac.Equal([]byte(r.Header.Get("X-CSRF-Token")), []byte(a.csrf(session))) {
			controlError(w, 403)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		err = a.live(ctx, key, session)
		if err != nil {
			a.mu.Lock()
			delete(a.sessions, key)
			a.mu.Unlock()
			controlError(w, 401)
			return
		}
		if r.URL.Path == "/auth/session" {
			if r.Method == http.MethodGet {
				a.sessionResponse(w, session)
				return
			}
			if r.Method == http.MethodDelete {
				a.mu.Lock()
				delete(a.sessions, key)
				a.mu.Unlock()
				// Local erasure precedes durable logout; uncertainty cannot resurrect it.
				_ = a.source.MutateAuthority(ctx, func(db r2dgit.Database) error {
					_, err := db.Exec(ctx, `UPDATE r2d_git_security_event SET action='control_logged_out' WHERE id=$1 AND action='control_authenticated'`, session.id)
					return err
				})
				http.SetCookie(w, &http.Cookie{Name: ControlCookie, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
				controlJSON(w, 200, map[string]bool{"signed_out": true})
				return
			}
		}
		r.Header.Set("X-User-ID", session.user)
		writer := &controlSessionWriter{ResponseWriter: w, authority: a, key: key, session: session, ctx: r.Context()}
		next.ServeHTTP(writer, humanSessionContext(r, HumanSession{UserID: session.user, SessionID: session.id, AuthenticatedAt: session.authenticated}))
	})
}

// Local logout/close/expiry and durable reconciliation are checked at each bounded
// response write as well as authentication. Existing output authority still checks
// every origin and the reader's own provider identity independently.
func (a *ProtectedControlAuth) live(ctx context.Context, key [32]byte, s controlSession) error {
	a.mu.Lock()
	current, ok := a.sessions[key]
	active := !a.closed && ok && current.id == s.id && a.now().Before(current.expires)
	a.mu.Unlock()
	if !active {
		return r2dgit.ErrPrincipal
	}
	if err := a.source.CheckControlSession(ctx, s.user, s.email, s.id); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	current, ok = a.sessions[key]
	if a.closed || !ok || current.id != s.id || !a.now().Before(current.expires) {
		return r2dgit.ErrPrincipal
	}
	return nil
}

type controlSessionWriter struct {
	http.ResponseWriter
	authority *ProtectedControlAuth
	key       [32]byte
	session   controlSession
	ctx       context.Context
}

func (w *controlSessionWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *controlSessionWriter) Write(raw []byte) (int, error) {
	total := 0
	for len(raw) > 0 {
		ctx, cancel := context.WithTimeout(w.ctx, time.Second)
		err := w.authority.live(ctx, w.key, w.session)
		cancel()
		if err != nil {
			return total, r2dgit.ErrRevoked
		}
		n := len(raw)
		if n > 16384 {
			n = 16384
		}
		wrote, err := w.ResponseWriter.Write(raw[:n])
		total += wrote
		if err != nil {
			return total, err
		}
		if wrote != n {
			return total, io.ErrShortWrite
		}
		raw = raw[n:]
	}
	return total, nil
}
func (w *controlSessionWriter) SetWriteDeadline(deadline time.Time) error {
	return http.NewResponseController(w.ResponseWriter).SetWriteDeadline(deadline)
}
func (w *controlSessionWriter) FlushError() error {
	ctx, cancel := context.WithTimeout(w.ctx, time.Second)
	defer cancel()
	if w.authority.live(ctx, w.key, w.session) != nil {
		return r2dgit.ErrRevoked
	}
	return http.NewResponseController(w.ResponseWriter).Flush()
}
