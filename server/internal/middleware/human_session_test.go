package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/multica-ai/multica/server/internal/auth"
)

func TestHumanSessionFromClaims(t *testing.T) {
	signedAt := time.Now().Add(-2 * time.Hour).Truncate(time.Second)

	session, ok := humanSessionFromClaims(jwt.MapClaims{
		"sub":       "user-1",
		"sid":       "session-1",
		"auth_time": float64(signedAt.Unix()),
	})
	if !ok {
		t.Fatal("a complete session token produced no human session")
	}
	if session.UserID != "user-1" {
		t.Fatalf("user id = %q, want %q", session.UserID, "user-1")
	}
	if session.SessionID != "session-1" {
		t.Fatalf("session id = %q, want %q", session.SessionID, "session-1")
	}
	if !session.AuthenticatedAt.Equal(signedAt) {
		t.Fatalf("authenticated at = %s, want %s", session.AuthenticatedAt, signedAt)
	}
}

func TestHumanSessionFromClaimsFallsBackToTheIssueTime(t *testing.T) {
	issuedAt := time.Now().Add(-30 * time.Minute).Truncate(time.Second)

	session, ok := humanSessionFromClaims(jwt.MapClaims{
		"sub": "user-1",
		"sid": "session-1",
		"iat": float64(issuedAt.Unix()),
	})
	if !ok {
		t.Fatal("a token without auth_time produced no human session")
	}
	if !session.AuthenticatedAt.Equal(issuedAt) {
		t.Fatalf("authenticated at = %s, want %s", session.AuthenticatedAt, issuedAt)
	}
}

func TestHumanSessionFromClaimsRefusesIncompleteTokens(t *testing.T) {
	cases := map[string]jwt.MapClaims{
		"no session id": {"sub": "user-1", "auth_time": float64(time.Now().Unix())},
		"no subject":    {"sid": "session-1", "auth_time": float64(time.Now().Unix())},
		"no time":       {"sub": "user-1", "sid": "session-1"},
		"empty":         {},
	}
	for name, claims := range cases {
		t.Run(name, func(t *testing.T) {
			if _, ok := humanSessionFromClaims(claims); ok {
				t.Fatal("an incomplete token produced a human session")
			}
		})
	}
}

func TestAuthAttachesAHumanSessionToASessionToken(t *testing.T) {
	token := generateToken(jwt.MapClaims{
		"sub":       "user-1",
		"email":     "user-1@example.com",
		"sid":       "session-1",
		"exp":       time.Now().Add(time.Hour).Unix(),
		"iat":       time.Now().Unix(),
		"auth_time": time.Now().Unix(),
	}, auth.JWTSecret())

	var seen HumanSession
	var seenOK bool
	handler := Auth(nil, nil, nil, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, seenOK = HumanSessionFromContext(r.Context())
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/me/git-identities", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if !seenOK {
		t.Fatal("the auth middleware did not attach a human session")
	}
	if seen.UserID != "user-1" {
		t.Fatalf("user id = %q, want %q", seen.UserID, "user-1")
	}
}

func TestAuthAttachesNoHumanSessionToAPersonalAccessToken(t *testing.T) {
	// A personal access token is a machine-style credential: it names a
	// user, but it is not proof that a human is present.
	var seenOK bool
	handler := Auth(nil, nil, nil, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, seenOK = HumanSessionFromContext(r.Context())
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/me/git-identities", nil)
	req.Header.Set("Authorization", "Bearer mul_not_a_real_token")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if seenOK {
		t.Fatal("a personal access token produced a human session")
	}
}

func TestHumanSessionFromClaimsRefusesACLIToken(t *testing.T) {
	// The CLI token is a bearer credential on disk; it must not authorize a
	// credential change even though it is a valid session JWT.
	if _, ok := humanSessionFromClaims(jwt.MapClaims{
		"sub":         "user-1",
		"sid":         "session-1",
		"auth_time":   float64(time.Now().Unix()),
		"auth_origin": "cli",
	}); ok {
		t.Fatal("a CLI token produced a human session")
	}
}
