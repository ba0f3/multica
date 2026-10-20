package middleware

import (
	"context"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type humanSessionKey struct{}

// HumanSession is the authenticated browser session of a signed-in human.
//
// It exists only for requests that carried a verified UI session token.
// A personal access token, a cloud PAT, a task token and a daemon token
// never produce one, so a handler that requires a HumanSession cannot be
// driven by a machine credential.
//
// AuthenticatedAt is the moment the user signed in, not the moment the token
// was last renewed. A renewed token keeps the original sign-in time, so a
// long-lived session still ages out of the "recently authenticated" window.
type HumanSession struct {
	UserID          string
	SessionID       string
	AuthenticatedAt time.Time
}

// HumanSessionFromContext returns the human session of the request.
func HumanSessionFromContext(ctx context.Context) (HumanSession, bool) {
	session, ok := ctx.Value(humanSessionKey{}).(HumanSession)
	return session, ok && session.UserID != "" && session.SessionID != "" && !session.AuthenticatedAt.IsZero()
}

// ContextWithHumanSession attaches a human session to a context.
//
// The auth middleware calls this for verified session tokens. It is exported
// so a handler test can build the same request the middleware produces
// instead of inventing a second way in.
func ContextWithHumanSession(ctx context.Context, session HumanSession) context.Context {
	return context.WithValue(ctx, humanSessionKey{}, session)
}

// humanSessionFromClaims builds the human session of a verified session token.
//
// A token without a session id or without a sign-in time is not a human
// session: the caller gets no session at all, and a handler that requires one
// refuses the request. That is deliberate — a half-populated session would
// either authenticate nobody or authenticate on a guess.
func humanSessionFromClaims(claims jwt.MapClaims) (HumanSession, bool) {
	sub, _ := claims["sub"].(string)
	sid, _ := claims["sid"].(string)
	if strings.TrimSpace(sub) == "" || strings.TrimSpace(sid) == "" {
		return HumanSession{}, false
	}
	authenticatedAt, ok := claims["auth_time"].(float64)
	if !ok {
		// A token issued before the auth_time claim existed still carries
		// the moment it was signed. Using it keeps those sessions usable
		// while they age out of the recent-auth window like any other.
		issuedAt, ok := claims["iat"].(float64)
		if !ok {
			return HumanSession{}, false
		}
		authenticatedAt = issuedAt
	}
	return HumanSession{
		UserID:          sub,
		SessionID:       sid,
		AuthenticatedAt: time.Unix(int64(authenticatedAt), 0).UTC(),
	}, true
}
