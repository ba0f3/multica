// Package r2dgit owns the lifecycle of per-user Git credentials: key
// generation, encrypted custody, provider verification and the public
// representation the UI is allowed to see.
//
// The package has one hard rule: a private key never leaves the trusted
// custody boundary. Nothing here returns private bytes to a caller that could
// put them in an HTTP response, a task payload, a worker mount or a log line.
package r2dgit

import "errors"

var (
	// ErrUnavailable means a dependency the operation needs is missing or
	// unreachable. It never means the operation succeeded.
	ErrUnavailable = errors.New("git_service_unavailable")
	// ErrScope means the caller asked for something outside its own scope.
	ErrScope = errors.New("git_scope_denied")
	// ErrPrincipal means no authenticated human could be proven for the
	// operation. An audit-only owner is not a principal.
	ErrPrincipal = errors.New("git_principal_unproven")
	// ErrIdentity means the credential exists but is not usable yet — it has
	// not been verified against its provider.
	ErrIdentity = errors.New("git_identity_unverified")
	// ErrConflict means the requested transition conflicts with the stored
	// state, for example a duplicate idempotency key.
	ErrConflict = errors.New("git_identity_conflict")
	// ErrRevoked means the credential was revoked and may no longer be used.
	ErrRevoked = errors.New("git_grant_revoked")
	// ErrProvider means the Git provider could not be reached or did not
	// answer in a way the adapter understands.
	ErrProvider = errors.New("git_provider_unavailable")
	// ErrProviderNotFound means the requested host is missing or disabled.
	// Unlike ErrScope, this is safe to expose when choosing a provider id.
	ErrProviderNotFound = errors.New("git_provider_not_configured")
)
