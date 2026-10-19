package r2dgit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// CacheDomain describes an authorized data partition, not an authorization
// proof or a filesystem boundary. No checkout/cache adapter may use this key
// before online project AND same-user provider authorization.
type CacheDomain struct {
	UserID, ProjectID, ResourceWorkspaceID, ProviderID, RepositoryID string
	PolicyEpoch, GrantEpoch, CredentialGeneration                    uint64
}

func CachePartition(run RunSecurityContext, grant RepositoryGrant) (string, error) {
	s, g := run.spec, grant.spec
	if !nonempty(s.ID, s.Binding.OriginatorUserID, s.Binding.ProjectID, s.Binding.ResourceWorkspaceID, g.ProviderID, g.RepositoryID) || g.ContextID != s.ID || s.PolicyEpoch == 0 || g.Epoch == 0 || g.CredentialGeneration == 0 {
		return "", ErrScope
	}
	return partition("cache", CacheDomain{UserID: s.Binding.OriginatorUserID, ProjectID: s.Binding.ProjectID, ResourceWorkspaceID: s.Binding.ResourceWorkspaceID, ProviderID: g.ProviderID, RepositoryID: g.RepositoryID, PolicyEpoch: s.PolicyEpoch, GrantEpoch: g.Epoch, CredentialGeneration: g.CredentialGeneration}), nil
}

func SessionPartition(run RunSecurityContext, grant RepositoryGrant) (string, error) {
	cache, err := CachePartition(run, grant)
	if err != nil {
		return "", err
	}
	if !nonempty(run.spec.AttemptID, run.spec.Binding.RuntimeID, run.spec.Binding.ExecutionWorkspaceID) {
		return "", ErrScope
	}
	return partition("session", struct{ Cache, Context, Attempt, Runtime, ExecutionWorkspace string }{cache, run.spec.ID, run.spec.AttemptID, run.spec.Binding.RuntimeID, run.spec.Binding.ExecutionWorkspaceID}), nil
}

func partition(kind string, value any) string {
	b, _ := json.Marshal(value)
	digest := sha256.Sum256(b)
	return kind + "-" + hex.EncodeToString(digest[:])
}
