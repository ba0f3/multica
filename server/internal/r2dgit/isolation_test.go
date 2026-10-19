package r2dgit

import "testing"

func TestCacheAndNativeSessionPartitions(t *testing.T) {
	r, g, _ := fixture(t)
	cache, err := CachePartition(r, g)
	if err != nil {
		t.Fatal(err)
	}
	session, err := SessionPartition(r, g)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*RunSecurityContext, *RepositoryGrant){
		func(r *RunSecurityContext, g *RepositoryGrant) { r.spec.Binding.OriginatorUserID = "human-b" },
		func(r *RunSecurityContext, g *RepositoryGrant) { r.spec.Binding.ProjectID = "project-b" },
		func(r *RunSecurityContext, g *RepositoryGrant) { r.spec.Binding.ResourceWorkspaceID = "team-c" },
		func(r *RunSecurityContext, g *RepositoryGrant) { g.spec.ProviderID = "provider-b" },
		func(r *RunSecurityContext, g *RepositoryGrant) { g.spec.RepositoryID = "repo-b" },
		func(r *RunSecurityContext, g *RepositoryGrant) { r.spec.PolicyEpoch++ },
		func(r *RunSecurityContext, g *RepositoryGrant) { g.spec.Epoch++ },
		func(r *RunSecurityContext, g *RepositoryGrant) { g.spec.CredentialGeneration++ },
	} {
		rr, gg := r, g
		change(&rr, &gg)
		other, _ := CachePartition(rr, gg)
		if other == cache {
			t.Fatal("security domains shared cache")
		}
	}
	for _, change := range []func(*RunSecurityContext){func(r *RunSecurityContext) { r.spec.ID = "new-context" }, func(r *RunSecurityContext) { r.spec.AttemptID = "retry" }, func(r *RunSecurityContext) { r.spec.Binding.RuntimeID = "runner-b" }, func(r *RunSecurityContext) { r.spec.Binding.ExecutionWorkspaceID = "team-c" }} {
		rr, gg := r, g
		change(&rr)
		gg.spec.ContextID = rr.spec.ID
		other, _ := SessionPartition(rr, gg)
		if other == session {
			t.Fatal("session reused across run/attempt/runtime")
		}
	}
	if _, err := CachePartition(RunSecurityContext{}, RepositoryGrant{}); err == nil {
		t.Fatal("empty security domain accepted")
	}
}
