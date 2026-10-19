package r2dgit

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

var fixtureNow = time.Date(2026, 10, 15, 20, 0, 0, 0, time.UTC)

type fixtureAuthority struct {
	rights CurrentRights
	err    error
	calls  int
	hook   func(int)
}

func (f *fixtureAuthority) Current(context.Context, ContextSpec, GrantSpec) (CurrentRights, error) {
	f.calls++
	if f.hook != nil {
		f.hook(f.calls)
	}
	return f.rights, f.err
}

func fixture(t *testing.T) (RunSecurityContext, RepositoryGrant, *fixtureAuthority) {
	t.Helper()
	b := TaskBinding{TaskID: "task-a", AgentID: "admin-owned-agent", RuntimeID: "runner-a", ExecutionWorkspaceID: "team-a", ResourceWorkspaceID: "team-b", ProjectID: "shared-project", OriginatorUserID: "human-a", OriginatorSource: "direct_human"}
	r, err := NewHumanRoot("context-a", "attempt-a", "human-a", b, 7, fixtureNow, fixtureNow.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	g, err := NewGrant(r, GrantSpec{ID: "grant-a", ContextID: "context-a", ProviderID: "provider-a", RepositoryID: "repo-a", IdentityID: "identity-a", CredentialGeneration: 2, Epoch: 3, Operations: []Operation{Read, Write}, WriteRefs: []string{"refs/heads/task/a"}, IssuedAt: fixtureNow, ExpiresAt: fixtureNow.Add(time.Hour)}, fixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	a := &fixtureAuthority{rights: CurrentRights{Binding: b, ActiveHuman: true, ProjectRead: true, ProjectContribute: true, RepositoryRead: true, RepositoryWrite: true, ContextActive: true, RootActive: true, GrantActive: true, IdentityReady: true, PolicyEpoch: 7, GrantEpoch: 3, CredentialGeneration: 2, ProviderID: "provider-a", RepositoryID: "repo-a", IdentityID: "identity-a", AllowedWriteRefs: []string{"refs/heads/task/a"}, Runtime: RuntimeEvidence{RuntimeID: "runner-a", ChannelID: "channel-a", Capabilities: []string{Capability}, OperatorApproved: true, Isolated: true}}}
	return r, g, a
}

func TestCurrentAuthorizationMatrix(t *testing.T) {
	tests := []struct {
		name   string
		change func(*CurrentRights)
		want   error
	}{
		{"explicit cross-workspace grant", func(*CurrentRights) {}, nil},
		{"offboarded human", func(c *CurrentRights) { c.ActiveHuman = false }, ErrPrincipal},
		{"substituted originator", func(c *CurrentRights) { c.Binding.OriginatorUserID = "admin" }, ErrPrincipal},
		{"substituted agent", func(c *CurrentRights) { c.Binding.AgentID = "foreign-agent" }, ErrPrincipal},
		{"foreign project", func(c *CurrentRights) { c.Binding.ProjectID = "foreign" }, ErrPrincipal},
		{"foreign resource workspace", func(c *CurrentRights) { c.Binding.ResourceWorkspaceID = "foreign" }, ErrPrincipal},
		{"no project permission", func(c *CurrentRights) { c.ProjectRead = false }, ErrScope},
		{"project read is not write", func(c *CurrentRights) { c.ProjectContribute = false }, ErrScope},
		{"provider repo denied", func(c *CurrentRights) { c.RepositoryRead = false }, ErrScope},
		{"provider write denied", func(c *CurrentRights) { c.RepositoryWrite = false }, ErrScope},
		{"foreign repo", func(c *CurrentRights) { c.RepositoryID = "foreign" }, ErrScope},
		{"foreign provider", func(c *CurrentRights) { c.ProviderID = "foreign" }, ErrScope},
		{"foreign identity", func(c *CurrentRights) { c.IdentityID = "identity-b" }, ErrScope},
		{"policy changed", func(c *CurrentRights) { c.PolicyEpoch++ }, ErrRevoked},
		{"grant changed", func(c *CurrentRights) { c.GrantEpoch++ }, ErrRevoked},
		{"key rotated", func(c *CurrentRights) { c.CredentialGeneration++ }, ErrRevoked},
		{"unverified key", func(c *CurrentRights) { c.IdentityReady = false }, ErrRevoked},
		{"cancelled root", func(c *CurrentRights) { c.RootActive = false }, ErrRevoked},
		{"inactive context", func(c *CurrentRights) { c.ContextActive = false }, ErrRevoked},
		{"revoked grant", func(c *CurrentRights) { c.GrantActive = false }, ErrRevoked},
		{"ref removed", func(c *CurrentRights) { c.AllowedWriteRefs = nil }, ErrScope},
		{"old daemon", func(c *CurrentRights) { c.Runtime.Capabilities = nil }, ErrRuntime},
		{"unapproved runtime", func(c *CurrentRights) { c.Runtime.OperatorApproved = false }, ErrRuntime},
		{"unsandboxed runtime", func(c *CurrentRights) { c.Runtime.Isolated = false }, ErrRuntime},
		{"wrong runner", func(c *CurrentRights) { c.Runtime.ChannelID = "channel-b" }, ErrRuntime},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, g, a := fixture(t)
			tc.change(&a.rights)
			err := (Authorizer{a}).Authorize(context.Background(), r, g, "channel-a", Write, "refs/heads/task/a", fixtureNow)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestNoFallbackPrincipalOrAutomationRoot(t *testing.T) {
	r, _, _ := fixture(t)
	for _, source := range []string{"", "owner_fallback", "backfill", "rule_owner", "trigger_owner", "unattributed", "delegation", "comment_source"} {
		t.Run(source, func(t *testing.T) {
			b := r.Spec().Binding
			b.OriginatorSource = source
			if _, err := NewHumanRoot("id", "attempt", "human-a", b, 7, fixtureNow, fixtureNow.Add(time.Hour)); !errors.Is(err, ErrPrincipal) {
				t.Fatalf("accepted %q: %v", source, err)
			}
		})
	}
	for _, human := range []string{"", "admin-owner", "human-b"} {
		if _, err := NewHumanRoot("id", "attempt", human, r.Spec().Binding, 7, fixtureNow, fixtureNow.Add(time.Hour)); !errors.Is(err, ErrPrincipal) {
			t.Fatalf("accepted human %q: %v", human, err)
		}
	}
	b := r.Spec().Binding
	b.OriginatorUserID = ""
	if _, err := NewHumanRoot("id", "attempt", "human-a", b, 7, fixtureNow, fixtureNow.Add(time.Hour)); err == nil {
		t.Fatal("null originator accepted")
	}
}

func TestSealedContextAndGrant(t *testing.T) {
	r, g, a := fixture(t)
	s := r.Spec()
	s.Binding.OriginatorUserID = "admin"
	gs := g.Spec()
	gs.Operations[0] = Write
	gs.WriteRefs[0] = "refs/heads/main"
	if r.Spec().Binding.OriginatorUserID != "human-a" || g.Spec().WriteRefs[0] != "refs/heads/task/a" {
		t.Fatal("caller mutated sealed values")
	}
	if err := (Authorizer{a}).Authorize(context.Background(), r, g, "channel-a", Read, "", fixtureNow); err != nil {
		t.Fatal(err)
	}
	a.rights.ProjectRead = false
	if err := (Authorizer{a}).Authorize(context.Background(), r, g, "channel-a", Read, "", fixtureNow); !errors.Is(err, ErrScope) {
		t.Fatal("cached grant bypassed current permission", err)
	}
	a.err = errors.New("db offline")
	if err := (Authorizer{a}).Authorize(context.Background(), r, g, "channel-a", Read, "", fixtureNow); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	if err := (Authorizer{}).Authorize(context.Background(), r, g, "channel-a", Read, "", fixtureNow); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := (Authorizer{a}).Authorize(cancelled, r, g, "channel-a", Read, "", fixtureNow); !errors.Is(err, ErrUnavailable) {
		t.Fatal("cancelled request authorized", err)
	}
}

func TestExplicitGrantAndExpiry(t *testing.T) {
	r, g, a := fixture(t)
	for _, tc := range []struct {
		g   RepositoryGrant
		op  Operation
		ref string
		now time.Time
	}{
		{RepositoryGrant{}, Read, "", fixtureNow},
		{g, Operation("clone-anywhere"), "", fixtureNow},
		{g, Write, "refs/heads/main", fixtureNow},
		{g, Read, "refs/heads/task/a", fixtureNow},
		{g, Read, "", fixtureNow.Add(time.Hour)},
		{g, Read, "", fixtureNow.Add(-time.Second)},
	} {
		if err := (Authorizer{a}).Authorize(context.Background(), r, tc.g, "channel-a", tc.op, tc.ref, tc.now); err == nil {
			t.Fatalf("accepted %+v", tc)
		}
	}
	for _, ref := range []string{"refs/heads/main", "refs/tags/v1", "refs/heads/task/*", "refs/heads/task/a..b", "refs/heads/task/.a", "refs/heads/task/a.lock", "refs/heads/task/a@{b", "refs/heads/task/a\nb", "refs/heads/task/", "refs/heads/task/a//b"} {
		s := g.Spec()
		s.WriteRefs = []string{ref}
		if _, err := NewGrant(r, s, fixtureNow); err == nil {
			t.Fatalf("accepted ref %q", ref)
		}
	}
}

func TestDelegationRetryAndNarrowing(t *testing.T) {
	r, g, a := fixture(t)
	b := r.Spec().Binding
	b.TaskID = "child"
	b.AgentID = "another-admin-agent"
	b.ParentTaskID = r.Spec().Binding.TaskID
	b.OriginatorSource = "delegation"
	child, err := Derive(r, "child-context", "child-attempt", b, Delegation, fixtureNow, fixtureNow.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	s := g.Spec()
	s.ID = "child-grant"
	s.ContextID = child.Spec().ID
	s.Operations = []Operation{Read}
	s.WriteRefs = nil
	s.ExpiresAt = fixtureNow.Add(time.Minute)
	cg, err := NarrowGrant(g, child, s, fixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewGrant(child, s, fixtureNow); !errors.Is(err, ErrScope) {
		t.Fatal("child bypassed parent grant narrowing", err)
	}
	a.rights.Binding = b
	if err := (Authorizer{a}).Authorize(context.Background(), child, cg, "channel-a", Read, "", fixtureNow); err != nil {
		t.Fatal(err)
	}
	// A completed parent's context need not be active in the current child
	// snapshot, but root cancellation must still invalidate the child.
	a.rights.RootActive = false
	if err := (Authorizer{a}).Authorize(context.Background(), child, cg, "channel-a", Read, "", fixtureNow); !errors.Is(err, ErrRevoked) {
		t.Fatal(err)
	}
	s.Operations = []Operation{Write}
	s.WriteRefs = []string{"refs/heads/task/other"}
	if _, err := NarrowGrant(g, child, s, fixtureNow); err == nil {
		t.Fatal("child widened refs")
	}
	b.OriginatorUserID = "human-b"
	if _, err := Derive(r, "new", "new-attempt", b, Delegation, fixtureNow, fixtureNow.Add(time.Minute)); err == nil {
		t.Fatal("child changed principal")
	}
	if _, err := Derive(r, "retry", "retry-attempt", r.Spec().Binding, Retry, fixtureNow, fixtureNow.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := Derive(r, "retry", r.Spec().AttemptID, r.Spec().Binding, Retry, fixtureNow, fixtureNow.Add(time.Minute)); err == nil {
		t.Fatal("attempt replay accepted")
	}
}

func TestLineageCyclesAndDepth(t *testing.T) {
	r, _, _ := fixture(t)
	for depth := 1; depth <= MaxDelegationDepth; depth++ {
		b := r.Spec().Binding
		b.ParentTaskID = b.TaskID
		b.TaskID = fmt.Sprintf("task-%d", depth)
		b.OriginatorSource = "delegation"
		next, err := Derive(r, fmt.Sprintf("context-%d", depth), fmt.Sprintf("attempt-%d", depth), b, Delegation, fixtureNow, fixtureNow.Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if depth > 2 {
			if _, err := Derive(r, "context-1", "different-attempt", b, Delegation, fixtureNow, fixtureNow.Add(time.Minute)); err == nil {
				t.Fatal("ancestor cycle accepted")
			}
			cycle := b
			cycle.TaskID = "task-a"
			if _, err := Derive(r, "fresh-context", "fresh-attempt", cycle, Delegation, fixtureNow, fixtureNow.Add(time.Minute)); !errors.Is(err, ErrPrincipal) {
				t.Fatal("ancestor task cycle accepted", err)
			}
		}
		r = next
	}
	b := r.Spec().Binding
	b.ParentTaskID = b.TaskID
	b.TaskID = "too-deep"
	if _, err := Derive(r, "too-deep", "too-deep", b, Delegation, fixtureNow, fixtureNow.Add(time.Minute)); err == nil {
		t.Fatal("depth overflow accepted")
	}
}
