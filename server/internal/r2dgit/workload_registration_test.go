package r2dgit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"testing"
	"time"
)

func TestWorkloadRegistrationSerializationAndImmutableScope(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{61}, 32))
	registry := &registeredWorkloads{now: func() time.Time { return now }, key: key.Public().(ed25519.PublicKey), entries: map[string]WorkloadEnrollmentRequest{}}
	request := WorkloadEnrollmentRequest{Context: ContextSpec{ID: "context"}, Grant: GrantSpec{Operations: []Operation{Read}, WriteRefs: []string{"refs/heads/task/a"}}, ChannelID: "channel", PolicyDigest: "policy", IssueID: "issue", AssignmentDigest: "assignment", ExpiresAt: now.Add(time.Minute)}
	enrollment := WorkloadEnrollment{Certificate: tls.Certificate{Certificate: [][]byte{[]byte("synthetic-certificate")}}, AcceptanceID: "synthetic-only"}
	bad := request
	bad.ExpiresAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := WorkloadRegistrationBytes(bad, enrollment.Certificate.Certificate[0], enrollment.AcceptanceID); err == nil {
		t.Fatal("invalid time serialized into signature domain")
	}
	enrollment.Signature = ed25519.Sign(key, nil)
	if registry.register(bad, enrollment) == nil {
		t.Fatal("degenerate signature accepted")
	}
	message, err := WorkloadRegistrationBytes(request, enrollment.Certificate.Certificate[0], enrollment.AcceptanceID)
	if err != nil {
		t.Fatal(err)
	}
	enrollment.Signature = ed25519.Sign(key, message)
	if err := registry.register(request, enrollment); err != nil {
		t.Fatal(err)
	}
	request.Grant.Operations[0] = Write
	request.Grant.WriteRefs[0] = "refs/heads/main"
	stored := registry.entries[request.Context.ID]
	if stored.Grant.Operations[0] != Read || stored.Grant.WriteRefs[0] != "refs/heads/task/a" {
		t.Fatal("stored signed grant aliased caller memory")
	}
	if registry.register(stored, enrollment) == nil {
		t.Fatal("registration replay accepted")
	}
}
