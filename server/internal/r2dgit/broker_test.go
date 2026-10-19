package r2dgit

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type fixtureTransport struct {
	mu                  sync.Mutex
	proofs, reads       []BoundOperation
	deny                bool
	proveHook, readHook func()
}

func (f *fixtureTransport) ProveRepository(_ context.Context, op BoundOperation) error {
	f.mu.Lock()
	f.proofs = append(f.proofs, op)
	f.mu.Unlock()
	if f.proveHook != nil {
		f.proveHook()
	}
	if f.deny {
		return errors.New("provider unavailable or access denied")
	}
	return nil
}
func (f *fixtureTransport) Read(_ context.Context, op BoundOperation) ([]byte, error) {
	f.mu.Lock()
	f.reads = append(f.reads, op)
	f.mu.Unlock()
	if f.readHook != nil {
		f.readHook()
	}
	return []byte("synthetic source for " + op.UserID), nil
}

type fixtureJournal struct {
	mu                      sync.Mutex
	intents                 map[string]BoundOperation
	outcomes                map[string]string
	failBegin, failComplete bool
	beginHook               func()
	completeHook            func()
}

func (f *fixtureJournal) Begin(_ context.Context, id string, op BoundOperation) (bool, error) {
	if f.beginHook != nil {
		f.beginHook()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failBegin {
		return false, errors.New("audit offline")
	}
	if f.intents == nil {
		f.intents = map[string]BoundOperation{}
	}
	if _, ok := f.intents[id]; ok {
		return false, nil
	}
	f.intents[id] = op
	return true, nil
}
func (f *fixtureJournal) Complete(_ context.Context, id, outcome string) error {
	if f.completeHook != nil {
		f.completeHook()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failComplete {
		return errors.New("audit offline")
	}
	if f.outcomes == nil {
		f.outcomes = map[string]string{}
	}
	f.outcomes[id] = outcome
	return nil
}

func brokerFixture(t *testing.T) (Broker, Lease, *fixtureAuthority, *fixtureTransport, *fixtureJournal) {
	t.Helper()
	r, g, a := fixture(t)
	lease, err := IssueLease(context.Background(), Authorizer{a}, r, g, "channel-a", Read, "", fixtureNow, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	transport := &fixtureTransport{}
	journal := &fixtureJournal{}
	return Broker{Authorizer: Authorizer{a}, Transport: transport, Journal: journal, Now: func() time.Time { return fixtureNow }}, lease, a, transport, journal
}

func TestBrokerSameUserProofBeforeEveryCacheRead(t *testing.T) {
	b, l, a, tr, j := brokerFixture(t)
	for _, id := range []string{"cold", "warm"} {
		data, err := b.Read(context.Background(), l, "channel-a", id)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != "synthetic source for human-a" {
			t.Fatalf("wrong source %q", data)
		}
	}
	if len(tr.proofs) != 2 || len(tr.reads) != 2 {
		t.Fatal("warm cache bypassed live provider proof")
	}
	for _, op := range tr.proofs {
		if op.UserID != "human-a" || op.IdentityID != "identity-a" || op.Generation != 2 || op.RepositoryID != "repo-a" || op.AttemptID != "attempt-a" {
			t.Fatalf("wrong bound identity %+v", op)
		}
	}
	if j.outcomes["warm"] != "succeeded" {
		t.Fatal("missing audit outcome")
	}
	a.rights.ProjectRead = false
	if data, err := b.Read(context.Background(), l, "channel-a", "after-revoke"); len(data) != 0 || !errors.Is(err, ErrScope) {
		t.Fatalf("revoked cached read: %q %v", data, err)
	}
	if len(tr.proofs) != 2 || len(tr.reads) != 2 {
		t.Fatal("revoked operation reached provider/cache")
	}
}

func TestBrokerNegativeBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name    string
		change  func(*Broker, *Lease, *fixtureAuthority, *fixtureTransport, *fixtureJournal)
		channel string
		want    error
		reads   int
	}{
		{"wrong channel", func(*Broker, *Lease, *fixtureAuthority, *fixtureTransport, *fixtureJournal) {}, "channel-b", ErrRevoked, 0},
		{"expired lease", func(b *Broker, l *Lease, a *fixtureAuthority, tr *fixtureTransport, j *fixtureJournal) {
			b.Now = func() time.Time { return fixtureNow.Add(time.Minute) }
		}, "channel-a", ErrRevoked, 0},
		{"provider outage", func(b *Broker, l *Lease, a *fixtureAuthority, tr *fixtureTransport, j *fixtureJournal) {
			tr.deny = true
		}, "channel-a", ErrProvider, 0},
		{"audit intent outage", func(b *Broker, l *Lease, a *fixtureAuthority, tr *fixtureTransport, j *fixtureJournal) {
			j.failBegin = true
		}, "channel-a", ErrAudit, 0},
		{"audit outcome outage", func(b *Broker, l *Lease, a *fixtureAuthority, tr *fixtureTransport, j *fixtureJournal) {
			j.failComplete = true
		}, "channel-a", ErrAudit, 1},
		{"offboarded after enqueue", func(b *Broker, l *Lease, a *fixtureAuthority, tr *fixtureTransport, j *fixtureJournal) {
			a.rights.ActiveHuman = false
		}, "channel-a", ErrPrincipal, 0},
		{"key rotation", func(b *Broker, l *Lease, a *fixtureAuthority, tr *fixtureTransport, j *fixtureJournal) {
			a.rights.CredentialGeneration++
		}, "channel-a", ErrRevoked, 0},
		{"revoked during proof", func(b *Broker, l *Lease, a *fixtureAuthority, tr *fixtureTransport, j *fixtureJournal) {
			tr.proveHook = func() { a.rights.RootActive = false }
		}, "channel-a", ErrRevoked, 0},
		{"revoked during data read", func(b *Broker, l *Lease, a *fixtureAuthority, tr *fixtureTransport, j *fixtureJournal) {
			tr.readHook = func() { a.rights.GrantActive = false }
		}, "channel-a", ErrRevoked, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, l, a, tr, j := brokerFixture(t)
			tc.change(&b, &l, a, tr, j)
			data, err := b.Read(context.Background(), l, tc.channel, "op")
			if len(data) != 0 || !errors.Is(err, tc.want) {
				t.Fatalf("got %q %v, want no data + %v", data, err, tc.want)
			}
			if len(tr.reads) != tc.reads {
				t.Fatalf("data reads = %d, want %d", len(tr.reads), tc.reads)
			}
		})
	}
}

func TestLeaseExpiresDuringProviderOrAudit(t *testing.T) {
	for _, phase := range []string{"proof", "audit"} {
		t.Run(phase, func(t *testing.T) {
			b, l, _, tr, j := brokerFixture(t)
			now := fixtureNow
			b.Now = func() time.Time { return now }
			expire := func() { now = fixtureNow.Add(time.Minute) }
			if phase == "proof" {
				tr.proveHook = expire
			} else {
				j.beginHook = expire
			}
			if data, err := b.Read(context.Background(), l, "channel-a", "op"); len(data) != 0 || !errors.Is(err, ErrRevoked) {
				t.Fatalf("expired lease: %q %v", data, err)
			}
			if len(tr.reads) != 0 {
				t.Fatal("lease expired before data access but transport read ran")
			}
		})
	}
}

func TestLeaseExpiryAcrossBlockingAuthorizationAndDelivery(t *testing.T) {
	for _, phase := range []string{"initial authorization", "pre-read authorization", "delivery authorization", "audit completion"} {
		t.Run(phase, func(t *testing.T) {
			b, l, a, tr, j := brokerFixture(t)
			now := fixtureNow
			b.Now = func() time.Time { return now }
			startCalls := a.calls
			if phase == "audit completion" {
				j.completeHook = func() { now = l.expires }
			} else {
				call := map[string]int{"initial authorization": 1, "pre-read authorization": 2, "delivery authorization": 4}[phase]
				a.hook = func(n int) {
					if n == startCalls+call {
						now = l.expires
					}
				}
			}
			data, err := b.Read(context.Background(), l, "channel-a", "delayed")
			if len(data) != 0 || !errors.Is(err, ErrRevoked) {
				t.Fatalf("delayed boundary delivered source: %q %v", data, err)
			}
			if (phase == "initial authorization" || phase == "pre-read authorization") && len(tr.reads) != 0 {
				t.Fatal("expired lease reached cache read")
			}
		})
	}
}

func TestLeaseOperationBindingAndTTL(t *testing.T) {
	r, g, a := fixture(t)
	for _, ttl := range []time.Duration{0, -time.Second, MaxLeaseTTL + time.Nanosecond} {
		if _, err := IssueLease(context.Background(), Authorizer{a}, r, g, "channel-a", Read, "", fixtureNow, ttl); err == nil {
			t.Fatal("unsafe lease TTL accepted", ttl)
		}
	}
	writeLease, err := IssueLease(context.Background(), Authorizer{a}, r, g, "channel-a", Write, "refs/heads/task/a", fixtureNow, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	b, _, _, tr, _ := brokerFixture(t)
	if _, err := b.Read(context.Background(), writeLease, "channel-a", "read-with-write-lease"); !errors.Is(err, ErrScope) {
		t.Fatal("write lease used for read", err)
	}
	if len(tr.proofs) != 0 {
		t.Fatal("wrong operation reached provider")
	}
	if err := b.Write(context.Background(), writeLease, "channel-a", "write", RefUpdate{}, nil); !errors.Is(err, ErrUnavailable) {
		t.Fatal("unsupported push enabled", err)
	}
}

func TestOperationIntentPreventsBlindReplay(t *testing.T) {
	b, l, _, tr, _ := brokerFixture(t)
	if _, err := b.Read(context.Background(), l, "channel-a", "same-op"); err != nil {
		t.Fatal(err)
	}
	if data, err := b.Read(context.Background(), l, "channel-a", "same-op"); len(data) != 0 || !errors.Is(err, ErrIndeterminate) {
		t.Fatalf("duplicate replay: %q %v", data, err)
	}
	if len(tr.reads) != 1 {
		t.Fatal("duplicate read replayed")
	}
}

func TestConcurrentHumansShareAgentWithoutIdentityOrSessionReuse(t *testing.T) {
	b, l, _, tr, j := brokerFixture(t)
	r, g, a := fixture(t)
	binding := r.Spec().Binding
	binding.OriginatorUserID = "human-b"
	rb, err := NewHumanRoot("context-b", "attempt-b", "human-b", binding, 7, fixtureNow, fixtureNow.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	gs := g.Spec()
	gs.ID = "grant-b"
	gs.ContextID = "context-b"
	gs.IdentityID = "identity-b"
	gb, err := NewGrant(rb, gs, fixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	a.rights.Binding = binding
	a.rights.IdentityID = "identity-b"
	lb, err := IssueLease(context.Background(), Authorizer{a}, rb, gb, "channel-a", Read, "", fixtureNow, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	bb := Broker{Authorizer: Authorizer{a}, Transport: tr, Journal: j, Now: b.Now}
	var wg sync.WaitGroup
	for _, job := range []struct {
		broker   Broker
		lease    Lease
		id, user string
	}{{b, l, "op-a", "human-a"}, {bb, lb, "op-b", "human-b"}} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			data, err := job.broker.Read(context.Background(), job.lease, "channel-a", job.id)
			if err != nil || string(data) != "synthetic source for "+job.user {
				t.Errorf("cross-human data/identity: %q %v", data, err)
			}
		}()
	}
	wg.Wait()
	pa, _ := SessionPartition(l.run, l.grant)
	pb, _ := SessionPartition(lb.run, lb.grant)
	if pa == pb {
		t.Fatal("native sessions shared across humans")
	}
}
