//go:build linux

package r2dgit

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

type workloadAuditDB struct {
	Database
	details outputDeliveryDetails
	action  string
}

func (d *workloadAuditDB) Exec(_ context.Context, _ string, args ...any) (pgconn.CommandTag, error) {
	d.action = args[3].(string)
	if err := json.Unmarshal(args[4].([]byte), &d.details); err != nil {
		return pgconn.CommandTag{}, err
	}
	return pgconn.NewCommandTag("INSERT 0 1"), nil
}

type workloadPartialWriter struct {
	header                http.Header
	partial, flushFailure bool
	accepted              int
	afterWrite            func()
}

func (w *workloadPartialWriter) Header() http.Header            { return w.header }
func (*workloadPartialWriter) WriteHeader(int)                  {}
func (*workloadPartialWriter) SetWriteDeadline(time.Time) error { return nil }
func (w *workloadPartialWriter) Write(body []byte) (int, error) {
	n := len(body)
	if w.partial {
		n = 7
	}
	w.accepted += n
	if w.afterWrite != nil {
		w.afterWrite()
	}
	if w.partial {
		return n, io.ErrShortWrite
	}
	return n, nil
}
func (w *workloadPartialWriter) FlushError() error {
	if w.flushFailure {
		return io.ErrClosedPipe
	}
	return nil
}

func TestWorkloadSnapshotPartialAccountingAndChunkRevocation(t *testing.T) {
	for _, mode := range []string{"partial", "flush-failure", "revoked-after-first-chunk"} {
		t.Run(mode, func(t *testing.T) {
			run, grant, authority := fixture(t)
			now := func() time.Time { return fixtureNow }
			channels := NewWorkloadChannels(Authorizer{authority}, now)
			_, cert := workloadPair(t, 31)
			lease, err := IssueLease(context.Background(), Authorizer{authority}, run, grant, "channel-a", Read, "", fixtureNow, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			if err := channels.register(cert, lease, context.Background()); err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest("GET", "https://broker/snapshot", nil)
			r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
			db := &workloadAuditDB{}
			app := &WorkloadApplication{channels: channels, service: &Service{Store: &Store{DB: db}, Now: now}}
			writer := &workloadPartialWriter{header: make(http.Header), partial: mode == "partial", flushFailure: mode == "flush-failure"}
			if mode == "revoked-after-first-chunk" {
				writer.afterWrite = func() { authority.rights.ProjectRead = false }
			}
			err = app.deliverSnapshot(context.Background(), lease, "channel-a", RepositorySnapshot{Head: strings.Repeat("a", 40), Pack: make([]byte, 2*outputChunkSize)}, writer, http.NewResponseController(writer), r)
			if err == nil || db.action != "restricted_source_delivery_aborted" || db.details.AcceptedBytes != writer.accepted {
				t.Fatalf("partial delivery undercount: err=%v action=%s audit=%d actual=%d", err, db.action, db.details.AcceptedBytes, writer.accepted)
			}
			if mode == "revoked-after-first-chunk" && writer.accepted != outputChunkSize {
				t.Fatal("bytes written after chunk revocation")
			}
			if mode != "revoked-after-first-chunk" {
				writer.accepted = 0
				err = app.deliverAssignment(context.Background(), lease, []byte(`{"title":"synthetic assignment","description":"private"}`), writer, http.NewResponseController(writer), r)
				if err == nil || db.action != "restricted_assignment_delivery_aborted" || db.details.AcceptedBytes != writer.accepted {
					t.Fatalf("assignment partial accounting: err=%v action=%s audit=%d actual=%d", err, db.action, db.details.AcceptedBytes, writer.accepted)
				}
			}
		})
	}
}

func TestWorkloadModelJSONPartialAccountingAndChunkRevocation(t *testing.T) {
	for _, mode := range []string{"partial", "flush-failure", "revoked-after-first-chunk"} {
		t.Run(mode, func(t *testing.T) {
			run, grant, authority := fixture(t)
			now := func() time.Time { return fixtureNow }
			channels := NewWorkloadChannels(Authorizer{authority}, now)
			_, cert := workloadPair(t, 32)
			lease, err := IssueLease(context.Background(), Authorizer{authority}, run, grant, "channel-a", Read, "", fixtureNow, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			if err := channels.register(cert, lease, context.Background()); err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest("POST", "https://broker/model", nil)
			r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
			db := &workloadAuditDB{}
			app := &WorkloadApplication{channels: channels, service: &Service{Store: &Store{DB: db}, Now: now}}
			writer := &workloadPartialWriter{header: make(http.Header), partial: mode == "partial", flushFailure: mode == "flush-failure"}
			if mode == "revoked-after-first-chunk" {
				writer.afterWrite = func() { authority.rights.ProjectRead = false }
			}
			err = app.deliverSourceJSON(context.Background(), lease, []byte(strings.Repeat("s", 2*outputChunkSize)), writer, http.NewResponseController(writer), r, "model")
			if err == nil || db.action != "restricted_model_delivery_aborted" || db.details.AcceptedBytes != writer.accepted {
				t.Fatalf("model delivery audit mismatch: %v %s %d %d", err, db.action, db.details.AcceptedBytes, writer.accepted)
			}
			if mode == "revoked-after-first-chunk" && writer.accepted != outputChunkSize {
				t.Fatal("model bytes delivered after revocation")
			}
		})
	}
}

func TestWorkloadMalformedStalledJSONRetainsReadDeadline(t *testing.T) {
	done := make(chan time.Duration, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		var out struct {
			Kind string `json:"kind"`
		}
		err := workloadJSON(w, r, http.NewResponseController(w), &out)
		if err == nil {
			t.Error("malformed JSON accepted")
		}
		http.Error(w, "denied", 403)
		done <- time.Since(started)
	}))
	defer server.Close()
	conn, err := net.Dial("tcp", strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = io.WriteString(conn, "POST /outputs HTTP/1.1\r\nHost: fixture\r\nContent-Length: 1024\r\nContent-Type: application/json\r\n\r\n!")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = http.ReadResponse(bufio.NewReader(conn), nil)
	select {
	case elapsed := <-done:
		if elapsed > 2500*time.Millisecond {
			t.Fatalf("malformed-body drain exceeded read budget: %s", elapsed)
		}
	case <-time.After(time.Second):
		t.Fatal("handler blocked draining malformed body")
	}
}
