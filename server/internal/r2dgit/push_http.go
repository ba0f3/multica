package r2dgit

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

// WorkloadChannel must authenticate a channel outside the workload and return
// its server-held lease. Headers, URLs and client JSON are not identity proof.
// No production implementation or route is installed until S4/S6 certification.
type WorkloadChannel interface {
	Authenticate(*http.Request) (Lease, string, error)
}

// PushHandler is a deliberately limited smart HTTP v0 service: one exact ref,
// SHA-1, no deletes, options, certificates, shallow graphs or other services.
// The URL does not choose a repository; the authenticated lease already did.
type PushHandler struct {
	Broker  Broker
	Channel WorkloadChannel
}

func writeOperationID(b Broker, l Lease, u RefUpdate) string {
	op := b.writeOperation(l)
	op.OldObject, op.NewObject = u.Old, u.New
	// Object IDs bind content. A repacked equivalent request must not obtain a
	// new mutation ID after a lost response; framing and pack encoding are absent.
	raw, _ := json.Marshal(op)
	sum := sha256.Sum256(raw)
	return "git-write-" + hex.EncodeToString(sum[:])
}

func parsePush(r io.Reader) (RefUpdate, []byte, error) {
	br := bufio.NewReader(r)
	p, err := pkt(br)
	if err != nil || len(p) == 0 || len(p) > 1024 {
		return RefUpdate{}, nil, ErrScope
	}
	line := strings.TrimSuffix(string(p), "\n")
	parts := strings.Split(line, "\x00")
	if len(parts) != 2 {
		return RefUpdate{}, nil, ErrScope
	}
	fields := strings.Split(parts[0], " ")
	if len(fields) != 3 {
		return RefUpdate{}, nil, ErrScope
	}
	u := RefUpdate{Old: fields[0], New: fields[1], Ref: fields[2]}
	if !u.valid() {
		return RefUpdate{}, nil, ErrScope
	}
	caps := map[string]bool{}
	// send-pack may put a space immediately after NUL. Only ASCII spaces
	// separate capabilities; tabs/newlines and protocol extensions still deny.
	for _, c := range parts[1] {
		if c != ' ' && (c < 33 || c > 126) {
			return RefUpdate{}, nil, ErrScope
		}
	}
	for _, cap := range strings.Fields(parts[1]) {
		if caps[cap] || cap != "report-status" && cap != "ofs-delta" && cap != "object-format=sha1" {
			return RefUpdate{}, nil, ErrScope
		}
		caps[cap] = true
	}
	if !caps["report-status"] {
		return RefUpdate{}, nil, ErrScope
	}
	p, err = pkt(br)
	if err != nil || p != nil {
		return RefUpdate{}, nil, ErrScope
	}
	pack, err := io.ReadAll(io.LimitReader(br, maxPackBytes+1))
	if err != nil || !packFraming(pack) {
		clear(pack)
		return RefUpdate{}, nil, ErrScope
	}
	return u, pack, nil
}

func (h PushHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	control := http.NewResponseController(w)
	fail := func() {
		_ = control.SetWriteDeadline(time.Now().Add(time.Second))
		http.Error(w, "git operation unavailable", http.StatusForbidden)
	}
	if h.Channel == nil || r.Header.Get("Git-Protocol") != "" || r.Header.Get("Content-Encoding") != "" {
		fail()
		return
	}
	l, channel, err := h.Channel.Authenticate(r)
	if err != nil {
		fail()
		return
	}
	if l.operation != Write || !validWriteRef(l.ref) {
		fail()
		return
	}
	if control.SetWriteDeadline(time.Time{}) != nil {
		fail()
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/info/refs" && r.URL.RawQuery == "service=git-receive-pack":
		old, err := h.Broker.WriteAdvertisement(ctx, l, channel, uuid.NewString())
		if err != nil {
			fail()
			return
		}
		// Start the delivery deadline after provider/policy/audit work.
		if control.SetWriteDeadline(time.Now().Add(time.Second)) != nil {
			fail()
			return
		}
		w.Header().Set("Content-Type", "application/x-git-receive-pack-advertisement")
		_ = writePkt(w, "# service=git-receive-pack\n")
		_, _ = io.WriteString(w, "0000")
		ref := l.ref
		if old == zeroObject {
			ref = "capabilities^{}"
		}
		_ = writePkt(w, old+" "+ref+"\x00report-status ofs-delta object-format=sha1\n")
		_, _ = io.WriteString(w, "0000")
	case r.Method == http.MethodPost && r.URL.Path == "/git-receive-pack" && r.URL.RawQuery == "" && r.Header.Get("Content-Type") == "application/x-git-receive-pack-request":
		if control.SetReadDeadline(time.Now().Add(5*time.Second)) != nil {
			fail()
			return
		}
		u, pack, err := parsePush(http.MaxBytesReader(w, r.Body, maxPackBytes+2048))
		defer clear(pack)
		if err != nil {
			fail()
			return
		}
		if control.SetReadDeadline(time.Time{}) != nil {
			fail()
			return
		}
		if err = h.Broker.Write(ctx, l, channel, writeOperationID(h.Broker, l, u), u, pack); err != nil {
			fail()
			return
		}
		if control.SetWriteDeadline(time.Now().Add(time.Second)) != nil {
			fail()
			return
		}
		w.Header().Set("Content-Type", "application/x-git-receive-pack-result")
		_ = writePkt(w, "unpack ok\n")
		_ = writePkt(w, "ok "+u.Ref+"\n")
		_, _ = io.WriteString(w, "0000")
	default:
		fail()
	}
}
