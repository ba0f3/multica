package r2dgit

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

// ProviderWritePolicy must prove current provider default/protected-branch
// policy, not infer it from an app ref allowlist. Git SSH cannot expose all of
// that metadata. Service intentionally has no implementation yet; writes remain
// unavailable without a separately trusted adapter (synthetic in local tests).
type ProviderWritePolicy interface {
	CheckGitWritePolicy(context.Context, BoundOperation) error
}

func (w *SSHWorker) checkWritePolicy(ctx context.Context, op BoundOperation) error {
	if w == nil || op.Operation != Write || !validWriteRef(op.Ref) {
		return ErrScope
	}
	policy, ok := w.registry.(ProviderWritePolicy)
	if !ok {
		return ErrUnavailable
	}
	if err := policy.CheckGitWritePolicy(ctx, op); err != nil {
		return err
	}
	return w.writeSession(ctx, op, "git-upload-pack", func(_ context.Context, _ *ssh.Session, in io.WriteCloser, r *bufio.Reader) error {
		refs, caps, err := advertisement(r)
		if err != nil {
			return err
		}
		var defaultRef string
		for cap := range caps {
			if strings.HasPrefix(cap, "symref=HEAD:") {
				if defaultRef != "" {
					return ErrScope
				}
				defaultRef = strings.TrimPrefix(cap, "symref=HEAD:")
			}
		}
		if defaultRef == "" || refs[defaultRef] == "" || defaultRef == op.Ref {
			return ErrScope
		}
		_, err = io.WriteString(in, "0000")
		return err
	})
}

// pkt reads protocol v0 only. Delimiter/response-end packets and oversized or
// noncanonical lengths are rejected, rather than guessed as another protocol.
func pkt(r io.Reader) ([]byte, error) {
	var size [4]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return nil, ErrProvider
	}
	for _, c := range size {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return nil, ErrProvider
		}
	}
	n, err := strconv.ParseUint(string(size[:]), 16, 16)
	if err != nil || n > 65520 || n != 0 && n < 5 {
		return nil, ErrProvider
	}
	if n == 0 {
		return nil, nil
	}
	p := make([]byte, n-4)
	if _, err = io.ReadFull(r, p); err != nil {
		return nil, ErrProvider
	}
	return p, nil
}

func writePkt(w io.Writer, line string) error {
	if len(line)+4 > 65520 {
		return ErrScope
	}
	_, err := fmt.Fprintf(w, "%04x%s", len(line)+4, line)
	return err
}

func advertisement(r io.Reader) (map[string]string, map[string]bool, error) {
	refs, caps := map[string]string{}, map[string]bool{}
	total := 0
	for n := 0; n < 16384; n++ {
		p, err := pkt(r)
		if err != nil {
			return nil, nil, err
		}
		if p == nil {
			if n == 0 {
				return nil, nil, ErrProvider
			}
			return refs, caps, nil
		}
		total += len(p)
		if total > 1<<20 {
			return nil, nil, ErrProvider
		}
		line := strings.TrimSuffix(string(p), "\n")
		parts := strings.Split(line, "\x00")
		if n == 0 {
			if len(parts) != 2 || len(parts[1]) > 4096 {
				return nil, nil, ErrProvider
			}
			for _, cap := range strings.Split(parts[1], " ") {
				if cap == "" {
					return nil, nil, ErrProvider
				}
				for _, c := range cap {
					if c <= 32 || c >= 127 {
						return nil, nil, ErrProvider
					}
				}
				if strings.HasPrefix(cap, "object-format=") && cap != "object-format=sha1" {
					return nil, nil, ErrProvider
				}
				caps[cap] = true
			}
		} else if len(parts) != 1 {
			return nil, nil, ErrProvider
		}
		fields := strings.Split(parts[0], " ")
		if len(fields) != 2 || !objectID(fields[0]) || len(fields[1]) > 1024 {
			return nil, nil, ErrProvider
		}
		ref := fields[1]
		for _, c := range ref {
			if c <= 32 || c == 127 {
				return nil, nil, ErrProvider
			}
		}
		if ref != "HEAD" && ref != "capabilities^{}" && !strings.HasPrefix(ref, "refs/") {
			return nil, nil, ErrProvider
		}
		if _, dup := refs[ref]; dup {
			return nil, nil, ErrProvider
		}
		if ref == "capabilities^{}" {
			if n != 0 || fields[0] != zeroObject {
				return nil, nil, ErrProvider
			}
		} else if fields[0] == zeroObject {
			return nil, nil, ErrProvider
		}
		if n > 0 {
			if _, empty := refs["capabilities^{}"]; empty {
				return nil, nil, ErrProvider
			}
		}
		refs[ref] = fields[0]
	}
	return nil, nil, ErrProvider
}

func (w *SSHWorker) writeSession(ctx context.Context, op BoundOperation, service string, fn func(context.Context, *ssh.Session, io.WriteCloser, *bufio.Reader) error) error {
	if op.Operation != Write {
		return ErrScope
	}
	t, err := w.target(ctx, op)
	if err != nil {
		return err
	}
	return w.withClient(ctx, t.Provider, t.SecretRef, t.Fingerprint, func(ctx context.Context, client *ssh.Client) error {
		s, err := client.NewSession()
		if err != nil {
			return ErrProvider
		}
		defer s.Close()
		in, err := s.StdinPipe()
		if err != nil {
			return ErrProvider
		}
		out, err := s.StdoutPipe()
		if err != nil {
			return ErrProvider
		}
		s.Stderr = &boundedBuffer{limit: 4096}
		// service is a worker constant, repository is catalog validated.
		if s.Start(service+" '"+t.Repository+".git'") != nil {
			return ErrProvider
		}
		return fn(ctx, s, in, bufio.NewReader(out))
	})
}

func (w *SSHWorker) WriteReference(ctx context.Context, op BoundOperation) (string, error) {
	if err := w.checkWritePolicy(ctx, op); err != nil {
		return "", err
	}
	old := zeroObject
	err := w.writeSession(ctx, op, "git-receive-pack", func(_ context.Context, _ *ssh.Session, in io.WriteCloser, r *bufio.Reader) error {
		refs, caps, err := advertisement(r)
		if err != nil {
			return err
		}
		if !caps["report-status"] {
			return ErrProvider
		}
		if oid, ok := refs[op.Ref]; ok {
			old = oid
		}
		_, err = io.WriteString(in, "0000")
		return err
	})
	return old, err
}

func (w *SSHWorker) ReadReference(ctx context.Context, op BoundOperation, expected string) ([]byte, error) {
	if !objectID(expected) || expected == zeroObject {
		return nil, ErrScope
	}
	var pack []byte
	err := w.writeSession(ctx, op, "git-upload-pack", func(_ context.Context, s *ssh.Session, in io.WriteCloser, r *bufio.Reader) error {
		refs, _, err := advertisement(r)
		if err != nil {
			return err
		}
		if refs[op.Ref] != expected {
			return ErrRejected
		}
		if writePkt(in, "want "+expected+"\n") != nil {
			return ErrProvider
		}
		if _, err = io.WriteString(in, "00000009done\n"); err != nil {
			return ErrProvider
		}
		if in.Close() != nil {
			return ErrProvider
		}
		p, err := pkt(r)
		if err != nil || string(p) != "NAK\n" {
			return ErrProvider
		}
		pack, err = io.ReadAll(io.LimitReader(r, maxPackBytes+1))
		if err != nil || !packFraming(pack) || s.Wait() != nil {
			return ErrProvider
		}
		return nil
	})
	if err != nil {
		clear(pack)
		return nil, err
	}
	return pack, nil
}

func (w *SSHWorker) Push(ctx context.Context, op BoundOperation, u RefUpdate, pack []byte, authorize func(context.Context) error) error {
	if !u.valid() || op.Ref != u.Ref || op.OldObject != u.Old || op.NewObject != u.New || !packFraming(pack) || authorize == nil {
		return ErrScope
	}
	digest := sha256.Sum256(pack)
	if op.PackDigest != hex.EncodeToString(digest[:]) {
		return ErrScope
	}
	sent := false
	err := w.writeSession(ctx, op, "git-receive-pack", func(ctx context.Context, s *ssh.Session, in io.WriteCloser, r *bufio.Reader) error {
		refs, caps, err := advertisement(r)
		if err != nil {
			return err
		}
		old := zeroObject
		if oid, ok := refs[u.Ref]; ok {
			old = oid
		}
		if old != u.Old || !caps["report-status"] {
			return ErrRejected
		}
		if err = w.checkWritePolicy(ctx, op); err != nil {
			return err
		}
		if err = authorize(ctx); err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ErrRevoked
		}
		// Nothing from the caller's protocol framing/capabilities is forwarded.
		sent = true
		if writePkt(in, u.Old+" "+u.New+" "+u.Ref+"\x00report-status\n") != nil {
			return ErrIndeterminate
		}
		if _, err = io.WriteString(in, "0000"); err != nil {
			return ErrIndeterminate
		}
		if _, err = in.Write(pack); err != nil {
			return ErrIndeterminate
		}
		if in.Close() != nil {
			return ErrIndeterminate
		}
		p, err := pkt(r)
		if err != nil || string(p) != "unpack ok\n" {
			return ErrIndeterminate
		}
		p, err = pkt(r)
		if err != nil || string(p) != "ok "+u.Ref+"\n" {
			return ErrIndeterminate
		}
		p, err = pkt(r)
		if err != nil || p != nil {
			return ErrIndeterminate
		}
		tail, err := io.ReadAll(io.LimitReader(r, 1))
		if err != nil || len(tail) != 0 || s.Wait() != nil {
			return ErrIndeterminate
		}
		return nil
	})
	if err != nil && sent {
		return ErrIndeterminate
	}
	return err
}
