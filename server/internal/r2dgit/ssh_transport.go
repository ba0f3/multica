package r2dgit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// SigningCustody exposes keys only inside the trusted worker callback. Neither
// a runner nor a transport subprocess receives a private-key file or agent socket.
type SigningCustody interface {
	WithSigner(context.Context, string, func(ssh.Signer) error) error
}

type EncryptedCustody interface {
	KeyCustody
	SigningCustody
}

type TransportTarget struct {
	Provider                           Provider
	Repository, SecretRef, Fingerprint string
}

type TransportRegistry interface {
	ResolveGitOperation(context.Context, BoundOperation) (TransportTarget, error)
}

type VerificationRegistry interface {
	ResolveGitVerification(context.Context, string, string, uint64, string) (string, error)
}

type PackValidator interface {
	Validate(context.Context, []byte, string) error
}

// SSHWorker uses only operator-supplied address rules and catalog authorities.
// It has no ambient SSH config, forwarding, multiplexing, password or agent auth.
// Constructing it does not enable any runner capability.
type SSHWorker struct {
	registry  TransportRegistry
	custody   SigningCustody
	addresses map[string][]netip.Prefix
	validator PackValidator
}

func NewSSHWorker(registry TransportRegistry, custody SigningCustody, addresses map[string][]netip.Prefix, validator PackValidator) (*SSHWorker, error) {
	if custody == nil || len(addresses) == 0 {
		return nil, ErrUnavailable
	}
	w := &SSHWorker{registry: registry, custody: custody, validator: validator, addresses: map[string][]netip.Prefix{}}
	for id, rules := range addresses {
		if !nonempty(id) || len(rules) == 0 {
			return nil, ErrScope
		}
		for _, rule := range rules {
			if !rule.IsValid() || rule.Bits() == 0 {
				return nil, ErrScope
			}
		}
		w.addresses[id] = append([]netip.Prefix(nil), rules...)
	}
	return w, nil
}

func (w *SSHWorker) withClient(ctx context.Context, p Provider, ref, fingerprint string, fn func(context.Context, *ssh.Client) error) error {
	if w == nil || w.custody == nil || !nonempty(p.ID, p.Host, ref) || p.Port < 1 || p.Port > 65535 || len(p.HostPins) == 0 || strings.ContainsAny(p.Host, "/@\\ \t\r\n") {
		return ErrProvider
	}
	rules := w.addresses[p.ID]
	if len(rules) == 0 {
		return ErrProvider
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", p.Host)
	if err != nil || len(ips) == 0 {
		return ErrProvider
	}
	for _, ip := range ips {
		allowed := false
		for _, rule := range rules {
			if rule.Contains(ip.Unmap()) {
				allowed = true
			}
		}
		if !allowed {
			return ErrProvider
		}
	}
	return w.custody.WithSigner(ctx, ref, func(signer ssh.Signer) error {
		if signer == nil || signer.PublicKey().Type() != ssh.KeyAlgoED25519 || (fingerprint != "" && ssh.FingerprintSHA256(signer.PublicKey()) != fingerprint) {
			return ErrIdentity
		}
		cfg := &ssh.ClientConfig{User: "git", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyAlgorithms: []string{ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512}, HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			pin := ssh.FingerprintSHA256(key)
			for _, allowed := range p.HostPins {
				if pin == allowed {
					return nil
				}
			}
			return ErrProvider
		}}
		address := net.JoinHostPort(ips[0].String(), strconv.Itoa(p.Port))
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
		if err != nil {
			return ErrProvider
		}
		defer conn.Close()
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		defer stop()
		c, ch, req, err := ssh.NewClientConn(conn, net.JoinHostPort(p.Host, strconv.Itoa(p.Port)), cfg)
		if err != nil {
			return ErrProvider
		}
		client := ssh.NewClient(c, ch, req)
		defer client.Close()
		if err := fn(ctx, client); err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ErrProvider
		}
		return nil
	})
}

type boundedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		return 0, ErrProvider
	}
	return b.Buffer.Write(p)
}

func (w *SSHWorker) Verify(ctx context.Context, p Provider, ref, id string, generation uint64) (Verification, error) {
	if (p.Kind != "github" && p.Kind != "gitea") || !nonempty(id) || generation == 0 {
		return Verification{}, ErrIdentity
	}
	registry, ok := w.registry.(VerificationRegistry)
	if !ok {
		return Verification{}, ErrIdentity
	}
	fingerprint, err := registry.ResolveGitVerification(ctx, p.ID, id, generation, ref)
	if err != nil || !nonempty(fingerprint) {
		return Verification{}, ErrIdentity
	}
	var login string
	err = w.withClient(ctx, p, ref, fingerprint, func(ctx context.Context, client *ssh.Client) error {
		s, err := client.NewSession()
		if err != nil {
			return ErrIdentity
		}
		defer s.Close()
		out, stderr := &boundedBuffer{limit: 4096}, &boundedBuffer{limit: 4096}
		s.Stdout, s.Stderr = out, stderr
		if s.Shell() != nil {
			return ErrIdentity
		}
		err = s.Wait()
		code := 0
		if err != nil {
			exit, ok := err.(*ssh.ExitError)
			if !ok {
				return ErrIdentity
			}
			code = exit.ExitStatus()
		}
		if p.Kind == "github" {
			login, err = verifyGitHubSSH(out.String(), stderr.String(), code, true)
		} else {
			login, err = verifyGiteaSSH(out.String(), stderr.String(), code, true)
		}
		return err
	})
	if err != nil {
		return Verification{}, ErrIdentity
	}
	return Verification{IdentityID: id, ProviderID: p.ID, Generation: generation, Login: login, HostPinned: true, VerifiedAt: time.Now().UTC()}, nil
}

func (s *Service) ResolveGitVerification(ctx context.Context, provider, id string, generation uint64, ref string) (string, error) {
	var fingerprint string
	err := s.Store.DB.QueryRow(ctx, `SELECT k.fingerprint FROM r2d_git_key k JOIN r2d_git_identity i ON i.id=k.identity_id WHERE i.id=$1 AND i.provider_id=$2 AND k.generation=$3 AND k.internal_secret_ref=$4 AND k.state IN ('pending_verification','ready')`, id, provider, generation, ref).Scan(&fingerprint)
	if err != nil {
		return "", ErrIdentity
	}
	return fingerprint, nil
}

var canonicalRepo = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$`)

func (w *SSHWorker) target(ctx context.Context, op BoundOperation) (TransportTarget, error) {
	if w == nil || w.registry == nil || (op.Operation != Read && op.Operation != Write) || (op.Operation == Read && op.Ref != "") || (op.Operation == Write && !validWriteRef(op.Ref)) || op.Generation == 0 || !nonempty(op.UserID, op.ProviderID, op.RepositoryID, op.IdentityID, op.ContextID, op.TaskID, op.AttemptID) {
		return TransportTarget{}, ErrScope
	}
	t, err := w.registry.ResolveGitOperation(ctx, op)
	if err != nil || t.Provider.ID != op.ProviderID || !canonicalRepo.MatchString(t.Repository) || strings.Contains(t.Repository, "..") || strings.HasSuffix(t.Repository, ".git") || !nonempty(t.SecretRef, t.Fingerprint) {
		return TransportTarget{}, ErrScope
	}
	return t, nil
}

func readAdvertisement(r *bufio.Reader) (string, error) {
	var head string
	total := 0
	for count := 0; count < 16384; count++ {
		var size [4]byte
		if _, err := io.ReadFull(r, size[:]); err != nil {
			return "", ErrProvider
		}
		n, err := strconv.ParseUint(string(size[:]), 16, 16)
		if err != nil {
			return "", ErrProvider
		}
		if n == 0 {
			if head == "" {
				return "", ErrProvider
			}
			return head, nil
		}
		if n < 4 || total+int(n) > 1<<20 {
			return "", ErrProvider
		}
		total += int(n)
		line := make([]byte, int(n)-4)
		if _, err := io.ReadFull(r, line); err != nil {
			return "", ErrProvider
		}
		text := strings.SplitN(strings.TrimSuffix(string(line), "\n"), "\x00", 2)[0]
		parts := strings.Split(text, " ")
		if len(parts) != 2 || len(parts[0]) != 40 {
			return "", ErrProvider
		}
		if _, err := hex.DecodeString(parts[0]); err != nil {
			return "", ErrProvider
		}
		if parts[1] == "HEAD" {
			if head != "" {
				return "", ErrProvider
			}
			head = parts[0]
		}
	}
	return "", ErrProvider
}

func (w *SSHWorker) transferSnapshot(ctx context.Context, op BoundOperation, read bool) (snapshot RepositorySnapshot, err error) {
	t, err := w.target(ctx, op)
	if err != nil {
		return RepositorySnapshot{}, err
	}
	if read && w.validator == nil {
		return RepositorySnapshot{}, ErrUnavailable
	}
	var pack []byte
	err = w.withClient(ctx, t.Provider, t.SecretRef, t.Fingerprint, func(ctx context.Context, client *ssh.Client) error {
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
		// The shell grammar is fixed; both path components are catalog-validated.
		if s.Start("git-upload-pack '"+t.Repository+".git'") != nil {
			return ErrProvider
		}
		r := bufio.NewReader(out)
		head, err := readAdvertisement(r)
		snapshot.Head = head
		if err != nil {
			return err
		}
		if !read {
			return nil
		}
		want := "want " + head + " ofs-delta\n"
		if _, err := fmt.Fprintf(in, "%04x%s00000009done\n", len(want)+4, want); err != nil {
			return ErrProvider
		}
		if in.Close() != nil {
			return ErrProvider
		}
		var response [8]byte
		if _, err := io.ReadFull(r, response[:]); err != nil || string(response[:]) != "0008NAK\n" {
			return ErrProvider
		}
		pack, err = io.ReadAll(io.LimitReader(r, (16<<20)+1))
		if err != nil || len(pack) < 12 || len(pack) > 16<<20 || string(pack[:4]) != "PACK" {
			clear(pack)
			pack = nil
			return ErrProvider
		}
		if s.Wait() != nil {
			clear(pack)
			pack = nil
			return ErrProvider
		}
		if w.validator.Validate(ctx, pack, head) != nil {
			clear(pack)
			pack = nil
			return ErrProvider
		}
		return nil
	})
	if err != nil {
		clear(pack)
		return RepositorySnapshot{}, err
	}
	snapshot.Pack = pack
	return snapshot, nil
}

func (w *SSHWorker) ProveRepository(ctx context.Context, op BoundOperation) error {
	_, err := w.transferSnapshot(ctx, op, false)
	return err
}
func (w *SSHWorker) Read(ctx context.Context, op BoundOperation) ([]byte, error) {
	snapshot, err := w.ReadSnapshot(ctx, op)
	return snapshot.Pack, err
}

func (w *SSHWorker) ReadSnapshot(ctx context.Context, op BoundOperation) (RepositorySnapshot, error) {
	return w.transferSnapshot(ctx, op, true)
}

// ResolveGitOperation accepts trusted structured IDs, never an agent URL/path.
// Run and output authorization occur before and after transport in their callers.
func (s *Service) ResolveGitOperation(ctx context.Context, op BoundOperation) (TransportTarget, error) {
	var t TransportTarget
	if (op.Operation != Read && op.Operation != Write) || (op.Operation == Read && op.Ref != "") || (op.Operation == Write && !validWriteRef(op.Ref)) {
		return t, ErrScope
	}
	err := s.Store.DB.QueryRow(ctx, `SELECT r.canonical_repository,k.internal_secret_ref,k.fingerprint
 FROM r2d_git_repository r JOIN r2d_git_identity i ON i.provider_id=r.provider_id AND i.user_id=$1 AND i.id=$3 AND NOT i.revoked
 JOIN r2d_git_key k ON k.identity_id=i.id AND k.generation=i.active_generation AND k.state='ready'
 WHERE r.id=$2 AND r.provider_id=$4 AND r.protected AND r.allow_read AND i.active_generation=$5 AND k.consent_project_ids @> jsonb_build_array(r.project_id::text)
 AND ($6='read' OR ($6='write' AND r.allow_write AND r.write_refs @> jsonb_build_array($7::text)))`, op.UserID, op.RepositoryID, op.IdentityID, op.ProviderID, op.Generation, string(op.Operation), op.Ref).Scan(&t.Repository, &t.SecretRef, &t.Fingerprint)
	if err != nil {
		return t, ErrScope
	}
	t.Provider, err = loadProvider(ctx, s.Store.DB, op.ProviderID)
	return t, err
}
