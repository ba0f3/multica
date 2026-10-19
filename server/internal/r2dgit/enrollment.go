package r2dgit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"reflect"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// RuntimeAcceptance is operator evidence about one reviewed policy and trusted
// worker certificate. Its signature is not evidence that a synthetic VM exists.
type RuntimeAcceptance struct {
	ID, ActorID, RuntimeID, PolicyDigest, WorkerCertificateSHA256 string
	ExpiresAt                                                     time.Time
	Signature                                                     []byte
}

func RuntimeAcceptanceBytes(a RuntimeAcceptance) ([]byte, error) {
	a.Signature = nil
	return json.Marshal(struct {
		Domain     string
		Acceptance RuntimeAcceptance
	}{"multica-runtime-acceptance-v1", a})
}

func validAcceptance(a RuntimeAcceptance, key ed25519.PublicKey, now time.Time) bool {
	for _, id := range []string{a.ID, a.ActorID, a.RuntimeID} {
		if _, err := uuid.Parse(id); err != nil {
			return false
		}
	}
	for _, digest := range []string{a.PolicyDigest, a.WorkerCertificateSHA256} {
		decoded, err := hex.DecodeString(digest)
		if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != digest {
			return false
		}
	}
	raw, err := RuntimeAcceptanceBytes(a)
	return err == nil && len(key) == ed25519.PublicKeySize && now.Before(a.ExpiresAt) && ed25519.Verify(key, raw, a.Signature)
}

// RecordRuntimeAcceptance is trusted operator tooling, not an HTTP route. The
// immutable event ID refuses replacement; revocation tombstones always win.
func (s *Service) RecordRuntimeAcceptance(ctx context.Context, a RuntimeAcceptance, key ed25519.PublicKey) error {
	if s == nil || s.Store == nil || s.Store.DB == nil || s.Now == nil {
		return ErrUnavailable
	}
	if !validAcceptance(a, key, s.Now()) || !activeHuman(ctx, s.Store.DB, a.ActorID) {
		return ErrRuntime
	}
	return s.Store.transaction(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO r2d_git_security_event(id,user_id,subject_id,action,details) VALUES($1,$2,$3,'operator_runtime_accepted',$4)`, a.ID, a.ActorID, a.RuntimeID, encode(a))
		return err
	})
}

func RuntimeRevocationBytes(id string) []byte { return []byte("multica-runtime-revocation-v1:" + id) }

func (s *Service) RevokeRuntimeAcceptance(ctx context.Context, id string, signature []byte, key ed25519.PublicKey) error {
	if s == nil || s.Store == nil || s.Store.DB == nil {
		return ErrUnavailable
	}
	if _, err := uuid.Parse(id); err != nil || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, RuntimeRevocationBytes(id), signature) {
		return ErrRuntime
	}
	return s.Store.transaction(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO r2d_git_security_event(id,user_id,subject_id,action,details) SELECT $2,user_id,id,'operator_runtime_revoked',$3 FROM r2d_git_security_event WHERE id=$1 AND action='operator_runtime_accepted'`, id, uuid.NewString(), encode(signature))
		if err != nil || tag.RowsAffected() != 1 {
			return ErrRuntime
		}
		return nil
	})
}

func (s *Service) runtimeAcceptance(ctx context.Context, id string, key ed25519.PublicKey) (RuntimeAcceptance, error) {
	var a RuntimeAcceptance
	if s == nil || s.Store == nil || s.Store.DB == nil || s.Now == nil {
		return a, ErrUnavailable
	}
	if err := s.checkRestore(ctx, s.Store.DB); err != nil {
		return a, err
	}
	var raw []byte
	if err := s.Store.DB.QueryRow(ctx, `SELECT details FROM r2d_git_security_event e WHERE e.id=$1 AND e.action='operator_runtime_accepted' AND NOT EXISTS(SELECT 1 FROM r2d_git_security_event revoked WHERE revoked.subject_id=e.id AND revoked.action='operator_runtime_revoked')`, id).Scan(&raw); err != nil || json.Unmarshal(raw, &a) != nil || a.ID != id || !validAcceptance(a, key, s.Now()) {
		return a, ErrRuntime
	}
	return a, nil
}

type EnrollmentIssuer struct {
	Service      *Service
	AcceptanceID string
	OperatorKey  ed25519.PrivateKey
	CA           *x509.Certificate
	CAKey        ed25519.PrivateKey
	// Entropy is supplied only by trusted composition. Nil uses OS randomness.
	Entropy io.Reader
}

type enrollmentWire struct {
	Certificate, PrivateKey, Signature []byte
	AcceptanceID                       string
}

func decodeBoundedJSON(reader io.Reader, limit int, out any) error {
	raw, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	defer clear(raw)
	if err != nil || len(raw) > limit {
		return ErrScope
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return ErrScope
	}
	var trailing any
	if d.Decode(&trailing) != io.EOF {
		return ErrScope
	}
	return nil
}

func (i EnrollmentIssuer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	deny := func() { http.Error(w, "workload enrollment unavailable", http.StatusForbidden) }
	if i.Service == nil || len(i.OperatorKey) != ed25519.PrivateKeySize || len(i.CAKey) != ed25519.PrivateKeySize || i.CA == nil || !i.CA.IsCA || r.Method != http.MethodPost || r.URL.Path != "/enroll" || r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Content-Encoding") != "" || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		deny()
		return
	}
	control := http.NewResponseController(w)
	if control.SetReadDeadline(time.Now().Add(time.Second)) != nil || control.SetWriteDeadline(time.Now().Add(3*time.Second)) != nil {
		deny()
		return
	}
	ctx, stop := context.WithTimeout(r.Context(), 2*time.Second)
	defer stop()
	a, err := i.Service.runtimeAcceptance(ctx, i.AcceptanceID, i.OperatorKey.Public().(ed25519.PublicKey))
	pin := sha256.Sum256(r.TLS.PeerCertificates[0].Raw)
	if err != nil || a.WorkerCertificateSHA256 != hex.EncodeToString(pin[:]) {
		deny()
		return
	}
	var request WorkloadEnrollmentRequest
	if decodeBoundedJSON(r.Body, 16384, &request) != nil || request.PolicyDigest != a.PolicyDigest || request.Context.Binding.RuntimeID != a.RuntimeID || !nonempty(request.ChannelID) {
		deny()
		return
	}
	now := i.Service.Now()
	if !now.Before(request.ExpiresAt) || request.ExpiresAt.After(now.Add(time.Minute)) || request.ExpiresAt.After(a.ExpiresAt) || request.ExpiresAt.After(i.CA.NotAfter) || now.Before(i.CA.NotBefore) {
		deny()
		return
	}
	// Reconstruct all authority and the assignment inside one DB snapshot. The
	// trusted peer does not get to invent a context merely because it has mTLS.
	if i.Service.validateEnrollment(ctx, request) != nil {
		deny()
		return
	}
	journal := SQLJournal{DB: i.Service.Store.DB, Restore: i.Service.Store.Restore}
	op := BoundOperation{UserID: request.Context.Binding.OriginatorUserID, ContextID: request.Context.ID, TaskID: request.Context.Binding.TaskID, AttemptID: request.Context.AttemptID, ProviderID: request.Grant.ProviderID, RepositoryID: request.Grant.RepositoryID, IdentityID: request.Grant.IdentityID, Generation: request.Grant.CredentialGeneration, Operation: Read}
	operationID := "enrollment-" + hexDigest([]byte(request.Context.ID+":"+request.ChannelID))
	if fresh, err := journal.Begin(ctx, operationID, op); err != nil || !fresh {
		deny()
		return
	}
	entropy := i.Entropy
	if entropy == nil {
		entropy = rand.Reader
	}
	public, private, err := ed25519.GenerateKey(entropy)
	if err != nil {
		deny()
		return
	}
	defer clear(private)
	serial := make([]byte, 16)
	if _, err = io.ReadFull(entropy, serial); err != nil {
		deny()
		return
	}
	serial[0] |= 1
	template := &x509.Certificate{SerialNumber: new(big.Int).SetBytes(serial), Subject: pkix.Name{CommonName: "protected-workload"}, NotBefore: now.Add(-time.Second), NotAfter: request.ExpiresAt, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(entropy, template, i.CA, public, i.CAKey)
	if err != nil {
		deny()
		return
	}
	message, err := WorkloadRegistrationBytes(request, der, a.ID)
	if err != nil {
		deny()
		return
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		deny()
		return
	}
	defer clear(encoded)
	if _, err = i.Service.runtimeAcceptance(ctx, a.ID, i.OperatorKey.Public().(ed25519.PublicKey)); err != nil {
		deny()
		return
	}
	if event(ctx, i.Service.Store.DB, request.Context.Binding.OriginatorUserID, request.Context.ID, "protected_workload_enrolled") != nil {
		deny()
		return
	}
	if journal.Complete(ctx, operationID, "succeeded") != nil {
		deny()
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(enrollmentWire{der, encoded, ed25519.Sign(i.OperatorKey, message), a.ID})
}

func (s *Service) validateEnrollment(ctx context.Context, request WorkloadEnrollmentRequest) error {
	return s.Store.readOnly(ctx, func(tx pgx.Tx) error {
		r, g, err := loadRun(ctx, tx, request.Context.ID, s.Now())
		if err != nil || r.spec != request.Context || !reflect.DeepEqual(g.spec, request.Grant) || request.ExpiresAt.After(g.spec.ExpiresAt) {
			return ErrPrincipal
		}
		current, err := s.currentIn(ctx, tx, r.spec, g.spec)
		if err != nil || !currentIssuable(current, r, g) {
			return ErrRevoked
		}
		assignment, issue, err := loadWorkloadAssignment(ctx, tx, r)
		raw, _ := json.Marshal(assignment)
		if err != nil || issue != request.IssueID || hexDigest(raw) != request.AssignmentDigest {
			return ErrPrincipal
		}
		return nil
	})
}

type HTTPWorkloadEnroller struct {
	endpoint string
	client   *http.Client
}

func NewHTTPWorkloadEnroller(endpoint string, config *tls.Config) (*HTTPWorkloadEnroller, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || config == nil || config.RootCAs == nil || config.InsecureSkipVerify || len(config.Certificates) != 1 || config.GetClientCertificate != nil || config.VerifyConnection != nil || config.VerifyPeerCertificate != nil {
		return nil, ErrRuntime
	}
	tlsConfig := config.Clone()
	if tlsConfig.ServerName != "" && tlsConfig.ServerName != u.Hostname() {
		return nil, ErrRuntime
	}
	tlsConfig.ServerName = u.Hostname()
	tlsConfig.RootCAs = config.RootCAs.Clone()
	tlsConfig.MinVersion = tls.VersionTLS13
	transport := &http.Transport{TLSClientConfig: tlsConfig, ResponseHeaderTimeout: 2 * time.Second, MaxConnsPerHost: 2}
	return &HTTPWorkloadEnroller{endpoint: endpoint + "/enroll", client: &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (e *HTTPWorkloadEnroller) Close() { e.client.CloseIdleConnections() }

func (e *HTTPWorkloadEnroller) Enroll(ctx context.Context, request WorkloadEnrollmentRequest) (WorkloadEnrollment, error) {
	var out WorkloadEnrollment
	raw, err := json.Marshal(request)
	if err != nil || len(raw) > 16384 {
		return out, ErrScope
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, e.endpoint, bytes.NewReader(raw))
	if err != nil {
		return out, ErrRuntime
	}
	r.Header.Set("Content-Type", "application/json")
	response, err := e.client.Do(r)
	if err != nil {
		return out, ErrRuntime
	}
	defer response.Body.Close()
	var wire enrollmentWire
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/json" || decodeBoundedJSON(response.Body, 16384, &wire) != nil {
		return out, ErrRuntime
	}
	defer clear(wire.PrivateKey)
	key, err := x509.ParsePKCS8PrivateKey(wire.PrivateKey)
	private, ok := key.(ed25519.PrivateKey)
	if err != nil || !ok {
		return out, ErrRuntime
	}
	cert, err := x509.ParseCertificate(wire.Certificate)
	if err != nil || !bytes.Equal(cert.RawSubjectPublicKeyInfo, mustPublicDER(private.Public())) {
		clear(private)
		return out, ErrRuntime
	}
	out = WorkloadEnrollment{Certificate: tls.Certificate{Certificate: [][]byte{wire.Certificate}, PrivateKey: private, Leaf: cert}, AcceptanceID: wire.AcceptanceID, Signature: wire.Signature}
	return out, nil
}

func mustPublicDER(key any) []byte { raw, _ := x509.MarshalPKIXPublicKey(key); return raw }
