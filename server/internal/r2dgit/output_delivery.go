package r2dgit

import (
	"context"
	"io"
	"reflect"
	"time"

	"github.com/google/uuid"
)

const (
	outputCheckTimeout = time.Second
	outputWriteTimeout = time.Second
	outputAuditTimeout = time.Second
	outputChunkSize    = 16 << 10
)

// OutputSink is a trusted response adapter. Write must flush the chunk before
// returning and enforce SetWriteDeadline, including while the peer is stalled.
// Unsupported response controllers must fail before Begin; no unbounded fallback.
type OutputSink interface {
	SetWriteDeadline(time.Time) error
	Begin(int)
	Write([]byte) (int, error)
}

type outputDeliveryDetails struct {
	DeliveryID       string                 `json:"delivery_id"`
	ContextID        string                 `json:"context_id"`
	RootID           string                 `json:"root_id"`
	OriginatorUserID string                 `json:"originator_user_id"`
	AgentID          string                 `json:"agent_id"`
	Sources          []outputDeliverySource `json:"sources"`
	AcceptedBytes    int                    `json:"accepted_bytes"`
	Reason           string                 `json:"reason,omitempty"`
}
type outputDeliverySource struct {
	Operation   BoundOperation `json:"operation"`
	Fingerprint string         `json:"fingerprint"`
}

func (s *Service) boundedOutputPlan(ctx context.Context, user, id string) (outputPlan, error) {
	checkCtx, cancel := context.WithTimeout(ctx, outputCheckTimeout)
	defer cancel()
	return s.readOutputPlan(checkCtx, user, id)
}
func (s *Service) outputDeliveryEvent(ctx context.Context, user, id, action string, details outputDeliveryDetails) error {
	auditCtx, cancel := context.WithTimeout(ctx, outputAuditTimeout)
	defer cancel()
	_, err := s.Store.DB.Exec(auditCtx, `INSERT INTO r2d_git_security_event(id,user_id,subject_id,action,details) VALUES($1,$2,$3,$4,$5)`, uuid.NewString(), user, id, action, encode(details))
	return err
}

// DeliverOutput revalidates the original access snapshot between bounded chunks.
// There is no concurrent unbounded writer or auth worker to outlive this request.
// The server-write cutoff covers local policy changes, not bytes already accepted
// by a socket/client. Process/WS revocation and other output surfaces remain S5 gates.
func (s *Service) DeliverOutput(ctx context.Context, user, id string, sink OutputSink) (err error) {
	if sink == nil || s.OutputProof == nil {
		return ErrUnavailable
	}
	before, err := s.boundedOutputPlan(ctx, user, id)
	if err != nil {
		return err
	}
	proofStarted := s.Now()
	prepareCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	body, err := s.ReadOutput(prepareCtx, user, id)
	cancel()
	if err != nil {
		return err
	}
	defer clear(body)
	details := outputDeliveryDetails{DeliveryID: uuid.NewString(), ContextID: before.ContextID, RootID: before.RootID, OriginatorUserID: before.Binding.OriginatorUserID, AgentID: before.Binding.AgentID}
	for _, source := range before.Access {
		details.Sources = append(details.Sources, outputDeliverySource{Operation: source.Operation, Fingerprint: source.Fingerprint})
	}
	if s.outputDeliveryEvent(ctx, user, id, "restricted_output_delivery_intent", details) != nil {
		return ErrAudit
	}
	begun := false
	reason := ""
	defer func() {
		if err != nil && begun {
			_ = sink.SetWriteDeadline(time.Now())
		}
		action := "restricted_output_delivery_completed"
		if err != nil {
			action = "restricted_output_delivery_aborted"
			details.Reason = reason
		}
		// On audit outage the durable intent remains without a terminal outcome.
		// Already accepted bytes cannot be recalled or described as denied delivery.
		if s.outputDeliveryEvent(context.WithoutCancel(ctx), user, id, action, details) != nil {
			if begun {
				_ = sink.SetWriteDeadline(time.Now())
			}
			err = ErrAudit
		}
	}()
	current := func() error {
		after, e := s.boundedOutputPlan(ctx, user, id)
		if e != nil || !reflect.DeepEqual(before, after) || ctx.Err() != nil {
			return ErrRevoked
		}
		return nil
	}
	for offset := 0; offset < len(body); {
		reason = "current_rights"
		if err = current(); err != nil {
			return err
		}
		// A slow delivery cannot turn its initial provider proof into an indefinite
		// authorization cache. Fail closed on timeout, then recheck local rights.
		if s.Now().Sub(proofStarted) >= 30*time.Second {
			proofCtx, stop := context.WithTimeout(ctx, outputCheckTimeout)
			for _, source := range before.Access {
				if s.OutputProof.ProveRepository(proofCtx, source.Operation) != nil {
					err = ErrProvider
					break
				}
			}
			stop()
			if err != nil {
				reason = "provider_proof"
				return err
			}
			proofStarted = s.Now()
			if err = current(); err != nil {
				return err
			}
		}
		reason = "write_deadline"
		if err = sink.SetWriteDeadline(time.Now().Add(outputWriteTimeout)); err != nil {
			return ErrRuntime
		}
		if !begun {
			sink.Begin(len(body))
			begun = true
		}
		end := min(offset+outputChunkSize, len(body))
		var n int
		n, err = sink.Write(body[offset:end])
		if n < 0 || n > end-offset {
			err = io.ErrShortWrite
			n = 0
		}
		details.AcceptedBytes += n
		if err == nil && n != end-offset {
			err = io.ErrShortWrite
		}
		if err != nil {
			reason = "write_failed"
			return err
		}
		offset = end
	}
	if ctx.Err() != nil {
		reason = "request_cancelled"
		return ctx.Err()
	}
	reason = "write_deadline"
	return sink.SetWriteDeadline(time.Time{})
}
