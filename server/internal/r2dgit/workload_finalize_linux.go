//go:build linux

package r2dgit

import (
	"context"
	"github.com/google/uuid"
	"net/http"
)

// FinalizeRequest contains content identities only. The server chooses the
// sole permitted feature ref and all provider/user authority from the grant.
type FinalizeRequest struct {
	Old, New string
	Pack     []byte
}

func (a *WorkloadApplication) finalize(ctx context.Context, read Lease, channel string, payload FinalizeRequest) error {
	l, err := a.writeLease(ctx, read, channel)
	if err != nil {
		return err
	}
	u := RefUpdate{Old: payload.Old, New: payload.New, Ref: l.ref}
	return a.broker.Write(ctx, l, channel, writeOperationID(a.broker, l, u), u, payload.Pack)
}

func (a *WorkloadApplication) writeLease(ctx context.Context, read Lease, channel string) (Lease, error) {
	if !hasOp(read.grant.spec, Write) || len(read.grant.spec.WriteRefs) != 1 || !a.service.Now().Before(read.expires) {
		return Lease{}, ErrScope
	}
	now := a.service.Now()
	return IssueLease(ctx, a.broker.Authorizer, read.run, read.grant, channel, Write, read.grant.spec.WriteRefs[0], now, read.expires.Sub(now))
}

func (a *WorkloadApplication) writeReference(ctx context.Context, l Lease, channel string) (string, error) {
	write, err := a.writeLease(ctx, l, channel)
	if err != nil {
		return "", err
	}
	if a.broker.Quarantine == nil {
		return "", ErrUnavailable
	}
	return a.broker.WriteAdvertisement(ctx, write, channel, uuid.NewString())
}

func (c *WorkloadClient) WriteReference(ctx context.Context) (string, error) {
	response, err := c.request(ctx, http.MethodGet, "/write-reference", nil)
	if err != nil {
		return "", ErrProvider
	}
	defer response.Body.Close()
	var out struct {
		Old string `json:"old"`
	}
	if response.StatusCode != http.StatusOK || decodeBoundedJSON(response.Body, 1024, &out) != nil || !objectID(out.Old) {
		return "", ErrScope
	}
	return out.Old, nil
}

func (c *WorkloadClient) Finalize(ctx context.Context, request FinalizeRequest) error {
	if len(request.Pack) > 512<<10 || !objectID(request.Old) || !objectID(request.New) {
		return ErrScope
	}
	response, err := c.request(ctx, http.MethodPost, "/finalize", request)
	if err != nil {
		return ErrIndeterminate
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return ErrIndeterminate
	}
	return nil
}
