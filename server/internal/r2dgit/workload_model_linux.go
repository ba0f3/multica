//go:build linux

package r2dgit

import (
	"context"
	"net/http"
	"time"
)

func (a *WorkloadApplication) generateModel(ctx context.Context, l Lease, channel, input string) (string, error) {
	if a.model == nil || len(input) == 0 || len(input) > 64<<10 {
		return "", ErrUnavailable
	}
	ctx, stop := context.WithTimeout(ctx, 25*time.Second)
	defer stop()
	check := func() error {
		bounded, done := context.WithTimeout(ctx, time.Second)
		defer done()
		if !a.service.Now().Before(l.expires) {
			return ErrRevoked
		}
		return a.broker.Authorizer.Authorize(bounded, l.run, l.grant, channel, Read, "", a.service.Now())
	}
	if err := check(); err != nil {
		return "", err
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if check() != nil {
					stop()
					return
				}
			}
		}
	}()
	defer func() { stop(); <-done }()
	s, g := l.run.spec, l.grant.spec
	op := BoundOperation{UserID: s.Binding.OriginatorUserID, ContextID: s.ID, TaskID: s.Binding.TaskID, AttemptID: s.AttemptID, ProviderID: g.ProviderID, RepositoryID: g.RepositoryID, IdentityID: g.IdentityID, Generation: g.CredentialGeneration, Operation: Read}
	id := "model-" + s.ID + "-" + s.AttemptID
	fresh, err := a.broker.Journal.Begin(ctx, id, op)
	if err != nil || !fresh {
		return "", ErrAudit
	}
	text, err := a.model.Generate(ctx, op, s.Binding.ProjectID, input)
	outcome := "succeeded"
	if err != nil {
		outcome = "indeterminate"
	}
	if a.broker.Journal.Complete(ctx, id, outcome) != nil {
		return "", ErrAudit
	}
	if err != nil {
		return "", err
	}
	if err = check(); err != nil {
		return "", err
	}
	return text, nil
}

func (c *WorkloadClient) Generate(ctx context.Context, input string) (string, error) {
	if len(input) == 0 || len(input) > 64<<10 {
		return "", ErrScope
	}
	response, err := c.request(ctx, http.MethodPost, "/model", struct {
		Input string `json:"input"`
	}{input})
	if err != nil {
		return "", ErrIndeterminate
	}
	defer response.Body.Close()
	var result struct {
		Content string `json:"content"`
	}
	if response.StatusCode != http.StatusOK || decodeBoundedJSON(response.Body, (64<<10)+1024, &result) != nil || len(result.Content) == 0 || len(result.Content) > 64<<10 {
		return "", ErrProvider
	}
	return result.Content, nil
}

// EnqueueChild hands an explicitly narrowed request to server-side admission.
// It returns an identifier, never the child's certificate/channel or native state.
func (c *WorkloadClient) EnqueueChild(ctx context.Context, request RunRequest) (string, error) {
	response, err := c.request(ctx, http.MethodPost, "/children", request)
	if err != nil {
		return "", ErrIndeterminate
	}
	defer response.Body.Close()
	var out struct {
		ContextID string `json:"context_id"`
	}
	if response.StatusCode != http.StatusOK || decodeBoundedJSON(response.Body, 1024, &out) != nil || !nonempty(out.ContextID) {
		return "", ErrScope
	}
	return out.ContextID, nil
}
