//go:build linux

package service

import (
	"context"
	"github.com/jackc/pgx/v5"
	"github.com/multica-ai/multica/server/internal/r2dgit"
	"github.com/multica-ai/multica/server/internal/util"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
)

// NewProtectedWorker supplies the ordinary application-owned terminal effects
// in the exact transaction that changes protected task status. Nil configuration
// is the production disabled state; no environment/credential discovery occurs.
func NewProtectedWorker(ctx context.Context, s *r2dgit.Service, c *r2dgit.ProtectedDeploymentConfig) (*r2dgit.ProtectedDeployment, error) {
	if c == nil {
		return nil, nil
	}
	config := *c
	config.Application.SettleTerminal = func(ctx context.Context, tx pgx.Tx, id string) error {
		parsed, err := util.ParseUUID(id)
		if err != nil {
			return err
		}
		q := db.New(tx)
		task, err := q.GetAgentTask(ctx, parsed)
		if err != nil {
			return err
		}
		return SettleTerminalTaskState(ctx, q, task)
	}
	return r2dgit.NewProtectedDeployment(ctx, s, &config)
}
