package r2dgit

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

// Checkpoint verification never borrows from a pool whose connections may all
// be held by the authorization transactions being verified.
func attachRestoreVerifier(g *RestoreGuard, db Database) error {
	pool, ok := db.(*pgxpool.Pool)
	if !ok {
		return ErrUnavailable
	}
	config := pool.Config().Copy()
	config.MaxConns = 1
	config.MinConns = 0
	config.MaxConnIdleTime = 30 * time.Second
	if config.ConnConfig.RuntimeParams == nil {
		config.ConnConfig.RuntimeParams = map[string]string{}
	}
	config.ConnConfig.RuntimeParams["default_transaction_read_only"] = "on"
	verifier, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		return err
	}
	g.DB = verifier
	g.close = verifier.Close
	return nil
}
