package main

import (
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	db "github.com/multica-ai/multica/server/pkg/db/generated"

	"github.com/multica-ai/multica/server/internal/r2dgit"
	"github.com/multica-ai/multica/server/internal/util/secretbox"
)

// gitCredentialService builds the per-user Git credential service from the
// environment.
//
// Production may use OpenBao (MULTICA_GIT_CUSTODY_*). Otherwise private keys
// are sealed with MULTICA_GIT_SECRET_KEY (or a JWT_SECRET-derived dev key)
// and stored in PostgreSQL.
func gitCredentialService(queries *db.Queries) *r2dgit.Service {
	store := r2dgit.NewSQLCStore(queries)

	custodyURL := strings.TrimSpace(os.Getenv("MULTICA_GIT_CUSTODY_URL"))
	custodyMount := strings.TrimSpace(os.Getenv("MULTICA_GIT_CUSTODY_MOUNT"))
	custodyToken := strings.TrimSpace(os.Getenv("MULTICA_GIT_CUSTODY_TOKEN"))

	if custodyURL != "" || custodyMount != "" || custodyToken != "" {
		if custodyURL == "" || custodyMount == "" || custodyToken == "" {
			slog.Warn("git credentials: OpenBao custody is incomplete; falling back to database custody when configured")
		} else {
			custody, err := r2dgit.NewBaoCustody(custodyURL, custodyMount, custodyToken, &http.Client{
				Timeout: 20 * time.Second,
			})
			if err != nil {
				slog.Error("git credentials: OpenBao custody was rejected", "error", err)
			} else {
				return r2dgit.NewService(store, custody, r2dgit.NewSSHVerifier(custody))
			}
		}
	}

	key, err := r2dgit.LoadGitSecretKey()
	if err != nil {
		slog.Debug("git credentials disabled: no custody key configured", "error", err)
		return nil
	}
	box, err := secretbox.New(key)
	if err != nil {
		slog.Error("git credentials disabled: custody key was rejected", "error", err)
		return nil
	}
	custody, err := r2dgit.NewDBCustody(queries, box)
	if err != nil {
		slog.Error("git credentials disabled: database custody could not start", "error", err)
		return nil
	}
	slog.Info("git credentials: using database custody (encrypted at rest in PostgreSQL)")
	return r2dgit.NewService(store, custody, r2dgit.NewSSHVerifier(custody))
}
