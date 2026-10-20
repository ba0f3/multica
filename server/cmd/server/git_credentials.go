package main

import (
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	db "github.com/multica-ai/multica/server/pkg/db/generated"

	"github.com/multica-ai/multica/server/internal/r2dgit"
)

// gitCredentialService builds the per-user Git credential service from the
// environment.
//
// A deployment without a complete custody configuration gets no service at
// all. The credential endpoints then answer that the capability is
// unavailable, which is the honest answer: a server that cannot keep a
// private key in encrypted custody must not pretend to hand out working Git
// credentials.
func gitCredentialService(queries *db.Queries) *r2dgit.Service {
	custodyURL := strings.TrimSpace(os.Getenv("MULTICA_GIT_CUSTODY_URL"))
	custodyMount := strings.TrimSpace(os.Getenv("MULTICA_GIT_CUSTODY_MOUNT"))
	custodyToken := strings.TrimSpace(os.Getenv("MULTICA_GIT_CUSTODY_TOKEN"))

	if custodyURL == "" && custodyMount == "" && custodyToken == "" {
		return nil
	}
	if custodyURL == "" || custodyMount == "" || custodyToken == "" {
		slog.Warn("git credentials disabled: MULTICA_GIT_CUSTODY_URL, MULTICA_GIT_CUSTODY_MOUNT and MULTICA_GIT_CUSTODY_TOKEN must all be set")
		return nil
	}

	custody, err := r2dgit.NewBaoCustody(custodyURL, custodyMount, custodyToken, &http.Client{
		Timeout: 20 * time.Second,
	})
	if err != nil {
		slog.Error("git credentials disabled: the custody configuration was rejected", "error", err)
		return nil
	}

	return r2dgit.NewService(
		r2dgit.NewSQLCStore(queries),
		custody,
		r2dgit.NewSSHVerifier(custody),
	)
}
