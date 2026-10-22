package r2dgit

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"

	"github.com/multica-ai/multica/server/internal/util/secretbox"
)

// LoadGitSecretKey returns the 32-byte master key for database Git custody.
//
// Prefer MULTICA_GIT_SECRET_KEY (base64, same shape as other secretbox keys).
// When it is unset, derive a dev-only key from JWT_SECRET so local stacks
// do not need OpenBao.
func LoadGitSecretKey() ([]byte, error) {
	if key, err := secretbox.LoadKey("MULTICA_GIT_SECRET_KEY"); err == nil {
		return key, nil
	}
	jwt := strings.TrimSpace(os.Getenv("JWT_SECRET"))
	if jwt == "" {
		return nil, fmt.Errorf("git custody: set MULTICA_GIT_SECRET_KEY or JWT_SECRET")
	}
	sum := sha256.Sum256([]byte("multica-r2d-git-custody:v1:" + jwt))
	return sum[:], nil
}
