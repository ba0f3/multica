package r2dgit

import (
	"crypto/rand"
	"io"

	"github.com/google/uuid"
)

// randomReader is the OS randomness source used for key generation. It is a
// named type so a test can substitute a deterministic source.
type randomReader struct{}

func (randomReader) Read(p []byte) (int, error) { return rand.Read(p) }

// newRandomID mints the identifier of a new identity, key or job.
//
// The identifier is a UUID so it matches the shape every other resource in
// the server uses and can be stored in a uuid column.
func newRandomID() string {
	return uuid.NewString()
}

var _ io.Reader = randomReader{}
