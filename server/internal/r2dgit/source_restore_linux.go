//go:build linux

package r2dgit

import (
	"os"
	"path/filepath"
)

// The directory is an operator-owned, out-of-band installation expectation.
// Removing/restoring the database cannot remove it. Once it exists, an absent
// or invalid witness never selects legacy mode. No file is created at startup.
func LoadSourceRestoreGuard(db Database, directory string, expected bool) *RestoreGuard {
	_, err := os.Lstat(directory)
	if os.IsNotExist(err) && !expected {
		return nil
	}
	closed := &RestoreGuard{DB: db}
	if err != nil {
		return closed
	}
	w, err := OpenFileRestoreWitness(filepath.Join(directory, "witness.json"))
	if err != nil {
		return closed
	}
	g := &RestoreGuard{ID: w.ID, Witness: w}
	if attachRestoreVerifier(g, db) != nil {
		return closed
	}
	return g
}
