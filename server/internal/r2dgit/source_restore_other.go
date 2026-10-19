//go:build !linux

package r2dgit

import "os"

// Protected restore witnesses require the accepted Linux deployment.
func LoadSourceRestoreGuard(db Database, directory string, expected bool) *RestoreGuard {
	_, err := os.Lstat(directory)
	if expected || !os.IsNotExist(err) {
		return &RestoreGuard{DB: db}
	}
	return nil
}
