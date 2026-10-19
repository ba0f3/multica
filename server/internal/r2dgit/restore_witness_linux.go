//go:build linux

package r2dgit

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

type FileRestoreWitness struct {
	path string
	ID   string
}

func (w *FileRestoreWitness) InstanceID() string { return w.ID }

type witnessState struct {
	Version    int    `json:"version"`
	Checkpoint string `json:"checkpoint"`
	ID         string `json:"id"`
}

// CreateFileRestoreWitness is explicit first-install tooling. The operator must
// keep this private file outside database/custody restores. Existing files are
// never overwritten or reset; missing/corrupt evidence refuses execution.
func CreateFileRestoreWitness(path string) (*FileRestoreWitness, error) {
	if !filepath.IsAbs(path) {
		return nil, ErrScope
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode().Perm() != 0700 {
		return nil, ErrRuntime
	}
	if stat, ok := parent.Sys().(*syscall.Stat_t); !ok || stat.Uid != uint32(os.Geteuid()) {
		return nil, ErrRuntime
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(witnessState{Version: 1, Checkpoint: uuid.NewString(), ID: uuid.NewString()})
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	err = d.Sync()
	d.Close()
	if err != nil {
		return nil, err
	}
	return OpenFileRestoreWitness(path)
}
func OpenFileRestoreWitness(path string) (*FileRestoreWitness, error) {
	if !filepath.IsAbs(path) {
		return nil, ErrScope
	}
	w := &FileRestoreWitness{path: path}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := w.Current(ctx); err != nil {
		return nil, err
	}
	return w, nil
}
func (w *FileRestoreWitness) locked(ctx context.Context, fn func(*os.File, witnessState) error) error {
	if w == nil {
		return ErrUnavailable
	}
	parent, err := os.Lstat(filepath.Dir(w.path))
	if err != nil || !parent.IsDir() || parent.Mode().Perm() != 0700 {
		return ErrRuntime
	}
	if stat, ok := parent.Sys().(*syscall.Stat_t); !ok || stat.Uid != uint32(os.Geteuid()) {
		return ErrRuntime
	}
	f, err := os.OpenFile(w.path, os.O_RDWR|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 256 {
		return ErrRuntime
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return ErrRuntime
	}
	for {
		err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if err != unix.EWOULDBLOCK {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Millisecond):
		}
	}
	defer unix.Flock(int(f.Fd()), unix.LOCK_UN)
	raw, err := io.ReadAll(io.LimitReader(f, 257))
	if err != nil {
		return err
	}
	var state witnessState
	if decodeBoundedJSON(bytes.NewReader(raw), 256, &state) != nil || state.Version != 1 || uuid.Validate(state.Checkpoint) != nil || uuid.Validate(state.ID) != nil || (w.ID != "" && w.ID != state.ID) {
		return ErrRevoked
	}
	if w.ID == "" {
		w.ID = state.ID
	}
	return fn(f, state)
}
func (w *FileRestoreWitness) Current(ctx context.Context) (string, error) {
	var current string
	err := w.locked(ctx, func(_ *os.File, s witnessState) error { current = s.Checkpoint; return nil })
	return current, err
}
func (w *FileRestoreWitness) Locked(ctx context.Context, fn func(string, func(string) error) error) error {
	return w.locked(ctx, func(f *os.File, s witnessState) error {
		return fn(s.Checkpoint, func(next string) error {
			if uuid.Validate(next) != nil || next == s.Checkpoint {
				return ErrScope
			}
			raw, _ := json.Marshal(witnessState{Version: 1, Checkpoint: next, ID: s.ID})
			if _, err := f.Seek(0, 0); err != nil {
				return err
			}
			if err := f.Truncate(0); err != nil {
				return err
			}
			if _, err := f.Write(raw); err != nil {
				return err
			}
			if err := f.Sync(); err != nil {
				return err
			}
			s.Checkpoint = next
			return nil
		})
	})
}
func (w *FileRestoreWitness) Advance(ctx context.Context, old, next string) error {
	return w.Locked(ctx, func(current string, advance func(string) error) error {
		if old != current {
			return ErrConflict
		}
		return advance(next)
	})
}
