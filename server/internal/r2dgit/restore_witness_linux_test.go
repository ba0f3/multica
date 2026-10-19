//go:build linux

package r2dgit

import (
	"context"
	"github.com/google/uuid"
	"os"
	"path/filepath"
	"testing"
)

func TestFileRestoreWitnessDurableCASAndRefusals(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "witness.json")
	w, err := CreateFileRestoreWitness(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	old, err := w.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	next := uuid.NewString()
	if err = w.Advance(ctx, old, next); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenFileRestoreWitness(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reopened.Current(ctx)
	if err != nil || got != next || reopened.ID != w.ID {
		t.Fatal("checkpoint not durable", got, err)
	}
	if w.Advance(ctx, old, uuid.NewString()) == nil {
		t.Fatal("old checkpoint replayed")
	}
	if _, err = CreateFileRestoreWitness(path); err == nil {
		t.Fatal("existing witness overwritten")
	}
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = w.Current(ctx); err == nil {
		t.Fatal("public witness accepted")
	}
	if err = os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err = os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err = OpenFileRestoreWitness(link); err == nil {
		t.Fatal("symlink witness accepted")
	}
	hard := filepath.Join(dir, "hard")
	if err = os.Link(path, hard); err != nil {
		t.Fatal(err)
	}
	if _, err = w.Current(ctx); err == nil {
		t.Fatal("multiple-link witness accepted")
	}
	if err = os.Remove(hard); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, []byte(`{"version":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = w.Current(ctx); err == nil {
		t.Fatal("corrupt witness accepted")
	}
	if LoadSourceRestoreGuard(nil, dir, false) == nil {
		t.Fatal("existing corrupt installation became legacy")
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if LoadSourceRestoreGuard(nil, dir, false) == nil {
		t.Fatal("missing expected witness became legacy")
	}
}
