package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStreamDaemonLogLastLines(t *testing.T) {
	for _, tc := range []struct {
		name, content, want string
		lines               int
	}{
		{"terminated", "a\nb\nc\n", "b\nc\n", 2},
		{"unterminated", "a\nb\nc", "b\nc", 2},
		{"zero", "a\nb\n", "", 0},
		{"empty", "", "", 10},
		{"large line", "old\n" + strings.Repeat("x", 10000) + "\nnew\n", "new\n", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "daemon.log")
			if err := os.WriteFile(path, []byte(tc.content), 0600); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			if err := streamDaemonLog(context.Background(), path, tc.lines, false, &out, time.Millisecond); err != nil {
				t.Fatal(err)
			}
			if out.String() != tc.want {
				t.Fatalf("tail = %q, want %q", out.String(), tc.want)
			}
		})
	}
}

type logChunkWriter chan string

func (w logChunkWriter) Write(p []byte) (int, error) { w <- string(p); return len(p), nil }

func TestStreamDaemonLogFollowsTruncationAndRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.log")
	if err := os.WriteFile(path, []byte("initial log with long content\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	chunks := make(logChunkWriter, 10)
	done := make(chan error, 1)
	go func() { done <- streamDaemonLog(ctx, path, 1, true, chunks, time.Millisecond) }()
	waitOutput := func(want string) {
		t.Helper()
		var got string
		timer := time.NewTimer(3 * time.Second)
		defer timer.Stop()
		for !strings.Contains(got, want) {
			select {
			case chunk := <-chunks:
				got += chunk
			case err := <-done:
				t.Fatalf("follower exited early: %v", err)
			case <-timer.C:
				t.Fatalf("waiting for %q, got %q", want, got)
			}
		}
	}
	waitOutput("initial log with long content\n")
	if err := os.WriteFile(path, []byte("truncated\n"), 0600); err != nil {
		t.Fatal(err)
	}
	waitOutput("truncated\n")
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	// The replacement is larger than the previous file, so size alone cannot detect rotation.
	if err := os.WriteFile(path, []byte("replacement log with even longer content\n"), 0600); err != nil {
		t.Fatal(err)
	}
	waitOutput("replacement log with even longer content\n")
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("follower ignored cancellation")
	}
}
