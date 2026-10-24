package workercheckout

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/multica-ai/multica/server/internal/daemon/repocache"
)

// BenchmarkRepoCacheCheckout measures the phases of a daemon-prepared checkout
// against a real 2,000-commit repository. It reports fetch, checkout, and
// write times in milliseconds per operation. Run explicitly with -bench; it is
// not part of normal CI.
func BenchmarkRepoCacheCheckout(b *testing.B) {
	remote := generateBenchRepo(b, 2000)
	if remote == "" {
		b.Skip("git fast-import unavailable")
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repos := []repocache.RepoInfo{{URL: remote}}
	opts := Options{AgentName: "bench", TaskID: "00000000-0000-0000-0000-000000000001"}

	b.Run("cold", func(b *testing.B) {
		var fetchNs, checkoutNs, writeNs int64
		for i := 0; i < b.N; i++ {
			// Fresh workdir (reset outside the timer) and empty cache root.
			workDir := b.TempDir()
			cache := repocache.New(b.TempDir(), logger)

			start := time.Now()
			prepared, err := cache.Prepare(context.Background(), "ws-bench", repos)
			fetchNs += time.Since(start).Nanoseconds()
			if err != nil {
				b.Fatalf("Prepare (cold): %v", err)
			}
			entry := Entry{URL: remote, CommitSHA: prepared[0].CommitSHA, CachePath: prepared[0].BarePath}

			start = time.Now()
			result, err := Checkout(context.Background(), workDir, entry, opts)
			checkoutNs += time.Since(start).Nanoseconds()
			if err != nil {
				b.Fatalf("Checkout (cold): %v", err)
			}

			start = time.Now()
			writeBenchFiles(b, result.Path)
			writeNs += time.Since(start).Nanoseconds()
		}
		b.ReportMetric(float64(fetchNs)/float64(b.N)/1e6, "fetch_ms")
		b.ReportMetric(float64(checkoutNs)/float64(b.N)/1e6, "checkout_ms")
		b.ReportMetric(float64(writeNs)/float64(b.N)/1e6, "write_ms")
	})

	b.Run("warm", func(b *testing.B) {
		// Pre-populate the cache once, outside the timer.
		cache := repocache.New(b.TempDir(), logger)
		if _, err := cache.Prepare(context.Background(), "ws-bench", repos); err != nil {
			b.Fatalf("Prepare (seed): %v", err)
		}
		b.ResetTimer()

		var fetchNs, checkoutNs, writeNs int64
		for i := 0; i < b.N; i++ {
			workDir := b.TempDir()

			start := time.Now()
			prepared, err := cache.Prepare(context.Background(), "ws-bench", repos)
			fetchNs += time.Since(start).Nanoseconds()
			if err != nil {
				b.Fatalf("Prepare (warm): %v", err)
			}
			entry := Entry{URL: remote, CommitSHA: prepared[0].CommitSHA, CachePath: prepared[0].BarePath}

			start = time.Now()
			result, err := Checkout(context.Background(), workDir, entry, opts)
			checkoutNs += time.Since(start).Nanoseconds()
			if err != nil {
				b.Fatalf("Checkout (warm): %v", err)
			}

			start = time.Now()
			writeBenchFiles(b, result.Path)
			writeNs += time.Since(start).Nanoseconds()
		}
		b.ReportMetric(float64(fetchNs)/float64(b.N)/1e6, "fetch_ms")
		b.ReportMetric(float64(checkoutNs)/float64(b.N)/1e6, "checkout_ms")
		b.ReportMetric(float64(writeNs)/float64(b.N)/1e6, "write_ms")
	})
}

// writeBenchFiles writes ten files into a checkout, mirroring the small writes
// a worker performs before it starts doing real work.
func writeBenchFiles(b *testing.B, dir string) {
	for i := 0; i < 10; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("bench-%d.txt", i)), []byte("data\n"), 0o644); err != nil {
			b.Fatalf("write bench file: %v", err)
		}
	}
}

// generateBenchRepo builds a repository with the given number of commits via
// git fast-import. It returns the repository path, or "" when the import could
// not be produced so callers can skip.
func generateBenchRepo(b *testing.B, commits int) string {
	b.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		return ""
	}
	dir := b.TempDir()
	if out, err := git(b, "", "init", "-q", dir); err != nil {
		b.Skipf("git init failed: %s: %v", out, err)
	}

	var sb strings.Builder
	for i := 1; i <= commits; i++ {
		ts := 1600000000 + i
		fmt.Fprintf(&sb, "commit refs/heads/main\n")
		fmt.Fprintf(&sb, "mark :%d\n", i)
		fmt.Fprintf(&sb, "author A U Thor <a@example.com> %d +0000\n", ts)
		fmt.Fprintf(&sb, "committer A U Thor <a@example.com> %d +0000\n", ts)
		msg := fmt.Sprintf("commit %d\n", i)
		fmt.Fprintf(&sb, "data %d\n%s", len(msg), msg)
		if i > 1 {
			fmt.Fprintf(&sb, "from :%d\n", i-1)
		}
		content := fmt.Sprintf("content %d\n", i)
		fmt.Fprintf(&sb, "M 644 inline file-%d.txt\n", i)
		fmt.Fprintf(&sb, "data %d\n%s", len(content), content)
		fmt.Fprintf(&sb, "\n")
	}

	stream := filepath.Join(b.TempDir(), "stream")
	f, err := os.Create(stream)
	if err != nil {
		b.Fatalf("create fast-import stream: %v", err)
	}
	w := bufio.NewWriter(f)
	if _, err := w.WriteString(sb.String()); err != nil {
		b.Fatalf("write fast-import stream: %v", err)
	}
	if err := w.Flush(); err != nil {
		b.Fatalf("flush fast-import stream: %v", err)
	}
	if err := f.Close(); err != nil {
		b.Fatalf("close fast-import stream: %v", err)
	}

	cmd := exec.Command("git", "-C", dir, "fast-import", "--quiet")
	in, err := os.Open(stream)
	if err != nil {
		b.Fatalf("open fast-import stream: %v", err)
	}
	defer in.Close()
	cmd.Stdin = in
	if out, err := cmd.CombinedOutput(); err != nil {
		b.Skipf("git fast-import failed: %s: %v", out, err)
	}
	if out, err := git(b, dir, "reset", "--hard", "refs/heads/main"); err != nil {
		b.Skipf("git reset after fast-import failed: %s: %v", out, err)
	}
	return dir
}
