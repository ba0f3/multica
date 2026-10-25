package daemon

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/multica-ai/multica/server/internal/daemon/repocache"
)

const dependentTestWorkspaceID = "11111111-1111-1111-1111-111111111111"

// repoCacheBackendOnly exposes exactly the repoCacheBackend contract and hides
// every optional interface, the way a test double or a degraded cache does.
type repoCacheBackendOnly struct{ repoCacheBackend }

// failingDependentsCache supports the dependents scan but never answers it.
type failingDependentsCache struct{ repoCacheBackendOnly }

func (failingDependentsCache) LiveDependentCachePaths() (map[string]struct{}, error) {
	return nil, errors.New("dependents scan failed")
}

// newDependentsTestDaemon gives the daemon the real repo cache rooted at the
// GC's .repos directory. That is what makes the GC scan the same records
// RecordDependents writes.
func newDependentsTestDaemon(t *testing.T, repoTTL time.Duration) (*Daemon, *repocache.Cache) {
	t.Helper()
	d := newGCTestDaemon(t, http.NewServeMux())
	d.cfg.GCRepoTTL = repoTTL
	cache := repocache.New(filepath.Join(d.cfg.WorkspacesRoot, reposDirName), d.logger)
	d.repoCache = cache
	return d, cache
}

// newPinnedRepoCache creates one cached bare repo that GCRepoTTL alone would
// evict if no dependent workdir pinned it.
func newPinnedRepoCache(t *testing.T, d *Daemon) string {
	t.Helper()
	barePath := newEvictTestRepo(t, d, dependentTestWorkspaceID, testRepoURL)
	writeLastUsed(t, barePath, time.Now().Add(-48*time.Hour))
	return barePath
}

func recordDependentWorkdir(t *testing.T, cache *repocache.Cache, workDir string, cachePaths ...string) {
	t.Helper()
	if err := cache.RecordDependents(dependentTestWorkspaceID, repocache.Dependent{
		WorkDir:    workDir,
		CachePaths: cachePaths,
		TaskID:     "task-1",
	}); err != nil {
		t.Fatalf("RecordDependents: %v", err)
	}
}

func repoCacheWorkspaceDir(d *Daemon) string {
	return filepath.Join(d.cfg.WorkspacesRoot, reposDirName, dependentTestWorkspaceID)
}

// TestRepoCacheKeptWhileDependentExists covers the whole point of the
// dependents record: an idle cache whose last workdir still exists must not be
// evicted, because that workdir's checkouts borrow objects from it through Git
// alternates.
func TestRepoCacheKeptWhileDependentExists(t *testing.T) {
	t.Parallel()

	d, cache := newDependentsTestDaemon(t, time.Nanosecond)
	barePath := newPinnedRepoCache(t, d)
	workDir := t.TempDir()
	recordDependentWorkdir(t, cache, workDir, barePath)

	stats := runRepoGC(d)

	if _, err := os.Stat(barePath); err != nil {
		t.Fatalf("cache with a live dependent workdir must survive eviction: %v", err)
	}
	if stats.repoCachesReclaimed != 0 {
		t.Errorf("repo_caches_reclaimed = %d, want 0", stats.repoCachesReclaimed)
	}
	if _, err := os.Stat(repoCacheWorkspaceDir(d)); err != nil {
		t.Errorf("workspace cache dir holding the dependent record was removed: %v", err)
	}
}

// TestRepoCacheEvictedAfterDependentRemoved covers release: once the workdir is
// gone the record retains nothing, so the cache and then the per-workspace
// directory (including .dependents) go away.
func TestRepoCacheEvictedAfterDependentRemoved(t *testing.T) {
	t.Parallel()

	d, cache := newDependentsTestDaemon(t, time.Nanosecond)
	barePath := newPinnedRepoCache(t, d)
	workDir := t.TempDir()
	recordDependentWorkdir(t, cache, workDir, barePath)

	if stats := runRepoGC(d); stats.repoCachesReclaimed != 0 {
		t.Fatalf("first cycle reclaimed %d caches, want 0 while the dependent exists", stats.repoCachesReclaimed)
	}
	if err := os.RemoveAll(workDir); err != nil {
		t.Fatalf("remove dependent workdir: %v", err)
	}

	stats := runRepoGC(d)

	if _, err := os.Stat(barePath); !os.IsNotExist(err) {
		t.Fatalf("cache must be evicted once its dependent workdir is gone, stat err = %v", err)
	}
	if stats.repoCachesReclaimed != 1 {
		t.Errorf("repo_caches_reclaimed = %d, want 1", stats.repoCachesReclaimed)
	}
	wsDir := repoCacheWorkspaceDir(d)
	if _, err := os.Stat(wsDir); !os.IsNotExist(err) {
		t.Errorf("workspace cache dir must be removed with its last repo, stat err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(wsDir, repocache.DependentsDirName)); !os.IsNotExist(err) {
		t.Errorf(".dependents must not keep an otherwise empty workspace cache dir alive, stat err = %v", err)
	}
}

// TestRepoCacheKeptAcrossDaemonRestartWithDependent pins the durability half:
// the process that created the checkout can be gone, and a new Daemon/Cache
// over the same root must still honor the record.
func TestRepoCacheKeptAcrossDaemonRestartWithDependent(t *testing.T) {
	t.Parallel()

	d, cache := newDependentsTestDaemon(t, time.Nanosecond)
	barePath := newPinnedRepoCache(t, d)
	workDir := t.TempDir()
	recordDependentWorkdir(t, cache, workDir, barePath)

	restarted := New(d.cfg, d.logger)
	stats := runRepoGC(restarted)

	if _, err := os.Stat(barePath); err != nil {
		t.Fatalf("a restarted daemon must honor the persisted dependent record: %v", err)
	}
	if stats.repoCachesReclaimed != 0 {
		t.Errorf("repo_caches_reclaimed = %d, want 0 after restart", stats.repoCachesReclaimed)
	}
}

// TestRepoCacheMaintenanceSkippedWhileDependent proves the second half of the
// pin: stale agent branches are still deleted, but the heavy reflog/gc pass
// must not run while a dependent exists. The sentinel is a dangling loose blob
// that `gc --prune` reclaims; it survives only because maintenance was skipped,
// and the control cycle at the end shows it was prunable all along.
func TestRepoCacheMaintenanceSkippedWhileDependent(t *testing.T) {
	t.Parallel()

	// Eviction disabled: this test is about the maintenance decision, and the
	// cache must survive both cycles for the sentinel to be comparable.
	d, cache := newDependentsTestDaemon(t, 0)
	barePath := newEvictTestRepo(t, d, dependentTestWorkspaceID, testRepoURL)

	const staleBranch = "agent/stale/87654321"
	runGitForGC(t, "", "-C", barePath, "branch", staleBranch, "HEAD")
	sentinelPath := writeOldLooseBlob(t, barePath, "dependent-maintenance-sentinel", 60*24*time.Hour)
	workDir := t.TempDir()
	recordDependentWorkdir(t, cache, workDir, barePath)

	runRepoGC(d)

	if gitRefExists(t, barePath, "refs/heads/"+staleBranch) {
		t.Fatal("stale agent branch must still be deleted while a dependent pins the cache")
	}
	if _, err := os.Stat(sentinelPath); err != nil {
		t.Fatalf("heavy maintenance pruned an object a live dependent still needs: %v", err)
	}
	if _, err := os.Stat(filepath.Join(barePath, repoMaintenanceMarker)); err != nil {
		t.Fatalf("heavy maintenance must stay pending while a dependent pins the cache: %v", err)
	}

	if err := os.RemoveAll(workDir); err != nil {
		t.Fatalf("remove dependent workdir: %v", err)
	}
	runRepoGC(d)

	if _, err := os.Stat(sentinelPath); !os.IsNotExist(err) {
		t.Fatalf("heavy maintenance should prune the sentinel once the dependent is gone, stat err = %v", err)
	}
}

// TestRepoCacheNoEvictionWhenDependentsScanFails is the fail-safe case: a scan
// that cannot answer must leave every cache exactly as it was, neither evicted
// nor maintained.
func TestRepoCacheNoEvictionWhenDependentsScanFails(t *testing.T) {
	t.Parallel()

	d, cache := newDependentsTestDaemon(t, time.Nanosecond)
	barePath := newPinnedRepoCache(t, d)
	const staleBranch = "agent/stale/87654321"
	runGitForGC(t, "", "-C", barePath, "branch", staleBranch, "HEAD")
	d.repoCache = failingDependentsCache{
		repoCacheBackendOnly: repoCacheBackendOnly{repoCacheBackend: cache},
	}

	stats := runRepoGC(d)

	if _, err := os.Stat(barePath); err != nil {
		t.Fatalf("a failed dependents scan must leave every cache untouched: %v", err)
	}
	if stats.repoCachesReclaimed != 0 {
		t.Errorf("repo_caches_reclaimed = %d, want 0 when the dependents scan fails", stats.repoCachesReclaimed)
	}
	if !gitRefExists(t, barePath, "refs/heads/"+staleBranch) {
		t.Error("a failed dependents scan must skip maintenance as well as eviction")
	}
	if _, err := os.Stat(repoCacheWorkspaceDir(d)); err != nil {
		t.Errorf("a failed dependents scan must not remove workspace cache dirs: %v", err)
	}
}

// TestRepoCacheKeptWhenDependentNamesCacheObjectsDir covers the spelling a
// reused workdir records: its Git alternates file names <bare>/objects, not the
// bare cache itself. Pinning the bare cache is what keeps that checkout usable.
func TestRepoCacheKeptWhenDependentNamesCacheObjectsDir(t *testing.T) {
	t.Parallel()

	d, cache := newDependentsTestDaemon(t, time.Nanosecond)
	barePath := newPinnedRepoCache(t, d)
	workDir := t.TempDir()
	recordDependentWorkdir(t, cache, workDir, filepath.Join(barePath, "objects"))

	stats := runRepoGC(d)

	if _, err := os.Stat(barePath); err != nil {
		t.Fatalf("a dependent naming the cache's objects dir must pin the whole cache: %v", err)
	}
	if stats.repoCachesReclaimed != 0 {
		t.Errorf("repo_caches_reclaimed = %d, want 0", stats.repoCachesReclaimed)
	}
}

// TestRepoCacheWithoutDependentsInterfaceKeepsEviction keeps the optional
// interface optional: a cache backend that cannot report dependents behaves
// exactly as it did before dependents existed.
func TestRepoCacheWithoutDependentsInterfaceKeepsEviction(t *testing.T) {
	t.Parallel()

	d, cache := newDependentsTestDaemon(t, time.Nanosecond)
	barePath := newPinnedRepoCache(t, d)
	d.repoCache = repoCacheBackendOnly{repoCacheBackend: cache}

	stats := runRepoGC(d)

	if _, err := os.Stat(barePath); !os.IsNotExist(err) {
		t.Fatalf("a backend without dependents support must keep the historical eviction, stat err = %v", err)
	}
	if stats.repoCachesReclaimed != 1 {
		t.Errorf("repo_caches_reclaimed = %d, want 1", stats.repoCachesReclaimed)
	}
}
