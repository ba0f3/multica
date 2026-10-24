package repocache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// dependentsRecordPath computes where RecordDependents must store workDir: one
// JSON record per absolute workdir, named by the first 16 lowercase hex chars
// of its SHA-256, under the workspace's .dependents directory. It deliberately
// repeats the naming rule instead of calling the implementation, so a change to
// the naming scheme fails the tests rather than silently passing them.
func dependentsRecordPath(root, workspaceID, workDir string) string {
	sum := sha256.Sum256([]byte(workDir))
	return filepath.Join(root, workspaceID, ".dependents", hex.EncodeToString(sum[:])[:16]+".json")
}

func readDependentRecord(t *testing.T, path string) Dependent {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read dependents record %s: %v", path, err)
	}
	var dep Dependent
	if err := json.Unmarshal(data, &dep); err != nil {
		t.Fatalf("decode dependents record %s: %v", path, err)
	}
	return dep
}

func TestDependentsRecordWritesHashedFileAndReplaces(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	cache := New(root, testLogger())
	workDir := t.TempDir()
	cachePath := filepath.Join(root, "ws-1", "github.com+org+repo.git")

	if err := cache.RecordDependents("ws-1", Dependent{
		WorkDir:    workDir,
		CachePaths: []string{cachePath},
		TaskID:     "task-1",
		AttemptID:  "attempt-1",
	}); err != nil {
		t.Fatalf("RecordDependents: %v", err)
	}

	recordPath := dependentsRecordPath(root, "ws-1", workDir)
	info, err := os.Stat(recordPath)
	if err != nil {
		t.Fatalf("dependents record %s: %v", recordPath, err)
	}
	if runtime.GOOS != "windows" {
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("record mode = %o, want 600", got)
		}
		dirInfo, err := os.Stat(filepath.Dir(recordPath))
		if err != nil {
			t.Fatalf("dependents dir: %v", err)
		}
		if got := dirInfo.Mode().Perm(); got != 0o700 {
			t.Fatalf("dependents dir mode = %o, want 700", got)
		}
	}
	want := Dependent{
		WorkDir:    workDir,
		CachePaths: []string{cachePath},
		TaskID:     "task-1",
		AttemptID:  "attempt-1",
	}
	if got := readDependentRecord(t, recordPath); !reflect.DeepEqual(got, want) {
		t.Fatalf("record = %+v, want %+v", got, want)
	}

	// A second record for the same workdir replaces the first: one task attempt
	// succeeding a previous one must not leave two retention claims behind.
	replacement := filepath.Join(root, "ws-1", "gitlab.com+org+other.git")
	if err := cache.RecordDependents("ws-1", Dependent{
		WorkDir:    workDir,
		CachePaths: []string{replacement},
		TaskID:     "task-2",
		AttemptID:  "attempt-2",
	}); err != nil {
		t.Fatalf("RecordDependents (replace): %v", err)
	}
	entries, err := os.ReadDir(filepath.Dir(recordPath))
	if err != nil {
		t.Fatalf("read dependents dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("dependents dir has %d entries, want the single replaced record", len(entries))
	}
	if got := readDependentRecord(t, recordPath); !reflect.DeepEqual(got, Dependent{
		WorkDir:    workDir,
		CachePaths: []string{replacement},
		TaskID:     "task-2",
		AttemptID:  "attempt-2",
	}) {
		t.Fatalf("replaced record = %+v", got)
	}
}

func TestLiveDependentCachePathsReturnsEveryPathOfLiveRecord(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	cache := New(root, testLogger())
	workDirA := t.TempDir()
	workDirB := t.TempDir()
	// Cleaned on write: the record must not keep a path the retention check
	// could fail to match against the cache's own absolute paths. Built by
	// concatenation because filepath.Join would clean it before the record is
	// written.
	sep := string(filepath.Separator)
	cachePathA := filepath.Join(root, "ws-1") + sep + "uncleaned" + sep + ".." + sep + "github.com+org+repo-a.git"
	cachePathB := filepath.Join(root, "ws-2", "github.com+org+repo-b.git")
	cachePathC := filepath.Join(root, "ws-2", "github.com+org+repo-c.git")

	if err := cache.RecordDependents("ws-1", Dependent{
		WorkDir:    workDirA,
		CachePaths: []string{cachePathA},
		TaskID:     "task-a",
	}); err != nil {
		t.Fatalf("RecordDependents(ws-1): %v", err)
	}
	// One task workdir can depend on several bare caches, and different
	// workspaces have their own records under the same root.
	if err := cache.RecordDependents("ws-2", Dependent{
		WorkDir:    workDirB,
		CachePaths: []string{cachePathB, cachePathC},
	}); err != nil {
		t.Fatalf("RecordDependents(ws-2): %v", err)
	}

	live, err := cache.LiveDependentCachePaths()
	if err != nil {
		t.Fatalf("LiveDependentCachePaths: %v", err)
	}
	want := map[string]struct{}{
		filepath.Clean(cachePathA): {},
		cachePathB:                 {},
		cachePathC:                 {},
	}
	if !reflect.DeepEqual(live, want) {
		t.Fatalf("live paths = %v, want %v", live, want)
	}
	if _, ok := live[cachePathA]; ok {
		t.Fatalf("uncleaned path survived as its own entry: %v", live)
	}
}

// TestLiveDependentCachePathsDropsRecordsOfRemovedWorkdir covers daemon
// restart: the next instance sees the record, finds the workdir gone, and both
// stops retaining the cache and deletes the record so it is not rescanned
// forever.
func TestLiveDependentCachePathsDropsRecordsOfRemovedWorkdir(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	cache := New(root, testLogger())
	keptWorkDir := t.TempDir()
	removedWorkDir := t.TempDir()
	keptCache := filepath.Join(root, "ws-1", "kept.git")
	orphanCache := filepath.Join(root, "ws-1", "orphan.git")

	for _, dep := range []Dependent{
		{WorkDir: keptWorkDir, CachePaths: []string{keptCache}},
		{WorkDir: removedWorkDir, CachePaths: []string{orphanCache}},
	} {
		if err := cache.RecordDependents("ws-1", dep); err != nil {
			t.Fatalf("RecordDependents(%s): %v", dep.WorkDir, err)
		}
	}
	if err := os.RemoveAll(removedWorkDir); err != nil {
		t.Fatalf("remove workdir: %v", err)
	}

	restarted := New(root, testLogger())
	live, err := restarted.LiveDependentCachePaths()
	if err != nil {
		t.Fatalf("LiveDependentCachePaths after restart: %v", err)
	}
	if want := map[string]struct{}{keptCache: {}}; !reflect.DeepEqual(live, want) {
		t.Fatalf("live paths = %v, want %v", live, want)
	}
	if _, err := os.Stat(dependentsRecordPath(root, "ws-1", removedWorkDir)); !os.IsNotExist(err) {
		t.Fatalf("stale record still present, stat error = %v", err)
	}
	if _, err := os.Stat(dependentsRecordPath(root, "ws-1", keptWorkDir)); err != nil {
		t.Fatalf("live record was removed: %v", err)
	}
}

func TestLiveDependentCachePathsIgnoresMalformedRecords(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	cache := New(root, testLogger())
	workDir := t.TempDir()
	cachePath := filepath.Join(root, "ws-1", "github.com+org+repo.git")
	if err := cache.RecordDependents("ws-1", Dependent{WorkDir: workDir, CachePaths: []string{cachePath}}); err != nil {
		t.Fatalf("RecordDependents: %v", err)
	}

	dir := filepath.Join(root, "ws-1", ".dependents")
	malformed := map[string]string{
		// Corrupt JSON, e.g. a truncated write from outside the daemon.
		"0000000000000000.json": "{not json",
		// Well-formed JSON naming a relative workdir: the daemon never writes
		// one, and statting it would resolve against the daemon's own cwd.
		"1111111111111111.json": `{"workdir":"relative/workdir","cache_paths":["` + filepath.ToSlash(filepath.Join(root, "ws-1", "elsewhere.git")) + `"]}`,
	}
	for name, contents := range malformed {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0o600); err != nil {
			t.Fatalf("write malformed record %s: %v", name, err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "not-a-record.txt"), []byte("ignored"), 0o600); err != nil {
		t.Fatalf("write unrelated file: %v", err)
	}
	if err := os.Mkdir(filepath.Join(dir, "directory.json"), 0o700); err != nil {
		t.Fatalf("create record-shaped directory: %v", err)
	}

	live, err := cache.LiveDependentCachePaths()
	if err != nil {
		t.Fatalf("LiveDependentCachePaths with malformed records: %v", err)
	}
	if want := map[string]struct{}{cachePath: {}}; !reflect.DeepEqual(live, want) {
		t.Fatalf("live paths = %v, want %v", live, want)
	}
	for _, name := range []string{"0000000000000000.json", "1111111111111111.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("malformed record %s was not left for inspection: %v", name, err)
		}
	}
}

func TestLiveDependentCachePathsWithoutRecordsIsEmpty(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	cache := New(root, testLogger())
	if err := os.MkdirAll(filepath.Join(root, "ws-1", "repo.git"), 0o755); err != nil {
		t.Fatalf("create workspace cache: %v", err)
	}

	live, err := cache.LiveDependentCachePaths()
	if err != nil {
		t.Fatalf("LiveDependentCachePaths: %v", err)
	}
	if len(live) != 0 {
		t.Fatalf("live paths = %v, want none", live)
	}

	// A cache root that has never been populated (first daemon start) has no
	// dependents either.
	fresh := New(filepath.Join(t.TempDir(), "missing"), testLogger())
	live, err = fresh.LiveDependentCachePaths()
	if err != nil {
		t.Fatalf("LiveDependentCachePaths on missing root: %v", err)
	}
	if len(live) != 0 {
		t.Fatalf("live paths on missing root = %v, want none", live)
	}
}

func TestRecordDependentsRejectsInvalidPaths(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	cache := New(root, testLogger())
	absoluteDir := t.TempDir()
	cachePath := filepath.Join(root, "ws-1", "repo.git")

	tests := []struct {
		name        string
		workspaceID string
		dep         Dependent
		wantInError string
	}{
		{
			name:        "relative workdir",
			workspaceID: "ws-1",
			dep:         Dependent{WorkDir: filepath.Join("relative", "workdir"), CachePaths: []string{cachePath}},
			wantInError: "workdir",
		},
		{
			name:        "empty workdir",
			workspaceID: "ws-1",
			dep:         Dependent{CachePaths: []string{cachePath}},
			wantInError: "workdir",
		},
		{
			name:        "relative cache path",
			workspaceID: "ws-1",
			dep:         Dependent{WorkDir: absoluteDir, CachePaths: []string{filepath.Join("relative", "repo.git")}},
			wantInError: "cache path",
		},
		{
			name:        "empty cache path",
			workspaceID: "ws-1",
			dep:         Dependent{WorkDir: absoluteDir, CachePaths: []string{""}},
			wantInError: "cache path",
		},
		{
			// An empty workspace writes outside every workspace's records, where
			// the retention scan would never see it.
			name:        "empty workspace",
			workspaceID: "",
			dep:         Dependent{WorkDir: absoluteDir, CachePaths: []string{cachePath}},
			wantInError: "workspace",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cache.RecordDependents(tt.workspaceID, tt.dep)
			if err == nil {
				t.Fatal("RecordDependents accepted invalid input")
			}
			if !strings.Contains(strings.ToLower(err.Error()), tt.wantInError) {
				t.Fatalf("error = %q, want it to mention %q", err, tt.wantInError)
			}
			if _, statErr := os.Stat(dependentsRecordPath(root, "ws-1", absoluteDir)); !os.IsNotExist(statErr) {
				t.Fatalf("invalid input wrote a record, stat error = %v", statErr)
			}
		})
	}
}
