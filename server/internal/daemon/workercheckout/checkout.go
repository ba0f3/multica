package workercheckout

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/multica-ai/multica/server/internal/daemon/processtree"
	"github.com/multica-ai/multica/server/internal/daemon/repocache"
)

// Options controls how Checkout builds or updates a task checkout.
type Options struct {
	// Ref optionally overrides the commit to check out. When set it names a
	// branch, tag, or commit that may be fetched from origin. Empty uses
	// entry.CommitSHA, which the daemon already fetched and resolved.
	Ref string
	// Fresh discards an existing checkout's local work — uncommitted changes,
	// untracked files, its branch position — and starts over from the base.
	// It is the only path that resets local work.
	Fresh bool
	// AgentName and TaskID name the branch the checkout starts on; they must
	// match what the host daemon used so branch names stay identical.
	AgentName string
	TaskID    string
}

// Result describes how Checkout left the checkout at Result.Path.
type Result struct {
	Path        string
	Branch      string
	BaseSHA     string
	Kept        bool // set when an existing checkout was left exactly as it was
	Ahead       int
	Behind      int
	Uncommitted int
	Unpushed    int
}

// Checkout builds a fresh checkout at <workDir>/<RepoDirName(entry.URL)> from
// the bare cache entry.CachePath, or updates an existing checkout there.
//
// A fresh checkout borrows the cache's objects through an alternates file
// instead of copying them, so it never hardlinks or mutates the shared cache.
// It works with an unreachable remote: the daemon already fetched and resolved
// the SHA, and only Options.Ref may contact origin. Options.Fresh is the only
// path that discards local work.
func Checkout(ctx context.Context, workDir string, entry Entry, opts Options) (Result, error) {
	if err := ValidateEntry(entry); err != nil {
		return Result{}, err
	}
	target := filepath.Join(workDir, repocache.RepoDirName(entry.URL))
	branch := repocache.BranchName(opts.AgentName, opts.TaskID)

	if existing, err := isExistingCheckout(target); err != nil {
		return Result{}, fmt.Errorf("stat checkout: %w", err)
	} else if existing {
		return updateExistingCheckout(ctx, target, entry, opts, branch)
	}
	return createCheckout(ctx, target, entry, opts, branch)
}

// isExistingCheckout reports whether target already holds a git checkout. It
// distinguishes a missing .git (not a checkout) from a stat error the caller
// must surface.
func isExistingCheckout(target string) (bool, error) {
	_, err := os.Stat(filepath.Join(target, ".git"))
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// createCheckout initializes a fresh checkout whose objects are borrowed from
// the cache via alternates. On failure it removes the partial checkout so a
// retry does not misclassify it as an existing one.
func createCheckout(ctx context.Context, target string, entry Entry, opts Options, branch string) (Result, error) {
	if err := os.MkdirAll(target, 0o755); err != nil {
		return Result{}, fmt.Errorf("create checkout directory: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(target)
		}
	}()

	if err := runGit(ctx, "", "init", "-q", target); err != nil {
		return Result{}, err
	}
	if err := runGit(ctx, target, "remote", "add", "origin", entry.URL); err != nil {
		return Result{}, err
	}
	if err := writeAlternates(target, entry.CachePath); err != nil {
		return Result{}, err
	}
	if err := copyCacheRefs(ctx, entry.CachePath, target); err != nil {
		return Result{}, err
	}
	baseSHA, err := resolveSHA(ctx, target, entry, opts.Ref)
	if err != nil {
		return Result{}, err
	}
	if err := runGit(ctx, target, "checkout", "-q", "-B", branch, baseSHA); err != nil {
		return Result{}, err
	}

	cleanup = false
	return Result{Path: target, Branch: branch, BaseSHA: baseSHA}, nil
}

// writeAlternates points the checkout's object lookup at the cache's object
// directory, so the checkout reads the cache's objects without copying or
// hardlinking them.
func writeAlternates(target, cachePath string) error {
	infoDir := filepath.Join(target, ".git", "objects", "info")
	if err := os.MkdirAll(infoDir, 0o755); err != nil {
		return fmt.Errorf("create objects/info directory: %w", err)
	}
	contents := filepath.Join(cachePath, "objects") + "\n"
	if err := os.WriteFile(filepath.Join(infoDir, "alternates"), []byte(contents), 0o644); err != nil {
		return fmt.Errorf("write alternates: %w", err)
	}
	return nil
}

// copyCacheRefs mirrors the cache's remote-tracking and tag refs into the
// checkout so an agent can diff and push against the same origin/* refs the
// daemon fetched. Symbolic refs (refs/remotes/origin/HEAD) are skipped because
// their %(symref) field is non-empty; copying one would materialize a plain
// ref pointing at its target's object instead of the symbolic pointer.
func copyCacheRefs(ctx context.Context, cachePath, target string) error {
	out, err := gitOutput(ctx, cachePath, "for-each-ref", "--format=%(refname) %(objectname) %(symref)", "refs/remotes/origin", "refs/tags")
	if err != nil {
		return fmt.Errorf("list cache refs: %w", err)
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ref, sha := fields[0], fields[1]
		if len(fields) >= 3 && fields[2] != "" {
			continue // symbolic ref
		}
		if err := runGit(ctx, target, "update-ref", ref, sha); err != nil {
			return fmt.Errorf("copy ref %s: %w", ref, err)
		}
	}
	return nil
}

// resolveSHA returns the commit to check out: opts.Ref when set (fetched from
// origin if the checkout does not already have it), otherwise the
// daemon-resolved entry.CommitSHA. Only the opts.Ref path may touch the
// network.
func resolveSHA(ctx context.Context, target string, entry Entry, ref string) (string, error) {
	if ref == "" {
		return entry.CommitSHA, nil
	}
	if sha, err := resolveCommit(ctx, target, ref); err == nil {
		return sha, nil
	}
	if err := runGit(ctx, target, "fetch", "--no-tags", "origin", ref); err != nil {
		return "", fmt.Errorf("fetch requested ref %q: %w", ref, err)
	}
	if sha, err := resolveCommit(ctx, target, "refs/remotes/origin/"+ref); err == nil {
		return sha, nil
	}
	// A branch ref lands in refs/remotes/origin/<ref>, but a tag or raw SHA is
	// stored only in FETCH_HEAD, so fall back to that before giving up.
	if sha, err := resolveCommit(ctx, target, "FETCH_HEAD"); err == nil {
		return sha, nil
	}
	return resolveCommit(ctx, target, ref)
}

func resolveCommit(ctx context.Context, repoPath, ref string) (string, error) {
	out, err := gitOutput(ctx, repoPath, "rev-parse", "--verify", ref+"^{commit}")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// updateExistingCheckout reconciles a checkout that already exists at target.
// A non-fresh checkout is left exactly as it is — HEAD, branch, index, and
// dirty files are kept, and only the ahead/behind/uncommitted/unpushed counts
// are reported against the new base. Fresh discards local work and re-checks
// out the base.
func updateExistingCheckout(ctx context.Context, target string, entry Entry, opts Options, branch string) (Result, error) {
	origin, err := gitOutput(ctx, target, "remote", "get-url", "origin")
	if err != nil {
		return Result{}, fmt.Errorf("resolve checkout origin: %w", err)
	}
	if origin != entry.URL {
		return Result{}, fmt.Errorf("checkout origin %q does not match %q", origin, entry.URL)
	}

	baseSHA, err := resolveSHA(ctx, target, entry, opts.Ref)
	if err != nil {
		return Result{}, err
	}

	if opts.Fresh {
		if err := runGit(ctx, target, "reset", "--hard"); err != nil {
			return Result{}, err
		}
		if err := runGit(ctx, target, "clean", "-fdx"); err != nil {
			return Result{}, err
		}
		if err := runGit(ctx, target, "checkout", "-q", "-B", branch, baseSHA); err != nil {
			return Result{}, err
		}
		return Result{Path: target, Branch: branch, BaseSHA: baseSHA}, nil
	}

	ahead, behind, err := countAheadBehind(ctx, target, baseSHA)
	if err != nil {
		return Result{}, err
	}
	uncommitted, err := countUncommitted(ctx, target)
	if err != nil {
		return Result{}, err
	}
	unpushed, err := countUnpushed(ctx, target)
	if err != nil {
		return Result{}, err
	}
	// Empty when HEAD is detached.
	currentBranch, _ := gitOutput(ctx, target, "symbolic-ref", "--short", "HEAD")
	return Result{
		Path:        target,
		Branch:      currentBranch,
		BaseSHA:     baseSHA,
		Kept:        true,
		Ahead:       ahead,
		Behind:      behind,
		Uncommitted: uncommitted,
		Unpushed:    unpushed,
	}, nil
}

// countAheadBehind reports how many commits HEAD has that base lacks (ahead)
// and how many base has that HEAD lacks (behind).
func countAheadBehind(ctx context.Context, repoPath, base string) (ahead, behind int, err error) {
	out, err := gitOutput(ctx, repoPath, "rev-list", "--left-right", "--count", "HEAD..."+base)
	if err != nil {
		return 0, 0, fmt.Errorf("count ahead/behind: %w", err)
	}
	fields := strings.Fields(out)
	if len(fields) != 2 {
		return 0, 0, fmt.Errorf("count ahead/behind: unexpected output %q", out)
	}
	if ahead, err = strconv.Atoi(fields[0]); err != nil {
		return 0, 0, fmt.Errorf("parse ahead count %q: %w", fields[0], err)
	}
	if behind, err = strconv.Atoi(fields[1]); err != nil {
		return 0, 0, fmt.Errorf("parse behind count %q: %w", fields[1], err)
	}
	return ahead, behind, nil
}

// countUncommitted reports the number of paths `git status` lists, untracked
// files included.
func countUncommitted(ctx context.Context, repoPath string) (int, error) {
	out, err := gitOutput(ctx, repoPath, "status", "--porcelain", "--untracked-files=all")
	if err != nil {
		return 0, fmt.Errorf("count uncommitted: %w", err)
	}
	count := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}
	return count, nil
}

// countUnpushed reports the commits on HEAD that no remote-tracking ref
// reaches. HEAD precedes --not so it stays a positive tip; --not then marks
// every remote-tracking ref as an exclusion.
func countUnpushed(ctx context.Context, repoPath string) (int, error) {
	out, err := gitOutput(ctx, repoPath, "rev-list", "--count", "HEAD", "--not", "--remotes")
	if err != nil {
		return 0, fmt.Errorf("count unpushed: %w", err)
	}
	count, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil {
		return 0, fmt.Errorf("parse unpushed count %q: %w", out, err)
	}
	return count, nil
}

// runGit runs git in dir, returning a wrapped error carrying stderr.
func runGit(ctx context.Context, dir string, args ...string) error {
	_, err := gitCombined(ctx, dir, args...)
	return err
}

// gitOutput runs git in dir and returns its trimmed combined output.
func gitOutput(ctx context.Context, dir string, args ...string) (string, error) {
	out, err := gitCombined(ctx, dir, args...)
	return strings.TrimSpace(out), err
}

func gitCombined(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	// The cache is owned by the daemon, so a worker running as a different UID
	// needs the same git hardening repocache uses: safe.directory=* trusts the
	// bind-mounted cache, and credential prompting is disabled so a fetch that
	// lacks credentials fails fast instead of blocking.
	cmd.Env = repocache.GitEnv()
	out, err := processtree.CombinedOutput(ctx, cmd, 5*time.Second)
	if err != nil {
		return strings.TrimSpace(string(out)), fmt.Errorf("git %v: %s: %w", args, strings.TrimSpace(string(out)), err)
	}
	return strings.TrimSpace(string(out)), nil
}
