package execenv

import (
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// mirrorProviderTree copies src into dst for an isolated worker's task home.
//
// It is the shared implementation behind the provider-specific isolated-home
// seeders (Claude, Antigravity). The rules match prepareOpenCodeIsolatedHome:
// walk the source, never follow host symlinks, create directories 0700, and
// copy regular files preserving their host mode (0600 by default). The one
// difference is the destination policy: files and directories are created only
// when missing, so a reused task home keeps whatever a prior run refreshed and
// a second prepare never overwrites it.
//
// A missing source is not an error: the caller logs a warning that auth may
// fail and continues. A missing or unreadable file mid-copy is surfaced so the
// caller can decide whether the copy is still usable.
func mirrorProviderTree(src, dst string, skipDirs map[string]bool, logger *slog.Logger) error {
	src = filepath.Clean(src)
	if _, err := os.Stat(src); err != nil {
		if os.IsNotExist(err) {
			if logger != nil {
				logger.Warn("execenv: provider home source missing (isolated run may fail auth)", "path", src)
			}
			return nil
		}
		return err
	}
	return filepath.WalkDir(src, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if entry.IsDir() && skipDirs[filepath.Base(rel)] {
			return fs.SkipDir
		}
		target := filepath.Join(dst, rel)
		if entry.IsDir() {
			// Create the directory only when missing so a reused home keeps
			// its refreshed contents; MkdirAll is a no-op when it exists.
			if _, err := os.Stat(target); os.IsNotExist(err) {
				if err := os.MkdirAll(target, 0o700); err != nil {
					return err
				}
			}
			return nil
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			// Never follow host symlinks into the worker; credentials must be copies.
			if logger != nil {
				logger.Warn("execenv: skip provider home symlink in isolated copy", "path", path)
			}
			return nil
		}
		// Copy files only if the target is missing so a reused task home keeps
		// its refreshed credentials rather than being rolled back to the host
		// snapshot from its first prepare.
		if _, err := os.Stat(target); err == nil {
			return nil
		} else if !os.IsNotExist(err) {
			return err
		}
		if err := copyRegularFile(path, target, entry); err != nil {
			return fmt.Errorf("copy %s: %w", path, err)
		}
		return nil
	})
}

// claudeIsolatedHomeSkipDirs are the bulky Claude Code session/history trees
// that are not needed for auth and would otherwise grow every task-home copy.
// Each is matched by its directory basename anywhere under ~/.claude; auth and
// settings files elsewhere in the tree are still copied.
var claudeIsolatedHomeSkipDirs = dirSet(
	"projects",
	"todos",
	"stats",
	"logs",
	"shell-snapshots",
	"file-history",
	"session-env",
	"downloads",
	"cache",
)

// antigravityIsolatedHomeSkipDirs are the disposable Antigravity trees that
// hold no auth and no resumeable conversation. antigravity-cli/brain is
// deliberately kept: `agy --conversation` resume reads transcripts from there.
var antigravityIsolatedHomeSkipDirs = dirSet(
	"tmp",
	"cache",
	"history",
)

func dirSet(names ...string) map[string]bool {
	set := make(map[string]bool, len(names))
	for _, name := range names {
		set[name] = true
	}
	return set
}

// claudeSourceHome returns the daemon user's Claude Code config source for the
// isolated task-home copy. CLAUDE_CONFIG_DIR wins when set, matching the CLI's
// own override; otherwise the default is ~/.claude.
func claudeSourceHome() (string, error) {
	if dir := strings.TrimSpace(os.Getenv("CLAUDE_CONFIG_DIR")); dir != "" {
		if !filepath.IsAbs(dir) {
			return "", fmt.Errorf("CLAUDE_CONFIG_DIR must be an absolute path")
		}
		return filepath.Clean(dir), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve user home: %w", err)
	}
	return filepath.Join(home, ".claude"), nil
}

// antigravitySourceHome returns the daemon user's ~/.gemini source directory
// for the isolated task-home copy.
func antigravitySourceHome() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve user home: %w", err)
	}
	return filepath.Join(home, ".gemini"), nil
}

// prepareClaudeIsolatedHome mirrors the daemon user's Claude Code config and
// credentials into the task home. Auth lives in ~/.claude (credentials.json,
// settings, plugins, skills) plus ~/.claude.json (MCP and user config); both
// must be copies so the worker never sees a host path.
func prepareClaudeIsolatedHome(taskHome string, logger *slog.Logger) error {
	if strings.TrimSpace(taskHome) == "" {
		return fmt.Errorf("task home is required")
	}
	configSrc, err := claudeSourceHome()
	if err != nil {
		return err
	}
	if err := mirrorProviderTree(configSrc, filepath.Join(taskHome, ".claude"), claudeIsolatedHomeSkipDirs, logger); err != nil {
		return fmt.Errorf("copy claude config: %w", err)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("resolve user home: %w", err)
	}
	stateSrc := filepath.Join(home, ".claude.json")
	target := filepath.Join(taskHome, ".claude.json")
	stateInfo, err := os.Lstat(stateSrc)
	if err != nil {
		if os.IsNotExist(err) {
			if logger != nil {
				logger.Warn("execenv: claude state source missing (isolated run may fail auth)", "path", stateSrc)
			}
			return nil
		}
		return err
	}
	if stateInfo.Mode()&fs.ModeSymlink != 0 {
		// Never follow host symlinks into the worker; credentials must be copies.
		if logger != nil {
			logger.Warn("execenv: skip claude state symlink in isolated copy", "path", stateSrc)
		}
		return nil
	}
	// Copy only if the target is missing so a reused task home keeps its
	// refreshed credentials.
	if _, statErr := os.Stat(target); statErr == nil {
		return nil
	} else if !os.IsNotExist(statErr) {
		return statErr
	}
	if err := copyRegularFile(stateSrc, target, fileInfoEntry(stateInfo)); err != nil {
		return fmt.Errorf("copy claude state: %w", err)
	}
	return nil
}

// fileInfoEntry adapts an fs.FileInfo into an fs.DirEntry so a single top-level
// file can be copied through copyRegularFile, which reads the source mode from
// a DirEntry.
func fileInfoEntry(info fs.FileInfo) fs.DirEntry {
	return &infoDirEntry{info: info}
}

type infoDirEntry struct {
	info fs.FileInfo
}

func (e *infoDirEntry) Name() string               { return e.info.Name() }
func (e *infoDirEntry) IsDir() bool                { return e.info.IsDir() }
func (e *infoDirEntry) Type() fs.FileMode          { return e.info.Mode().Type() }
func (e *infoDirEntry) Info() (fs.FileInfo, error) { return e.info, nil }

// prepareAntigravityIsolatedHome mirrors the daemon user's ~/.gemini auth and
// app data into the task home. Top-level auth/config JSON files and the
// antigravity-cli/ app data (including brain, which --conversation resume
// reads) are copied; disposable tmp/cache/history trees are skipped.
func prepareAntigravityIsolatedHome(taskHome string, logger *slog.Logger) error {
	if strings.TrimSpace(taskHome) == "" {
		return fmt.Errorf("task home is required")
	}
	src, err := antigravitySourceHome()
	if err != nil {
		return err
	}
	return mirrorProviderTree(src, filepath.Join(taskHome, ".gemini"), antigravityIsolatedHomeSkipDirs, logger)
}
