//go:build linux

package r2dgit

import (
	"bytes"
	"context"
	"os"
	"path"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

type ProtectedFileChange struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

func applyProtectedChanges(ctx context.Context, git, directory, head string, changes []ProtectedFileChange) (string, []byte, error) {
	if !objectID(head) || len(changes) == 0 || len(changes) > 16 {
		return "", nil, ErrScope
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return "", nil, ErrScope
	}
	defer root.Close()
	seen := map[string]bool{}
	total := 0
	for _, change := range changes {
		name := change.Path
		if name == "." || path.Clean(name) != name || path.IsAbs(name) || strings.ContainsAny(name, "\\\x00\r\n") || len(name) > 256 || seen[name] || !utf8.ValidString(change.Content) {
			return "", nil, ErrScope
		}
		seen[name] = true
		total += len(change.Content)
		if total > 32<<10 {
			return "", nil, ErrScope
		}
		parts := strings.Split(name, "/")
		for index, part := range parts {
			if part == ".." || strings.HasPrefix(part, ".") {
				return "", nil, ErrScope
			}
			if index == len(parts)-1 {
				break
			}
			parent := strings.Join(parts[:index+1], "/")
			info, err := root.Lstat(parent)
			if os.IsNotExist(err) {
				if root.Mkdir(parent, 0700) != nil {
					return "", nil, ErrScope
				}
			} else if err != nil || !info.IsDir() {
				return "", nil, ErrScope
			}
		}
		file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
		if err != nil {
			return "", nil, ErrScope
		}
		info, statErr := file.Stat()
		if statErr != nil || !info.Mode().IsRegular() {
			file.Close()
			return "", nil, ErrScope
		}
		if err := file.Truncate(0); err != nil {
			file.Close()
			return "", nil, ErrRuntime
		}
		_, writeErr := file.WriteString(change.Content)
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			return "", nil, ErrRuntime
		}
	}
	ctx, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	run := func(input []byte, limit int, args ...string) ([]byte, error) {
		cmd, err := quarantineCommand(ctx, git, append([]string{"-C", directory, "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "protocol.allow=never", "-c", "commit.gpgsign=false", "-c", "pack.threads=1"}, args...)...)
		if err != nil {
			return nil, err
		}
		cmd.Env = []string{"HOME=" + directory, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_COUNT=0", "GIT_TERMINAL_PROMPT=0", "GIT_NO_REPLACE_OBJECTS=1", "GIT_AUTHOR_NAME=Multica", "GIT_AUTHOR_EMAIL=protected@invalid", "GIT_COMMITTER_NAME=Multica", "GIT_COMMITTER_EMAIL=protected@invalid", "LC_ALL=C"}
		out := &boundedBuffer{limit: limit}
		cmd.Stdout = out
		cmd.Stderr = &boundedBuffer{limit: 4096}
		cmd.Stdin = bytes.NewReader(input)
		if cmd.Run() != nil {
			return nil, ErrRuntime
		}
		return out.Bytes(), nil
	}
	if _, err := run(nil, 1024, "add", "--all", "--", "."); err != nil {
		return "", nil, err
	}
	tree, err := run(nil, 1024, "write-tree")
	if err != nil {
		return "", nil, err
	}
	treeID := strings.TrimSpace(string(tree))
	if !objectID(treeID) {
		return "", nil, ErrScope
	}
	commit, err := run([]byte("Protected workload changes\n"), 1024, "commit-tree", treeID, "-p", head)
	if err != nil {
		return "", nil, err
	}
	newHead := strings.TrimSpace(string(commit))
	if !objectID(newHead) {
		return "", nil, ErrScope
	}
	pack, err := run([]byte(newHead+"\n"), 512<<10, "pack-objects", "--stdout", "--revs", "--threads=1")
	if err != nil || !packFraming(pack) {
		clear(pack)
		return "", nil, ErrScope
	}
	return newHead, pack, nil
}
