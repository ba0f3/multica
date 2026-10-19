package r2dgit

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// GitQuarantine validates objects in a separate process with an empty
// environment and fresh object database. It never receives a key or SSH socket.
// This is pack validation, not the protected workload sandbox.
type GitQuarantine struct{ GitExecutable, Root string }

func packFraming(pack []byte) bool {
	if len(pack) < 32 || len(pack) > maxPackBytes || string(pack[:4]) != "PACK" {
		return false
	}
	version := binary.BigEndian.Uint32(pack[4:8])
	if version != 2 && version != 3 || binary.BigEndian.Uint32(pack[8:12]) > 32768 {
		return false
	}
	sum := sha1.Sum(pack[:len(pack)-20])
	return bytes.Equal(sum[:], pack[len(pack)-20:])
}

func (q GitQuarantine) Validate(ctx context.Context, pack []byte, head string) error {
	_, err := q.prepare(ctx, nil, pack, RefUpdate{New: head}, false)
	return err
}

// Prepare imports an authenticated base and untrusted (possibly thin) pack,
// checks a closed commit graph and fast-forward, then exports only reachable
// objects. Caller bytes are copied before parsing; no key enters this process.
func (q GitQuarantine) Prepare(ctx context.Context, base, incoming []byte, u RefUpdate) ([]byte, error) {
	if !u.valid() || (u.Old != zeroObject && len(base) == 0) || (u.Old == zeroObject && len(base) != 0) {
		return nil, ErrScope
	}
	return q.prepare(ctx, base, incoming, u, true)
}

func (q GitQuarantine) prepare(ctx context.Context, base, incoming []byte, u RefUpdate, write bool) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if !filepath.IsAbs(q.GitExecutable) || !filepath.IsAbs(q.Root) || !objectID(u.New) || u.New == zeroObject {
		return nil, ErrUnavailable
	}
	if len(base) > maxPackBytes || len(incoming) > maxPackBytes {
		return nil, ErrScope
	}
	incoming = bytes.Clone(incoming)
	defer clear(incoming)
	base = bytes.Clone(base)
	defer clear(base)
	if !packFraming(incoming) || len(base) > 0 && !packFraming(base) {
		return nil, ErrScope
	}
	info, err := os.Stat(q.GitExecutable)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
		return nil, ErrUnavailable
	}
	dir, err := os.MkdirTemp(q.Root, "git-quarantine-")
	if err != nil {
		return nil, ErrUnavailable
	}
	defer os.RemoveAll(dir)
	run := func(input []byte, limit int, args ...string) ([]byte, error) {
		cmd, err := quarantineCommand(ctx, q.GitExecutable, append([]string{"-c", "core.hooksPath=/dev/null", "-c", "protocol.allow=never", "-c", "pack.threads=1", "-c", "index.threads=1"}, args...)...)
		if err != nil {
			return nil, err
		}
		cmd.Env = []string{"HOME=" + dir, "XDG_CONFIG_HOME=" + dir, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_COUNT=0", "GIT_TERMINAL_PROMPT=0", "GIT_NO_REPLACE_OBJECTS=1", "LC_ALL=C"}
		cmd.Stdin = bytes.NewReader(input)
		out, stderr := &boundedBuffer{limit: limit}, &boundedBuffer{limit: 4096}
		cmd.Stdout, cmd.Stderr = out, stderr
		if cmd.Run() != nil {
			return nil, ErrProvider
		}
		return out.Bytes(), nil
	}
	repo := filepath.Join(dir, "objects.git")
	if _, err = run(nil, 1<<20, "init", "--bare", "--template=", repo); err != nil {
		return nil, err
	}
	git := func(input []byte, limit int, args ...string) ([]byte, error) {
		return run(input, limit, append([]string{"--git-dir=" + repo}, args...)...)
	}
	if len(base) > 0 {
		if _, err = git(base, 1<<20, "index-pack", "--threads=1", "--strict", "--stdin"); err != nil {
			return nil, err
		}
	}
	args := []string{"index-pack", "--threads=1", "--strict", "--stdin"}
	if write {
		args = append(args, "--fix-thin")
	}
	if _, err = git(incoming, 1<<20, args...); err != nil {
		return nil, err
	}
	indexes, err := filepath.Glob(filepath.Join(repo, "objects", "pack", "*.idx"))
	if err != nil || len(indexes) < 1 || len(indexes) > 2 {
		return nil, ErrProvider
	}
	var expanded uint64
	count := 0
	for _, idx := range indexes {
		metadata, err := git(nil, 1<<20, "verify-pack", "-v", idx)
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(metadata), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 5 || len(fields[0]) != 40 {
				continue
			}
			size, err := strconv.ParseUint(fields[2], 10, 64)
			if err != nil || size > 8<<20 || size > (64<<20)-expanded {
				return nil, ErrScope
			}
			expanded += size
			count++
			if count > 32768 {
				return nil, ErrScope
			}
		}
	}
	if count == 0 {
		return nil, ErrProvider
	}
	objectType, typeErr := git(nil, 1<<20, "cat-file", "-t", u.New)
	if typeErr != nil || string(objectType) != "commit\n" {
		return nil, ErrScope
	}
	if write && u.Old != zeroObject {
		oldType, typeErr := git(nil, 1<<20, "cat-file", "-t", u.Old)
		if typeErr != nil || string(oldType) != "commit\n" {
			return nil, ErrScope
		}
		if _, err = git(nil, 1<<20, "merge-base", "--is-ancestor", u.Old, u.New); err != nil {
			return nil, ErrScope
		}
	}
	if _, err = git(nil, 1<<20, "fsck", "--strict", "--no-reflogs", u.New); err != nil {
		return nil, err
	}
	commits, err := git(nil, 1<<20, "rev-list", u.New)
	if err != nil {
		return nil, err
	}
	list := strings.Fields(string(commits))
	if len(list) == 0 || len(list) > 256 {
		return nil, ErrScope
	}
	for _, commit := range list {
		if !objectID(commit) {
			return nil, ErrProvider
		}
		tree, err := git(nil, 1<<20, "ls-tree", "-rz", commit)
		if err != nil {
			return nil, err
		}
		for _, entry := range bytes.Split(tree, []byte{0}) {
			parts := bytes.SplitN(entry, []byte{'\t'}, 2)
			if len(parts) != 2 {
				continue
			}
			name := strings.ToLower(filepath.Base(string(parts[1])))
			if strings.HasPrefix(string(parts[0]), "160000 ") || name == ".gitmodules" || name == ".lfsconfig" || name == ".gitattributes" {
				return nil, ErrScope
			}
		}
	}
	if !write {
		return nil, nil
	}
	pack, err := git([]byte(u.New+"\n"), maxPackBytes, "pack-objects", "--stdout", "--revs", "--threads=1")
	if err != nil || !packFraming(pack) {
		clear(pack)
		return nil, ErrProvider
	}
	return pack, nil
}
