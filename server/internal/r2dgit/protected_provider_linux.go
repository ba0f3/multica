//go:build linux

package r2dgit

import (
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// RunResponsesProvider is the image's bounded direct HTTP Responses adapter. It sends no login,
// environment, executable or conversation state to the gateway. The selected
// finite context is explicit; larger/binary/symlink repositories are refused.
func RunResponsesProvider(ctx context.Context, socket string, input io.Reader, output io.Writer) error {
	var request ProtectedProviderInput
	if decodeBoundedJSON(input, 32768, &request) != nil || request.Version != 1 || !objectID(request.Head) || !nonempty(request.Assignment.Title) || !filepath.IsAbs(request.Directory) {
		return ErrScope
	}
	cwd, err := os.Getwd()
	if err != nil || cwd != request.Directory {
		return ErrScope
	}
	type sourceFile struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	files := []sourceFile{}
	root, err := os.OpenRoot(request.Directory)
	if err != nil {
		return ErrScope
	}
	defer root.Close()
	total := 0
	entries := 0
	err = filepath.WalkDir(request.Directory, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || ctx.Err() != nil {
			return ErrRuntime
		}
		entries++
		if entries > 256 {
			return ErrScope
		}
		rel, err := filepath.Rel(request.Directory, path)
		if err != nil {
			return ErrScope
		}
		if rel == ".git" && entry.IsDir() {
			return filepath.SkipDir
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() || len(files) >= 32 {
			return ErrScope
		}
		info, err := entry.Info()
		if err != nil || info.Size() > (32<<10)-int64(total) {
			return ErrScope
		}
		file, err := root.Open(rel)
		if err != nil {
			return ErrRuntime
		}
		raw, err := io.ReadAll(io.LimitReader(file, int64((32<<10)-total)+1))
		file.Close()
		if err != nil || len(raw) > (32<<10)-total || !utf8.Valid(raw) || strings.IndexByte(string(raw), 0) >= 0 {
			clear(raw)
			return ErrScope
		}
		total += len(raw)
		files = append(files, sourceFile{filepath.ToSlash(rel), string(raw)})
		clear(raw)
		return nil
	})
	if err != nil || len(files) == 0 {
		return ErrScope
	}
	prompt, err := json.Marshal(struct {
		Instructions string             `json:"instructions"`
		Assignment   WorkloadAssignment `json:"assignment"`
		Head         string             `json:"head"`
		Files        []sourceFile       `json:"files"`
	}{`Complete the assignment using only these repository files. Return one JSON object {"content":"answer","changes":[{"path":"relative/path","content":"complete new text"}]}. Changes may be empty. No tools, URLs, credentials, hidden paths, file deletion or external repositories are available. At most 16 changed files and 32768 total changed bytes.`, request.Assignment, request.Head, files})
	if err != nil || len(prompt) > 64<<10 {
		return ErrScope
	}
	defer clear(prompt)
	client, err := NewWorkloadClient(socket)
	if err != nil {
		return err
	}
	defer client.Close()
	text, err := client.Generate(ctx, string(prompt))
	if err != nil {
		return err
	}
	var result struct {
		Content string                `json:"content"`
		Changes []ProtectedFileChange `json:"changes"`
	}
	if decodeBoundedJSON(strings.NewReader(text), 64<<10, &result) != nil || len(result.Content) == 0 || len(result.Changes) > 16 {
		return ErrScope
	}
	kind := "artifact"
	if len(result.Changes) > 0 {
		kind = "diff"
	}
	return json.NewEncoder(output).Encode(ProtectedProviderResult{Version: 1, Kind: kind, Content: result.Content, Changes: result.Changes})
}
