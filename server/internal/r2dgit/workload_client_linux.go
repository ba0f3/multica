//go:build linux

package r2dgit

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// WorkloadClient belongs inside an accepted image entrypoint. Its sole network
// endpoint is the supervisor's per-run socket. It has no key, enrollment,
// repository selector, ambient HTTP proxy or direct provider connection.
type WorkloadClient struct {
	client    *http.Client
	transport *http.Transport
}

func NewWorkloadClient(socket string) (*WorkloadClient, error) {
	if !filepath.IsAbs(socket) {
		return nil, ErrScope
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}, MaxConnsPerHost: 1, ResponseHeaderTimeout: 25 * time.Second}
	return &WorkloadClient{client: &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, transport: transport}, nil
}
func (c *WorkloadClient) Close() { c.transport.CloseIdleConnections() }

func (c *WorkloadClient) Assignment(ctx context.Context) (WorkloadAssignment, error) {
	var assignment WorkloadAssignment
	response, err := c.request(ctx, http.MethodGet, "/assignment", nil)
	if err != nil {
		return assignment, ErrUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/json" {
		return assignment, ErrScope
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxAssignmentBytes+1))
	if err != nil || len(raw) > maxAssignmentBytes {
		return assignment, ErrScope
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&assignment) != nil || !nonempty(assignment.Title) {
		return WorkloadAssignment{}, ErrScope
	}
	var trailing any
	if d.Decode(&trailing) != io.EOF {
		return WorkloadAssignment{}, ErrScope
	}
	return assignment, nil
}

func (c *WorkloadClient) request(ctx context.Context, method, path string, payload any) (*http.Response, error) {
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(raw)
	}
	r, err := http.NewRequestWithContext(ctx, method, "http://workload"+path, body)
	if err != nil {
		return nil, err
	}
	if payload != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	return c.client.Do(r)
}

// Prepare checks out the authenticated snapshot into new private state. Paths
// and executable are trusted entrypoint configuration, never task payload. The
// helper is not a host sandbox and must only execute in the certified workload.
func (c *WorkloadClient) Prepare(ctx context.Context, gitExecutable, root string) (directory, head string, err error) {
	info, err := os.Lstat(root)
	if err != nil || !filepath.IsAbs(root) || !info.IsDir() || info.Mode().Perm() != 0700 {
		return "", "", ErrRuntime
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return "", "", ErrRuntime
	}
	response, err := c.request(ctx, http.MethodGet, "/snapshot", nil)
	if err != nil {
		return "", "", ErrProvider
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/x-git-packed-objects" {
		return "", "", ErrProvider
	}
	head = response.Header.Get("Multica-Git-Head")
	pack, err := io.ReadAll(io.LimitReader(response.Body, maxPackBytes+1))
	defer clear(pack)
	if err != nil || !packFraming(pack) || !objectID(head) || head == zeroObject {
		return "", "", ErrProvider
	}
	if (GitQuarantine{GitExecutable: gitExecutable, Root: root}).Validate(ctx, pack, head) != nil {
		return "", "", ErrProvider
	}
	directory, err = os.MkdirTemp(root, "protected-")
	if err != nil {
		return "", "", ErrRuntime
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(directory)
			directory = ""
			head = ""
		}
	}()
	gitCtx, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	run := func(input []byte, args ...string) error {
		cmd, e := quarantineCommand(gitCtx, gitExecutable, append([]string{"-c", "core.hooksPath=/dev/null", "-c", "protocol.allow=never", "-c", "pack.threads=1", "-c", "index.threads=1"}, args...)...)
		if e != nil {
			return e
		}
		cmd.Env = []string{"HOME=" + directory, "XDG_CONFIG_HOME=" + directory, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_COUNT=0", "GIT_TERMINAL_PROMPT=0", "GIT_NO_REPLACE_OBJECTS=1", "LC_ALL=C"}
		cmd.Stdin = bytes.NewReader(input)
		cmd.Stdout = &boundedBuffer{limit: 1 << 20}
		cmd.Stderr = &boundedBuffer{limit: 4096}
		if cmd.Run() != nil {
			return ErrProvider
		}
		return nil
	}
	if err = run(nil, "init", "--template=", directory); err != nil {
		return
	}
	if err = run(pack, "-C", directory, "index-pack", "--threads=1", "--strict", "--stdin"); err != nil {
		return
	}
	err = run(nil, "-C", directory, "checkout", "--detach", "--force", head, "--")
	return
}

// Submit stores one restricted final result and acknowledges the exact durable
// receipt. The entrypoint must exit zero only after this succeeds. No retries or
// generic stdout/log fallback are permitted for ambiguous responses.
func (c *WorkloadClient) Submit(ctx context.Context, kind, content string) (string, error) {
	response, err := c.request(ctx, http.MethodPost, "/outputs", struct {
		Kind    string `json:"kind"`
		Content string `json:"content"`
	}{kind, content})
	if err != nil {
		return "", ErrIndeterminate
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", ErrScope
	}
	var receipt struct {
		OutputID string `json:"output_id"`
	}
	d := json.NewDecoder(io.LimitReader(response.Body, 1025))
	d.DisallowUnknownFields()
	if d.Decode(&receipt) != nil || !nonempty(receipt.OutputID) {
		return "", ErrIndeterminate
	}
	var trailing any
	if d.Decode(&trailing) != io.EOF {
		return "", ErrIndeterminate
	}
	ack, err := c.request(ctx, http.MethodPost, "/acknowledge", receipt)
	if err != nil {
		return "", ErrIndeterminate
	}
	defer ack.Body.Close()
	if ack.StatusCode != http.StatusNoContent {
		return "", ErrIndeterminate
	}
	return receipt.OutputID, nil
}
