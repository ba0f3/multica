package sandbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// NativeRuntimeRequest is selected by the daemon from its own runtime account,
// not from the task's environment or the human who requested a rerun.
type NativeRuntimeRequest struct {
	Provider       string
	Executable     string
	Home           string
	Env            map[string]string
	ForbiddenRoots []string
}

type NativeLink struct {
	Path   string
	Target string
}

type NativeRuntime struct {
	Provider       string
	Executable     string
	Home           string
	ProfileKey     string
	Version        string
	ReadOnly       []Mount
	ReadOnlyInputs []Mount
	Writable       []Mount
	Links          []NativeLink
	PrivatePaths   []string
	Env            map[string]string
	ProfileLimit   int
	BinDirs        []string
}

type NativeVersionDetector func(context.Context, string, string) (string, error)

type nativeWatch struct {
	path     string
	follow   bool
	info     os.FileInfo
	children bool
}

type nativeRuntimeEntry struct {
	runtime NativeRuntime
	watch   []nativeWatch
}

type NativeRuntimeResolver struct {
	mu      sync.Mutex
	detect  NativeVersionDetector
	entries map[string]nativeRuntimeEntry
}

func NewNativeRuntimeResolver(detect NativeVersionDetector) *NativeRuntimeResolver {
	return &NativeRuntimeResolver{detect: detect, entries: make(map[string]nativeRuntimeEntry)}
}

var nativeProfileEnvKeys = []string{
	"CODEX_HOME", "CURSOR_DATA_DIR", "CURSOR_CONFIG_DIR", "OPENCODE_CONFIG_DIR",
	"XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME",
}

func (r *NativeRuntimeResolver) Resolve(ctx context.Context, request NativeRuntimeRequest) (NativeRuntime, error) {
	var err error
	request, err = normalizeNativeRuntimeRequest(request)
	if err != nil {
		return NativeRuntime{}, err
	}

	encoded, err := json.Marshal(request)
	if err != nil {
		return NativeRuntime{}, err
	}
	key := string(encoded)
	r.mu.Lock()
	defer r.mu.Unlock()
	if entry, ok := r.entries[key]; ok && nativeWatchesMatch(entry.watch) {
		return cloneNativeRuntime(entry.runtime), nil
	}

	result, watch, err := resolveNativeRuntimeLayout(request)
	if err != nil {
		return NativeRuntime{}, err
	}

	if r.detect == nil {
		return NativeRuntime{}, fmt.Errorf("native sandbox: no trusted version detector")
	}
	result.Version, err = r.detect(ctx, request.Provider, request.Executable)
	if err != nil {
		return NativeRuntime{}, fmt.Errorf("native sandbox: detect %s version: %w", request.Provider, err)
	}
	if strings.TrimSpace(result.Version) == "" {
		return NativeRuntime{}, fmt.Errorf("native sandbox: %s did not report a version", request.Provider)
	}

	r.entries[key] = nativeRuntimeEntry{runtime: cloneNativeRuntime(result), watch: watch}
	return result, nil
}

func normalizeNativeRuntimeRequest(request NativeRuntimeRequest) (NativeRuntimeRequest, error) {
	request.Provider = strings.ToLower(strings.TrimSpace(request.Provider))
	if request.Provider == "mcode" {
		return request, fmt.Errorf("native sandbox: MCode is not supported; use MiniMax through OpenCode")
	}
	if !ProviderSupportsNativeHost(request.Provider) {
		return request, fmt.Errorf("native sandbox: provider %q is not supported", request.Provider)
	}
	if err := nativeAbsolutePath(request.Home); err != nil {
		return request, fmt.Errorf("native sandbox home: %w", err)
	}
	if err := nativeAbsolutePath(request.Executable); err != nil {
		return request, fmt.Errorf("native sandbox executable: %w", err)
	}
	requestPathEnv := request.Env["PATH"]
	selectors := make(map[string]string)
	for _, key := range nativeProfileEnvKeys {
		if value := request.Env[key]; value != "" {
			selectors[key] = value
		}
	}
	request.Env = selectors
	if path := requestPathEnv; path != "" {
		request.Env["PATH"] = path
	}
	return request, nil
}

// ResolveNativeInstallation resolves original code and profile paths without
// executing code or asserting a CLI version. Only the isolated version probe
// uses this layout; task launches require NativeRuntimeResolver.Resolve.
func ResolveNativeInstallation(request NativeRuntimeRequest) (NativeRuntime, error) {
	normalized, err := normalizeNativeRuntimeRequest(request)
	if err != nil {
		return NativeRuntime{}, err
	}
	result, _, err := resolveNativeRuntimeLayout(normalized)
	return result, err
}

func resolveNativeRuntimeLayout(request NativeRuntimeRequest) (NativeRuntime, []nativeWatch, error) {
	result := NativeRuntime{Provider: request.Provider, Executable: request.Executable, Home: request.Home, Env: make(map[string]string)}
	var watch []nativeWatch
	profilePaths, err := nativeProfilePaths(request, &result)
	if err != nil {
		return NativeRuntime{}, nil, err
	}
	for _, path := range profilePaths {
		if err := validateNativeGrant(request, path); err != nil {
			return NativeRuntime{}, nil, fmt.Errorf("native sandbox profile: %w", err)
		}
		if err := os.MkdirAll(path, 0700); err != nil {
			return NativeRuntime{}, nil, fmt.Errorf("native sandbox profile directory: %w", err)
		}
		resolved, links, err := nativeResolveLinks(path)
		if err != nil {
			return NativeRuntime{}, nil, err
		}
		result.Links = appendNativeLinks(result.Links, links...)
		result.Writable = append(result.Writable, Mount{Source: resolved, Target: resolved})
		if err := watchNativePath(&watch, path); err != nil {
			return NativeRuntime{}, nil, err
		}
	}
	if err := validateNativeGrant(request, request.Executable); err != nil {
		return NativeRuntime{}, nil, err
	}
	resolved, links, err := nativeResolveLinks(request.Executable)
	if err != nil {
		return NativeRuntime{}, nil, fmt.Errorf("native sandbox executable: %w", err)
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
		return NativeRuntime{}, nil, fmt.Errorf("native sandbox executable must be an executable regular file: %s", request.Executable)
	}
	result.Links = appendNativeLinks(links, result.Links...)
	if err := watchNativePath(&watch, request.Executable); err != nil {
		return NativeRuntime{}, nil, err
	}
	if err := resolveNativeInstallation(request, resolved, &result, &watch); err != nil {
		return NativeRuntime{}, nil, err
	}
	if request.Provider == "codex" {
		universal := filepath.Join(request.Home, ".agents", "skills")
		if _, err := os.Stat(universal); err == nil {
			start := len(result.ReadOnly)
			watchStart := len(watch)
			if _, err := grantNativeReadOnly(request, universal, &result, &watch); err != nil {
				return NativeRuntime{}, nil, err
			}
			result.ReadOnlyInputs = append(result.ReadOnlyInputs, result.ReadOnly[start:]...)
			result.ReadOnly = result.ReadOnly[:start]
			for i := watchStart; i < len(watch); i++ {
				watch[i].children = true
			}
		} else if !os.IsNotExist(err) {
			return NativeRuntime{}, nil, err
		} else {
			watch = append(watch, nativeWatch{path: universal, follow: true})
		}
	}
	if err := resolveNativeBuildTools(request, &result, &watch); err != nil {
		return NativeRuntime{}, nil, err
	}
	for _, link := range result.Links {
		if err := watchNativePath(&watch, link.Path); err != nil {
			return NativeRuntime{}, nil, err
		}
	}
	primary, err := filepath.EvalSymlinks(profilePaths[0])
	if err != nil {
		return NativeRuntime{}, nil, err
	}
	// HOME aliases must not create independent leases for the same native store.
	digest := sha256.Sum256([]byte(request.Provider + "\x00" + primary))
	result.ProfileKey = hex.EncodeToString(digest[:])
	return result, watch, nil
}

func nativeProfilePaths(request NativeRuntimeRequest, result *NativeRuntime) ([]string, error) {
	choose := func(key, fallback string) string {
		if value := request.Env[key]; value != "" {
			result.Env[key] = value
			return value
		}
		result.Env[key] = fallback
		return fallback
	}
	home := request.Home
	switch request.Provider {
	case "codex":
		return []string{choose("CODEX_HOME", filepath.Join(home, ".codex"))}, nil
	case "cursor":
		paths := []string{filepath.Join(home, ".cursor"), choose("CURSOR_CONFIG_DIR", filepath.Join(home, ".config", "cursor")), filepath.Join(home, ".cache", "cursor-compile-cache")}
		if selected := request.Env["CURSOR_DATA_DIR"]; selected != "" {
			paths = append(paths, choose("CURSOR_DATA_DIR", selected))
		}
		return paths, nil
	case "opencode":
		configHome := choose("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
		dataHome := choose("XDG_DATA_HOME", filepath.Join(home, ".local", "share"))
		stateHome := choose("XDG_STATE_HOME", filepath.Join(home, ".local", "state"))
		cacheHome := choose("XDG_CACHE_HOME", filepath.Join(home, ".cache"))
		config := filepath.Join(configHome, "opencode")
		if selected := request.Env["OPENCODE_CONFIG_DIR"]; selected != "" {
			config = choose("OPENCODE_CONFIG_DIR", selected)
		}
		return []string{filepath.Join(dataHome, "opencode"), config, filepath.Join(stateHome, "opencode"), filepath.Join(cacheHome, "opencode")}, nil
	default:
		return nil, fmt.Errorf("native sandbox: unsupported profile")
	}
}

func nativeAbsolutePath(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return fmt.Errorf("path must be absolute, clean and narrower than root: %q", path)
	}
	return nil
}

func validateNativeGrant(request NativeRuntimeRequest, path string) error {
	if err := nativeAbsolutePath(path); err != nil {
		return err
	}
	canonical, err := nativeResolveExistingParent(path)
	if err != nil {
		return err
	}
	home, err := filepath.EvalSymlinks(request.Home)
	if err != nil {
		return err
	}
	if isUnder(home, canonical) {
		return fmt.Errorf("native sandbox: a grant must not expose the host home or its parent: %q", path)
	}
	for _, root := range append(append([]string{}, request.ForbiddenRoots...), filepath.Join(home, ".ssh"), filepath.Join(home, ".multica")) {
		resolved, err := nativeResolveExistingParent(root)
		if err != nil {
			return err
		}
		if isUnder(canonical, resolved) || isUnder(resolved, canonical) {
			return fmt.Errorf("native sandbox: grant %q overlaps forbidden path %q", path, root)
		}
	}
	return nil
}

func nativeResolveExistingParent(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil {
		return resolved, nil
	}
	if !os.IsNotExist(err) {
		return "", err
	}
	parent := filepath.Dir(path)
	if parent == path {
		return "", err
	}
	base, err := nativeResolveExistingParent(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(base, filepath.Base(path)), nil
}

func nativeResolveLinks(path string) (string, []NativeLink, error) {
	var links []NativeLink
	seen := make(map[string]bool)
	current := path
	for range 64 {
		parts := strings.Split(strings.TrimPrefix(current, string(filepath.Separator)), string(filepath.Separator))
		prefix := string(filepath.Separator)
		changed := false
		for i, part := range parts {
			prefix = filepath.Join(prefix, part)
			info, err := os.Lstat(prefix)
			if err != nil {
				return "", nil, err
			}
			if info.Mode()&os.ModeSymlink == 0 {
				continue
			}
			if seen[prefix] {
				return "", nil, fmt.Errorf("native sandbox: cyclic symlink at %q", prefix)
			}
			seen[prefix] = true
			target, err := os.Readlink(prefix)
			if err != nil {
				return "", nil, err
			}
			links = append(links, NativeLink{Path: prefix, Target: target})
			resolved := target
			if !filepath.IsAbs(target) {
				resolved = filepath.Join(filepath.Dir(prefix), target)
			}
			current = filepath.Join(append([]string{resolved}, parts[i+1:]...)...)
			changed = true
			break
		}
		if !changed {
			return current, links, nil
		}
	}
	return "", nil, fmt.Errorf("native sandbox: too many symlinks")
}

func resolveNativeInstallation(request NativeRuntimeRequest, executable string, result *NativeRuntime, watch *[]nativeWatch) error {
	if err := grantNativeProgram(request, executable, result, watch, nil); err != nil {
		return err
	}
	if request.Provider == "codex" {
		packages := filepath.Join(result.Env["CODEX_HOME"], "packages")
		if isUnder(executable, packages) {
			if _, err := grantNativeReadOnly(request, packages, result, watch); err != nil {
				return err
			}
		}
		companion := filepath.Join(filepath.Dir(executable), "codex-code-mode-host")
		if _, err := os.Stat(companion); err == nil {
			if err := grantNativeProgram(request, companion, result, watch, nil); err != nil {
				return err
			}
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	if request.Provider == "cursor" {
		root := filepath.Dir(executable)
		index := filepath.Join(root, "index.js")
		if _, err := os.Stat(index); err == nil {
			if filepath.Base(filepath.Dir(root)) != "versions" || filepath.Base(filepath.Dir(filepath.Dir(root))) != "cursor-agent" {
				return fmt.Errorf("native sandbox: unsupported Cursor companion layout; use the original versioned installer")
			}
			if _, err := grantNativeReadOnly(request, root, result, watch); err != nil {
				return err
			}
			if err := watchNativePath(watch, index); err != nil {
				return err
			}
			if err := grantNativeProgram(request, filepath.Join(root, "node"), result, watch, nil); err != nil {
				return err
			}
		} else if !os.IsNotExist(err) {
			return err
		}
	}

	return resolveNativeNodePackage(request, executable, result, watch)
}

func watchNativePath(watch *[]nativeWatch, path string) error {
	for _, follow := range []bool{false, true} {
		info, err := os.Lstat(path)
		if follow {
			info, err = os.Stat(path)
		}
		if err != nil {
			return err
		}
		*watch = append(*watch, nativeWatch{path: path, follow: follow, info: info})
	}
	return nil
}

func nativeWatchesMatch(watch []nativeWatch) bool {
	for _, item := range watch {
		info, err := os.Lstat(item.path)
		if item.follow {
			info, err = os.Stat(item.path)
		}
		if item.info == nil {
			if os.IsNotExist(err) {
				continue
			}
			return false
		}
		if err != nil || !os.SameFile(item.info, info) || info.Mode() != item.info.Mode() {
			return false
		}
		// Directory children include tokens and sessions. Their changes must
		// not turn every task into another installation/version probe.
		if (!info.IsDir() || item.children) && (info.Size() != item.info.Size() || !info.ModTime().Equal(item.info.ModTime())) {
			return false
		}
	}
	return true
}

func appendNativeLinks(links []NativeLink, extra ...NativeLink) []NativeLink {
	for _, link := range extra {
		found := false
		for _, existing := range links {
			if existing.Path == link.Path {
				found = true
				break
			}
		}
		if !found {
			links = append(links, link)
		}
	}
	return links
}

func cloneNativeRuntime(value NativeRuntime) NativeRuntime {
	value.ReadOnly = append([]Mount(nil), value.ReadOnly...)
	value.ReadOnlyInputs = append([]Mount(nil), value.ReadOnlyInputs...)
	value.Writable = append([]Mount(nil), value.Writable...)
	value.Links = append([]NativeLink(nil), value.Links...)
	value.PrivatePaths = append([]string(nil), value.PrivatePaths...)
	value.BinDirs = append([]string(nil), value.BinDirs...)
	env := make(map[string]string, len(value.Env))
	for key, entry := range value.Env {
		env[key] = entry
	}
	value.Env = env
	return value
}
