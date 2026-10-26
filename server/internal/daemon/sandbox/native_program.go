package sandbox

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

var nativePackageComponent = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._-]{0,99}$`)

func grantNativeReadOnly(request NativeRuntimeRequest, path string, result *NativeRuntime, watch *[]nativeWatch) (string, error) {
	if err := validateNativeGrant(request, path); err != nil {
		return "", err
	}
	canonical, links, err := nativeResolveLinks(path)
	if err != nil {
		return "", err
	}
	if err := validateNativeGrant(request, canonical); err != nil {
		return "", err
	}
	result.Links = appendNativeLinks(result.Links, links...)
	found := false
	for _, mount := range result.ReadOnly {
		found = found || mount.Source == canonical && mount.Target == canonical
	}
	if !found {
		result.ReadOnly = append(result.ReadOnly, Mount{Source: canonical, Target: canonical, ReadOnly: true})
	}
	if err := watchNativePath(watch, path); err != nil {
		return "", err
	}
	return canonical, nil
}

func grantNativeProgram(request NativeRuntimeRequest, path string, result *NativeRuntime, watch *[]nativeWatch, stack map[string]bool) error {
	canonical, err := grantNativeReadOnly(request, path, result, watch)
	if err != nil {
		return err
	}
	if stack == nil {
		stack = map[string]bool{}
	}
	if stack[canonical] || len(stack) >= 8 {
		return fmt.Errorf("native sandbox: cyclic or excessive script interpreter chain")
	}
	stack[canonical] = true
	defer delete(stack, canonical)
	if err := resolveNativeELF(request, canonical, result, watch); err != nil {
		return err
	}
	file, err := os.Open(canonical)
	if err != nil {
		return err
	}
	data, err := io.ReadAll(io.LimitReader(file, 4096))
	_ = file.Close()
	if err != nil {
		return err
	}
	if len(data) >= 4 && string(data[:4]) == "\x7fELF" {
		return nil
	}
	if !strings.HasPrefix(string(data), "#!") {
		return fmt.Errorf("native sandbox: unsupported executable format at %q", path)
	}
	line, _, _ := strings.Cut(string(data), "\n")
	fields := strings.Fields(strings.TrimPrefix(line, "#!"))
	if len(fields) == 0 || len(fields) > 2 || !filepath.IsAbs(fields[0]) {
		return fmt.Errorf("native sandbox: unsupported shebang in %q", path)
	}
	interpreter := fields[0]
	if filepath.Base(interpreter) == "env" {
		if len(fields) != 2 || strings.HasPrefix(fields[1], "-") || strings.ContainsAny(fields[1], "/\\") {
			return fmt.Errorf("native sandbox: unsupported env shebang in %q", path)
		}
		if err := grantNativeProgram(request, interpreter, result, watch, stack); err != nil {
			return err
		}
		interpreter, err = nativeFindProgram(request.Env["PATH"], fields[1])
		if err != nil {
			return fmt.Errorf("native sandbox: original %s interpreter: %w", fields[1], err)
		}
		result.BinDirs = appendNativeDir(result.BinDirs, filepath.Dir(interpreter))
	}
	return grantNativeProgram(request, interpreter, result, watch, stack)
}

func nativeFindProgram(pathEnv, name string) (string, error) {
	if pathEnv == "" {
		return "", fmt.Errorf("trusted daemon PATH is required")
	}
	for _, dir := range filepath.SplitList(pathEnv) {
		if !filepath.IsAbs(dir) {
			return "", fmt.Errorf("relative daemon PATH entries are unsupported")
		}
		path := filepath.Join(dir, name)
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && info.Mode()&0111 != 0 {
			return path, nil
		}
	}
	return "", os.ErrNotExist
}

func appendNativeDir(paths []string, path string) []string {
	for _, item := range paths {
		if item == path {
			return paths
		}
	}
	return append(paths, path)
}

// Build tools are optional. Only recognized code distributions are granted;
// their package-manager prefix or the user's entire bin tree is never exposed.
func resolveNativeBuildTools(request NativeRuntimeRequest, result *NativeRuntime, watch *[]nativeWatch) error {
	if request.Env["PATH"] == "" {
		return nil
	}
	if node, err := nativeFindProgram(request.Env["PATH"], "node"); err == nil {
		if err := grantNativeProgram(request, node, result, watch, nil); err != nil {
			return err
		}
		result.BinDirs = appendNativeDir(result.BinDirs, filepath.Dir(node))
	}
	goPath, err := nativeFindProgram(request.Env["PATH"], "go")
	if err != nil {
		return nil
	}
	canonical, _, err := nativeResolveLinks(goPath)
	if err != nil {
		return err
	}
	root := filepath.Dir(filepath.Dir(canonical))
	for _, name := range []string{"VERSION", "src/runtime/runtime2.go", "pkg/tool/" + runtime.GOOS + "_" + runtime.GOARCH + "/compile"} {
		if info, err := os.Stat(filepath.Join(root, filepath.FromSlash(name))); err != nil || !info.Mode().IsRegular() {
			return nil
		}
	}
	if _, err := grantNativeReadOnly(request, root, result, watch); err != nil {
		return err
	}
	if err := grantNativeProgram(request, goPath, result, watch, nil); err != nil {
		return err
	}
	if err := watchNativePath(watch, filepath.Join(root, "VERSION")); err != nil {
		return err
	}
	result.BinDirs = appendNativeDir(result.BinDirs, filepath.Dir(goPath))
	return nil
}

func resolveNativeNodePackage(request NativeRuntimeRequest, executable string, result *NativeRuntime, watch *[]nativeWatch) error {
	if filepath.Base(filepath.Dir(executable)) != "bin" {
		return nil
	}
	root := filepath.Dir(filepath.Dir(executable))
	metadata := filepath.Join(root, "package.json")
	data, err := os.ReadFile(metadata)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var manifest struct {
		Name                 string            `json:"name"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
	}
	if json.Unmarshal(data, &manifest) != nil {
		return fmt.Errorf("native sandbox: invalid installation package metadata")
	}
	expected := map[string]string{"codex": "@openai/codex", "opencode": "opencode-ai"}[request.Provider]
	if expected == "" || manifest.Name != expected {
		return nil
	}
	if _, err := grantNativeReadOnly(request, root, result, watch); err != nil {
		return err
	}
	if err := watchNativePath(watch, metadata); err != nil {
		return err
	}
	arch := map[string]string{"amd64": "x64", "arm64": "arm64"}[runtime.GOARCH]
	prefix := "opencode-" + runtime.GOOS + "-" + arch
	if request.Provider == "codex" {
		prefix = "@openai/codex-" + runtime.GOOS + "-" + arch
	}
	for name := range manifest.OptionalDependencies {
		if name != prefix && !strings.HasPrefix(name, prefix+"-") {
			continue
		}
		base := filepath.Base(name)
		if !nativePackageComponent.MatchString(base) || strings.TrimPrefix(name, "@openai/") != base {
			continue
		}
		dependency := filepath.Join(filepath.Dir(root), base)
		if _, err := os.Stat(dependency); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return err
		}
		if _, err := grantNativeReadOnly(request, dependency, result, watch); err != nil {
			return err
		}
		if err := watchNativePath(watch, filepath.Join(dependency, "package.json")); err != nil {
			return err
		}
	}
	return nil
}
