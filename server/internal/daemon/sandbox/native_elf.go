package sandbox

import (
	"debug/elf"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Resolve ELF metadata without ldd or executing an interpreter on the host.
// Homebrew's loader and transitive libraries often live outside Node's prefix.
func resolveNativeELF(request NativeRuntimeRequest, executable string, result *NativeRuntime, watch *[]nativeWatch) error {
	seen := map[string]bool{}
	defaults := []string{"/lib64", "/usr/lib64", "/lib", "/usr/lib"}
	for _, root := range []string{"/lib", "/usr/lib"} {
		matches, _ := filepath.Glob(filepath.Join(root, "*-linux-gnu"))
		defaults = append(matches, defaults...)
	}
	var visit func(string, []string, bool) error
	visit = func(path string, inherited []string, dependency bool) error {
		if err := validateNativeGrant(request, path); err != nil {
			return err
		}
		canonical, links, err := nativeResolveLinks(path)
		if err != nil {
			return err
		}
		for _, link := range links {
			if err := watchNativePath(watch, link.Path); err != nil {
				return err
			}
			if !nativeSystemPath(link.Path) {
				result.Links = appendNativeLinks(result.Links, link)
			}
		}
		if err := watchNativePath(watch, path); err != nil {
			return err
		}
		if seen[canonical] {
			return nil
		}
		seen[canonical] = true
		if len(seen) > 256 {
			return fmt.Errorf("native sandbox: ELF dependency graph is too large")
		}
		file, err := os.Open(canonical)
		if err != nil {
			return err
		}
		defer file.Close()
		magic := make([]byte, 4)
		_, err = io.ReadFull(file, magic)
		if err != nil || string(magic) != "\x7fELF" {
			if dependency {
				return fmt.Errorf("native sandbox: library %q is not ELF", path)
			}
			return nil
		}
		parsed, err := elf.NewFile(file)
		if err != nil {
			return fmt.Errorf("native sandbox ELF %q: %w", path, err)
		}
		if dependency {
			result.ReadOnly = append(result.ReadOnly, Mount{Source: canonical, Target: canonical, ReadOnly: true})
		}
		for _, program := range parsed.Progs {
			if program.Type == elf.PT_INTERP {
				if program.Filesz > 4096 {
					return fmt.Errorf("native sandbox: invalid ELF interpreter")
				}
				data, err := io.ReadAll(program.Open())
				if err != nil {
					return err
				}
				interpreter := strings.TrimRight(string(data), "\x00")
				if err := visit(interpreter, nil, true); err != nil {
					return fmt.Errorf("native sandbox ELF interpreter: %w", err)
				}
			}
		}
		needed, err := parsed.ImportedLibraries()
		if err != nil {
			return err
		}
		runpaths, err := parsed.DynString(elf.DT_RUNPATH)
		if err != nil {
			return err
		}
		rpaths, err := parsed.DynString(elf.DT_RPATH)
		if err != nil {
			return err
		}
		expand := func(values []string) ([]string, error) {
			var paths []string
			for _, value := range values {
				for _, entry := range strings.Split(value, ":") {
					if entry == "" {
						continue
					}
					entry = strings.ReplaceAll(strings.ReplaceAll(entry, "${ORIGIN}", filepath.Dir(canonical)), "$ORIGIN", filepath.Dir(canonical))
					platform := ""
					switch runtime.GOARCH {
					case "amd64":
						platform = "x86_64"
					case "arm64":
						platform = "aarch64"
					}
					entry = strings.ReplaceAll(strings.ReplaceAll(entry, "${PLATFORM}", platform), "$PLATFORM", platform)
					if strings.Contains(entry, "$") || !filepath.IsAbs(entry) {
						return nil, fmt.Errorf("native sandbox: unsupported ELF runpath in %q", path)
					}
					paths = append(paths, filepath.Clean(entry))
				}
			}
			return paths, nil
		}
		own, err := expand(rpaths)
		if err != nil {
			return err
		}
		search := append(append([]string{}, own...), inherited...)
		children := search
		if len(runpaths) > 0 {
			run, err := expand(runpaths)
			if err != nil {
				return err
			}
			search = append(append([]string{}, inherited...), run...)
			children = inherited
		}
		search = append(search, defaults...)
		for _, name := range needed {
			selected := ""
			if filepath.IsAbs(name) {
				selected = name
			} else if strings.Contains(name, "/") {
				return fmt.Errorf("native sandbox: relative ELF dependency %q", name)
			} else {
				for _, directory := range search {
					candidate := filepath.Join(directory, name)
					if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
						selected = candidate
						break
					}
				}
			}
			if selected == "" {
				return fmt.Errorf("native sandbox: original ELF dependency %q required by %q is unavailable", name, path)
			}
			if err := visit(selected, children, true); err != nil {
				return err
			}
		}
		return nil
	}
	return visit(executable, nil, false)
}

func nativeSystemPath(path string) bool {
	for _, root := range []string{"/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc"} {
		if isUnder(path, root) {
			return true
		}
	}
	return false
}
