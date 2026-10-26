//go:build linux

package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type nativeInstallFixture struct {
	request NativeRuntimeRequest
	install string
	profile string
}

func newNativeInstallFixture(t *testing.T, provider string) nativeInstallFixture {
	t.Helper()
	home := t.TempDir()
	write := func(path, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0700); err != nil {
			t.Fatal(err)
		}
	}
	fixture := nativeInstallFixture{request: NativeRuntimeRequest{Provider: provider, Home: home, Env: map[string]string{}, ForbiddenRoots: []string{filepath.Join(home, ".ssh"), filepath.Join(home, ".multica"), filepath.Join(home, "workspaces")}}}
	switch provider {
	case "codex":
		fixture.install = filepath.Join(home, "installs", "codex", "releases", "v1")
		fixture.profile = filepath.Join(home, ".codex")
		fixture.request.Executable = filepath.Join(home, ".local", "bin", "codex")
		write(filepath.Join(fixture.install, "bin", "codex"), "#!/bin/sh\nexit 0\n")
		write(filepath.Join(fixture.install, "bin", "codex-code-mode-host"), "#!/bin/sh\nexit 0\n")
		if err := os.MkdirAll(filepath.Dir(fixture.request.Executable), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(fixture.install, "bin", "codex"), fixture.request.Executable); err != nil {
			t.Fatal(err)
		}
	case "cursor":
		fixture.install = filepath.Join(home, ".local", "share", "cursor-agent", "versions", "v1")
		fixture.profile = filepath.Join(home, ".cursor")
		fixture.request.Executable = filepath.Join(fixture.install, "cursor-agent")
		write(fixture.request.Executable, "#!/bin/sh\nexit 0\n")
		write(filepath.Join(fixture.install, "node"), "#!/bin/sh\nexit 0\n")
		write(filepath.Join(fixture.install, "index.js"), "fake-cursor")
	case "opencode":
		fixture.install = filepath.Join(home, ".opencode")
		fixture.profile = filepath.Join(home, ".local", "share", "opencode")
		fixture.request.Executable = filepath.Join(fixture.install, "bin", "opencode")
		write(fixture.request.Executable, "#!/bin/sh\nexit 0\n")
	case "mcode":
		fixture.install = filepath.Join(home, ".minimax-code")
		fixture.profile = filepath.Join(home, ".minimax")
		fixture.request.Executable = filepath.Join(fixture.install, "bin", "mcode")
		write(fixture.request.Executable, "#!/bin/sh\nroot=$(dirname \"$0\")/..\nrelease=$(cat \"$root/current\")\nexec \"$root/releases/$release/.mcode-launcher\" \"$@\"\n")
		write(filepath.Join(fixture.install, "current"), "0.6.13\n")
		node := filepath.Join(home, "toolchains", "node", "bin", "node")
		write(node, "#!/bin/sh\nexit 0\n")
		write(filepath.Join(fixture.install, "releases", "0.6.13", ".mcode-launcher"), "#!/bin/sh\nnode='"+node+"'\nexec \"$node\" \"$root/lib/node_modules/@minimax-ai/code/cli.js\" \"$@\"\n")
	}
	if err := os.MkdirAll(fixture.profile, 0700); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func TestNativeRuntimeKeepsOriginalLauncherAndProfile(t *testing.T) {
	for _, provider := range []string{"codex", "cursor", "opencode"} {
		t.Run(provider, func(t *testing.T) {
			fixture := newNativeInstallFixture(t, provider)
			resolver := NewNativeRuntimeResolver(func(_ context.Context, gotProvider, executable string) (string, error) {
				if gotProvider != provider || executable != fixture.request.Executable {
					t.Fatalf("detector received %q %q", gotProvider, executable)
				}
				return "9.0.0", nil
			})
			runtime, err := resolver.Resolve(t.Context(), fixture.request)
			if err != nil {
				t.Fatal(err)
			}
			if runtime.Executable != fixture.request.Executable || runtime.Home != fixture.request.Home || runtime.Version != "9.0.0" {
				t.Fatalf("native launch identity changed: %+v", runtime)
			}
			found := false
			for _, mount := range runtime.Writable {
				if mount.Source == fixture.request.Home {
					t.Fatal("native profile grant exposes the entire home")
				}
				if mount.Source == fixture.profile && mount.Target == fixture.profile && !mount.ReadOnly {
					found = true
				}
			}
			if !found || runtime.ProfileKey == "" {
				t.Fatalf("original profile is missing: %+v", runtime)
			}
			if provider == "codex" && (len(runtime.Links) == 0 || runtime.Links[0].Path != fixture.request.Executable) {
				t.Fatal("the original launcher symlink was not preserved")
			}
		})
	}
}

func TestNativeRuntimeCachesVersionUntilInstallChanges(t *testing.T) {
	fixture := newNativeInstallFixture(t, "codex")
	calls := 0
	resolver := NewNativeRuntimeResolver(func(context.Context, string, string) (string, error) {
		calls++
		return "9.0.0", nil
	})
	first, err := resolver.Resolve(t.Context(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	first.Env["CODEX_HOME"] = "untrusted-mutation"
	for range 3 {
		got, err := resolver.Resolve(t.Context(), fixture.request)
		if err != nil || got.Env["CODEX_HOME"] != fixture.profile {
			t.Fatalf("cached result mutated: %+v, %v", got, err)
		}
	}
	if calls != 1 {
		t.Fatalf("warm resolves performed %d version probes, want 1", calls)
	}
	if err := os.WriteFile(filepath.Join(fixture.profile, "auth.json"), []byte("rotated credential"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve(t.Context(), fixture.request); err != nil || calls != 1 {
		t.Fatalf("credential refresh invalidated installation cache: calls=%d err=%v", calls, err)
	}
	replacement := filepath.Join(fixture.request.Home, "installs", "codex", "releases", "v2", "bin", "codex")
	if err := os.MkdirAll(filepath.Dir(replacement), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(replacement, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(fixture.request.Executable); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(replacement, fixture.request.Executable); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve(t.Context(), fixture.request); err != nil || calls != 2 {
		t.Fatalf("upgrade was not resolved: calls=%d err=%v", calls, err)
	}
}

func TestNativeRuntimeRejectsUntrustedProfileEscape(t *testing.T) {
	for _, kind := range []string{"relative", "whole-home", "forbidden-symlink"} {
		t.Run(kind, func(t *testing.T) {
			fixture := newNativeInstallFixture(t, "codex")
			profile := "relative-profile"
			if kind == "whole-home" {
				profile = fixture.request.Home
			}
			if kind == "forbidden-symlink" {
				secret := filepath.Join(fixture.request.Home, ".ssh")
				if err := os.MkdirAll(secret, 0700); err != nil {
					t.Fatal(err)
				}
				profile = filepath.Join(fixture.request.Home, "profile-link")
				if err := os.Symlink(secret, profile); err != nil {
					t.Fatal(err)
				}
			}
			fixture.request.Env["CODEX_HOME"] = profile
			resolver := NewNativeRuntimeResolver(func(context.Context, string, string) (string, error) {
				t.Fatal("invalid profile reached executable probing")
				return "", nil
			})
			if _, err := resolver.Resolve(t.Context(), fixture.request); err == nil {
				t.Fatal("an unsafe native profile was granted")
			}
		})
	}
}

func TestNativeRuntimeProtectsCodeStoredInsideTheProfile(t *testing.T) {
	fixture := newNativeInstallFixture(t, "codex")
	packages := filepath.Join(fixture.profile, "packages")
	executable := filepath.Join(packages, "standalone", "releases", "v1", "bin", "codex")
	if err := os.MkdirAll(filepath.Dir(executable), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(fixture.request.Executable); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(executable, fixture.request.Executable); err != nil {
		t.Fatal(err)
	}
	resolver := NewNativeRuntimeResolver(func(context.Context, string, string) (string, error) { return "9.0.0", nil })
	got, err := resolver.Resolve(t.Context(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	for _, mount := range got.ReadOnly {
		if mount.Source == packages && mount.Target == packages && mount.ReadOnly {
			return
		}
	}
	t.Fatal("the writable profile would expose other installed Codex versions as writable")
}

func TestNativeRuntimeInvalidatesRetargetedParentSymlink(t *testing.T) {
	fixture := newNativeInstallFixture(t, "codex")
	parent := filepath.Dir(fixture.install)
	current := filepath.Join(parent, "current")
	if err := os.Symlink("v1", current); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(fixture.request.Executable); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(current, "bin", "codex"), fixture.request.Executable); err != nil {
		t.Fatal(err)
	}
	calls := 0
	resolver := NewNativeRuntimeResolver(func(context.Context, string, string) (string, error) { calls++; return "9.0.0", nil })
	if _, err := resolver.Resolve(t.Context(), fixture.request); err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(parent, "v2", "bin", "codex")
	if err := os.MkdirAll(filepath.Dir(replacement), 0700); err != nil {
		t.Fatal(err)
	}
	// The executable inode is unchanged, but its companion code directory changed.
	if err := os.Link(filepath.Join(fixture.install, "bin", "codex"), replacement); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(current); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("v2", current); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve(t.Context(), fixture.request); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("retargeted installation kept a stale mount plan: detector calls=%d", calls)
	}
}

func TestNativeRuntimeProfileLeaseIdentitySurvivesHomeAliases(t *testing.T) {
	fixture := newNativeInstallFixture(t, "codex")
	resolver := NewNativeRuntimeResolver(func(context.Context, string, string) (string, error) { return "0.7.0", nil })
	first, err := resolver.Resolve(t.Context(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "same-home")
	if err := os.Symlink(fixture.request.Home, alias); err != nil {
		t.Fatal(err)
	}
	fixture.request.Home = alias
	second, err := resolver.Resolve(t.Context(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	if second.ProfileKey != first.ProfileKey {
		t.Fatal("the same physical provider profile could acquire two independent attempt leases")
	}
}

func TestNativeStandaloneInstallDoesNotGrantSiblingState(t *testing.T) {
	fixture := newNativeInstallFixture(t, "codex")
	if err := os.Remove(fixture.request.Executable); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.request.Executable, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(fixture.request.Home, ".local", "share", "opencode", "auth.json")
	if err := os.MkdirAll(filepath.Dir(secret), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secret, []byte("unrelated-provider-credential"), 0600); err != nil {
		t.Fatal(err)
	}
	runtime, err := NewNativeRuntimeResolver(func(context.Context, string, string) (string, error) { return "9.0.0", nil }).Resolve(t.Context(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	for _, mount := range runtime.ReadOnly {
		if isUnder(secret, mount.Source) {
			t.Fatalf("standalone executable grants unrelated credentials through %s", mount.Source)
		}
	}
}

func TestNativeCodexGrantsUniversalSkillsReadOnly(t *testing.T) {
	fixture := newNativeInstallFixture(t, "codex")
	universal := filepath.Join(fixture.request.Home, ".agents", "skills")
	if err := os.MkdirAll(filepath.Join(universal, "shared"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(universal, "shared", "SKILL.md"), []byte("universal instruction"), 0600); err != nil {
		t.Fatal(err)
	}
	runtime, err := NewNativeRuntimeResolver(func(context.Context, string, string) (string, error) { return "9.0.0", nil }).Resolve(t.Context(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	for _, mount := range append(runtime.ReadOnly, runtime.ReadOnlyInputs...) {
		if mount.Source == universal && mount.Target == universal && mount.ReadOnly {
			return
		}
	}
	t.Fatal("enabled universal skills and provider symlink targets are absent")
}

func TestNativeEnvInterpreterIsGrantedAndInvalidatesOnUpgrade(t *testing.T) {
	fixture := newNativeInstallFixture(t, "opencode")
	if err := os.WriteFile(fixture.request.Executable, []byte("#!/usr/bin/env node\n// fixture\n"), 0700); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(fixture.request.Home, "toolchain", "bin")
	if err := os.MkdirAll(bin, 0700); err != nil {
		t.Fatal(err)
	}
	var versions []string
	for _, name := range []string{"node-1", "node-2"} {
		path := filepath.Join(fixture.request.Home, "toolchain", name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
			t.Fatal(err)
		}
		versions = append(versions, path)
	}
	selected := filepath.Join(bin, "node")
	if err := os.Symlink(versions[0], selected); err != nil {
		t.Fatal(err)
	}
	fixture.request.Env["PATH"] = bin + string(os.PathListSeparator) + "/usr/bin:/bin"
	calls := 0
	resolver := NewNativeRuntimeResolver(func(context.Context, string, string) (string, error) { calls++; return "9.0.0", nil })
	runtime, err := resolver.Resolve(t.Context(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, mount := range runtime.ReadOnly {
		found = found || mount.Source == versions[0]
	}
	if !found {
		t.Fatal("original env-selected interpreter is not granted")
	}
	if err := os.Remove(selected); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(versions[1], selected); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve(t.Context(), fixture.request); err != nil || calls != 2 {
		t.Fatalf("interpreter upgrade kept stale metadata: calls=%d err=%v", calls, err)
	}
}

func TestNativeCompanionUpgradeInvalidatesUnchangedLauncher(t *testing.T) {
	fixture := newNativeInstallFixture(t, "cursor")
	calls := 0
	resolver := NewNativeRuntimeResolver(func(context.Context, string, string) (string, error) { calls++; return "9.0.0", nil })
	if _, err := resolver.Resolve(t.Context(), fixture.request); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture.install, "index.js"), []byte("updated companion code"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve(t.Context(), fixture.request); err != nil || calls != 2 {
		t.Fatalf("companion upgrade kept stale metadata: calls=%d err=%v", calls, err)
	}
}

func TestNativeUniversalSkillInstallInvalidatesAbsentGrant(t *testing.T) {
	fixture := newNativeInstallFixture(t, "codex")
	resolver := NewNativeRuntimeResolver(func(context.Context, string, string) (string, error) { return "9.0.0", nil })
	if _, err := resolver.Resolve(t.Context(), fixture.request); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(fixture.request.Home, ".agents", "skills")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	runtime, err := resolver.Resolve(t.Context(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	for _, mount := range runtime.ReadOnlyInputs {
		if mount.Source == root {
			return
		}
	}
	t.Fatal("first universal skill installation remains invisible until restart")
}

func TestNativeMcodeRefusedBeforeAccessingItsProfile(t *testing.T) {
	fixture := newNativeInstallFixture(t, "mcode")
	if err := os.RemoveAll(fixture.profile); err != nil {
		t.Fatal(err)
	}
	probes := 0
	resolver := NewNativeRuntimeResolver(func(context.Context, string, string) (string, error) {
		probes++
		return "9.0.0", nil
	})
	_, err := resolver.Resolve(t.Context(), fixture.request)
	if err == nil || !strings.Contains(err.Error(), "OpenCode") {
		t.Fatalf("MCode must direct the user to OpenCode: %v", err)
	}
	if probes != 0 {
		t.Fatal("unsupported MCode reached a CLI version probe")
	}
	if _, err := os.Stat(fixture.profile); !os.IsNotExist(err) {
		t.Fatalf("unsupported MCode created its account profile: %v", err)
	}
}
