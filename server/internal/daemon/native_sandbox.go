package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/multica-ai/multica/server/internal/daemon/execenv"
	"github.com/multica-ai/multica/server/internal/daemon/sandbox"
	"github.com/multica-ai/multica/server/internal/daemon/workercheckout"
	"github.com/multica-ai/multica/server/pkg/agent"
)

type nativeResourceScope interface {
	Preflight(context.Context) error
	Command(string, []string) (*exec.Cmd, error)
	Stop(context.Context, string) error
}

func (d *Daemon) usesNativeSandbox() bool {
	return d.cfg.SandboxEnabled && d.cfg.TaskSandboxBackend == "bwrap"
}

func (d *Daemon) nativeRuntime(ctx context.Context, provider, executable string) (sandbox.NativeRuntime, nativeResourceScope, error) {
	d.nativeMu.Lock()
	if d.nativeScope == nil {
		d.nativeScope = &sandbox.NativeScope{BwrapPath: d.cfg.BwrapPath, Limits: sandbox.NativeLimits{MemoryBytes: d.cfg.DockerMemoryBytes, PIDsLimit: d.cfg.DockerPIDsLimit, NanoCPUs: d.cfg.DockerNanoCPUs}}
	}
	scope := d.nativeScope
	if d.nativeResolver == nil {
		d.nativeResolver = sandbox.NewNativeRuntimeResolver(d.detectNativeVersion)
	}
	resolver := d.nativeResolver
	d.nativeMu.Unlock()
	if err := scope.Preflight(ctx); err != nil {
		return sandbox.NativeRuntime{}, nil, fmt.Errorf("%w: native resource preflight: %w", errSandboxUnavailable, err)
	}
	request, err := d.nativeRuntimeRequest(provider, executable)
	if err != nil {
		return sandbox.NativeRuntime{}, nil, err
	}
	runtime, err := resolver.Resolve(ctx, request)
	if err != nil {
		return runtime, nil, fmt.Errorf("%w: %w", errSandboxUnavailable, err)
	}
	return runtime, scope, nil
}

var nativeSelectorKeys = []string{"CODEX_HOME", "CURSOR_DATA_DIR", "CURSOR_CONFIG_DIR", "OPENCODE_CONFIG_DIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "MINIMAX_DATA_DIR", "MAVIS_DATA_DIR"}

func (d *Daemon) nativeRuntimeRequest(provider, executable string) (sandbox.NativeRuntimeRequest, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return sandbox.NativeRuntimeRequest{}, err
	}
	env := map[string]string{}
	for _, key := range nativeSelectorKeys {
		if value := os.Getenv(key); value != "" {
			env[key] = value
		}
	}
	env["PATH"] = os.Getenv("PATH")
	return sandbox.NativeRuntimeRequest{Provider: provider, Executable: executable, Home: home, Env: env, ForbiddenRoots: []string{d.cfg.WorkspacesRoot}}, nil
}

// Version probes get an empty home and no repository, task credentials or shared
// profile. A mutable provider config must not load plugins in the host daemon.
func (d *Daemon) detectNativeVersion(ctx context.Context, provider, executable string) (string, error) {
	request, err := d.nativeRuntimeRequest(provider, executable)
	if err != nil {
		return "", err
	}
	layout, err := sandbox.ResolveNativeInstallation(request)
	if err != nil {
		return "", err
	}
	root, err := os.MkdirTemp("", "multica-native-version-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(root)
	for _, dir := range []string{"home", "tmp", "cwd"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0700); err != nil {
			return "", err
		}
	}
	self := d.cfg.SandboxSelfPath
	if self == "" {
		self, err = os.Executable()
		if err != nil {
			return "", err
		}
	}
	extras := append([]sandbox.Mount{}, layout.ReadOnly...)
	network, err := sandbox.RuntimeNetworkMounts()
	if err != nil {
		return "", err
	}
	extras = append(extras, network...)
	for i, mount := range layout.Writable {
		source := filepath.Join(root, fmt.Sprintf("profile-%d", i))
		if err := os.Mkdir(source, 0700); err != nil {
			return "", err
		}
		extras = append(extras, sandbox.Mount{Source: source, Target: mount.Target})
	}
	for i, target := range layout.PrivatePaths {
		source := filepath.Join(root, fmt.Sprintf("marker-%d", i))
		if err := os.Mkdir(source, 0700); err != nil {
			return "", err
		}
		extras = append(extras, sandbox.Mount{Source: source, Target: target})
	}
	probeEnv := map[string]string{"PATH": sandboxPath()}
	for key, value := range layout.Env {
		probeEnv[key] = value
	}
	probeEnv["PATH"] = strings.Join(append(append([]string{}, layout.BinDirs...), sandboxPath()), string(os.PathListSeparator))
	policy := sandbox.Policy{TaskRoot: root, HomeDir: filepath.Join(root, "home"), HostHome: layout.Home, TempDir: filepath.Join(root, "tmp"), CheckoutDir: filepath.Join(root, "cwd"), RuntimeRoots: sandboxRuntimeRoots(), ExtraMounts: extras, Links: layout.Links, AllowedRoots: []string{root}, ForbiddenRoots: []string{d.cfg.WorkspacesRoot, filepath.Join(layout.Home, ".multica"), filepath.Join(layout.Home, ".ssh"), filepath.Join(layout.Home, ".docker")}, AllowedExactPaths: extraMountSources(extras), Env: probeEnv, Command: []string{executable, "--version"}}
	args, err := sandbox.BuildArgs(policy, self)
	if err != nil {
		return "", err
	}
	bwrap := d.cfg.BwrapPath
	if bwrap == "" {
		bwrap = "bwrap"
	}
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// A fresh private PID namespace and die-with-parent also contain probe hooks.
	cmd := exec.CommandContext(probeCtx, bwrap, args...)
	cmd.WaitDelay = time.Second
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("isolated version probe failed: %w: %.1024s", err, strings.TrimSpace(string(output)))
	}
	version := nativeVersionPattern.FindString(string(output))
	if version == "" {
		return "", fmt.Errorf("isolated %s version probe returned no version", provider)
	}
	return version, nil
}

var nativeVersionPattern = regexp.MustCompile(`[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?`)

type nativeAttemptBackend struct {
	worker  *sandbox.IPCBackend
	profile sandbox.NativeRuntime
	onSpawn func()
	prepare func(*sandbox.IPCBackend) (func() error, error)
}

func (b *nativeAttemptBackend) Execute(ctx context.Context, prompt string, opts agent.ExecOptions) (*agent.Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var lease *sandbox.NativeProfileLease
	if b.profile.ProfileLimit == 1 {
		root := os.Getenv("XDG_RUNTIME_DIR")
		if root == "" {
			root = fmt.Sprintf("/run/user/%d", os.Getuid())
		}
		var err error
		lease, err = sandbox.AcquireNativeProfileLease(ctx, filepath.Join(root, "multica-native-profiles"), b.profile.ProfileKey)
		if err != nil {
			return nil, fmt.Errorf("native profile busy or unavailable: %w", err)
		}
	}
	worker := *b.worker
	var cleanupStorage func() error
	if b.prepare != nil {
		var err error
		cleanupStorage, err = b.prepare(&worker)
		if err != nil {
			_ = lease.Close()
			return nil, err
		}
	}
	worker.Start = func(cmd *exec.Cmd) (func(), error) {
		if b.onSpawn != nil {
			b.onSpawn()
		}
		release, err := sandbox.StartNativeOwnedProcess(cmd)
		if err != nil {
			return nil, err
		}
		return func() { release(); _ = lease.Close() }, nil
	}
	opts.NativeProfile = true
	session, err := worker.Execute(ctx, prompt, opts)
	if err != nil {
		if cleanupStorage != nil {
			err = errors.Join(err, cleanupStorage())
		}
		_ = lease.Close()
	}
	return session, err
}

func (d *Daemon) bwrapBackend(provider string, config agent.Config, env *execenv.Environment, profileDir, agentSocket, attemptID string, repos []workercheckout.Entry, extraCachePaths []string) (agent.Backend, error) {
	if env == nil {
		return nil, fmt.Errorf("%w: no execution environment", errSandboxUnavailable)
	}
	if !sandbox.ProviderSupportsNativeHost(provider) {
		return nil, fmt.Errorf("%w: provider %q requires the docker backend; native support is not validated", errSandboxUnavailable, provider)
	}
	bwrap := d.cfg.BwrapPath
	if bwrap == "" {
		bwrap = "bwrap"
	}
	if _, err := exec.LookPath(bwrap); err != nil {
		return nil, fmt.Errorf("%w: bwrap executable: %w", errSandboxUnavailable, err)
	}
	runtime, scope, err := d.nativeRuntime(context.Background(), provider, config.ExecutablePath)
	if err != nil {
		return nil, err
	}
	self := d.cfg.SandboxSelfPath
	if self == "" {
		self, err = os.Executable()
		if err != nil {
			return nil, err
		}
	}
	extras := append([]sandbox.Mount{}, runtime.Writable...)
	network, err := sandbox.RuntimeNetworkMounts()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errSandboxUnavailable, err)
	}
	extras = append(extras, network...)
	extras = append(extras, runtime.ReadOnly...)
	extras = append(extras, runtime.ReadOnlyInputs...)
	if env.MulticaConfigRoot != "" {
		extras = append(extras, sandbox.Mount{Source: env.MulticaConfigRoot, Target: env.MulticaConfigRoot})
	}
	if err := repoCacheOverlapError(repos, extraCachePaths, env, "", ""); err != nil {
		return nil, err
	}
	for _, entry := range repos {
		extras = append(extras, sandbox.Mount{Source: entry.CachePath, Target: entry.CachePath, ReadOnly: true})
	}
	for _, path := range extraCachePaths {
		extras = append(extras, sandbox.Mount{Source: path, Target: path, ReadOnly: true})
	}
	manifest := filepath.Join(env.RootDir, workercheckout.ManifestFileName)
	if len(repos) > 0 {
		extras = append(extras, sandbox.Mount{Source: manifest, Target: filepath.Join(env.MulticaConfigRoot, workercheckout.ManifestFileName), ReadOnly: true})
	}
	cacheDir := filepath.Join(env.RootDir, "tool-cache")
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return nil, err
	}
	extras = append(extras, sandbox.Mount{Source: cacheDir, Target: cacheDir})
	if env.GitKnownHostsPath != "" {
		extras = append(extras, sandbox.Mount{Source: env.GitKnownHostsPath, Target: env.GitKnownHostsPath, ReadOnly: true})
	}
	if env.WorkerCABundlePath != "" {
		extras = append(extras, sandbox.Mount{Source: env.WorkerCABundlePath, Target: env.WorkerCABundlePath, ReadOnly: true})
	}
	agentEnv := map[string]string{}
	for key, value := range config.Env {
		agentEnv[key] = value
	}
	for _, key := range nativeSelectorKeys {
		delete(agentEnv, key)
	}
	for key, value := range runtime.Env {
		agentEnv[key] = value
	}
	agentEnv["HOME"] = runtime.Home
	for _, key := range []string{"TMPDIR", "TMP", "TEMP"} {
		agentEnv[key] = sandbox.TempPath
	}
	binDirs := append([]string{"/run/multica"}, runtime.BinDirs...)
	binDirs = append(binDirs, filepath.Dir(runtime.Executable), sandboxPath())
	agentEnv["PATH"] = strings.Join(binDirs, string(os.PathListSeparator))
	if agentSocket != "" {
		agentEnv["SSH_AUTH_SOCK"] = sandbox.AgentSocketPath
	}
	if env.MulticaConfigRoot != "" {
		agentEnv["MULTICA_TASK_CONFIG_ROOT"] = env.MulticaConfigRoot
	}
	for key, value := range map[string]string{"GOCACHE": filepath.Join(cacheDir, "go-build"), "GOPATH": filepath.Join(cacheDir, "go"), "NPM_CONFIG_CACHE": filepath.Join(cacheDir, "npm")} {
		if agentEnv[key] == "" && !(key == "NPM_CONFIG_CACHE" && agentEnv["npm_config_cache"] != "") {
			agentEnv[key] = value
		}
	}
	if env.WorkerCABundlePath != "" {
		for key, value := range sandbox.CAEnv(env.WorkerCABundlePath) {
			agentEnv[key] = value
		}
	}
	config.Env = agentEnv
	config.CLIVersion = runtime.Version
	if provider == "codex" {
		config.CodexVersion = runtime.Version
	}
	cfg := sandbox.ConfigFromAgent(config)
	cfg.AttemptID = attemptID
	unit := "multica-" + strings.TrimPrefix(sandbox.SanitizeContainerName(attemptID), "multica-") + ".scope"
	worker := &sandbox.IPCBackend{Provider: provider, Config: cfg, KeepStdinOpen: true, WorkerCwd: env.WorkDir}
	prepare := func(worker *sandbox.IPCBackend) (cleanup func() error, retErr error) {
		privateRoot, err := os.MkdirTemp(env.RootDir, "native-attempt-")
		if err != nil {
			return nil, err
		}
		removeStorage := func() error { return os.RemoveAll(privateRoot) }
		cleanup = removeStorage
		output := filepath.Join(env.RootDir, "outputs", filepath.Base(privateRoot))
		defer func() {
			if retErr != nil {
				retErr = errors.Join(retErr, removeStorage(), os.RemoveAll(output))
			}
		}()
		dirs := map[string]string{}
		for _, name := range []string{"home", "tmp"} {
			dirs[name] = filepath.Join(privateRoot, name)
			if err := os.Mkdir(dirs[name], 0700); err != nil {
				return nil, err
			}
		}
		if err := os.MkdirAll(output, 0700); err != nil {
			return nil, err
		}
		mounts := append([]sandbox.Mount(nil), extras...)
		for i, target := range runtime.PrivatePaths {
			source := filepath.Join(privateRoot, fmt.Sprintf("marker-%d", i))
			if err := os.Mkdir(source, 0700); err != nil {
				return nil, err
			}
			mounts = append(mounts, sandbox.Mount{Source: source, Target: target})
		}
		policy := sandbox.Policy{TaskRoot: env.RootDir, HomeDir: dirs["home"], HostHome: runtime.Home, TempDir: dirs["tmp"], OutputDir: output, CheckoutDir: env.WorkDir, CheckoutTarget: env.WorkDir, RuntimeRoots: sandboxRuntimeRoots(), ExtraMounts: mounts, Links: append(append([]sandbox.NativeLink{}, runtime.Links...), sandbox.NativeLink{Path: "/run/multica/multica", Target: "worker"}), AgentSocket: agentSocket, AllowedRoots: []string{env.RootDir}, ForbiddenRoots: []string{d.cfg.WorkspacesRoot, filepath.Join(runtime.Home, ".multica"), filepath.Join(runtime.Home, ".ssh"), filepath.Join(runtime.Home, ".docker")}, AllowedExactPaths: append([]string{agentSocket}, extraMountSources(mounts)...), Env: map[string]string{"PATH": agentEnv["PATH"]}}
		args, err := sandbox.BuildArgs(policy, self)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", errSandboxUnavailable, err)
		}
		worker.Launch = func() (*exec.Cmd, error) { return scope.Command(unit, append([]string{bwrap}, args...)) }
		worker.StopAttempt = func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			return scope.Stop(ctx, unit)
		}
		worker.AfterReap = cleanup
		return cleanup, nil
	}
	return &nativeAttemptBackend{worker: worker, profile: runtime, prepare: prepare}, nil
}

func (d *Daemon) resolveNativeAgentEntry(ctx context.Context, provider string, entry AgentEntry) (AgentEntry, string, *execenv.NativeProfile, error) {
	if _, err := os.Stat(entry.Path); err != nil {
		if entry.Command == "" {
			return entry, "", nil, fmt.Errorf("native executable is missing: %w", err)
		}
		path, lookupErr := exec.LookPath(entry.Command)
		if lookupErr != nil {
			return entry, "", nil, fmt.Errorf("resolve native executable after upgrade: %w", lookupErr)
		}
		entry.Path = path
	}
	runtime, _, err := d.nativeRuntime(ctx, provider, entry.Path)
	if err != nil {
		return entry, "", nil, err
	}
	if err := checkAgentMinVersion(provider, runtime.Version); err != nil {
		return entry, "", nil, fmt.Errorf("native runtime version: %w", err)
	}
	return entry, runtime.Version, &execenv.NativeProfile{Home: runtime.Home, Env: runtime.Env}, nil
}
