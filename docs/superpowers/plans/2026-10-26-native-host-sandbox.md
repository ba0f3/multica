# Native host sandbox implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run Codex, Cursor, OpenCode and MCode through the Multica worker inside an opt-in Linux bubblewrap boundary using their original installations and profiles.

**Architecture:** Resolve trusted provider installations and profile grants once, invalidate cached results when their inputs change, and render explicit same-path mounts into an empty home. Run each worker in a transient user-systemd resource scope and a private bubblewrap process namespace. Preserve the Docker path and reuse worker IPC and repository-cache checkout.

**Tech Stack:** Go, bubblewrap, Linux namespaces, systemd user scopes/cgroup v2, existing provider adapters and worker IPC.

**Spec:** `docs/superpowers/specs/2026-10-26-native-host-sandbox-design.md`

## Global Constraints

- Enable only with `MULTICA_TASK_SANDBOX=bwrap`; keep Docker as the default until every acceptance criterion passes on k7 and garlic.
- Execute the worker, adapter, CLI, MCP, hooks and descendants inside the boundary before repository config is read.
- Preserve executable, interpreter, library, home and selected profile paths. Never mount the entire host home.
- Native preparation does not copy profiles, export/import credentials, rewrite credential databases, or replace provider launchers/interpreters.
- Bind only trusted runtime/profile grants and the task's own workdir, temporary directory, output, task API config, signing socket and read-only repository caches.
- Keep configured CPU, memory and PID limits. Missing enforceable namespaces or resource controls fail closed without another backend.
- Share native profile locks in the same scope as their protected state. MCode uses private `.mcode-active` state and one attempt per profile until concurrency is proven safe.
- Preserve resume identity and report rejected continuity through the existing adapter contract.
- Cache resolution/preflight; detect installation or configuration changes on the next task without probing CLI version every task.
- Keep the current fetch and network policies. Record monotonic phase timings without secrets or claims of model-only latency.
- Default tests use fake CLI installations. Real-agent tests require `agentintegration` and `MULTICA_RUN_REAL_AGENT_SMOKE=1` before account or executable access.
- Acceptance includes real filesystem/process tests, all four providers on both hosts, and warm fake-worker launch p95 <=250 ms over at least 100 runs.
- Do not merge, push, publish, alter host security policy, or replace installed provider binaries as part of implementation.

## Review Focus

1. A profile or install path traverses symlinks into another task or credential store: Task 1 resolves paths, Task 2 refuses the unauthorized grant.
2. A shared native lock uses host PIDs or lives beside a profile: Tasks 1 and 3 model its actual scope, Task 7 checks host/worker coexistence.
3. A CLI upgrade keeps the launcher path unchanged: Task 1 invalidates the installation/version cache using symlink, pointer and executable fingerprints.
4. A worker reports a result or crashes while detached descendants remain: Tasks 3 and 4 terminate the entire attempt before releasing ownership.
5. A reused workdir changes provider or runtime profile: Tasks 5 and 6 preserve the selected account/session and do not apply another provider's copied credentials or task metadata to shared profiles.

### Task 1: Resolve and cache trusted native installations and profiles

**Files:** Create `server/internal/daemon/sandbox/native_runtime.go`, `native_runtime_test.go`; modify `sandbox/providers.go`, `providers_test.go`.

**Interfaces:**
- Produces `NativeRuntimeRequest{Provider, Executable, Home string; Env map[string]string; ForbiddenRoots []string}` and `NativeRuntime{Provider, Executable, Home, ProfileKey, Version string; ReadOnly, Writable []Mount; Links []NativeLink; PrivatePaths []string; Env map[string]string; ProfileLimit int}`. `NativeLink{Path, Target string}` preserves installer symlinks; private paths name namespace-local process markers.
- Produces `NewNativeRuntimeResolver(NativeVersionDetector) *NativeRuntimeResolver` and `Resolve(context.Context, NativeRuntimeRequest) (NativeRuntime, error)`; `NativeVersionDetector` is `func(context.Context, string, string) (string, error)` for provider and original executable.
- Provider grants come from daemon-owned runtime/profile configuration, never task-provided environment values. Native support is limited to the four named providers.

- [ ] Step 1: Add fake-install tests `TestNativeRuntimeKeepsOriginalLauncherAndProfile`, `TestNativeRuntimeCachesVersionUntilInstallChanges`, `TestNativeRuntimeRejectsUntrustedProfileEscape`, and `TestNativeRuntimeDeclaresMcodeLockScope`. Assert original executable and selected profile, one detector call across warm resolves, a changed symlink/current pointer causing a fresh detection, rejected traversal and explicit profile serialization.
- [ ] Step 2: Run `go -C server test ./internal/daemon/sandbox -run 'TestNativeRuntime' -count=1`. Expected: FAIL because native resolution is absent.
- [ ] Step 3: Implement provider-specific metadata resolution, canonical path validation and cached immutable results. Inspect the actual vendor launcher/lock layout before choosing grants. Record any unsupported layout explicitly instead of guessing.
- [ ] Step 4: Run the same command. Expected: PASS, including upgrade invalidation and no user CLI lookup.
- [ ] Step 5: Commit `feat(sandbox): resolve trusted native provider profiles`.

### Task 2: Replace host-home exposure with explicit same-path policy

**Files:** Modify `sandbox/policy.go`, `policy_test.go`, `bwrap_smoke_test.go`, `server/internal/daemon/sandbox_launch.go`, `sandbox_launch_test.go`; create `sandbox/native_policy_test.go`.

**Interfaces:**
- Consumes Task 1's `NativeRuntime` mount grants.
- `Policy.HostHome` is the original home pathname covered by the task's empty `HomeDir`; remove `ReadOnlyHome` and `HiddenHomePaths` and migrate every caller.
- `Policy.OutputDir` binds only this task's output; existing `BuildArgs(Policy, self string) ([]string, error)` remains the renderer.
- Produces validated mount order: runtime roots, empty home/temp/workdir/output, explicitly granted profile paths, cache/task API/signing mounts, worker command.

- [ ] Step 1: Add tests that run a fake worker and assert allowed artifact writes, original HOME, denied sibling task/host SSH/Git/Multica credentials, read-only code/cache, nested mounts surviving home shadows, and rejection of symlink source/target escapes.
- [ ] Step 2: Run `go -C server test ./internal/daemon/sandbox ./internal/daemon -run 'TestNativePolicy|TestBuildArgs|TestSandbox' -count=1`. Expected: FAIL on whole-home exposure or missing native fields.
- [ ] Step 3: Implement explicit grants, source and destination validation, private namespaces, capability dropping and verified no-new-privileges behavior. Remove the superseded whole-home policy and its tests.
- [ ] Step 4: Run the same command and the opt-in fake-worker bwrap smoke. Expected: PASS with real access-denial and write artifacts.
- [ ] Step 5: Commit `fix(sandbox): grant native profiles without exposing host home`.

### Task 3: Enforce native resource limits and attempt/profile lifecycle

**Files:** Create `sandbox/native_scope_linux.go`, `native_scope_other.go`, `native_scope_test.go`, `native_profile_lock.go`, `native_profile_lock_test.go`; modify daemon config/launcher only for wiring these boundaries.

**Interfaces:**
- Produces `NativeLimits{MemoryBytes, PIDsLimit, NanoCPUs int64}` using existing configured limit values.
- Produces `NativeScope` with cached `Preflight(context.Context) error`, `Command(unit string, argv []string) (*exec.Cmd, error)` and idempotent `Stop(context.Context, unit string) error`.
- Produces a cancellable, process-released profile lease keyed by `NativeRuntime.ProfileKey`; MCode's limit is one.
- Linux scopes use user-systemd/cgroup v2. Other platforms return an explicit unsupported error.

- [ ] Step 1: Write tests for rejected unavailable controllers, exact effective CPU/memory/PID limits, cancellation/normal exit/worker crash/daemon death killing detached descendants, repeated cleanup, and profile lease contention/recovery after owner exit.
- [ ] Step 2: Run `go -C server test ./internal/daemon/sandbox -run 'TestNativeScope|TestNativeProfileLease' -count=1`. Expected: FAIL before implementation.
- [ ] Step 3: Implement validated transient scope names, resource preflight/cache, parent-death handling, whole-scope cleanup and trusted profile leases. Do not mount cgroup control or host management sockets into workers.
- [ ] Step 4: Run the same command and real fake-worker resource/lifecycle probes. Expected: PASS and no surviving descendant or stale lease.
- [ ] Step 5: Commit `feat(sandbox): enforce native attempt resources and cleanup`.

### Task 4: Add worker-ready and real CLI-start timing events

**Files:** Modify `sandbox/ipc.go`, `ipc_test.go`, `backend.go`, `backend_test.go`, `worker.go`; add agent process-start callback tests alongside the four adapters and their common ACP/process helpers.

**Interfaces:**
- Produces `FrameWorkerReady` and `FrameCLIStarted` worker-to-supervisor frames.
- Produces an optional `agent.ExecOptions.OnCLIStarted func()` callback invoked after successful CLI process start, once per execution, never after a failed spawn or a version probe.
- Produces `IPCBackend.OnWorkerReady`, `OnCLIStarted` hooks and a configurable worker cwd for original-path native execution; Docker retains its current cwd.

- [ ] Step 1: Add IPC and fake-CLI tests proving readiness precedes spawn, failed spawn never emits CLI-start, control/session frames still work, and terminal/result/cancel paths stop the native attempt before completion is delivered.
- [ ] Step 2: Run `go -C server test ./internal/daemon/sandbox ./pkg/agent -run 'TestWorker|TestIPC|TestCLIStarted|TestNativeAttempt' -count=1`. Expected: FAIL for missing lifecycle events/callbacks.
- [ ] Step 3: Wire lifecycle events through existing adapters and worker protocol. Keep timings diagnostic and monotonic; do not infer spawn timing from first output.
- [ ] Step 4: Run the same command, then the affected package suites. Expected: PASS with unchanged supplement/resume/cancellation contracts.
- [ ] Step 5: Commit `feat(worker): report readiness and CLI process startup`.

### Task 5: Prepare native tasks without copying provider state

**Files:** Create `execenv/native.go`, `native_test.go`; modify `execenv/execenv.go` and provider preparation branches.

**Interfaces:**
- Produces `execenv.NativeProfile{Home string; Env map[string]string}` as a daemon-supplied selection in Prepare/Reuse parameters.
- Native mode retains task context, task API configuration, workdir, skills and managed MCP while skipping Docker profile copying, OpenCode auth export/import, Codex home seeding and MCode lock deletion.
- Produces the original home/profile environment for the native launcher. Resume reuses the same workdir and selected profile.

- [ ] Step 1: Add Prepare/Reuse tests using synthetic profiles containing sentinel credentials, sessions and locks. Assert unchanged shared bytes/inodes, no credential export command, no new task credential/profile copies, preserved task-side context/MCP/skills, and correct selection after switching providers.
- [ ] Step 2: Run `go -C server test ./internal/daemon/execenv -run 'TestNative' -count=1`. Expected: FAIL on copied/seeding behavior or missing native selection.
- [ ] Step 3: Separate common task preparation from backend-specific provider preparation and wire original-profile environment without mutating shared configuration for per-task settings.
- [ ] Step 4: Run the same command and the execenv suite. Expected: PASS for native mode and the unchanged Docker behavior.
- [ ] Step 5: Commit `feat(execenv): preserve native profiles during task preparation`.

### Task 6: Launch native workers with repository cache and phase metrics

**Files:** Modify `daemon.go`, `sandbox_launch.go`, `sandbox_launch_test.go`, `task_phase_timing.go`, `task_phase_timing_test.go`, runtime resolution tests and repository preparation tests.

**Interfaces:**
- Consumes Tasks 1-5's runtime, policy, scope, profile lease, environment and IPC events.
- Bwrap uses the existing read-only cache entries and checkout manifest, task-scoped Git signer and task API token. Fetch semantics remain unchanged.
- Emits `repo_prepare_ms`, `runtime_resolve_ms`, `environment_prepare_ms`, `sandbox_launch_ms`, `cli_start_ms`, `first_output_ms`, `turn_total_ms` with task, attempt, provider and backend.

- [ ] Step 1: Add fake-worker daemon tests for all four provider selections, original executable/profile, no Docker/native-version subprocess on a warm launch, repository/cache manifest accessibility, canceled/failed launch without fallback, correct rerun originator/signing scope, and literal monotonic timing intervals.
- [ ] Step 2: Run `go -C server test ./internal/daemon -run 'TestNative|TestTaskPhase|TestBwrap|TestSandbox|Test.*RepoCache' -count=1`. Expected: FAIL on unsupported MCode/legacy home preparation/missing telemetry.
- [ ] Step 3: Integrate the native path before CLI/backend configuration can read repo state. Preserve profile ownership across reruns and cache invalidation across upgrades. Keep bwrap opt-in and Docker default.
- [ ] Step 4: Run the same command and all affected package suites. Expected: PASS with Docker regressions covered and every native startup failure classified clearly.
- [ ] Step 5: Commit `feat(daemon): launch native sandbox workers with phase timings`.

### Task 7: Prove real provider continuity and shared-lock behavior

**Files:** Create `server/internal/daemon/native_worker_integration_test.go`; extend real-agent helpers without making default tests inspect installed CLIs; update `Makefile` and `AGENTS.md` with the authorized test command.

**Interfaces:**
- Consumes the production native launcher and environment path, not a parallel smoke-only implementation.
- Real tests are `agentintegration` and check `MULTICA_RUN_REAL_AGENT_SMOKE=1` before executable/account access. Explicitly select the host account home.

- [ ] Step 1: Add a matrix for Codex/Cursor/OpenCode/MCode: fresh tool artifact, resume same session plus remembered canary, provider change, fresh task after failure, and daemon restart. Add host CLI/worker coexistence, same-profile worker contention, refresh and native migration-lock checks.
- [ ] Step 2: Run without opt-in and then against the production integration from Tasks 1-6. Expected: no account is accessed without opt-in; record real failures as regressions before production fixes. Acceptance-only tests can pass initially when earlier tasks already supply the behavior.
- [ ] Step 3: Resolve integration defects through failing regression tests. Never repair auth by copying token rows, deleting native shared locks or changing the installed CLI. Ask only if a required host login or privileged host change is genuinely needed.
- [ ] Step 4: Run the exact real-agent matrix on k7 and garlic and retain redacted session/artifact/locking evidence in the plan workspace. Expected: all required scenarios pass, or record the exact external blocker without claiming provider support.
- [ ] Step 5: Commit `test(sandbox): verify native provider continuity and shared locks`.

### Task 8: Measure launch latency and document the deployment contract

**Files:** Add native fake-worker acceptance/benchmark tests alongside sandbox/daemon tests; update `docs/security/tool-isolation.md`, relevant daemon configuration docs and error/preflight guidance.

**Interfaces:**
- Consumes Task 6's `sandbox_launch_ms` measurement and Task 7's host validation evidence.
- Reports the measured p95 for at least 100 warm fake-worker attempts on each reference host; uses the real production launcher and worker-ready event.

- [ ] Step 1: Write a launch acceptance test collecting >=100 monotonic samples, verifying artifact and cleanup per attempt, and asserting p95 <=250 ms. Add negative preflight tests for missing limits/namespaces and upgraded CLI cache invalidation.
- [ ] Step 2: Run before optimization. Expected: retain actual measurements; only failing acceptance behavior justifies a production optimization and requires RED→GREEN verification.
- [ ] Step 3: Optimize only measured launcher overhead. Document shared-profile trust, exact host prerequisites, lock scopes, opt-in rollout and existing network policy. Change the Linux default only if every spec criterion has real passing evidence.
- [ ] Step 4: Run full Go verification through the guarded repository command, native fake-worker acceptance on both hosts, and the real-provider matrix after any runtime change. Expected: green suite and recorded acceptance numbers with no leaked secrets.
- [ ] Step 5: Commit `docs(sandbox): document validated native host execution`.
