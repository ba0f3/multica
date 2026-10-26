# User codebases and read-only host view implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans inline. Steps use checkbox syntax for tracking.

**Goal:** Give every execution user their own base repositories, preserve parallel task checkouts, and support original host installations through a read-only host view.

**Architecture:** Typed cache scopes flow from server principal to repository cache, task ownership, worker mounts and retention. Native host visibility uses a masked root overlay instead of enumerating installation dependencies. PID visibility remains private, as explicitly selected by the user.

**Tech Stack:** Go, Git, bubblewrap, user systemd/cgroup v2, existing worker IPC.

**Spec:** `docs/superpowers/specs/2026-10-26-user-codebases-host-view-design.md`

## Global constraints

- Work locally in the existing feature worktree; no garlic SSH, uploads, deployments, restarts or installed-provider changes.
- Cache identity is server-proven workspace + execution user; never a runtime-owner fallback.
- No cross-user object sharing, checkout reuse or cache alternates. Keep old unscoped data unmounted; migration itself does not delete it. Existing GC retention remains in force.
- Fetch current refs before resolving a task snapshot; failures do not use stale code.
- Root read-only visibility intentionally exposes provider credentials; writable state stays explicitly granted. Mask other users' managed code and host-control channels.
- Keep Docker/default selection and fail closed after selecting native.
- Keep configured resources and whole-attempt cleanup. Keep private PID namespaces; MCode0.6.13 remains unsupported.
- No provider database edits, launcher rewriting, credential copies or lock deletion. Real account tests are opt-in on k7 only.

## Review focus

1. A task claims another user's cache via request fields, symlink aliases, old alternates or reused workdir. Tasks1–3 include concrete denial tests.
2. Workspace/background sync or GC still assumes one shared base. Tasks1–2 migrate these callers and preserve live dependencies.
3. Root overlays accidentally re-expose hidden code through an alias, bind mount or process filesystem. Task4 has real kernel probes.
4. Read-only Unix sockets or `/proc` allow mutation/control despite read-only files. Task4 explicitly hides control channels.
5. Private PID namespaces and the MCode0.6.13 refusal remain in force; broader filesystem visibility must not weaken process isolation or cleanup.

### Task 1: Encode user ownership in repository cache operations

**Files:** `repocache/scope.go`, `cache.go`, `prepare.go`, `dependents.go`, `identity.go`, existing cache tests and daemon cache interfaces/test doubles.

**Interfaces:** Introduce `repocache.Scope{WorkspaceID, UserID string}` with safe component validation and root resolution. Replace workspace-only parameters of code-owning operations with Scope; `WorktreeParams.Scope` replaces its workspace-only identity. Workspace-wide metadata publication explicitly enumerates owned scopes.

- [ ] Write failing tests for separate stores/locks/refs/dependents for two users, same-user reuse and rejected empty/traversing scope.
- [ ] Run guarded cache tests; observe behavioral RED.
- [ ] Implement scoped paths and migrate every direct caller/test double; remove workspace-only APIs.
- [x] Verify cache/retention/hook tests and commit.

### Task 2: Resolve the execution user and wire task/cache/GC boundaries

**Files:** `handler/daemon.go`, claim tests; `daemon.go`, `health.go`, repo preparation and GC tests.

**Interfaces:** Claimed `ExecutionUserID` is set independently of Git signing. Derive `Scope` from Task and registered active checkout task, not JSON. Strict prepare, extra alternate admission, dependent retention and GC use the same scope. Background workspace registration refreshes metadata, not owner-authenticated shared clones.

- [ ] Write RED tests for signing-disabled principals, missing principal on code task, spoofed checkout scope, cross-user alternates and independent concurrent tasks.
- [ ] Migrate registration/prepare/checkout/settings/GC flow; preserve non-code task startup.
- [ ] Verify handler/daemon scoped tests, fake-worker runTask and guarded cache suites; commit.

### Task 3: Bind task environments and resume to their execution user

**Files:** `execenv/root_identity.go`, `execenv.go`, ownership tests, daemon root/reuse wiring and tests.

**Interfaces:** Execution-user ownership participates in environment/root identity and persisted ownership proof. Reuse requires matching workspace + user. Legacy/mismatched roots remain untouched and cannot be mounted; a task gets a fresh environment with continuity reported correctly.

- [ ] Add RED tests for two users, wrong-user reuse, old owner records, rename/restart and concurrent claims.
- [ ] Implement ownership and propagate through preparation/helper IPC/reuse/GC.
- [ ] Run affected ownership, preparation and daemon resume tests; commit.

### Task 4: Replace narrow native grants with a masked read-only host view

**Files:** `sandbox/policy.go`, `native_runtime.go`, new host-view policy/tests, `native_sandbox.go`, related execenv/provider configuration and documentation.

**Interfaces:** Render trusted host root read-only, replace process/device/runtime views, hide all managed code/admin roots and aliases, then restore the scoped user base read-only and explicit task/profile writable grants. Keep original executable/profile paths; remove obsolete narrow-install mount machinery rather than adding a competing compatibility layer.

- [ ] Write failing fake-runtime and kernel tests for original code/tool paths, host read-only writes, provider state writes, sibling-user denial, aliases and host-control socket denial.
- [ ] Implement overlay order and immutable validated scope/grants.
- [ ] Run real fake-worker boundary/lifecycle probes and synthetic Git round trip locally; commit.

### Task 5: Preserve private PID isolation and the MCode refusal

**Files:** native policy/scope/lifecycle and MCode compatibility tests.

**Interfaces:** The user chose private PID namespaces and no MCode0.6.13 support. Keep resource ownership, cleanup and the known-version refusal unchanged.

- [x] User decision: retain private PID namespaces; do not add a shared-host PID mode.
- [ ] Verify the known MCode0.6.13 refusal and fake-process/cgroup cleanup regressions.
- [ ] Run authorized k7 fresh/resume/restart checks for supported Codex, Cursor and OpenCode providers. Do not attempt unsupported MCode login/profile access.

### Task 6: Complete integration, review and delivery

**Files:** `docs/security/tool-isolation.md`, `AGENTS.md`, existing synthetic/real smoke targets and tests.

- [ ] Document per-user ownership, read-only host visibility, writable grants and exact process-isolation limits; supersede old spec guidance.
- [ ] Run narrow affected tests, kernel/filesystem/ownership/Git probes and full managed guarded Go race verification with the local dev API stopped.
- [ ] Perform one fresh whole-change review, fix material findings RED→GREEN and verify.
- [ ] Commit local results, restore only the local managed environment, keep garlic untouched and report precise limitations.
