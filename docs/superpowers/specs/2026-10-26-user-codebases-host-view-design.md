# User codebases and a read-only host filesystem

## Intent and authorization

The user chose one codebase per execution user, with independent task checkouts, and requested a read-only host filesystem view to reduce provider installation incompatibilities. Provider credential secrecy is explicitly deferred. This supersedes the empty-HOME and narrow-installation grants in the earlier native-host-sandbox spec. Keep all work local: garlic remains on upstream0.7.0 with no deployment, upload, restart or installed-CLI changes.

## Chosen approach

- Base caches live at `.repos/<workspace_id>/<execution_user_id>/<canonical_repo>.git`. Each task owns a private checkout and Git database; host-created private checkouts copy objects without hardlinks, while worker checkouts may read objects through alternates to that user's read-only cache. No shared Git worktree administration.
- The execution user is resolved by the server from the task's proven originator, independently of whether Git signing is enabled. Never substitute the runtime owner, agent owner or person pressing rerun. Code tasks without a proven execution user fail with an actionable error. No-repository tasks can run without a user cache.
- Native workers receive an original-path read-only host view. Hide the configured managed code/cache/workdir root and its aliases first, then expose the current user's selected workspace base read-only and the current task's checkout/temp/output/config writable. Keep daemon administrative state and host management sockets hidden. Provider profiles required for auth/session refresh remain writable at original paths; credentials of other providers are not promised hidden.
- A whole-root read-only bind does not make Unix sockets safe or fix PID-namespace liveness. Rebuild `/proc` and `/dev`, hide `/run`, `/sys` and management socket aliases, and hide existing filesystem socket paths and their aliases after profile grants. Restore only task IPC. Future sockets outside masked roots and TCP/abstract sockets follow the unchanged host network policy.

## Alternatives

1. One writable checkout per user/repo: rejected because the user chose concurrent task checkouts.
2. Per-user bases and private task checkouts: selected explicitly by the user. Costs one initial clone and retained cache per user/repo.
3. A shared workspace-wide base: rejected. A user must not gain access to another user's cached private code merely because both tasks name the same remote URL. Read-only mounts prevent writes but still permit reading cached objects. Keep per-user stores despite the initial clone time and duplicate storage for users working on the same repo.

## Repository behavior

Use an explicit `repocache.Scope{WorkspaceID, UserID}` across prepare/lookup/checkout/dependents/GC; reject empty or unsafe components at the cache boundary. Migrate callers rather than preserving workspace-only cache APIs. Workspace registration retains repository metadata and settings, but does not clone all users' code using the daemon owner's credentials. Fetch/ref resolution is strict per task with that task's signing lease.

Concurrent tasks for the same user/repo serialize base mutations and receive independent branches and `.git` databases. Users with the same remote URL never share object stores, refs, locks or dependent records. Do not seed new user stores from old shared caches or migrate data destructively. Migration leaves existing unscoped caches/workdirs intact for rollback and never admits or automatically adopts them. Ordinary GC may still reclaim terminal legacy task environments with valid existing workspace/task provenance.

Record execution-user ownership with task environments and root indexes. Resume/reuse and every alternate/cache path must match workspace and user. A missing legacy ownership proof or another user's workdir requires a fresh environment, preserving old files. Local in-place directories remain subject to their explicit existing admission policy.

HTTP daemon checkout is task-authenticated: derive scope from registered active-task metadata, never request JSON. Settings/hook reconciliation and cache retention understand all scoped user stores without mutating another user's code.

## Native filesystem

Trusted root metadata determines masks and writable grants. Mask the configured managed root, its descendant filesystems and bind aliases, and Multica administrator configuration. Arbitrary historical or other-profile roots outside that configured root remain ordinary read-only host paths. Expose one selected user base and one current task; disallow symlink or alternate escapes into other users. Runtime roots are host read-only at original paths, preserving executables, Node and shared libraries. Task temp/build caches and outputs remain task-owned. Profile directories and lock scopes follow the original providers. Do not copy credentials, rewrite vendor launchers, edit provider databases or delete their locks.

Keep current network policy, no-new-privileges, capability dropping and configured CPU/memory/PID limits. Docker remains available and uses the same scoped caches. No automatic backend fallback. The broader view is a filesystem-write boundary, not credential or network-exfiltration isolation.

## MCode compatibility decision

The native backend supports Codex, Cursor and OpenCode with private PID namespaces. MCode is excluded before any account/profile access or version probe, regardless of version. Use MiniMax through OpenCode instead.

## Verification and delivery

Default tests use fake providers. Test two users sharing a URL, same-user concurrent tasks, fresh fetch/ref, lost Git access, ownership/reuse/alternates, symlink aliases, hidden sibling code, read-only host files, allowed profile writes, management socket denial and lifecycle/cgroup limits. Synthetic Git round trips exercise checkout, pull, push and uncached refs in Docker and native mode. Real supported-provider tests may run only on k7 under the existing explicit opt-in; no remote garlic activity. Native MCode remains refused and is covered by a default regression.

Commit locally after verification. Do not merge, push, tag, publish or change garlic.
