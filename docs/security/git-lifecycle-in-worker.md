# Git lifecycle: worker boundary vs performance

Spec requires Git **driven by the task** (clone, fetch, probe, hooks) to run inside the Docker/bwrap boundary with the user's signing socket—not via host `multica repo checkout` or daemon repocache on behalf of the agent.

## What we do today (hybrid)

| Phase | Where it runs | Credential |
| --- | --- | --- |
| Initial workdir prepare (claim) | Host `execenv` / daemon | Daemon orchestration; primary repo often materialized before container starts |
| `multica repo checkout` during agent | Host HTTP → `repocache` | Task token; **disabled when sandbox/Docker is active** |
| Agent `git clone/fetch/push` | Container (or bwrap) | Per-attempt `SSH_AUTH_SOCK` |

Blocking host checkout closes the main bypass; prepare-on-host remains for latency on large monorepos.

## Why moving *everything* into the worker can be slow

1. **Shared bare cache (`.repos`)** — Host repocache keeps one bare clone per URL and cheap worktrees. A cold `git clone` inside every container duplicates network and disk for large histories.
2. **No cross-attempt reuse** — Each attempt gets private `.git` in the task filesystem; retry does not inherit another attempt's objects unless the supervisor reuses the same mount root (by design for isolation).
3. **Layer copy** — Binding a prepared host directory into the container is fast; re-cloning inside the container is not.
4. **LFS / partial clone** — Features depend on provider and git version in the image; not automatic wins.

## Design options (no single “free” fix)

| Approach | Isolation | Large-repo cost | Notes |
| --- | --- | --- | --- |
| **A. Hybrid (current direction)** | Agent Git in container; supervisor prepare once on host mount | Low for primary repo | Must keep host checkout API disabled for sandboxed tasks |
| **B. Read-only bare cache mount** | Task writes only in `/workspace/repo`; cache read-only | Medium | Daemon maintains cache; container `git clone --reference` or worktree from snapshot |
| **C. Supervisor warm inside boundary** | Worker subprocess runs prepare before agent | High per attempt if full clone | Same slowness unless cache/reference used |
| **D. Shallow/partial clone policy** | Full | Lower network | Trade depth for speed; may break agents expecting full history |

**Recommendation for MVP:** keep **A**, document **B** as the next step for monorepos, avoid claiming full in-worker lifecycle until prepare/finalize paths are moved or cache-mount is implemented and tested.

## Finalize and hooks

Finalize (commit push, worktree cleanup) on the host with task-modified hooks still violates the boundary. Long term, finalize should run in the same container or via a narrow RPC that does not execute arbitrary repo scripts on the host identity.

## Operator tuning

- Increase prepare timeout for huge repos before enabling protected Docker on those workspaces.
- Pin image git version; use `GIT_TRACE` only in disposable tests.
- For Gitea/GitHub, prefer shallow clone in agent instructions when repo size is known.
