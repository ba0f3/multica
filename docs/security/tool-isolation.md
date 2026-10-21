# Tool isolation (Git security MVP)

This document describes how Multica constrains **Codex**, **Cursor**, and **OpenCode** when `MULTICA_TASK_SANDBOX` enables the Docker or bubblewrap worker boundary. **Network deny** (egress policy) is a separate follow-up; it is not required for the rules below.

## Scope

| Layer | What it does |
| --- | --- |
| Provider gate | Only `codex`, `cursor`, and `opencode` may run when the sandbox is enabled (`server/internal/daemon/sandbox/providers.go`). |
| Worker boundary | Agent CLI runs inside Docker or bwrap; Session IPC and git signing stay on controlled mounts. |
| Provider prep | `IsolatedToolBoundary` on execenv prepare/reuse copies provider secrets into the task env and fixes container identity paths. |
| Launch argv | OpenCode rejects `--server` and forces `--standalone` on 2.x inside the boundary (`server/pkg/agent/opencode_isolated.go`). |

## Codex

- Per-task `CODEX_HOME` is prepared under the task env root.
- On the host, `auth.json` and related files are symlinked from shared `~/.codex`.
- In the worker, the same files are **copied** so symlinks never point at host paths the container cannot follow.

## Cursor

- Managed MCP writes `.cursor/mcp.json` in the checkout as usual.
- Workspace trust and MCP approval keys use **`/workspace/repo`** (`execenv.IsolatedContainerWorkdir`), matching the worker cwd, not the host-side absolute workdir path.
- Optional `CURSOR_MCP_AUTH_SOURCE` is **copied** into the task `CURSOR_DATA_DIR` when isolated (no symlink to host).

## OpenCode

- **`--server` is forbidden** in the isolated boundary so the agent cannot attach to a host or shared background service.
- **OpenCode 2.x** runs with **`--standalone`** so the service stays in the worker process tree (cancellation and tool execution remain inside the boundary).
- **OpenCode 2.x + Multica-managed MCP** is still refused at launch (`ErrOpenCodeV2MCPUnsupported`) until MUL-7523 delivers env-backed MCP via standalone; use OpenCode 1.x or remove composed MCP servers for isolated 2.x tasks.

## Environment signals

| Variable | When set |
| --- | --- |
| `MULTICA_ISOLATED_TOOL_BOUNDARY=1` | Agent process inside the worker |
| `MULTICA_HOST_REPO_CHECKOUT=disabled` | Host `POST /repo/checkout` blocked for the task token |

## Verification

Automated:

```bash
go test ./server/internal/daemon/sandbox/...
go test ./server/internal/daemon/ -run 'Sandbox|Docker|Provider'
go test ./server/pkg/agent/ -run 'OpenCodeIsolated|EnforceOpenCode'
go test ./server/internal/daemon/execenv/ -run Cursor
```

Manual Docker checklist: [docker-task-worker-manual-test.md](./docker-task-worker-manual-test.md).
