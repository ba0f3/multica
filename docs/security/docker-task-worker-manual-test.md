# Manual test: Docker task worker

Use this on a host with Docker installed. The cloud agent VM has no Docker engine; CI here only runs **fake-docker** unit tests.

## Prerequisites

- Linux with Docker (rootful or rootless with working cgroup limits).
- Branch `feature/git-security-mvp` built or image from `docker/task-worker/Dockerfile`.
- Git custody configured (`MULTICA_GIT_CUSTODY_*`) if testing real signing.
- Do **not** use production keys unless explicitly authorized.

## Build worker image

From repository root:

```bash
docker build -f docker/task-worker/Dockerfile \
  -t multica/task-worker:local \
  --build-arg VERSION=dev --build-arg COMMIT=$(git rev-parse --short HEAD) \
  .
docker images multica/task-worker:local --digests
```

Record **image digest** in your test notes.

## Daemon environment

```bash
export MULTICA_TASK_SANDBOX=docker
export MULTICA_TASK_PROTECTED=1
export MULTICA_DOCKER_TASK_IMAGE=multica/task-worker:local
# Optional limits (verify with docker inspect during a run):
export MULTICA_DOCKER_TASK_MEMORY=4294967296
export MULTICA_DOCKER_TASK_PIDS_LIMIT=512
export MULTICA_DOCKER_TASK_NETWORK=bridge
```

Legacy bwrap-only hosts: `MULTICA_TASK_SANDBOX=1` or `bwrap` still selects bubblewrap.

## Smoke checklist

1. **Launch** — start a task with a fake agent executable path first; confirm `docker ps` shows `multica-attempt-*` and container exits on cancel.
2. **Paths** — inside container (debug entrypoint): `echo $HOME $SSH_AUTH_SOCK` → `/home/agent`, `/run/multica/ssh-agent.sock`.
3. **Host checkout blocked** — with sandbox on, `multica repo checkout` from the task must fail with *host repo checkout is disabled*; native `git clone` in workdir should still work when signer is configured.
4. **A/B** — two tasks same runtime: distinct attempt sockets and no shared `SSH_AUTH_SOCK` path.
5. **Teardown** — cancel task: container removed, signing socket directory under `git-agent/<task>/<attempt>/` gone.

## Native agents (authorized only)

Per AGENTS.md:

```bash
(cd server && MULTICA_RUN_REAL_AGENT_SMOKE=1 go test -tags=agentintegration ./pkg/agent -run '<TestName>' -count=1 -v)
```

Pin Codex/Cursor/OpenCode versions in the image before claiming compatibility.

## Evidence to record

Commit SHA, image digest, Docker mode (rootless/rootful), env vars, test type (unit vs manual), pass/fail/blocked — update `docs/security/git-security-mvp-status.md`.
