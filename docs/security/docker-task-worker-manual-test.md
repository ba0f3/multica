# Manual test: Docker task worker

Use this on a host with Docker installed. The cloud agent VM has no Docker engine; CI here only runs **fake-docker** unit tests.

## Prerequisites

- Linux with Docker (rootful or rootless with working cgroup limits).
- Branch `feature/git-security-mvp` built or image from `docker/task-worker/Dockerfile`.
- Git credentials: database custody is on when `JWT_SECRET` or `MULTICA_GIT_SECRET_KEY` is set (private keys sealed in Postgres). Optional OpenBao: `MULTICA_GIT_CUSTODY_*`.
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

Or tag the same image as the daemon default so you do not need
`MULTICA_DOCKER_TASK_IMAGE` (Docker uses the local tag and does not pull GHCR):

```bash
docker tag multica/task-worker:local ghcr.io/r2d-ai/multica-task-worker:latest
```

`make task-worker-image` builds and applies both tags.

The image ships the `multica` worker binary only (Debian/glibc base). For isolated
**codex**, **cursor**, and **opencode** tasks, the daemon bind-mounts the host CLI
into `/usr/local/bin/<basename>` read-only at launch time — you do not bake agent
CLIs into the image for local dev.

Record **image digest** in your test notes.

## Daemon environment

```bash
export MULTICA_TASK_SANDBOX=docker
export MULTICA_TASK_PROTECTED=1
# Optional if you tagged ghcr.io/r2d-ai/multica-task-worker:latest locally:
# export MULTICA_DOCKER_TASK_IMAGE=multica/task-worker:local
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
