# Manual test: Docker task worker

Use this on a host with Docker installed. Release CI builds and smoke-tests the
worker image for Linux amd64 and arm64, then publishes it to GHCR. Task isolation
and agent compatibility still require the checks below.

## Prerequisites

- Linux with Docker (rootful or rootless with working cgroup limits).
- Worker image from GHCR or built from `docker/task-worker/Dockerfile`.
- Git credentials: database custody is on when `JWT_SECRET` or `MULTICA_GIT_SECRET_KEY` is set (private keys sealed in Postgres). Optional OpenBao: `MULTICA_GIT_CUSTODY_*`.
- Do **not** use production keys unless explicitly authorized.

## Build worker image

To use a published release, set
`MULTICA_DOCKER_TASK_IMAGE=ghcr.io/ba0f3/multica-task-worker:<release-tag>`.
Stable releases also update the daemon's default `latest` tag.

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
docker tag multica/task-worker:local ghcr.io/ba0f3/multica-task-worker:latest
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
# Optional if you tagged ghcr.io/ba0f3/multica-task-worker:latest locally:
# export MULTICA_DOCKER_TASK_IMAGE=multica/task-worker:local
# Optional limits (verify with docker inspect during a run):
export MULTICA_DOCKER_TASK_MEMORY=4294967296
export MULTICA_DOCKER_TASK_PIDS_LIMIT=512
export MULTICA_DOCKER_TASK_NETWORK=bridge
# Extra CA the worker must trust for private Git hosts (public cert material):
export MULTICA_DOCKER_TASK_CA_BUNDLE=/home/tui/Projects/multica/.orca/drops/MUOI_TIEU_XANH.crt
```

Legacy bwrap-only hosts: `MULTICA_TASK_SANDBOX=1` or `bwrap` still selects bubblewrap.

`MULTICA_DOCKER_TASK_CA_BUNDLE` names a host PEM file whose valid `CERTIFICATE`
blocks the daemon appends to the worker's CA bundle (the machine trust the repo
cache already hands over, plus the extra file). Set it and restart the daemon;
a configured path that is missing, unreadable, or holds no valid certificate
fails the task at prepare rather than dropping trust.

## Smoke checklist

1. **Launch** — start a task with a fake agent executable path first; confirm `docker ps` shows `multica-attempt-*` and container exits on cancel.
2. **Paths** — inside container (debug entrypoint): `echo $HOME $SSH_AUTH_SOCK` → `/home/agent`, `/run/multica/ssh-agent.sock`.
3. **Host checkout blocked** — with sandbox on, `multica repo checkout` from the task must fail with *host repo checkout is disabled*; native `git clone` in workdir should still work when signer is configured.
4. **A/B** — two tasks same runtime: distinct attempt sockets and no shared `SSH_AUTH_SOCK` path.
5. **Teardown** — cancel task: container removed, signing socket directory under `git-agent/<task>/<attempt>/` gone.
6. **CA bundle** — with `MULTICA_DOCKER_TASK_CA_BUNDLE` set, `docker inspect <container>` must show a read-only mount of the task's `ca-bundle.pem` at `/home/agent/.multica/ca-bundle.pem` and the CA env vars (`GIT_SSL_CAINFO`, `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`) all pointing there.

## Native agents (authorized only)

Per AGENTS.md:

```bash
(cd server && MULTICA_RUN_REAL_AGENT_SMOKE=1 go test -tags=agentintegration ./pkg/agent -run '<TestName>' -count=1 -v)
```

Pin Codex/Cursor/OpenCode versions in the image before claiming compatibility.

## Evidence to record

Commit SHA, image digest, Docker mode (rootless/rootful), env vars, test type (unit vs manual), pass/fail/blocked — update `docs/security/git-security-mvp-status.md`.
