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

### Bake the CA into the worker image

Instead of mounting a host bundle per task, bake a self-signed/private CA into
the worker image's system trust store so the daemon can leave the image's
`/etc/ssl/certs` untouched:

```bash
make task-worker-image-ca CA_CERT=/home/tui/Projects/multica/.orca/drops/MUOI_TIEU_XANH.crt
docker push ghcr.io/ba0f3/multica-task-worker:ca
```

Then point the daemon at that image:

```bash
export MULTICA_DOCKER_TASK_IMAGE=ghcr.io/ba0f3/multica-task-worker:ca
```

With a baked CA, leave `MULTICA_DOCKER_TASK_CA_BUNDLE` unset. When it is set (or
the server sends extra CAs), the daemon mounts a bundle and sets
`GIT_SSL_CAINFO`/`SSL_CERT_FILE`, which *replace* the image's system store — so
that bundle must include every CA the worker needs, or the baked CA is lost.

Verify the installed file and the merged bundle in the image:

```bash
docker run --rm --entrypoint sh <image> -c 'test -f /usr/local/share/ca-certificates/multica-extra-ca.crt && grep -c "BEGIN CERTIFICATE" /etc/ssl/certs/ca-certificates.crt'
```

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

Legacy bwrap-only hosts: `MULTICA_TASK_SANDBOX=bwrap` still selects bubblewrap (the `1`/`true`/`on`/`yes` values select Docker). bwrap has no task repo manifest and no worker CA bundle, so the repo-cache and CA checks below apply only to the Docker backend.

`MULTICA_DOCKER_TASK_CA_BUNDLE` names a host PEM file whose valid `CERTIFICATE`
blocks the daemon appends to the worker's CA bundle (the machine trust the repo
cache already hands over, plus the extra file). Set it and restart the daemon;
a configured path that is missing, unreadable, or holds no valid certificate
fails the task at prepare rather than dropping trust.

To make the setting permanent, add it to the daemon's systemd unit and reload:

```ini
# In the daemon's [Service] section:
Environment="MULTICA_DOCKER_TASK_CA_BUNDLE=/home/tui/Projects/multica/.orca/drops/MUOI_TIEU_XANH.crt"
```

```bash
systemctl --user daemon-reload
systemctl --user restart <daemon-unit>
```

For a system service, use `systemctl daemon-reload` and
`systemctl restart <daemon-unit>` instead.

The daemon startup log reports the configured path and whether it exists.

## Smoke checklist

1. **Launch** — start a task with a fake agent executable path first; confirm `docker ps` shows `multica-attempt-*` and container exits on cancel.
2. **Paths** — inside container (debug entrypoint): `echo $HOME $SSH_AUTH_SOCK` → `/home/agent`, `/run/multica/ssh-agent.sock`.
3. **Repo cache mounts** — `docker inspect -f '{{range .Mounts}}{{.Source}} -> {{.Destination}} {{.Mode}}{{"\n"}}{{end}}' <container>` must show:
   - the task manifest mounted read-only: `<env-root>/repo-cache.json -> /home/agent/.multica/repo-cache.json ro`;
   - one read-only bind per task repo, with the host cache path as both source and destination (`<workspaces-root>/.repos/<workspace-id>/<repo>.git -> ... ro`);
   - no unrelated sibling repository or another task's workdir. A reused workdir may add read-only caches named by its own alternates, but only under the workspace cache root;
   - the workspace checkout mounted read-write at `/workspace/repo` only.

   `docker exec <container> cat /home/agent/.multica/repo-cache.json` lists exactly the task repo URLs. A write inside a mounted cache (for example `docker exec <container> touch <cache>/worker-write`) must fail with a read-only filesystem error.
4. **In-worker checkout** — with the task container running, run `multica repo checkout <url>` from the task workdir (or `docker exec -w /workspace/repo <container> multica repo checkout <url>`). It must succeed without `MULTICA_DAEMON_PORT`/`MULTICA_TOKEN` and report the checkout path and branch. Then verify:
   - `git -C <path> remote get-url origin` is the real repository URL, not the cache path;
   - `cat <path>/.git/objects/info/alternates` names the mounted cache's `objects` directory;
   - `git -C <path> branch --show-current` is the task branch, and `git status --short` is clean.
5. **Host checkout blocked** — with the sandbox on, the host daemon `POST /repo/checkout` must still reject the task token with *host repo checkout is disabled*. The in-worker command above must not contact the host daemon.
6. **A/B** — two tasks on the same runtime and repo: both manifests point at the same bare cache, but the containers have distinct workdirs and attempt sockets. A second task's manifest lists only its own `task.Repos`; neither container mounts the other's workdir, and `ls` in the second container cannot see the first task's files.
7. **Reuse divergence** — reuse the first task's workdir, leave an uncommitted file and an unpushed commit, then run `repo checkout` again. The output must say the existing checkout was kept and report commits ahead/behind, uncommitted files, and unpushed commits; `git log` and `git status` must show the work untouched. Then run `repo checkout ... --fresh`: it resets to the new base and drops unpushed commits, uncommitted changes, and untracked and ignored files. Push anything you need first.
8. **Cache retention** — after the task ends, the cache listed in the manifest still exists while the env root exists, and a daemon restart followed by another checkout still works. The env root's removal and the next GC cycle drop its dependents record; the cache then becomes evictable under the normal repo TTL. It must not disappear while a live workdir still references it.
9. **CA bundle** — with `MULTICA_DOCKER_TASK_CA_BUNDLE` set, `docker inspect <container>` must show a read-only mount of the task's `ca-bundle.pem` at `/home/agent/.multica/ca-bundle.pem` and the CA env vars (`GIT_SSL_CAINFO`, `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`) all pointing there.
10. **Teardown** — cancel task: container removed, signing socket directory under `git-agent/<task>/<attempt>/` gone.

## Native agents (authorized only)

Per AGENTS.md:

```bash
(cd server && MULTICA_RUN_REAL_AGENT_SMOKE=1 go test -tags=agentintegration ./pkg/agent -run '<TestName>' -count=1 -v)
```

Pin Codex/Cursor/OpenCode versions in the image before claiming compatibility.

## Evidence to record

Commit SHA, image digest, Docker mode (rootless/rootful), env vars, test type (unit vs manual), pass/fail/blocked — update `docs/security/git-security-mvp-status.md`.
