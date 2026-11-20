# Release runbook

## Normal release

Release from a reviewed commit on `main` by creating and pushing a new semantic
version tag such as `v0.18.4`. The Release workflow intentionally has no manual
trigger: a tag push is the only event that can publish binaries, Homebrew
formulae, and release container images.

The verification job runs the Go tests and `govulncheck` before any publishing
job starts. The vulnerability scan is fail-closed by default.

Release notes use GoReleaser's GitHub changelog to credit commit authors and
recognized co-authors between the previous and current tags. Keep all commits,
including documentation, tests, and chores, so their authors are credited too.
Commit-subject `@` characters are separated from the following text with an HTML
comment; only the generated author mentions populate GitHub's Contributors list.

CI and release jobs require Go `~1.27.4`: at least 1.27.4, while accepting
newer 1.27 patches. This security floor is independent of the development
minimum in `server/go.mod`. A plain `1.27.x` can resolve to an older patch
while the `setup-go` version manifest catches up with an official Go release.
When raising the security floor, update all Go workflows and the pinned
Go builder images in `Dockerfile` and `docker/task-worker/Dockerfile` together
so shipped binaries also receive the fixes.

## CLI and daemon

The daemon has no separate artifact: it ships inside the `multica` CLI built
from `server/cmd/multica`. The `release` job runs GoReleaser on every owner, so a
fork's tag publishes `multica-cli-<version>-<os>-<arch>` archives (plus the
legacy `multica_<os>_<arch>` names), `checksums.txt`, and the Windows/macOS
desktop metadata assets for its own repository.

Homebrew is pushed to `<owner>/homebrew-tap` when
`HOMEBREW_TAP_GITHUB_TOKEN` is set. Upstream defaults the owner to
`multica-ai` from `github.repository_owner`; a fork that wants its own tap sets
the `HOMEBREW_TAP_OWNER` repository variable and the token secret. Without the
token the formula is generated into `dist/` but not pushed, and the CLI release
still succeeds.

Daemons installed from a fork's release do not update from it by default:
`multica update` reads `multica-ai/multica` unless
`MULTICA_RELEASE_API_BASE_URL` and `MULTICA_RELEASE_DOWNLOAD_BASE_URL` point at
a mirror carrying that fork's assets. Keep `MULTICA_DAEMON_AUTO_UPDATE` off
when running a patched fork, or the next update replaces it with upstream.

## Container images

After verification, the workflow builds and pushes `multica-backend`,
`multica-web`, and `multica-task-worker` to `ghcr.io/<repository-owner>/`.
These jobs also run on forks using `GITHUB_TOKEN` with `packages: write`;
they do not require the upstream Homebrew token.

Each image supports `linux/amd64` and `linux/arm64`, built on native runners.
The worker runs `multica --version` on each platform before its digest is
included in the published manifest. Images receive the exact release tag
such as `v0.7.1` and a `sha-<commit>` tag. Only stable releases update `latest`;
prereleases keep their own version and SHA tags.

The daemon defaults to `ghcr.io/ba0f3/multica-task-worker:latest`. Set
`MULTICA_DOCKER_TASK_IMAGE=ghcr.io/ba0f3/multica-task-worker:<release-tag>`
or use an image digest to pin a worker release. Other forks must set this
variable to their own published image.

### Manual release (`make` / script)

When CI cannot run the Release workflow, publish from a tagged checkout on a machine with Docker Buildx, GoReleaser, and `gh` authenticated (`repo` + `write:packages`):

```bash
git checkout v0.9.0-p1
export GITHUB_TOKEN="$(gh auth token)"   # or a PAT with contents + packages write

make release-verify RELEASE_TAG=v0.9.0-p1
make release-publish RELEASE_TAG=v0.9.0-p1
```

Targets map to `scripts/release-publish.sh`:

| Target | Action |
| --- | --- |
| `release-build` | `goreleaser release --snapshot` → `dist/` only |
| `release-verify` | Same tests + `govulncheck` as the CI `verify` job |
| `release-cli` | GoReleaser → GitHub Release assets (+ Homebrew when `HOMEBREW_TAP_GITHUB_TOKEN` is set) |
| `release-images` | `multica-backend`, `multica-web`, `multica-task-worker` → `ghcr.io/<owner>/` |
| `release-images-worker` | Worker image only (`RELEASE_TAG=latest` allowed) |
| `release-publish` | `verify` + `cli` + `images` (skip with `SKIP_VERIFY=1`, `SKIP_CLI=1`, or `SKIP_IMAGES=1`) |

Override image namespace with `GHCR_OWNER` when needed. Forks that track `ba0f3/multica` should publish under `ghcr.io/ba0f3/…` (owner from `git remote origin`, not `gh repo view` upstream).

**GHCR login:** `make release-images` logs into `ghcr.io` unless `SKIP_GHCR_LOGIN=1`. Token order: `GHCR_TOKEN` (or `GHCR_PUSH_TOKEN` / `GITHUB_PACKAGES_TOKEN`), then `GITHUB_TOKEN`, then `gh auth token` — and the latter must include `write:packages` or push fails with `permission_denied`. A plain `docker push ghcr.io/ba0f3/ccload:latest` can still work when an older `docker login` used a classic PAT, while the release script overwrote GHCR with an OAuth token that only has `repo`. Fix: `gh auth refresh -h github.com -s write:packages -s read:packages`, or `export GHCR_TOKEN=<classic PAT with write:packages>`, or `docker login ghcr.io` then `SKIP_GHCR_LOGIN=1 make release-images …`. Fine-grained PATs must allow write to each container package (`multica-backend`, `multica-web`, `multica-task-worker`), not only `ccload`.

Multi-arch defaults to `linux/amd64,linux/arm64` (`PLATFORMS`). Worker smoke uses `linux/amd64` (`SMOKE_PLATFORM`).

`release-verify` / `verify` runs the same Go suite as CI. When `.env` or `.env.worktree` exists, it also runs `scripts/ensure-postgres.sh` and migrations (`RELEASE_ENSURE_DB=1`, same idea as `make test`). Set `RELEASE_ENSURE_DB=0` to skip that step. If `DATABASE_URL` is set in your shell but Postgres is down, either unset it, run `make up`, or rely on the auto-prepare when `.env` is present.

Lib tests: `bash scripts/release-publish-lib.test.sh`.

### Publish only the worker image

The Worker image workflow also supports manual runs without creating a release
or publishing backend/web images. Run it on `main` to publish the default worker:

```bash
gh workflow run worker-image.yml --repo ba0f3/multica --ref main -f tag_name=latest
```

Set `tag_name` to publish a different image tag. Enable `is_stable` to also update
`latest` when publishing a version tag. The same native builds and CLI smoke
tests run for manual and release-triggered publication. Manual runs do not run
the full release Go test suite or vulnerability scan.

## Emergency vulnerability-scan bypass

Use the bypass only when `govulncheck` itself or its live vulnerability database
is unavailable, or when maintainers have documented a confirmed false positive
that blocks an urgent release. Never use it to publish a release with an
unresolved reachable vulnerability.

1. Record the reason and maintainer approval in the release issue or pull
   request, and confirm no other release is in progress.
2. In **Settings → Secrets and variables → Actions → Variables**, set the
   repository variable `ALLOW_VULN_BYPASS_FOR_TAG` to the exact release tag,
   for example `v0.18.4`.
3. Re-run the failed Release workflow for that tag. A different tag, an empty
   value, or any typo keeps the scan enabled.
4. Confirm the verification log contains the explicit bypass warning and retain
   the workflow URL in the incident record.
5. Delete `ALLOW_VULN_BYPASS_FOR_TAG` immediately after the release run
   completes. The tag-scoped value prevents a concurrent release with another
   tag from inheriting the bypass.

Every Go binary retains its compiler version in the standard Go build metadata;
use `go version -m <binary>` when auditing a downloaded release artifact.

## Stable release promotion

GoReleaser publishes a public release with `make_latest: false`. Installed stable
clients and CLI entry points that read Latest keep using the previous complete
version while Desktop artifacts are uploading. Homebrew continues to publish
normally because CLI archives are already public; container tags are independent.
The release page and GitHub notifications can show the new release before promotion.

`.github/workflows/promote-release.yml` is the only entry point for changing
Latest. The Linux/Windows Desktop matrix calls it after both builds succeed.
After the manual macOS release has signed, notarized, verified, and uploaded both
architectures, the release-desktop skill dispatches the same workflow:

```bash
gh workflow run promote-release.yml --repo multica-ai/multica --ref main -f tag=vX.Y.Z
```

The workflow uses the reviewed validator from `main`, not executable code from the
requested tag. It serializes promotion globally and only promotes a stable
semantic version newer than the current Latest. Repeating a completed promotion
or finishing an older release after a hotfix leaves Latest unchanged.

The gate checks all six update metadata files (`latest-mac.yml`,
`latest-x64-mac.yml`, `latest.yml`, `latest-arm64.yml`, `latest-linux.yml`, and
`latest-linux-arm64.yml`), their version against the tag, and each referenced
artifact's architecture, upload status, and byte size. It also requires all six
CLI targets in both legacy and versioned archive names plus `checksums.txt`.
macOS update metadata must reference the ZIP; Windows requires EXE and Linux
AppImage. Missing blockmaps do not block promotion. The macOS `afterSign` hook
runs `spctl` and `stapler validate` after notarization and before packaging/upload
for explicit publishing builds. The release skill requires code signing so an
unsigned build cannot skip that hook. These host checks do not run for unsigned
local builds or other platforms. The gate does not download large binaries to
recalculate SHA-512.

Missing or inconsistent assets produce a `waiting` result with a list of blockers
and leave Latest unchanged. This is normal when macOS and CI finish in either
order. The next completed upload path tries again. API/authentication failures
fail the job. Inspect the promotion run result; a successful dispatch only means
the run was queued. If needed, correct the failed upload and dispatch the workflow
again. Do not bypass the gate with a direct `gh release edit --latest`.

Land this workflow on `main` before the first release using `make_latest: false`.
Until promotion succeeds, stable clients stay on the previous version. Existing
clients need no changes to benefit from the release ordering fix; friendly failure
messages and download recovery require the newly shipped Desktop client.

For a faulty release, publish a higher patch version through the same gate.
Do not move Latest backwards: already installed Windows arm64 clients predating
the downgrade guard may install the older binary. Removing `make_latest: false`
reintroduces the incomplete-release window and is not a version rollback.
