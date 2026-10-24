# Release runbook

## Normal release

Release from a reviewed commit on `main` by creating and pushing a new semantic
version tag such as `v0.18.4`. The Release workflow intentionally has no manual
trigger: a tag push is the only event that can publish binaries, Homebrew
formulae, and release container images.

The verification job runs the Go tests and `govulncheck` before any publishing
job starts. The vulnerability scan is fail-closed by default.

CI and release jobs require Go `~1.27.3`: at least 1.27.3, while accepting
newer 1.27 patches. This security floor is independent of the development
minimum in `server/go.mod`. A plain `1.27.x` can resolve to an older patch
while the `setup-go` version manifest catches up with an official Go release.
When raising the security floor, update all Go workflows and the pinned
Go builder images in `Dockerfile` and `docker/task-worker/Dockerfile` together
so shipped binaries also receive the fixes.

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
