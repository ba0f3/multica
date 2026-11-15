#!/usr/bin/env bash
# Local release publishing: replaces the Release workflow when CI is unavailable.
# Publishes CLI archives (GoReleaser), container images (GHCR), matching .github/workflows/release.yml.
#
# Usage:
#   TAG=v0.9.0-p1 GITHUB_TOKEN=... bash scripts/release-publish.sh all
#   bash scripts/release-publish.sh verify
#   bash scripts/release-publish.sh images-worker
#
# See .github/RELEASING.md § "Manual release (make / script)".

set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
# shellcheck source=scripts/release-publish-lib.sh
source "$SCRIPT_DIR/release-publish-lib.sh"

PLATFORMS=${PLATFORMS:-linux/amd64,linux/arm64}
BUILDER_NAME=${BUILDER_NAME:-multica-release}

usage() {
	cat <<'EOF'
Usage: release-publish.sh <command>

Commands:
  build            GoReleaser snapshot (dist/ only, no upload)
  verify           Go tests + govulncheck (pre-release gate)
  cli              GoReleaser release --clean (GitHub Release assets)
  images           backend + web + task-worker to GHCR
  images-worker    task-worker only (no GitHub Release)
  all              verify, cli, images (honors SKIP_* env)

Environment:
  TAG                      Release tag (vX.Y.Z); default: exact tag on HEAD
  GITHUB_TOKEN             contents:write + packages:write (gh auth token -s ...)
  GHCR_OWNER               Image namespace (default: gh repo owner)
  PLATFORMS                Docker platforms (default: linux/amd64,linux/arm64)
  HOMEBREW_TAP_GITHUB_TOKEN  Optional; omit to skip Homebrew tap upload
  HOMEBREW_TAP_OWNER       Tap owner (default: GHCR_OWNER)
  SKIP_VERIFY=1            Skip verify in `all`
  SKIP_CLI=1               Skip GoReleaser in `all`
  SKIP_IMAGES=1            Skip GHCR pushes in `all`
  SKIP_VULNCHECK=1         Skip govulncheck (document reason; CI bypass uses ALLOW_VULN_BYPASS_FOR_TAG)
  ALLOW_VULN_BYPASS_FOR_TAG  When equal to TAG, skip govulncheck with a warning
  RELEASE_ENSURE_DB=1      When .env / RELEASE_ENV_FILE exists, start local Postgres and migrate (like make test)
  RELEASE_ENV_FILE         Env file path (default: .env or .env.worktree)
EOF
}

die() {
	printf '%s\n' "$*" >&2
	exit 1
}

require_cmd() {
	command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

release_resolve_tag() {
	if [[ -n "${TAG:-}" ]]; then
		printf '%s\n' "$TAG"
		return
	fi
	if git -C "$ROOT_DIR" describe --exact-match --tags HEAD 2>/dev/null; then
		return
	fi
	die "Set TAG=vX.Y.Z or check out the release tag commit first."
}

release_resolve_owner() {
	if [[ -n "${GHCR_OWNER:-}" ]]; then
		printf '%s\n' "$GHCR_OWNER"
		return
	fi
	local url owner
	url=$(git -C "$ROOT_DIR" config --get remote.origin.url 2>/dev/null || true)
	if [[ -n "$url" ]]; then
		if [[ "$url" =~ github\.com[:/]([^/]+)/[^/]+ ]]; then
			owner="${BASH_REMATCH[1]}"
			owner="${owner%.git}"
			printf '%s\n' "$owner"
			return
		fi
	fi
	require_cmd gh
	gh repo view --json owner -q .owner.login
}

release_assert_head_at_tag() {
	local tag=$1
	local head tag_commit
	head=$(git -C "$ROOT_DIR" rev-parse HEAD)
	tag_commit=$(git -C "$ROOT_DIR" rev-parse "$tag^{commit}" 2>/dev/null) || die "Tag not found: $tag"
	if [[ "$head" != "$tag_commit" ]]; then
		die "HEAD ($head) is not tag $tag ($tag_commit). Checkout the tag before publishing."
	fi
}

release_ensure_token() {
	if [[ -n "${GITHUB_TOKEN:-}" ]]; then
		return
	fi
	if gh auth token >/dev/null 2>&1; then
		GITHUB_TOKEN=$(gh auth token)
		export GITHUB_TOKEN
		return
	fi
	die "Set GITHUB_TOKEN or run 'gh auth login' with packages + repo scope."
}

release_login_ghcr() {
	local owner=$1
	release_ensure_token
	printf '%s\n' "$GITHUB_TOKEN" | docker login ghcr.io -u "$owner" --password-stdin >/dev/null
}

release_ensure_buildx() {
	require_cmd docker
	if ! docker buildx inspect "$BUILDER_NAME" >/dev/null 2>&1; then
		docker buildx create --name "$BUILDER_NAME" --driver docker-container --use >/dev/null
	else
		docker buildx use "$BUILDER_NAME" >/dev/null 2>&1 || docker buildx use "$BUILDER_NAME"
	fi
}

release_image_tags() {
	local image=$1
	local tag=$2
	local sha=$3
	local -a tags=(
		"-t" "$image:$tag"
		"-t" "$image:sha-$sha"
	)
	if release_tag_is_stable "$tag"; then
		tags+=("-t" "$image:latest")
	fi
	printf '%s\n' "${tags[@]}"
}

release_build_push_image() {
	local dockerfile=$1
	local image=$2
	local tag=$3
	local full_sha=$4
	local -a tag_args=()
	local arg
	while IFS= read -r arg; do
		[[ -n "$arg" ]] && tag_args+=("$arg")
	done < <(release_image_tags "$image" "$tag" "$full_sha")

	echo "==> buildx push $image ($dockerfile)"
	docker buildx build \
		--builder "$BUILDER_NAME" \
		--platform "$PLATFORMS" \
		-f "$ROOT_DIR/$dockerfile" \
		--pull \
		"${tag_args[@]}" \
		--build-arg "VERSION=$tag" \
		--build-arg "COMMIT=$full_sha" \
		--push \
		"$ROOT_DIR"
}

release_smoke_worker() {
	local owner=$1
	local tag=$2
	local image="ghcr.io/$owner/multica-task-worker:$tag"
	echo "==> smoke: $image"
	docker run --rm --platform "${SMOKE_PLATFORM:-linux/amd64}" "$image" multica --version
}

# Matches `make test`: when a dev env file exists, ensure Postgres is up and migrated.
release_prepare_database() {
	if [[ "${RELEASE_ENSURE_DB:-1}" != 1 ]]; then
		return 0
	fi
	local env_file=${RELEASE_ENV_FILE:-}
	if [[ -z "$env_file" ]]; then
		if [[ -f "$ROOT_DIR/.env" ]]; then
			env_file="$ROOT_DIR/.env"
		elif [[ -f "$ROOT_DIR/.env.worktree" ]]; then
			env_file="$ROOT_DIR/.env.worktree"
		fi
	elif [[ "$env_file" != /* ]]; then
		env_file="$ROOT_DIR/$env_file"
	fi
	if [[ -z "$env_file" || ! -f "$env_file" ]]; then
		echo "==> No .env; skipping local Postgres prepare (DB tests skip unless DATABASE_URL is set)"
		return 0
	fi
	echo "==> Preparing database from $env_file (RELEASE_ENSURE_DB=1)"
	bash "$ROOT_DIR/scripts/ensure-postgres.sh" "$env_file"
	set -a
	# shellcheck disable=SC1090
	source "$env_file"
	set +a
	export DATABASE_URL
	(cd "$ROOT_DIR/server" && go run ./cmd/migrate up)
}

cmd_build() {
	require_cmd goreleaser
	cd "$ROOT_DIR"
	goreleaser release --snapshot --clean --skip=publish
	echo "Artifacts under dist/"
}

cmd_verify() {
	local tag
	tag=$(release_resolve_tag)
	release_validate_tag "$tag" || exit 1
	require_cmd go
	cd "$ROOT_DIR"
	release_prepare_database
	bash scripts/test-go.test.sh
	bash scripts/test-go.sh --race
	if [[ "${SKIP_VULNCHECK:-}" == 1 ]] || [[ "${ALLOW_VULN_BYPASS_FOR_TAG:-}" == "$tag" ]]; then
		echo "::warning::govulncheck skipped for $tag"
	else
		(cd server && go tool govulncheck ./...)
	fi
	echo "verify ok for $tag"
}

cmd_cli() {
	local tag owner tap_owner
	tag=$(release_resolve_tag)
	release_validate_tag "$tag" || exit 1
	release_assert_head_at_tag "$tag"
	release_ensure_token
	require_cmd goreleaser
	owner=$(release_resolve_owner)
	tap_owner=${HOMEBREW_TAP_OWNER:-$owner}
	export GITHUB_TOKEN
	export HOMEBREW_TAP_OWNER="$tap_owner"
	if [[ -z "${HOMEBREW_TAP_GITHUB_TOKEN:-}" ]]; then
		export HOMEBREW_SKIP_UPLOAD=true
	else
		export HOMEBREW_TAP_GITHUB_TOKEN
		export HOMEBREW_SKIP_UPLOAD=false
	fi
	cd "$ROOT_DIR"
	echo "==> GoReleaser release $tag (owner=$owner)"
	goreleaser release --clean
}

cmd_images() {
	local tag owner full_sha short_sha
	tag=$(release_resolve_tag)
	release_validate_tag "$tag" || exit 1
	release_assert_head_at_tag "$tag"
	owner=$(release_resolve_owner)
	full_sha=$(git -C "$ROOT_DIR" rev-parse HEAD)
	short_sha=$(git -C "$ROOT_DIR" rev-parse --short HEAD)
	release_login_ghcr "$owner"
	release_ensure_buildx
	release_build_push_image Dockerfile "ghcr.io/$owner/multica-backend" "$tag" "$full_sha"
	release_build_push_image Dockerfile.web "ghcr.io/$owner/multica-web" "$tag" "$full_sha"
	release_build_push_image docker/task-worker/Dockerfile "ghcr.io/$owner/multica-task-worker" "$tag" "$full_sha"
	release_smoke_worker "$owner" "$tag"
	echo "Images published under ghcr.io/$owner (tag=$tag sha-$short_sha)"
}

cmd_images_worker() {
	local tag owner full_sha
	tag=${TAG:-latest}
	if [[ "$tag" != latest ]] && ! release_validate_tag "$tag"; then
		exit 1
	fi
	owner=$(release_resolve_owner)
	full_sha=$(git -C "$ROOT_DIR" rev-parse HEAD)
	release_login_ghcr "$owner"
	release_ensure_buildx
	release_build_push_image docker/task-worker/Dockerfile "ghcr.io/$owner/multica-task-worker" "$tag" "$full_sha"
	release_smoke_worker "$owner" "$tag"
}

cmd_all() {
	if [[ "${SKIP_VERIFY:-}" != 1 ]]; then
		cmd_verify
	fi
	if [[ "${SKIP_CLI:-}" != 1 ]]; then
		cmd_cli
	fi
	if [[ "${SKIP_IMAGES:-}" != 1 ]]; then
		cmd_images
	fi
	echo "release-publish all complete"
}

main() {
	local cmd=${1:-}
	case "$cmd" in
	build) cmd_build ;;
	verify) cmd_verify ;;
	cli) cmd_cli ;;
	images) cmd_images ;;
	images-worker) cmd_images_worker ;;
	all) cmd_all ;;
	-h|--help|help|"") usage ;;
	*) die "Unknown command: $cmd (try --help)" ;;
	esac
}

main "$@"
