# Shared helpers for scripts/release-publish.sh (sourced, not executed).
# shellcheck shell=bash

release_validate_tag() {
	local tag=$1
	if [[ ! $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
		printf '%s\n' "Release tags must look like vX.Y.Z or vX.Y.Z-suffix; got '$tag'." >&2
		return 1
	fi
	if [[ $tag == *-dirty* ]]; then
		printf '%s\n' "Refusing to release from dirty tag '$tag'." >&2
		return 1
	fi
	return 0
}

# Stable releases have no prerelease suffix (a hyphen after the semver triple).
release_tag_is_stable() {
	local tag=$1
	if [[ $tag == v*-* ]]; then
		return 1
	fi
	return 0
}
