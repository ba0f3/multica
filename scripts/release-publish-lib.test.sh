#!/usr/bin/env bash
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=scripts/release-publish-lib.sh
source "$SCRIPT_DIR/release-publish-lib.sh"

fail() {
	echo "$*" >&2
	exit 1
}

test_validate_tag_accepts_stable() {
	release_validate_tag v0.9.0-p1 || fail "expected v0.9.0-p1"
	release_validate_tag v1.2.3 || fail "expected v1.2.3"
}

test_validate_tag_rejects_bad() {
	if release_validate_tag not-a-tag 2>/dev/null; then
		fail "expected reject not-a-tag"
	fi
	if release_validate_tag v0.9.0-dirty 2>/dev/null; then
		fail "expected reject dirty"
	fi
}

test_stable_detection() {
	release_tag_is_stable v1.0.0 || fail "v1.0.0 should be stable"
	if release_tag_is_stable v1.0.0-rc1; then
		fail "rc should not be stable"
	fi
}

test_validate_tag_accepts_stable
test_validate_tag_rejects_bad
test_stable_detection
echo "release-publish-lib tests ok"
