#!/usr/bin/env bash
# Match the deployed daemon's process visibility without weakening profile guards.
set -euo pipefail

if [[ "$(uname -s)" != Linux ]]; then
  echo 'Isolated profile tests require Linux PID and mount namespaces.' >&2
  exit 2
fi

test_uid="$(id -u)"
test_gid="$(id -g)"
test_cargo="$(command -v cargo)"
test_workspace="$(cd "$(dirname "$0")/.." && pwd)"
cd "$test_workspace"

sudo -n --preserve-env=HOME,PATH,CARGO_HOME,RUSTUP_HOME,CARGO_PROFILE_DEV_OPT_LEVEL,CARGO_PROFILE_DEV_DEBUG,CARGO_PROFILE_TEST_DEBUG,CARGO_INCREMENTAL \
  unshare --mount --pid --fork --mount-proc --kill-child \
  --setgid "$test_gid" --setuid "$test_uid" \
  "$test_cargo" test "$@"
