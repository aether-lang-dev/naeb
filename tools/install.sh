#!/bin/sh
# Installs target/build/bin/naeb to ${PREFIX:-$HOME/.local}/bin/naeb (run by
# .install.ae after the build). The old file is removed first and the new one
# copied in, never rewritten in place: an in-place rewrite of a signed binary
# is killed by macOS.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
SRC="$ROOT/target/build/bin/naeb"
BIN="${PREFIX:-$HOME/.local}/bin"
DEST="$BIN/naeb"
[ -x "$SRC" ] || { echo "install: $SRC is not built (aeb .build.ae)" >&2; exit 1; }
mkdir -p "$BIN"
rm -f "$DEST"
install -m 755 "$SRC" "$DEST"
echo "installed $DEST"
# From outside the checkout, so the version is what a user sees.
# (an empty directory: naeb refuses to run from a project that contains itself).
TMP=$(mktemp -d)
trap 'rmdir "$TMP"' EXIT
(cd "$TMP" && "$DEST" --version 2>/dev/null) || { echo "install: $DEST does not run" >&2; exit 1; }
echo "note: the installed naeb still needs this checkout to stay at $ROOT (naeb build compiles policies against its ae/policy_lib)"
