#!/bin/sh
# Builds the red-team launcher (naeb with the fixtures' fence) and runs the
# red-team fixtures against it: ae/tests/redteam/run.sh [case-prefix ...].
# Then, with no case-prefix, attribution.py: each refusal is reported with
# the command that caused it.
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$ROOT"
mkdir -p target/redteam
ae build ae/tests/redteam/launcher.ae --lib ae -o target/redteam/naeb-redteam >target/redteam/build.log 2>&1 || {
    tail -30 target/redteam/build.log
    exit 1
}
NAEB="$PWD/target/redteam/naeb-redteam" NAEB_LAUNCHER=1 python3 -I ae/tests/redteam/redteam.py "$@"
[ $# -gt 0 ] || NAEB="$PWD/target/redteam/naeb-redteam" python3 -I ae/tests/redteam/attribution.py
