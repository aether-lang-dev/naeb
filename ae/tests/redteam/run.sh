#!/bin/sh
# Runs the red-team fixtures against the built naeb (aeb .build.ae), each
# fixture project's policy built by `naeb build -y` against this checkout:
# ae/tests/redteam/run.sh [case-prefix ...]. Then, with no case-prefix,
# attribution.py (each refusal is reported with the command that caused it)
# and naeb_policy.py (how naeb builds, checks and loads a policy).
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$ROOT"
NAEB=${NAEB:-$ROOT/target/build/bin/naeb}
[ -x "$NAEB" ] || { echo "no $NAEB: run aeb .build.ae first"; exit 1; }
mkdir -p target/redteam
status=0
NAEB="$NAEB" NAEB_FENCED=1 python3 -I ae/tests/redteam/redteam.py "$@" || status=1
if [ $# -eq 0 ]; then
    NAEB="$NAEB" python3 -I ae/tests/redteam/attribution.py || status=1
    NAEB="$NAEB" python3 -I ae/tests/redteam/naeb_policy.py || status=1
fi
exit $status
