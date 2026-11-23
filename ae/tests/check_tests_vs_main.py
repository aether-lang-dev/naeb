#!/usr/bin/env python3
"""tests/ and scripts/stats.py may differ from upstream's (the `main` branch,
which mirrors upstream) only by renaming words: naeb's names for upstream's.

The reverse substitution is applied to this branch's copy of each file and the
result must equal main's, so an edit that is not a rename fails here, and a
file added or removed relative to main is reported.
"""
import re
import subprocess
import sys

RULES = [  # (this branch's text, upstream's text); applied in this order
    (r"NAEB_", "NIB_"),
    (r"naeb_version", "nib_version"),
    (r"refused by naeb", "refused by nib"),
    (r"You are naeb", "You are nib"),
    (r"ae/tests/naeb-unfenced", "zig-out/bin/nib"),
    (r"\.naeb-\*", ".nib-*"),
    (r"\.naeb/skills", ".nib/skills"),
    (r"\.naeb/sessions", ".nib/sessions"),
    (r'tmp / "\.naeb"', 'tmp / ".nib"'),
    (r"naeb: Unknown option: --x (\S+) run naeb --help", r"nib: Unknown option: --x \1 run nib --help"),
    (r"HOME/\.naeb fallback", "HOME/.nib fallback"),
]
SCOPE = ("tests/", "scripts/stats.py")


def git(*args):
    return subprocess.run(["git", *args], capture_output=True, text=True, check=True).stdout


def main():
    ref = "main"
    if subprocess.run(["git", "rev-parse", "--verify", "-q", ref], capture_output=True).returncode != 0:
        ref = "origin/main"
    here = {f for f in git("ls-files", *SCOPE).splitlines()}
    there = {f for f in git("ls-tree", "-r", "--name-only", ref, *SCOPE).splitlines()}
    bad = []
    for f in sorted(here | there):
        if f not in here or f not in there:
            bad.append(f"{f}: only on {'main' if f in there else 'this branch'}")
            continue
        text = open(f, encoding="utf-8").read()
        for new, old in RULES:
            text = re.sub(new, old, text)
        if text != git("show", f"{ref}:{f}"):
            bad.append(f"{f}: differs from {ref} by more than the name substitutions")
    if bad:
        print("\n".join(bad), file=sys.stderr)
        print(f"tests/ must differ from {ref} only by renamed words (ae/tests/check_tests_vs_main.py)", file=sys.stderr)
        return 1
    print(f"tests/ and scripts/stats.py differ from {ref} only by name substitutions")
    return 0


sys.exit(main())
