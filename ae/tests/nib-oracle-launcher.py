#!/usr/bin/env python3
"""Stands in for upstream's `zig-out/bin/nib` when upstream's own end-to-end
tests (tests/*.py, unchanged) drive the port.

Those tests hard-code the program path `zig-out/bin/nib` and configure it
through upstream's NIB_* environment variables. naeb is configured through
NAEB_* only, with no fallback, so this launcher translates each NIB_X in its
environment to NAEB_X and runs target/build/bin/naeb-unfenced. That is the
only place the old names survive, and only in the test harness.

NIB_HOME is also left in place: upstream's mock workers (tests/mock_agent.py,
tests/mock_llm_tool.py) read it from their own environment to find the
configuration directory the test gave the program. Every other NIB_ name is
removed, so a variable naeb is meant to scrub from what it starts cannot leak
back to a mock under its old name.
"""
import os
import sys

root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
real = os.path.join(root, "target", "build", "bin", "naeb-unfenced")
env = {}
for key, value in os.environ.items():
    if key.startswith("NIB_"):
        env["NAEB_" + key[4:]] = value
        if key == "NIB_HOME":
            env[key] = value
    else:
        env[key] = value
os.execve(real, [real] + sys.argv[1:], env)
