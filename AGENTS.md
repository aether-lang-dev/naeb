# naeb

naeb is a coding agent written in Aether: a port of [nib-code](https://github.com/yyydddkkk/nib-code),
the Zig agent by jackyyy (GitHub: yyydddkkk, MIT). The design is theirs: the
model gets one tool, `run(code)`, writes one JavaScript script per step that
reads, edits and checks the project, and sees the result. naeb runs that agent
on Aether, with the scripts on QuickJS, and adds a project fence (below).
Upstream's original source tree (`src/`, `build.zig`) is kept in the branch
untouched, for reference and for merges; it is not built here.

The port's own status is in [PORT_STATUS.md](PORT_STATUS.md) (which upstream file
each Aether module ports, through which upstream commit, and what is left) and
[TODO.md](TODO.md). Terminology (Session, Turn, Step, Run) is in
[CONTEXT.md](CONTEXT.md); decisions are in [docs/adr/](docs/adr/) (upstream's) and
[docs/naeb/adr/](docs/naeb/adr/) (the fence).

## Branches

- `aether-port` is the port and the default branch. Commit straight to it; no
  other branches, no pull requests. `git pull --rebase` before each push; never
  force-push.
- Upstream is a respectful divergence, not a collaboration: nothing is sent
  back to nib-code (no pull requests, no patches). The port tracks upstream's
  changes and ports those that make sense; one day it may have diverged too far
  to, and that is accepted. Upstream's Zig tree stays in this branch as the
  reference to port from.
- `main` mirrors upstream (`upstream` remote, `yyydddkkk/nib-code`) and is never
  committed to. Move it with `git fetch upstream && git checkout main && git
  merge --ff-only upstream/main`, then merge `main` into `aether-port`.
- Expect conflicts only where this branch edited upstream's files: `tests/*.py`
  and `scripts/stats.py` (renamed words only), the user-facing docs under `docs/`
  (renamed words), `CONTEXT.md`, `README*.md`, `LICENSE`. Resolve by taking
  upstream's text and re-applying the renames. `ae/tests/check_tests_vs_main.py`
  (run by `ae/tests/upstream-e2e.sh`) must pass afterwards: it reverses the
  renames in `tests/` and `scripts/stats.py` and requires the result to equal
  `main`.
- The port follows upstream: a changed upstream file that the port covers is
  ported (`tools/upstream-diff.sh` lists what upstream changed in each ported
  file since the commit PORT_STATUS records), with its tests, and the row in
  PORT_STATUS moves.

## Porting an upstream change

How far behind: the port is ported through upstream 0.13.0 (a2dd439, per-file
commits in PORT_STATUS); upstream's head is 0.20.0 (e6b1cb4, 2026-11-20). To port
a change: fast-forward `main` to upstream and merge it here (the Zig sources and
renamed docs/tests come across), run `tools/upstream-diff.sh` to see what changed
in each ported file, port the change into the matching `ae/naeb/` module with its
`ae/tests/*_test.ae` cases (upstream's inline Zig tests are ported by name), bring
upstream's Python tests across (they are the oracle, with renamed words only),
show a new test failing before the port and passing after, run the three suites
below, and move the file's row in PORT_STATUS to the new commit. A change that
makes no sense here (the Codex sign-in, the self-updater) is left out and the
reason is written in PORT_STATUS.

## Layout

```
ae/naeb_main.ae      the program's entry; its name, naeb, is set once, in .build.ae
ae/naeb/<concept>/   one Aether module per upstream file or concept, imported as naeb.<concept>
ae/term/             the TUI's terminal layer (standalone: imports std only); its own README and tests
ae/policy_lib/       what a project's naeb.ae imports (naeb.policy, naeb_templates.*)
ae/tests/            std.spec suites (*_test.ae), the e2e harness (upstream-e2e.sh, run_upstream.py,
                     check_tests_vs_main.py, run-unfenced), redteam/ (the fence's attack suite)
tools/               check_layers.sh (which module may import which), upstream-diff.sh, tui_tests.sh
asks/                what the port needs from Aether, written up for Aether's maintainers
tests/, scripts/     upstream's Python end-to-end tests and mock providers; stats.py and charts.py
docs/                upstream's docs (user-facing ones use naeb's names); docs/naeb/ is the fence's
.build.ae, .install.ae, .tests.ae   aeb build, install and test definitions
pins                 the Aether (AE_PIN) and aeb (AEB_REF) versions last verified
```

Names: environment variables are `NAEB_*`, state is in `~/.naeb`, project skills
in `.naeb/skills`, hook commands receive `NAEB_EVENT`, `NAEB_FILES` and
`NAEB_TURN_STATUS`, and the Session log header carries `naeb_version` and `mode`.
Upstream's docs that are not user-facing references (ADRs, release notes,
benchmarks) still say nib.

## Build and test

Toolchain: `ae` and `aeb`, installed with aeb's `get.sh` at the versions in `pins`
(`. ./pins` sets `AE_PIN` and `AEB_REF`); `ae version doctor` checks it. Also a C
compiler, OpenSSL 3 and `python3`.

```sh
aeb .build.ae                 # target/build/bin/naeb (writes only under target/)
aeb .install.ae               # build, then install ${PREFIX:-$HOME/.local}/bin/naeb (tools/install.sh)
aeb .tests.ae                 # 89 targets: 85 std.spec suites plus workspace.sh, redteam/run.sh,
                              # tui_e2e.sh and tools/check_layers.sh
ae/tests/upstream-e2e.sh      # upstream's Python tests against the built binary (the oracle)
ae/tests/redteam/run.sh       # the fence's attack suite alone
tools/tui_tests.sh            # the TUI suites alone; ae/term/run-tests.sh for the terminal layer
```

- The oracle is `tests/test_*.py`. They drive `ae/tests/run-unfenced`, which runs
  `naeb --mode unfenced`, because their mock providers are on loopback and the
  fence allows no egress. `tests/` and `scripts/stats.py` may differ from `main`
  only by renamed words. Do not change an assertion to make a test pass; fix the
  port, or write the gap up in `asks/` and leave the case out in
  `ae/tests/upstream-e2e.sh` with its reason. Left out by policy: the Codex
  classes (no Codex sign-in or WebSocket) and `test_update.py`, `test_install.py`.
  Last known: 29 of 30 files pass; `test_effort.py` fails in its Codex half.
- The red-team suite makes unix sockets under the checkout, so it fails from a
  long path (the limit is 107 bytes). Run the whole thing from a checkout whose
  path is short (about 30 characters), and run `ae/tests/redteam/run.sh` alone if
  `aeb .tests.ae` fails there under load. It must report 0 holes.
- A regression test is shown failing on the old code before it is trusted on the new.

## Hard rules

- API keys only (OpenAI, Anthropic, DeepSeek, Grok, or a custom endpoint). No
  Codex subscription sign-in.
- Never call a real model provider or a real host. Tests use the mock providers
  in `tests/` and fixtures on loopback or `.invalid`; no recorded provider
  traffic is kept. Never put a real key in a file or a test.
- The fence must never weaken. `naeb` is fenced by default; the project's
  `naeb.ae` can only widen it through `naeb build`, which shows the diff and asks
  the person. Unfenced mode is selected only by `--mode unfenced` as the first two
  command-line arguments of the person starting naeb: no environment variable,
  config key, project file, skill, hook, tool or sub-agent can select it, a
  sub-agent of a fenced naeb is started fenced, and it is announced on a terminal's stderr and
  in the Session log. Any change near `ae/naeb/fence/`, `tools/jail`, `tools/egress`,
  `app` (mode and start-up) or the sub-agent launch needs `ae/tests/redteam/run.sh`
  with 0 holes, and a new case that fails against the weakened code first.
- Tools return complete data to scripts; nothing is silently truncated.
- `ae/term` imports only `std`; `tools/check_layers.sh` pins every module's imports,
  and a wider import is a reviewed change to that file.
- No back-compat shims: change the API and update every caller. No shared mutable
  global state: give instances their own state and pass it explicitly.

## Aether

The port tracks the latest Aether release; `pins` records what was last verified,
and a bump is its own commit saying what it re-verified (a tracking-only bump says
so). A gap in Aether is written up as `asks/<topic>.md` (motivation, a minimal
repro, what it blocks); when a fix lands the ask is updated to say so, not deleted.
Work around the gap in the meantime and mark the workaround.
