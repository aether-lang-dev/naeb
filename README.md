<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-dark.svg">
    <img src="docs/assets/logo-light.svg" alt="naeb" width="96">
  </picture>
</p>

<h1 align="center">naeb</h1>

<p align="center">A port of nib-code to <a href="https://github.com/aether-lang-dev/aether">Aether</a></p>

**naeb is a port to the Aether language of
[nib-code](https://github.com/yyydddkkk/nib-code), the coding agent written in
Zig by jackyyy (GitHub: [yyydddkkk](https://github.com/yyydddkkk)).**

## Credit

The agent is jackyyy's. nib-code is a small, focused, quiet coding agent
that works in Runs: the model is given a single tool, `run(code)`, writes one
JavaScript script that reads, edits and checks your project in a single step,
and sees the result. That design, the single `run(code)` tool, the prompts,
the session and log formats, the TUI, the test suite and mock providers, the
documentation under `docs/` and the original Zig implementation are all
theirs. naeb exists to run that same agent on Aether; it adds a port and a
project fence, and it does not replace or improve on the design. If you want
the original, go to
[yyydddkkk/nib-code](https://github.com/yyydddkkk/nib-code) (command name
`nib`, MIT). Upstream's own README, with its benchmark numbers, is
[there](https://github.com/yyydddkkk/nib-code#readme).

## A divergent fork

This repository is a fork of nib-code that has diverged on purpose, and the
port is renamed to match.

- **Respectful divergence.** Nothing here is sent back to nib-code: no pull
  requests, no patches. naeb tracks upstream's changes and ports the ones that
  make sense; one day it may have diverged so far that it cannot, and that is
  accepted.
- **Branches.** `main` mirrors upstream's `main` and is never committed to.
  `aether-port` (the default branch) is the port; everything described here
  is on it. The Zig sources (`src/`, `build.zig`), upstream's Python end-to-end
  tests and mock providers (`tests/`) and upstream's docs are kept as upstream
  wrote them, so that upstream's changes merge in cleanly and the port can be
  checked against them. The Aether sources are under `ae/`. Which upstream
  file each Aether module ports, and through which upstream commit, is in
  [PORT_STATUS.md](PORT_STATUS.md).
- **Aether instead of Zig.** The agent is built from Aether, compiled to C,
  with the agent's Run scripts on QuickJS embedded through Aether's
  `contrib.quickjs`.
- **A project fence.** `naeb` runs the agent inside a project fence against
  supply-chain attacks (below), which upstream does not have.
  `naeb --mode unfenced ...` runs it with no fence, as upstream's `nib` does;
  it is chosen only by those first two arguments on the command line, announced
  on stderr and recorded in the Session log, and it is what upstream's own tests
  are run with.
- **API keys only.** OpenAI, Anthropic, DeepSeek, Grok (xAI) and your own
  Responses or Chat Completions endpoint. The Codex subscription sign-in, its
  WebSocket protocol and the Codex backend are not ported, by choice.
- **No self-updater.** `update` is not ported (it downloads upstream's
  releases). Update with `git pull` and a rebuild.
- **No prebuilt binary yet.** Build from source, below.
- **Benchmarks.** Upstream's speed, cost and memory numbers were measured on
  its Zig build and are not claimed for naeb.
- **Behind upstream.** The port is ported through upstream 0.13.0 (a2dd439);
  upstream's head is 0.20.0 (e6b1cb4, 2026-11-20). PORT_STATUS.md lists, file by
  file, the upstream commit each Aether module is ported through. A port of an
  upstream change is done in the matching `ae/naeb/` module with tests, checked
  against upstream's own tests.
- **Names.** Everything the port names itself is `naeb`: the command, the
  `NAEB_*` environment variables (upstream's `NIB_*`), `~/.naeb` (upstream's
  `~/.nib`), `.naeb/skills` in a project, the hook variables `NAEB_EVENT`,
  `NAEB_FILES` and `NAEB_TURN_STATUS`, the `naeb_version` field of the Session
  log header, and the Aether modules under `ae/naeb/`. The user-facing docs
  under `docs/` (config, providers, skills, session log and the like) use these
  names; upstream's ADRs, release notes, benchmarks and Codex notes are as
  upstream wrote them. Upstream's Python tests in `tests/` carry the same
  renamed words and nothing else.

## Licence

MIT, as upstream's. [LICENSE](LICENSE) is upstream's licence text with its
copyright line, "Copyright (c) 2026 jackyyy", unaltered, and below it the line
"Portions copyright 2026 - Aether language developers" for the port. The port's
changes are under the same licence.

## Set up

macOS (Apple silicon) and Linux x86_64, where it is tested. Linux arm64
should work but is not tested yet.

### 1. The Aether toolchain

One command installs `ae` (the compiler) and `aeb` (the build tool), pinned
to the versions naeb is verified against. Those versions are in [pins](pins):

```sh
. ./pins   # sets AE_PIN and AEB_REF
curl -fsSL https://raw.githubusercontent.com/aether-lang-dev/aeb/main/get.sh \
  | AE_PIN=$AE_PIN AEB_REF=$AEB_REF sh
```

Both land in `~/.local/bin` (`PREFIX=` changes that); put it on your `PATH`. `ae version doctor` checks the install. A newer Aether release usually
works too: `ae version install <v>` and `ae version use <v>` switch between
versions.

You also need a C compiler (Xcode's command line tools on macOS, gcc or clang
on Linux) and OpenSSL 3 or later:
- **macOS:** `brew install openssl`.
- **Debian or Ubuntu:** `apt install libssl-dev`.

### 2. Build

```sh
git clone -b aether-port https://github.com/aether-lang-dev/naeb.git naeb
cd naeb
aeb .build.ae          # builds target/build/bin/naeb
```

### 3. Install

```sh
aeb .install.ae        # builds, then installs ${PREFIX:-$HOME/.local}/bin/naeb
naeb --version         # naeb 0.13.0-ae
```

`PREFIX=/some/dir aeb .install.ae` installs under `/some/dir/bin`. The old file
is removed before the new one is copied in. To update, run `git pull`, then
`aeb .install.ae` again. Project policies need no rebuild unless naeb says so.
Keep the checkout where it is: `naeb build` compiles policies against its
`ae/policy_lib` (`NAEB_SRC` points elsewhere).

## Use

```sh
cd your-project
naeb                          # interactive
naeb ask 'explain the entry points'
naeb -c                       # continue the last session here
naeb --mode unfenced ask '...'   # no project fence, as upstream's nib behaves
```

`naeb` is fenced by default (see below); `--mode unfenced` must be the first two
arguments and is announced on stderr. Run the installed `naeb` from your project:
it refuses to start from a binary inside a directory the fence lets commands write.

On first run, start `naeb` and use `/provider` to choose a service and paste
its API key. The key is entered masked and stored in `~/.naeb/auth.json` with
mode 0600. `naeb login <service>` does the same from the shell. `/model` picks
a model. Your own endpoint: [providers](docs/providers.md).

- **Keys:** Enter sends, Shift+Enter adds a line, Esc cancels. `@` completes
  file paths.
- **Commands:** type `/` for the list: `/provider`, `/model`, `/effort`,
  `/undo`, `/tasks`, `/skills`, `/status`.
- **Simple mode:** `/simple` or Ctrl+S hides everything but the conversation.
- **MCP:** `/mcp` turns on MCP servers from config.toml.
- **Hooks:** optional sandboxed `after_edit` and `turn_end` commands, see
  [hooks](docs/config.md#hooks).
- **Conventions:** project ones go in `AGENTS.md`, personal ones in
  `~/.naeb/AGENTS.md`.

## Fenced: naeb

`naeb` runs the agent inside a project fence against supply-chain attacks
([ADR 0001](docs/naeb/adr/0001-supply-chain-sandbox.md)): its commands
(bash, hooks, MCP servers) and its own tools cannot read your home outside
the project, write outside it, or reach any host the project has not
allowed, and get no secrets from naeb's environment. Linux (Landlock and
namespaces) and macOS (`sandbox-exec`).

`naeb --mode unfenced ...` turns the fence off, for upstream's behaviour. Only
the person starting naeb can: it must be the first two arguments of the command
line, no environment variable, config key, project file, skill, hook or
sub-agent can set it, a sub-agent of a fenced naeb is always fenced, and a naeb
started from inside a fenced Run is still inside that Run's OS jail. Unfenced
runs say so on stderr and in the Session log header (`"mode":"unfenced"`).

The project says what it needs in `naeb.ae` at its root, in Aether:

```aether
import naeb.policy
import naeb_templates.maven

fence(p: ptr) {
    maven.apply(p)                                  // ~/.m2/repository, Maven Central
    policy.allow_host(p, "repo.example.com", 443)
    policy.set_env(p, "BUNDLE_USER_HOME", "${policy.project_root(p)}/.bundle/user")
}
```

```sh
naeb build        # shows naeb.ae's diff since the last build, asks, compiles it
naeb              # the TUI, fenced; also naeb ask, naeb js
```

`naeb build` compiles the policy (about a second) into
`~/.naeb/launchers/<project>-<hash>/`, outside everything the fence lets
commands write. naeb refuses to start when `naeb.ae` changed since it was
built, so an edit or a pull that widens the fence waits for your review.
`naeb.ae` itself is read-only inside the fence. A project without one runs
in the default fence (the project only, no egress). Grow the policy from
the denials: each names the path or `host:port`.

In the TUI naeb grows it with you. When a Turn ends after the fence refused
something, naeb shows the `naeb.ae` lines that would allow it (many files
under one directory become one line, never a directory holding a secret,
never `~`) as a diff and asks:

```text
 refused read under ~/.fixture-cache/a · 20 refusals · tool
 refused egress 127.0.0.1:62089 · b1
 --- naeb.ae
 +++ naeb.ae (proposed)
 @@ -2,4 +2,10 @@

  fence(p: ptr) {
      policy.allow_host(p, "allowed.invalid", 443)
 +
 +    // Approved 2026-11-15: refused read under ~/.fixture-cache/a, 20 refusals (tool)
 +    policy.allow_read(p, "~/.fixture-cache/a")
 +
 +    // Approved 2026-11-15: refused egress 127.0.0.1:62089 (b1)
 +    policy.allow_host(p, "127.0.0.1", 62089)
  }
 Allow? [y/N]
```

`y` writes the lines into `naeb.ae`, rebuilds the policy as `naeb build`
does and loads it before the next Run, in the same Session; anything else
declines, and a declined refusal is not offered again in that Session.
Only your key does this: the model cannot write `naeb.ae` or answer the
prompt. `naeb ask` and `naeb js` never ask; the refusals and their
suggested lines are in their results.

### Maven broker (experimental)

With `policy.maven_broker(p)` in `naeb.ae`, fenced builds run offline
(`MAVEN_ARGS=--offline`) against a `~/.m2/repository` they can read but
never write, whatever else the policy allows. The model runs the build,
collects what it missed from the errors and asks for it:
`tools.maven_fetch({ gavs: ["g:a:v", ...] })`. naeb itself fetches it,
outside the fence, without running Maven, mvnw, Gradle or a JVM: only
coordinates reachable from the project's POMs, only from the repositories
`naeb.ae` names, checksums checked, OpenPGP signatures verified against
your keyring, versions at least `maven_min_age_days` old (default 7), each
file written atomically into `~/.m2/repository`.

```aether
fence(p: ptr) {
    maven.apply(p)
    policy.maven_broker(p)
    policy.maven_repository(p, "https://repo.maven.apache.org/maven2")
    policy.maven_min_age_days(p, 7)
    policy.maven_keyring(p, "~/.naeb/maven/trusted-keys.asc")
}
```

A version too young is refused; in the TUI naeb asks once per coordinate:

```text
 Maven broker refused org.example:lib:2.0: naeb.ae asks for versions published 7 days ago or more
     org.example:lib:2.0 · published 2 days ago
 Fetch it anyway (this time, these versions only)? [y/N]
```

Every fetch and refusal is in the Session log (`maven_fetch`) and in
`/fence`. Experimental: the details, limits and open questions are in
[ADR 0001](docs/naeb/adr/0001-supply-chain-sandbox.md#the-maven-broker-experimental).

## A Run

```text
  Run · edit 2 files · bash
    ae/naeb/grep/module.ae +38 −9 · ae/naeb/tools/module.ae +2 −1
    read ae/naeb/grep/module.ae · read ae/naeb/tools/module.ae · grep ae
    └─ b1 bash aeb .tests.ae · 4s · completed ✓ exit 0

  1 Run · 2 steps · 41s · 6.6k tokens
```

Each script shows as one block: what changed, what was read and what ran.
Click a Run to see its diff, result and script; Ctrl+O opens the latest one.

## Safety

naeb runs model-written code with your permissions, as you would yourself.
- **bash** refuses obviously destructive commands.
- **Workspace mode:** `[sandbox] mode = "workspace"` limits writes to the
  project, temp dirs and build caches. It uses Landlock on Linux (kernel 5.19
  or later, Landlock ABI 2; on older kernels bash runs unsandboxed, as
  upstream's does) and `sandbox-exec` on macOS.
- **Commit before you start.**
- **Logs:** sessions and tool results are logged locally in `~/.naeb/sessions`
  (mode 0600). `NAEB_RECORD=off` stops tool recording.

## Develop

```sh
aeb .tests.ae               # the port's unit suites
tools/tui_tests.sh          # the TUI suites
tools/check_layers.sh       # which module may import which
ae/tests/upstream-e2e.sh    # upstream's own Python end-to-end tests
```

Upstream's tests and mock providers in `tests/` are the parity oracle. They are
edited only to rename words (`ae/tests/check_tests_vs_main.py` enforces it);
they need `python3` and talk only to local mocks. Gaps found in
Aether are written up in [asks/](asks/) and fixed in Aether itself.
[PORT_STATUS.md](PORT_STATUS.md) has the per-host results and what is left.

## More

[Principles](docs/principles.md) · [Docs](docs/README.md) · [Providers](docs/providers.md) · [Config](docs/config.md) · [Port status](PORT_STATUS.md) · [Upstream nib](https://github.com/yyydddkkk/nib-code) · [MIT](LICENSE)
