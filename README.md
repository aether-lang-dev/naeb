<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-dark.svg">
    <img src="docs/assets/logo-light.svg" alt="nib" width="96">
  </picture>
</p>

<h1 align="center">naeb</h1>

<p align="center">nib, ported to <a href="https://github.com/aether-lang-dev/aether">Aether</a></p>

A small, focused, quiet coding agent. naeb is the Aether port of
[nib](https://github.com/yyydddkkk/nib-code) (Zig, MIT, © jackyyy): the same
agent, feature for feature, built from Aether instead of Zig. It builds two
commands: `nib`, upstream's behaviour, and `naeb`, the same agent inside a
project fence (below).

nib works in Runs: the model writes one JavaScript script that reads, edits
and checks your project in a single step. In naeb that script runs on
QuickJS embedded through Aether's `contrib.quickjs`.

This branch, `aether-port`, is the port. `main` mirrors upstream nib and is
never committed to; the port tracks it. Which upstream file each Aether module
ports, and through which upstream commit, is in
[PORT_STATUS.md](PORT_STATUS.md).

## Differences from upstream nib

- **API keys only.** OpenAI, Anthropic, DeepSeek, Grok (xAI) and your own
  Responses or Chat Completions endpoint. The Codex subscription sign-in, its
  WebSocket protocol and the Codex backend are not ported, by choice.
- **No self-updater.** `nib update` is not ported (it downloads upstream's
  releases). Update with `git pull` and a rebuild.
- **No prebuilt binary yet.** Build from source, below. Release binaries may
  come later.
- **Benchmarks.** Upstream's speed, cost and memory numbers were measured on
  its Zig build and are not claimed for naeb. See
  [upstream's README](https://github.com/yyydddkkk/nib-code#readme).

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
git clone -b aether-port https://github.com/paul-hammant/naeb-code.git naeb
cd naeb
aeb .build.ae          # builds target/build/bin/nib and target/build/bin/naeb
```

### 3. Install

```sh
install -m 755 target/build/bin/nib ~/.local/bin/nib
install -m 755 target/build/bin/naeb ~/.local/bin/naeb
nib --version          # nib 0.13.0-ae
```

To update, run `git pull`, then `aeb .build.ae`, then the `install` lines
again. Project policies need no rebuild unless naeb says so. Keep the
checkout: `naeb build` compiles policies against its `ae/policy_lib`
(`NAEB_SRC` points elsewhere).

## Use

```sh
cd your-project
nib                          # interactive
nib ask 'explain the entry points'
nib -c                       # continue the last session here
```

On first run, start `nib` and use `/provider` to choose a service and paste
its API key. The key is entered masked and stored in `~/.nib/auth.json` with
mode 0600. `nib login <service>` does the same from the shell. `/model` picks
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
  `~/.nib/AGENTS.md`.

## Fenced: naeb

`naeb` runs the agent inside a project fence against supply-chain attacks
([ADR 0001](docs/naeb/adr/0001-supply-chain-sandbox.md)): its commands
(bash, hooks, MCP servers) and its own tools cannot read your home outside
the project, write outside it, or reach any host the project has not
allowed, and get no secrets from naeb's environment. Linux (Landlock and
namespaces) and macOS (`sandbox-exec`).

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

## A Run

```text
  Run · edit 2 files · bash
    ae/nib/grep/module.ae +38 −9 · ae/nib/tools/module.ae +2 −1
    read ae/nib/grep/module.ae · read ae/nib/tools/module.ae · grep ae
    └─ b1 bash aeb .tests.ae · 4s · completed ✓ exit 0

  1 Run · 2 steps · 41s · 6.6k tokens
```

Each script shows as one block: what changed, what was read and what ran.
Click a Run to see its diff, result and script; Ctrl+O opens the latest one.

## Safety

nib runs model-written code with your permissions, as you would yourself.
- **bash** refuses obviously destructive commands.
- **Workspace mode:** `[sandbox] mode = "workspace"` limits writes to the
  project, temp dirs and build caches. It uses Landlock on Linux (kernel 5.19
  or later, Landlock ABI 2; on older kernels bash runs unsandboxed, as
  upstream's does) and `sandbox-exec` on macOS.
- **Commit before you start.**
- **Logs:** sessions and tool results are logged locally in `~/.nib/sessions`
  (mode 0600). `NIB_RECORD=off` stops tool recording.

## Develop

```sh
aeb .tests.ae               # the port's unit suites
tools/tui_tests.sh          # the TUI suites
tools/check_layers.sh       # which module may import which
ae/tests/upstream-e2e.sh    # upstream's own Python end-to-end tests, unchanged
```

Upstream's tests and mock providers in `tests/` are the parity oracle and are
never edited; they need `python3` and talk only to local mocks. Gaps found in
Aether are written up in [asks/](asks/) and fixed in Aether itself.
[PORT_STATUS.md](PORT_STATUS.md) has the per-host results and what is left.

## More

[Principles](docs/principles.md) · [Docs](docs/README.md) · [Providers](docs/providers.md) · [Config](docs/config.md) · [Port status](PORT_STATUS.md) · [Upstream nib](https://github.com/yyydddkkk/nib-code) · [MIT](LICENSE)
