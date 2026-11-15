---
status: accepted
date: 2026-11-15
---

# 0001: A project fence against supply-chain attacks

naeb's own ADR series, separate from upstream's `docs/adr/` numbering. It
extends upstream's [ADR 0004](../../adr/0004-two-layer-isolation.md) (write-only
workspace sandbox) and [0006](../../adr/0006-deny-dangerous-commands.md)
(deny-list, credential paths) without changing them: everything here is off
unless a project's launcher gives naeb a policy.

## Threat

Code that runs during a build or test (npm `postinstall`, gem native
extensions, Maven plugins and `.mvn/extensions.xml`, `setup.py`, Gradle
plugins), and a prompt-injected model driving naeb's tools. The attacker
wants to:

1. read secrets: `~/.ssh`, `~/.aws`, `~/.config/gh`, browser profiles,
   keychains, `~/.nib/auth.json`, secrets in environment variables;
2. send them out over the network;
3. persist: shell rc files, LaunchAgents and systemd user units, git hooks,
   other projects, `~/.m2/settings.xml`;
4. tamper with the policy itself.

Today, workspace mode limits only writes by child processes. Reads and the
network are open, and naeb's in-process tools (read, grep, glob, view, fetch)
are not limited at all.

## The direction (decided by Paul, not reopened here)

- A per-project **launcher** in Aether (`naeb.ae`) declares the policy as
  code and starts naeb. Templates for toolchains (Maven, Gradle, npm, ...)
  are ordinary Aether modules the launcher imports.
- The policy grows by trial and error: on a denial naeb proposes a launcher
  diff, the user approves, naeb rebuilds and re-execs with `--resume <id>`
  between Turns. The launcher sits outside every writable root.
- Enforcement first. A prebuilt naeb library/binary is deferred: for now the
  launcher is compiled together with naeb's sources.

## Decision

**One policy object, two layers.** The launcher builds a `Fence`
(`nib.fence`): reads allowed and denied, extra writable roots, paths
inside the roots that stay read-only, egress `host:port` pairs, environment
variables passed to children. It is an instance handed to
`nib.app.run(fence)` and from there to the Session's Tools; nothing is
module state. The in-process tools check it (layer 1); the same Fence
becomes a jail spec for every child process naeb starts: bash, background
bash, hooks, MCP stdio servers (layer 2). Sub-agents are naeb itself, re-run
through the launcher binary, so they rebuild the same Fence from code.

**Fail closed.** With a Fence, a child is never started unconfined: where
the OS jail cannot be applied, the command is refused with the reason.
Without a Fence nothing changes (upstream's off/workspace behaviour and its
tests stay as they are).

### Reads

`$HOME` is closed: nothing below it is readable except the project, the
writable roots and what the Fence allows. A built-in deny-list (`~/.ssh`,
`~/.aws`, `~/.gnupg`, `~/.config/gh`, `~/.kube`, `~/.docker`, `~/.netrc`,
`~/.git-credentials`, `~/.npmrc`, `~/.pypirc`, `~/.gem/credentials`,
`~/.m2/settings*.xml`, `~/.gradle/gradle.properties`, cloud CLIs, browser
profiles, keychains, `$NIB_HOME`, `~/.codex`) wins even inside an allowed
path, except where the Fence allows that exact path. A deny-list alone was
rejected: secrets live in too many places to list, and a home-closed default
makes a missing entry fail visibly (a denial) instead of silently (a leak).
Metadata (`stat`) stays visible on both OSes; contents do not.

| | Linux | macOS |
|---|---|---|
| Mechanism | Landlock `READ_FILE`/`READ_DIR` (ABI 1+), path-beneath rules | `sandbox-exec`, `(deny file-read-data ...)` |
| Deny inside allow | rules computed by splitting a granted directory into its entries around the denied path (a snapshot at spawn: entries created later in a split directory are unreadable) | rules emitted shallow to deep; the last matching rule wins (verified on macOS 27.3) |
| In-process | `read`, `view`, `grep`, `glob` check the canonical path; grep/glob skip denied subtrees | same |

### Writes

The project, temp dirs and devices, plus `Fence.allow_write` entries. The
workspace cache allowlist is *not* applied under a Fence: templates add what a
toolchain needs (`~/.m2/repository`, not `~/.m2`, so `settings.xml` stays out
of reach). Inside the project `.git/hooks`, `.git/config` and any
`Fence.deny_write` path stay read-only.

| | Linux | macOS |
|---|---|---|
| Roots | Landlock write rights (as workspace mode) | SBPL `(allow file-write* (subpath ...))` |
| Read-only inside a root | user + mount namespace, read-only bind mount (Landlock cannot subtract from a granted tree) | `(deny file-write* (subpath ...))` after the allows |

Landlock ABI 1 (no `REFER`) is accepted under a Fence: cross-directory
rename fails, which is a usability cost, not a hole.

### Network egress

Neither Landlock (TCP ports only, ABI 4) nor SBPL can filter by host name.
Landlock port rules were rejected outright: allowing the proxy's port allows
that port on every host, and the port is visible in the child's environment.

Children get **no network except a naeb-run proxy**. The proxy speaks
`CONNECT host:port` (TLS is tunnelled, never intercepted) and absolute-form
`GET http://host/...`; it allows only the Fence's `host:port` pairs, resolves
names itself (children have no DNS), and answers others with 403 naming the
pair. Denials are collected per Tools and reported with the bash result.

| | Linux | macOS |
|---|---|---|
| Confinement | unprivileged user + network + mount namespace: only a loopback | `(deny network*)` `(allow network-outbound (remote ip "localhost:<port>"))` |
| Path to the proxy | the helper relays 127.0.0.1:3128 inside the namespace to the proxy's Unix socket (path sockets are not network-namespaced) | the proxy listens on 127.0.0.1:<port> |
| Verified | `unshare -Urn` works unprivileged on ae-x64 (Ubuntu 22.04, kernel 6.8) and cachyos (7.3) | other localhost ports, a Unix socket, DNS and 1.1.1.1 all refused; the allowed port connects |

Children are told about the proxy through `HTTP(S)_PROXY`, `http(s)_proxy`,
`ALL_PROXY`, `NODE_USE_ENV_PROXY=1`, and `JAVA_TOOL_OPTIONS`
(`-Dhttp(s).proxyHost/Port`). That covers curl, git, pip, gem, npm, Node 24+
and most JVM tools. Maven's own transport reads `settings.xml` proxies: the
Maven template supplies a settings file outside the project; where a tool
ignores every hint it fails to connect, which is the safe direction.

A local test that binds a port and connects to it works on Linux (the
namespace has its own loopback) but not on macOS, where SBPL cannot tell a
child's own server from a host service; `Fence.allow_loopback()` opens
localhost on macOS and is a named hole.

### Holes and how each is closed

| Hole | Linux | macOS |
|---|---|---|
| Existing Unix sockets (`docker.sock`, the D-Bus session bus, ssh-agent) | Landlock `RESOLVE_UNIX` (ABI 9) where available; below it a seccomp filter refuses `socket(AF_UNIX)` and `io_uring_setup` (socketpair still works) | `deny network*` refuses Unix connects (verified) |
| Abstract Unix sockets | network namespace (abstract names are per netns); also Landlock scope (ABI 6) | n/a |
| Daemons, `setsid`, double fork | the restriction is inherited by every descendant; no unconfined process is reachable (sockets above) | same; `launchctl submit` fails inside `sandbox-exec` (observed, not explained); `(deny lsopen)` stops `open` (verified) |
| Apple events (`osascript` driving Terminal) | n/a | `(deny appleevent-send)`, **unverified** (testing it would prompt) |
| ptrace, `/proc/<naeb>/environ`, signals | Landlock limits ptrace and sensitive `/proc` files to the domain; the user namespace too; signal scope (ABI 6) | a child *can* read naeb's initial environment through `KERN_PROCARGS2` (verified; no SBPL operation stops it without breaking the child): naeb overwrites secret values in its own initial environment at start-up under a Fence |
| Secrets in the environment | children get an allow-list environment (`PATH`, `HOME`, locale, terminal, temp, user/shell names, toolchain homes) plus `Fence.pass_env` names plus the proxy variables | same |
| Clipboard, TUI `open` | run from naeb's own unconfined process, on the user's action; the model can no longer read secrets in-process, so it has nothing secret to place there | same |
| MCP stdio servers, hooks | started inside the same jail spec | same |
| Keychain | home-closed reads deny the login keychain file; `security dump-keychain` then lists only the System keychain (observed) | |

### naeb restricting its own process: not now

Restricting naeb after start-up (holding `auth.json` open first) would put
the in-process tools under the kernel's check too. It is not done in this
round because: on Linux a Landlock domain is inherited by every child, so
the TUI's `open` launcher (browsers, editors), clipboard helpers and the
sub-agent re-exec would all run confined, and naeb's own provider traffic
cannot be limited by host (ports only); on macOS there is no supported way
for a process to sandbox itself (`sandbox_init` is deprecated and private
in practice). A later phase can apply a Linux file-only domain to naeb
(deny-list reads, no network rules) once the `open`/clipboard helpers are
started through a pre-forked unconfined helper.

### Denials reaching the model

- In-process tools fail with the path or `host:port` named (`denied by the
  project fence: read ~/.ssh/id_ed25519`).
- Proxy denials are listed in the bash result under `fence_denied` (only
  under a Fence; upstream's result shape is unchanged otherwise).
- A child's file denial is a plain `EACCES`/`EPERM`: Landlock reports no
  path to the caller. Options for later: Landlock audit records (ABI 7; need
  root to read), seccomp user notification on `openat` (heavy), or `strace`
  on demand. macOS logs violations to the unified log (`log stream
  --predicate 'sender == "Sandbox"'`), which naeb could read after a failed
  command. Neither is in this round.

### Policy integrity

The launcher and its compiled binary live outside every writable root
(`~/.naeb/launchers/<project>/`); naeb's in-process tools and children are
refused writes there by the same Fence, and `$NIB_HOME` is read-denied to
children. A re-exec after approval runs the binary the launcher rebuilt;
the approved build is identified by the SHA-256 of the launcher source and
binary recorded in the Session log before the re-exec and checked after it.
Approval is a TUI prompt showing the launcher diff, a deliberate departure
from upstream's no-approvals rule (ADR 0006) because the policy is the one
thing the model must not widen by itself. The approval loop is a later
phase; the first round ships the launcher hook only.

## Red-team plan

`ae/tests/redteam/run.sh`, local only: a temp `HOME` with a fake key and
fake `auth.json` holding a canary, a fake package whose install script runs
each attack, two TCP listeners on 127.0.0.1 (one allowed, one the "exfil"
host) and a planted Unix socket. No real secret or host is touched. Each
case asserts refusal on macOS and Linux.

| Case | Layer | Attack |
|---|---|---|
| `c-read-ssh`, `c-read-auth` | child | `cat` the fake key / auth.json |
| `c-exfil-direct` | child | POST the canary to the exfil listener |
| `c-exfil-proxy` | child | the same through `$HTTPS_PROXY` |
| `c-allowed` | child | positive control: the allowed listener through the proxy |
| `c-write-rc`, `c-write-hook`, `c-write-m2` | child | append to `~/.zshrc`, write `.git/hooks/pre-commit`, `~/.m2/settings.xml` |
| `c-unix` | child | connect to the planted socket |
| `c-env`, `c-parent-env` | child | find the canary in its own environment, and in naeb's |
| `i-read`, `i-grep`, `i-glob` | in-process | read the key, grep `$HOME` for the canary, glob `~/.ssh` |
| `i-write-rc`, `i-write-hook`, `i-write-launcher` | in-process | write `~/.zshrc`, the hook, the launcher |
| `i-fetch-exfil`, `i-fetch-allowed` | in-process | fetch the exfil URL; positive control |

## Implementation order

1. Red-team fixtures, failing on today's code.
2. `nib.fence` and the launcher entry (`nib.app.run(fence)`), consulted by
   the in-process tools.
3. Child enforcement: reads, writes, read-only paths, the proxy and its
   confinement, Unix sockets, the environment.
4. naeb confining itself: deferred (above).
5. Launcher templates (Maven, npm) and the launcher location; then the
   approve, rebuild, re-exec loop.
6. Later: per-command scopes, denial paths for children, Windows.

## Consequences

- A project with a launcher gets reads, writes and egress confined on Linux
  (kernel with user namespaces; Landlock ABI 1+) and macOS. Without one,
  naeb behaves as upstream.
- Toolchains need their `$HOME` paths and hosts declared; the first runs
  of a new project hit denials until the launcher has them.
- Per-command tightening (say, Maven Central only for `mvn`) is matched on
  command text, so it is convenience, not a boundary: the boundary is the
  union of every scope. It is left for later.
- Windows is a gap: no equivalent of Landlock or SBPL is used; naeb with a
  Fence refuses to start commands there.
- Aether asks (separate from naeb work): Landlock read/write/net and scope
  rights plus namespace entry in `std.sandbox` (extends
  `asks/aether-landlock-write-roots.md`); a seccomp filter primitive; a
  `spawn` with a pre-exec hook so the helper re-exec is not needed; a way
  to scrub a process's initial environment.

## Open questions for Paul

1. Launcher location: `~/.naeb/launchers/<project>/naeb.ae`, or beside the
   project but outside its root (`../<project>.naeb.ae`)?
2. Should naeb's own provider traffic (models, web search) also be limited to
   the Fence's hosts? It is not now: the provider is naeb's, not the project's.
3. The default home allow-list: only `~/.gitconfig` and `~/.config/git`
   are readable by default; everything else comes from templates. Too tight?
4. macOS loopback: keep it closed by default (tests binding localhost fail)
   or open it and accept local services as reachable?
5. Linux below Landlock ABI 9: refusing `socket(AF_UNIX)` breaks tools that
   talk to local daemons on purpose (ssh-agent, Docker). Acceptable?
6. Approval UX: a diff in the TUI with y/n, or open the launcher in
   `$EDITOR` and rebuild when it is saved?
