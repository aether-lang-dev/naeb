---
status: accepted
date: 2026-11-15
---

# 0001: A project fence against supply-chain attacks

naeb's own ADR series, separate from upstream's `docs/adr/` numbering. It
extends upstream's [ADR 0004](../../adr/0004-two-layer-isolation.md) (write-only
workspace sandbox) and [0006](../../adr/0006-deny-dangerous-commands.md)
(deny-list, credential paths) without changing them: `nib` stays as upstream,
and everything here is `naeb`'s, the second binary.

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

- A per-project **policy** in Aether (`naeb.ae` at the project root) declares
  the fence as code. Templates for toolchains (Maven, Gradle, npm, ...) are
  ordinary Aether modules the policy imports.
- **One `naeb` binary** on `PATH` (2026-11-15). `naeb build` compiles the
  project's policy into a small shared library under
  `~/.naeb/launchers/<key>/`, outside every writable root; `naeb` dlopens it
  at start and calls it to build the Fence. One process, no shell, no exec
  chain. A policy rebuild takes about a second (one small file); a naeb
  update needs none unless the interface version changed. (Until then each
  project's launcher was compiled together with all of naeb: a 4.4 MB
  executable per project, about 17 s to build, and every naeb update meant
  rebuilding every launcher.)
- The policy grows by trial and error: on a denial naeb proposes a `naeb.ae`
  diff, the user approves, naeb rebuilds the library and re-execs with
  `--resume <id>` between Turns.

## Decision

**One policy object, two layers.** naeb builds a `Fence` (`nib.fence`)
from the policy library (`nib.fence.policy`): reads allowed and denied,
extra writable roots, paths inside the roots that stay read-only, egress
`host:port` pairs, environment variables passed to or set for children. It
is an instance handed from `nib.app.run_naeb` to the Session's Tools;
nothing is module state. The in-process tools check it (layer 1); the same Fence
becomes a jail spec for every child process naeb starts: bash, background
bash, hooks, MCP stdio servers (layer 2). Sub-agents are naeb itself, re-run from
the same binary in the same project, so they load the same policy and pass
the same checks.

**Fail closed.** naeb always has a Fence: a project without `naeb.ae` gets
the default one (the project only, no egress) and a one-line notice. There
is no `naeb --unfenced`; that is `nib`. A child is never started
unconfined: where the OS jail cannot be applied, the command is refused with
the reason. `nib` has no Fence and nothing changes there (upstream's
off/workspace behaviour and its tests stay as they are).

### Reads

`$HOME` is closed: nothing below it is readable except the project, the
writable roots and what the Fence allows. The account's home from the user
database is closed too when it differs from `$HOME`: a child that loses
`$HOME` falls back to it (bash does), which the red-team run found when a
fenced child read the real `~/.ssh` of the account running the fixtures.
A fenced child's environment always carries the Fence's `$HOME`. A built-in deny-list (`~/.ssh`,
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
pair. The proxy has no listener of its own: each fenced child (a bash
command, foreground or background; a hook run; an MCP stdio server for as
long as it runs) and each `tools.fetch` opens its own channel to it, a
127.0.0.1 port (macOS, fetch) or a Unix socket (Linux), which records only
the refusals made through it and closes when its owner ends. A process a
command leaves running after it returns loses the proxy with it.

| | Linux | macOS |
|---|---|---|
| Confinement | unprivileged user + network + mount namespace: only a loopback | `(deny network*)` `(allow network-outbound (remote ip "localhost:<port>"))` |
| Path to the proxy | the helper relays 127.0.0.1:3128 inside the namespace to the child's own Unix socket of the proxy (path sockets are not network-namespaced) | the child's own channel of the proxy listens on 127.0.0.1:<port> |
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
| ptrace, `/proc/<naeb>/environ`, signals | Landlock limits ptrace and sensitive `/proc` files to the domain; the user namespace too; signal scope (ABI 6) | a child *can* read naeb's initial environment through `KERN_PROCARGS2` (verified; no SBPL operation stops it without breaking the child): under a Fence naeb moves its environment to the heap and zeroes the initial area first thing (`jail.scrub_environ`). Pointers `os.getenv` returned before then are zeroed too, so `nib.fence` copies every string it is handed |
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
- Proxy denials are per command: a bash result lists under `fence_denied`
  only what the proxy refused that command's own processes (a background
  command's in its own result when it is delivered), never another
  command's, a hook's, an MCP server's or a fetch's. Only under a Fence;
  upstream's result shape is unchanged otherwise.
- `tools.fetch` fails with the pair named, like the file tools:
  `denied by the project fence: egress example.com:443`.
- A child's file denial is a plain `EACCES`/`EPERM`: Landlock reports no
  path to the caller. Options for later: Landlock audit records (ABI 7; need
  root to read), seccomp user notification on `openat` (heavy), or `strace`
  on demand. macOS logs violations to the unified log (`log stream
  --predicate 'sender == "Sandbox"'`), which naeb could read after a failed
  command. Neither is in this round.

### Policy integrity

- **Where.** The policy's source is `naeb.ae` at the project root
  (`jail.project_root(cwd)`). `naeb build` keeps everything else in
  `~/.naeb/launchers/<key>/`: the library (`policy.dylib` on macOS,
  `policy.so` on Linux), the build record (`policy.built`), the approved
  copy of `naeb.ae`, and `build/` (the source it compiled). `<key>` is the
  project's basename and the first 12 hex digits of the SHA-256 of its
  canonical path, so two projects named `app` do not share one.
- **Read-only to the fenced.** naeb itself (not the policy) makes `naeb.ae`
  read-only to every fenced writer, in-process tools and children alike.
  `~/.naeb` is on the secrets list (no fenced reads) and in no writable root.
- **Outside every writable root.** naeb refuses to start (exit 2, the path
  named) when the library's directory lies inside a root its commands may
  write: checked against the default fence before the library is loaded and
  against the full fence after (a policy cannot `allow_write("~/.naeb")`),
  and likewise when the `naeb` binary itself does.
- **The record.** `naeb build` writes `interface`, `project` (canonical),
  `source_sha256` (of `naeb.ae`), `library_sha256`, `naeb_src` (the
  naeb-code checkout compiled against) and `naeb_commit`. At start naeb
  refuses (exit 2) a missing record ("naeb.ae has not been built; review it
  and run: naeb build"), a `naeb.ae` that no longer matches ("naeb.ae
  changed since it was built; review it and run: naeb build"), a library
  that is not the one built, a record for another project, and another
  interface. An edit or a pull that widens the fence cannot take effect
  before `naeb build` has shown it.
- **Approval.** `naeb build [-y]` shows the unified diff of `naeb.ae`
  against the approved copy (against nothing, the first time) and asks y/N
  on stdin; EOF is no, and nothing changes. `-y` skips the question (for
  scripts that show the diff themselves). Only a successful compile replaces
  the library, the approved copy and the record. A deliberate departure from
  upstream's no-approvals rule (ADR 0006): the policy is the one thing the
  model must not widen by itself. The in-TUI approval loop (propose a diff
  on a denial, rebuild, re-exec `--resume`) is a later phase.
- **Sources.** naeb compiles the policy against the checkout it was built
  in (`build_info.source_dir()`, written by `.build.ae`), or `NAEB_SRC`, and
  only against its `ae/policy_lib`: `naeb.policy` and the templates. naeb's
  own modules are not on that path.

### The policy interface

The library carries no copy of `nib.fence` or of anything whose memory
layout naeb owns, so a naeb update cannot meet a policy built against
other layouts. naeb passes a table of C function pointers and its version:

```c
int32_t aether_naeb_policy_interface(void);            /* the version built for */
int32_t aether_naeb_policy_v1(const struct naeb_fence_api *api, void *fence);

struct naeb_fence_api {                                 /* version 1 */
    int64_t version;
    void (*allow_read)(void *fence, const char *path);
    void (*deny_read)(void *fence, const char *path);
    void (*allow_write)(void *fence, const char *path);
    void (*deny_write)(void *fence, const char *path);
    void (*allow_host)(void *fence, const char *host, int32_t port);
    void (*pass_env)(void *fence, const char *name);
    void (*set_env)(void *fence, const char *name, const char *value);
    void (*allow_loopback)(void *fence);
    void (*open_home)(void *fence);
    const char *(*home)(void *fence);
    const char *(*project_root)(void *fence);
    const char *(*platform)(void *fence);              /* "macos", "linux" */
};
```

- naeb's side is `ae/nib/fence/policy/policy_host.c`: `dlopen(RTLD_NOW |
  RTLD_LOCAL)`, `dlsym` of the two exports, the version check, the call. Each
  call through the table is copied (`strdup`) into a list of operations
  that `nib.fence.policy` then applies to the Fence in Aether; the policy's
  strings never outlive its call.
- The policy's side is the `naeb.policy` module (`ae/policy_lib/naeb/policy`),
  which declares the table field for field and calls through it. `naeb
  build` appends the two exports to the compiled copy of `naeb.ae`; the
  author writes only `fence(p: ptr)`.
- **The interface-version rule.** The table is append-only and its layout is
  the interface. Any change to it (a new field, a changed signature) bumps
  `NAEB_POLICY_INTERFACE` in `policy_host.c` and `INTERFACE` in `naeb.policy`
  together. naeb refuses a library built for another version, from the
  record before loading it and from the library's own export after
  ("rebuild the policy: naeb build"); the policy refuses a table of another
  version (it returns non-zero). Nothing else about naeb is part of the
  interface, so any other naeb update needs no policy rebuild.
- The library is built with `ae build --emit=lib`, capability-empty: a
  policy cannot import `std.fs`, `std.os`, `std.net` or declare an `extern`,
  so loading it can only declare a fence, not act. It carries an Aether
  runtime of its own (macOS's two-level namespace and `ae`'s `-Bsymbolic` on
  ELF keep the two apart), about 160 KB, and stays loaded for the process's
  life.
- Windows: not yet (`LoadLibrary`, and no jail to apply anyway; naeb with a
  Fence refuses commands there).

## How a policy looks

```aether
import naeb.policy
import naeb_templates.maven

fence(p: ptr) {
    maven.apply(p)
    policy.allow_host(p, "repo.example.com", 443)
    policy.set_env(p, "BUNDLE_USER_HOME", "${policy.project_root(p)}/.bundle/user")
}
```

Paths may start with `~/`; `deny_write` paths may be relative to the
project. `naeb build` compiles it (`ae build --emit=lib --lib
<checkout>/ae/policy_lib`). Templates live under
`ae/policy_lib/naeb_templates/` (`maven`, `gradle`, `npm`), outside `nib.*`.

## Red-team plan

`ae/tests/redteam/run.sh`, local only: a temp `HOME` with a fake key and
fake `auth.json` holding a canary, a fake package whose install script runs
each attack, two TCP listeners on 127.0.0.1 (one allowed, one the "exfil"
host) and a planted Unix socket. No real secret or host is touched. Each
case asserts refusal on macOS and Linux.

| Case | Layer | Attack |
|---|---|---|
| `c-read-ssh`, `c-read-auth` | child | `cat` the fake key / auth.json (the latter with the path built at run time, past the command-text deny-list) |
| `c-account-home`, `c-home-env` | child | read a canary planted in the account's real home; `$HOME` is the fixture's |
| `c-exfil-direct` | child | POST the canary to the exfil listener |
| `c-exfil-proxy` | child | the same through `$HTTPS_PROXY` |
| `c-allowed` | child | positive control: the allowed listener through the proxy |
| `c-write-rc`, `c-write-hook`, `c-write-m2` | child | append to `~/.zshrc`, write `.git/hooks/pre-commit`, `~/.m2/settings.xml` |
| `c-unix` | child | connect to the planted socket |
| `c-env`, `c-parent-env` | child | find the canary in its own environment, and in naeb's |
| `i-read`, `i-grep`, `i-glob` | in-process | read the key, grep `$HOME` for the canary, glob `~/.ssh` |
| `c-write-policy`, `c-write-library` | child | append to `naeb.ae`, to the built policy library |
| `i-write-rc`, `i-write-hook`, `i-write-policy`, `i-write-library` | in-process | write `~/.zshrc`, the hook, `naeb.ae`, the policy library |
| `i-fetch-exfil`, `i-fetch-allowed` | in-process | fetch the exfil URL; positive control |
| `x-naeb-in-root` | start-up | run naeb from a copy inside the project |

The fixture project's policy (`naeb.ae`, allowing the allowed listener) is
built with `naeb build -y` into the fixture `HOME`. `ae/tests/redteam/attribution.py`
(run by `run.sh`) checks that each refusal reaches only the command that
caused it: a fetch, two concurrent commands, a background command and an
MCP server. `ae/tests/redteam/naeb_policy.py` (also run by `run.sh`) checks
the policy's life: the default fence without `naeb.ae`, a refused changed
`naeb.ae`, `naeb build` with EOF or `n` changing nothing, two projects named
alike getting two keys, another interface refused (in the record and in the
library), a changed library refused, a library inside a writable root
refused, the templates, `set_env`, and a sub-agent loading the same policy.

Status (2026-11-15): every case refused on macOS 27.3, ae-x64 (Ubuntu
22.04, kernel 6.8, Landlock ABI 4: the seccomp path for Unix sockets) and
cachyos (kernel 7.3, ABI 11: `RESOLVE_UNIX`). Without a Fence (workspace
mode) the same fixtures find 15 holes on macOS.

## Implementation order

1. Red-team fixtures, failing on today's code. *Done.*
2. `nib.fence`, consulted by the in-process tools; the egress proxy for
   `tools.fetch`. *Done.*
3. Child enforcement: reads, writes, read-only paths, the proxy and its
   confinement, Unix sockets, the environment; bash, hooks, MCP stdio.
   *Done.*
4. naeb confining itself: deferred (above).
5. Templates (Maven, Gradle, npm) and the location check. *Done.* The one
   `naeb` binary loading a policy library built by `naeb build`, with the
   interface version and the build record (replacing per-project launcher
   executables). *Done.* The in-TUI approve, rebuild, re-exec `--resume`
   loop: *not yet*.
6. Later: per-command scopes, denial paths for children, Windows.

## Consequences

- Under naeb every project gets reads, writes and egress confined on Linux
  (kernel with user namespaces; Landlock ABI 1+) and macOS; `naeb.ae` widens
  the default fence. `nib` behaves as upstream.
- Toolchains need their `$HOME` paths and hosts declared; the first runs
  of a new project hit denials until `naeb.ae` has them.
- `naeb build` needs `ae` on `PATH` and the naeb-code checkout naeb was
  built in (or `NAEB_SRC`); running a built policy needs neither.
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

1. *(Settled 2026-11-15: `naeb.ae` at the project root, read-only to the
   fenced; its build outside, under `~/.naeb/launchers/<key>/`.)*
2. Should naeb's own provider traffic (models, web search) also be limited to
   the Fence's hosts? It is not now: the provider is naeb's, not the project's.
3. The default home allow-list: only `~/.gitconfig` and `~/.config/git`
   are readable by default; everything else comes from templates. Too tight?
4. macOS loopback: keep it closed by default (tests binding localhost fail)
   or open it and accept local services as reachable?
5. Linux below Landlock ABI 9: refusing `socket(AF_UNIX)` breaks tools that
   talk to local daemons on purpose (ssh-agent, Docker). Acceptable?
6. Approval UX: a diff in the TUI with y/n, or open `naeb.ae` in
   `$EDITOR` and rebuild when it is saved? (`naeb build` asks y/N on the
   diff today.)
