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
  diff, the user approves, naeb rebuilds the library and loads it between
  Runs, in the same process and Session ("Approval in the TUI" below; the
  re-exec with `--resume <id>` first planned here was not needed).

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
| In-process | `read`, `view`, `grep`, `glob`, `edit`, `write` check the canonical path, then open the file and check it again as opened (below); grep/glob skip denied subtrees | same |

**Path identity in the in-process tools.** A path string is only one
spelling of a file: on a case-insensitive volume `~/.SSH` is `~/.ssh`,
macOS names any file `/.vol/<device>/<inode>` and every Data-volume file
again under `/System/Volumes/Data`, `/dev/fd/<n>` reopens whatever naeb
holds, and a symlink swapped in after a check redirects the open that
follows it. So the tools open first and decide on what they opened
(`tools.atomic_file`, C stand-in `pathfd.c`):

- The open never blocks or takes a terminal (`O_NONBLOCK | O_NOCTTY`);
  anything but a regular file (or a directory, where a listing is wanted) is
  refused `NotFile`, so a FIFO, socket or `/dev/fd/0` no longer hangs a
  call.
- The decision is on the path the descriptor names: macOS
  `fcntl(F_GETPATH)` (on-disk case; firmlinks and `/.vol` mapped back, both
  verified on macOS 27.3), Linux `readlink(/proc/self/fd/N)`. That path is
  accepted only when a `stat` of it is the descriptor's own file (`st_dev`,
  `st_ino`); otherwise the call is refused. The data is read from the same
  descriptor.
- On a volume that compares names case-insensitively (macOS
  `fpathconf(_PC_CASE_SENSITIVE)`; Linux vfat/exfat, or a casefold
  directory) rules, credential paths, writable roots and read-only paths are
  compared with ASCII case folded. The volume is asked, never assumed.
- Writes: the target's directory is opened (made component by component
  with `mkdirat`, each opened from its opened parent without following a
  symlink) and checked as opened, against the writable roots and read-only
  paths, before anything is created in it; the leaf is checked as
  `<that directory>/<leaf>`; the new file is created with `O_EXCL |
  O_NOFOLLOW` in that directory and renamed over the leaf there
  (`renameat`). A leaf that has become a symlink is refused.
- grep/glob open the root as above, list each directory through its own
  descriptor, enter a subdirectory only by `openat(O_NOFOLLOW)` from its
  opened parent, and grep opens each file again as above.

Residue: names are folded ASCII only; a non-ASCII name differing only in
case or Unicode normalization in a rule path that does not exist yet would
not match (existing paths compare in their on-disk form). A hard link
planted outside the fence (no fenced writer can make one into a denied
directory) names the same file under an allowed path, for both layers.
The TUI's `/undo` (the user's action, not the model's) still restores
files by name; a background command swapping a directory for a symlink at
that moment could redirect a restore.

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
| Other spellings of a fenced file in-process: case, `/.vol`, `/System/Volumes/Data`, `/dev/fd`, `/proc/self/fd`, a symlink swapped in after the check | in-process tools decide on the opened descriptor (Reads, "Path identity") | same; case, `/.vol` and the firmlink are macOS's own |
| Inherited descriptors (`c-devfd`): a descriptor naeb was started with, open on a fenced file, reaches every child, and Landlock and SBPL check opens, not descriptors already open | naeb marks every inherited descriptor above 2 close-on-exec first thing (`atomic_file.cloexec_inherited`, from `/proc/self/fd`); `nib` keeps upstream's behaviour | same, from `/dev/fd` |
| An allowed name that resolves (or rebinds) to a local service (`c-rebind`, `i-fetch-rebind`) | the proxy resolves the name itself and connects to an address it vetted, never re-resolving: loopback, private (RFC 1918, ULA, `fec0::/10`), carrier-grade NAT (`100.64/10`), link-local, unspecified, multicast and reserved addresses, and IPv4-mapped, IPv4-compatible, NAT64 and 6to4 forms of them, only when an `allow_host` names that very address for the port (a wildcard or a name never does). The refusal is an `egress` record with `reason` ("resolves to 127.0.0.1, a loopback address") and a suggestion naming the address | same |

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

Every refusal reaches the model as one record, whichever layer made it:

```json
{"op": "read", "resource": "/home/u/.npmrc", "layer": "child", "command_id": "b3",
 "suggestion": "policy.allow_read(p, \"~/.npmrc\")"}
```

`op` is `read`, `write`, `egress` (the proxy), `network` (a direct
connection the OS refused), `socket` (a Unix socket) or the OS's own
operation name; `layer` is `tool` (naeb's in-process tools) or `child` (a
process naeb started); `command_id` is the bash task id (`b3`),
`hook:<event>` or `mcp:<server>`, absent for a tool. `reason` (egress
only, when the pair is allowed but where its name resolves is not) says
why: `resolves to 127.0.0.1, a loopback address`. `suggestion` is the
`naeb.ae` line that would allow it, as text only, absent where no policy
line can (naeb's own files, `.git/hooks`, `.git/config`, `naeb.ae`, a path
the policy itself denies). Nothing is ever widened automatically: the user
approves a change in the TUI (below), or edits `naeb.ae` and runs `naeb
build`. Where the records are:

- a bash result (foreground, or a background one when it is delivered),
  an MCP call's result, a failed hook's payload: `fence_denied: [...]`;
- an in-process tool's rejection: the error message is unchanged
  (`denied by the project fence: read ~/.ssh/id_ed25519`) and the `Error`
  carries `fence_denied`; an uncaught one prints it after the stack;
- a sub-agent: its Runs' records reach the parent through `run_end`
  (`fence_denied`) and the agent result's `fence_denied`;
- the model is told the field in the fenced tool table; `nib`, with no
  Fence, keeps upstream's shapes and descriptions.

In detail:

- In-process tools fail with the path or `host:port` named (`denied by the
  project fence: read ~/.ssh/id_ed25519`).
- Proxy denials are per command: a bash result lists under `fence_denied`
  only what the proxy refused that command's own processes (a background
  command's in its own result when it is delivered), never another
  command's, a hook's, an MCP server's or a fetch's. Only under a Fence;
  upstream's result shape is unchanged otherwise.
- `tools.fetch` fails with the pair named, like the file tools:
  `denied by the project fence: egress example.com:443`.
- A child's own refusals by the OS are named too, in the same
  `fence_denied`, per command (bash foreground and background, a hook run
  in its failure payload and the session log, an MCP stdio server in the
  result of each `tools.mcp` call). The OS only answers `EACCES`/`EPERM`,
  so naeb names the path itself:
  - **macOS:** every denial of a child's SBPL profile carries a tag of that
    child's own as its message (`(deny file-read-data (subpath ...) (with
    message "naeb-<pid>-<n>"))`), and the sandbox's report of it in the
    unified log ends with that tag. One `log stream --predicate 'sender ==
    "Sandbox" AND eventMessage CONTAINS "naeb-<pid>-"'` per naeb process,
    started on the first fenced child, sorts the reports by tag (the tag is
    inherited by every descendant, so a process tree is attributed whole).
    When the command ends, naeb runs a sentinel, a one-rule `sandbox-exec`
    whose denial carries the command's tag, and takes the command's entries
    once the sentinel's report has arrived: the reports reach the stream in
    about a millisecond, and the sentinel orders them. Measured on macOS
    27.3 (M-series): about 7 ms per fenced command (15 ms to 22 ms for a
    `true`), denied or not; the stream itself costs one process for the
    session. A plain user's `log stream` sees the sandbox's reports; where it
    cannot start, commands still run, without names. The stream stops when
    naeb exits (a shell holding naeb's end of a pipe kills it on EOF).
    Network denials are named as `network *:<port>` (the sandbox does not log
    the address) and Unix sockets as `socket <path>`.
  - **Linux:** Landlock's audit records (ABI 7) go to the kernel audit log,
    which an unprivileged process cannot read (`dmesg_restrict=1` and no
    `CAP_AUDIT_READ` on both lab hosts, ABI 4 and 11), and ABI 4 has none.
    So the helper's relay supervises the command with seccomp user
    notification (kernel 5.5+, unprivileged): the open, create, remove,
    rename and truncate families are sent to the relay, which reads the path
    from the caller (`process_vm_readv`; the relay is its ancestor), resolves
    it as the caller sees it, checks it against the grants the command's
    Landlock domain holds (and the read-only binds), writes a refused one to
    a report file of the command's own under `$NIB_HOME/run`, and lets the
    call continue (`SECCOMP_USER_NOTIF_FLAG_CONTINUE`). Landlock still
    decides; the relay only names what it will refuse, so an ordinary
    permission failure (a `chmod 000` file inside the grants) is never named.
    Cost: each trapped call is a round trip to the relay, about 11 µs on
    cachyos (bare metal, N100; the relay asks for the kernel's synchronous
    wake-up, 6.6+): `python3 -c "import asyncio, json, http.client"` 89 → 95
    ms, `cc -c` of a small file 22 → 24 ms, `/bin/true` unchanged, and a
    `find | xargs cat` over 20 000 files 0.11 → 0.33 s; on ae-x64 (a VM,
    kernel 6.8) the same import 0.25 → 0.29 s, `cc -c` 0.08 → 0.08 s and the
    `find | xargs cat` 0.11 → 0.31 s. (The relay used to
    notice its command's exit only at a 100 ms poll timeout; it now wakes on
    `SIGCHLD`, which took about 50 ms off every fenced command on average.)
    Other calls than those path
    families cost nothing. A process the command leaves running after it
    returns (a daemon) loses the proxy, as before; its trapped calls go on
    through a copy of the relay, in a session of its own, that names nothing
    more and exits once no process uses the filter (`POLLHUP`; without it the
    calls would fail with `ENOSYS`). Not named: refusals of `exec` (no Landlock right is used),
    of Unix sockets below ABI 9 (the seccomp `EACCES`), and of the network
    (the namespace has only a loopback).
  - Rejected: guessing from `EACCES` text in the output (an ordinary
    permission failure looks the same), `strace` (ptrace on every call),
    and an `LD_PRELOAD` shim (misses static binaries, and naeb would ship a
    second file).

### The policy in force, visible

`tools.fence()` (only under naeb; not in upstream's table, so `nib` has no
such tool) returns the fence as data: `platform`, `policy` (`file`,
`sha256`, `library`, `library_sha256`, as the build record vouched for them
at start; `null` for the default fence), `project`, `home`, `home_open`,
`reads` and `read_denied` (the read rules both layers apply: reads are open
except `read_denied`, with `reads` reopened inside them, deeper paths
winning), `writes`, `read_only`, `hosts`, `loopback`, `env_passed` (the
allow-list plus `pass_env`), `env_set`, and `maven` (the Maven broker's
settings, `null` when it is off) with `maven_fetches` (what it fetched and
refused this Session) when it is on. A sub-agent is naeb loading the
same policy, so its `tools.fence()` is the parent's. The TUI's `/fence`
shows the same as text (listed in `/help` and the menu only under naeb), and
`/status` says `Sandbox: project fence · /fence`.

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
  model must not widen by itself. The same departure is now in the TUI too
  (below).

### Approval in the TUI

Implemented 2026-11-15, answering open question 6: a unified diff with y/N
now; opening the proposed change in `$EDITOR` to adjust it before applying
is the planned next step (TODO.md).

- **What is offered.** The TUI collects every refusal record with a
  `suggestion` from Run results (`run_end`'s `fence_denied`) and delivered
  background bash results. Records whose line is not exactly
  `policy.allow_read(p, "path")`, `policy.allow_write(p, "path")` or
  `policy.allow_host(p, "host", port)` with a plain argument (printable
  ASCII, no quote, backslash, `$` or brace) are not offered.
  Suggestions are grouped (`nib.fence.proposal`) so a build tool refused on
  thousands of files is one line: one `allow_host` per `host:port`; paths
  under their nearest common directory, unless that directory is `$HOME`,
  contains it, is `/` (or, outside `$HOME`, has fewer than two components),
  or is, contains or lies in a forbidden path (the secrets list, the
  policy's own denials, the project, `$NIB_HOME`), in which case each
  directory directly below it is grouped on its own. So refusals under
  `~/.m2/repository` and `~/.m2/wrapper/dists/...` become two lines, never
  `~/.m2` (it holds `settings.xml`). A write line also answers the read
  refusals beneath it. Templates (`maven.apply(p)`) are not suggested.
- **When.** Never while a Turn runs or the user is typing: once the Turn
  ends (and the input is empty, no `/provider` flow or pinned menu is open)
  everything collected since the last prompt is one prompt, duplicates
  merged. Each op and resource is offered once per Session, whatever the
  answer. `ask`, `--json` and `js` never prompt: the records stay in
  `fence_denied` and nothing changes.
- **The prompt.** One line per proposed line saying what it answers
  (`refused egress 127.0.0.1:4100 · b1`, `refused read under
  ~/.m2/repository · 2314 refusals · b3`), the unified diff of `naeb.ae`
  (`--- naeb.ae`, `+++ naeb.ae (proposed)`, three lines of context;
  `--- /dev/null` when the project has none yet), then `Allow? [y/N]`. Only
  `y` or `Y` applies; any other key declines, except PgUp, PgDn and
  Shift+Up/Down, which scroll. The lines go last in `fence(p: ptr)`'s body,
  each after `// Approved <YYYY-MM-DD>: refused <op> <resource> (<command
  ids>)` (UTC date). When that place is not certain (no or two `fence(p:
  ptr)` bodies, another parameter name, the closing `}` not on a line of its
  own, an unterminated string or comment, unbalanced braces), naeb.ae is not
  touched: the lines are shown to add by hand and build with `naeb build`.
- **Applying** (naeb's own unconfined code, on the user's key; `nib.fence.
  policy.approve`, on a worker thread): refused, with naeb.ae untouched,
  when naeb.ae on disk is no longer what the prompt was made from or its
  SHA-256 is not the one the policy in force was built from (someone else
  edited it: no merge). Otherwise the new text is compiled exactly as `naeb
  build` compiles it (the same `compile_` and `commit_`), to a library named
  for the process and the source's hash, which is dlopened under that name
  (dlopen returns a library it already loaded by its path, so the canonical
  `policy.dylib`/`policy.so` could not load new code twice) and run into a
  new Fence. naeb.ae is checked once more, then written; the library is
  renamed over the canonical one (the loaded mapping stays valid), the
  approved copy and the record written. A failed compile, load or write
  leaves naeb.ae byte for byte as it was (a written naeb.ae is put back),
  the old library, record and Fence in force, and shows the error with the
  compiler's first lines. No versioned library is left behind; superseded
  libraries stay mapped (about 160 KB each) for the life of the process.
- **Between Runs.** The new Fence replaces the Session's
  (`session.swap_fence`): at once when no Run executes, else as the running
  Run ends, so a Run never sees two fences. The Tools get a new egress proxy
  for it; MCP servers started later get its spec. Commands still running
  (background bash, MCP servers already started, a Run moved to the
  background, which reads the Tools' fence on its next call) keep what they
  started with where they hold it. Sub-agents started afterwards load the
  rebuilt policy from disk. The Session id does not change; `/fence` shows
  the new policy.
- **The record.** The Session log gets `fence_approval`: `ok`, the `lines`,
  the `diff`, naeb.ae's and the library's SHA-256 before and after, and the
  `error` of a failed one. The transcript gets one line: `naeb.ae changed ·
  policy rebuilt and loaded`, or `naeb.ae not changed · <why>`.
- **The model cannot widen the fence.** It cannot write naeb.ae (read-only
  to every fenced writer) or `~/.naeb`, and nothing it sends opens or
  answers the prompt: the prompt is the TUI's, built from naeb's own refusal
  records, answered only by a key. A `tools.fence_request` letting the
  model propose lines up front was considered and left out for now: the
  records already carry every line the prompt can offer.
- Tests: `ae/tests/fence_proposal_test.ae` (grouping, placing, the diff),
  `ae/tests/tui_fence_test.ae` (the prompt and its keys) and
  `ae/tests/redteam/fence_approval.py` (y, n, an edited naeb.ae, a broken
  build, `ask --json`, end to end on a pty with the mock provider).
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
    /* version 2 (2026-11-15) */
    void (*setting)(void *fence, const char *name, const char *value);
};
```

`setting` carries named settings (`maven.broker`, `maven.repository`,
`maven.min_age_days`, `maven.keyring`, `maven.require_signatures`) so a
later ecosystem's broker needs no new field; naeb refuses a policy that
uses a name it does not know (exit 2, the name given), so a policy never
silently means less than it says.

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

### The Maven broker (experimental)

Added 2026-11-15, experimental: on only when `naeb.ae` says so, its shape
may change. The fence keeps a build from writing `~/.m2/repository` and
from reaching hosts; until now a Maven project then had to open both
(`maven.apply(p)`), and every plugin and POM extension the build ran could
write the shared repository other projects build from. With the broker on,
fenced code never writes it; naeb's own code does, after checks, and only
for what the project's POMs say they need.

```aether
fence(p: ptr) {
    maven.apply(p)                      // reads, ~/.m2/wrapper; its ~/.m2/repository write is dropped
    policy.maven_broker(p)
    policy.maven_repository(p, "https://repo.maven.apache.org/maven2")   // none named: Central
    policy.maven_min_age_days(p, 7)     // the default
    policy.maven_keyring(p, "~/.naeb/maven/trusted-keys.asc")
    policy.maven_require_signatures(p)  // optional
}
```

- **Offline fenced builds.** `~/.m2/repository` is readable and never
  writable to fenced writers: an `allow_write` at or below it is dropped,
  and a writable root above it gets it as a read-only path. Children get
  `MAVEN_ARGS=--offline` (prepended to a `MAVEN_ARGS` the policy sets),
  which Maven 3.9+ and the wrapper honour, so a build fails at once on what
  is missing instead of trying the network. The flag is convenience, not
  the boundary: a build that drops it still cannot write the repository.
  (A settings file with `<offline>` was rejected: `~/.m2/settings.xml` is on
  the secrets list, and one elsewhere needs `-s` on every command line.) A
  write refused under the repository carries no `allow_write` suggestion.
- **`tools.maven_fetch({ gavs })`** (only with the broker on) → `{ ok,
  fetched: [{ gav, requested, repo, files: [{ file, sha256, checksum,
  signature }], signature, age_days, override }], present: [gav], refused:
  [{ gav, reason, young? }] }`. Coordinates are `g:a:v`, `g:a:type:v`,
  `g:a:type:classifier:v` or a range (`g:a:[1.0,2.0)`), as build errors
  print them; snapshots are refused. The tool table's entry is the Maven
  skill: run the build offline, collect every missing coordinate from the
  errors (artifacts, POMs, plugins, parent POMs, BOMs), fetch them in one
  call, rerun. It lives in the table (seen whenever the broker is on)
  rather than as a `SKILL.md`, which a Session loads only when configured.
- **naeb's own resolver, no build tool.** The fetch runs in naeb's
  unconfined process (`nib.maven.*`): POMs are parsed (`std.xml`), never
  built; no Maven, mvnw, Gradle or JVM is started, so no plugin, extension
  or build script runs outside the fence. aeb's `aeb-resolve.jar` (bld's
  resolver) was considered and not used: it needs a JVM, downloads straight
  into its cache from Maven Central plus extra repositories (no allow-list,
  no age or signature check before writing) and cannot be pointed at a
  fixture repository alone. The resolver expands the closure itself:
  parents, imported BOMs, `dependencyManagement`, properties, compile and
  runtime dependencies (not optional ones, not test or provided scope of
  dependencies), version ranges. It does not mediate versions (nearest
  wins): it fetches the declared version, or the project's managed one;
  anything Maven then still misses is asked for again.
- **Checks before anything is written**, per requested coordinate:
  1. *Reachable from the project's POMs:* `pom.xml` at the project root and
     its modules, their parents, imported BOMs, dependencies (any scope),
     `dependencyManagement`, plugins with their dependencies, build
     extensions, and transitively the compile/runtime dependencies of what
     they name. The default-lifecycle plugins (`org.apache.maven.plugins`'
     clean, resources, compiler, surefire, jar, install, ...) are reachable
     in any version, as Maven's super POM binds them. Otherwise refused
     ("not reachable from the project's POMs"), with nothing requested from
     any repository for it. A walk reads at most 3000 POMs.
  2. *Allowed repositories only*, in `naeb.ae`'s order; a repository a POM
     names is never used. The refusal names it with the line that would
     allow it (`policy.maven_repository(p, "<url>")`). No redirect is
     followed, no proxy from the environment is used.
  3. *Checksums:* the strongest of `.sha512`, `.sha256`, `.sha1` the
     repository publishes must match; none published is a refusal.
  4. *Signatures:* where the repository has a `.asc`, an OpenPGP v4
     signature (RSA or Ed25519; SHA-1/224/256/384/512) is verified in Aether
     (`nib.maven.pgp`, std.cryptography) against the keyring: a bad or
     unreadable signature is a refusal; a key not in the keyring is recorded
     as `unknown key <fingerprint>` and allowed unless
     `maven_require_signatures`. The keyring is trusted as given (no expiry,
     revocation or web of trust) and must lie outside every writable root
     (naeb refuses to start otherwise: a fenced command could add a key).
     The record has room for provenance attestations (Sigstore, SLSA) later.
  5. *Age:* the publish date is the repository's `Last-Modified` for the
     version's `.pom` (Maven Central's is the real publish date: Paul
     checked it for jsoup 1.18.1). Younger than `maven_min_age_days` (default 7) is
     refused with the ages; a range resolves to the newest version old
     enough (from `maven-metadata.xml`). No date with a minimum above 0 is
     a refusal.
  The checks of one requested coordinate's closure are all or nothing: a
  failed check anywhere in it writes none of it, and the reason names the
  file. A write that fails afterwards (a planted symlink) stops there;
  files of the closure written before it stay (each verified).
- **Writes** go into the canonical `~/.m2/repository` only: each file is
  written to a temporary name in its directory and renamed over the leaf
  (`atomic_file.replace_at`); the directories are opened component by
  component from the root without following symlinks, each checked to lie
  inside the root (`open_dir`), so a symlink planted inside the repository
  cannot redirect a write; a leaf that is a symlink is refused. A file
  already there (a regular file) is not fetched again.
- **A too-young version, approved.** The refusal is also a `fence_denied`
  record `{op: "maven_age", resource, young: [{gav, age_days}],
  min_age_days}` (no `suggestion`). The TUI offers it after any `naeb.ae`
  change, through the same prompt machinery, one coordinate per prompt
  (`Fetch it anyway (this time, these versions only)? [y/N]`); only `y`
  fetches, on a worker thread, with exactly those versions exempt from the
  age check, and the transcript says what was fetched. Each coordinate is
  offered once per Session. `ask`, `--json` and `js` never prompt: the
  refusal stays in the result and `fence_denied`.
- **Records.** Every artifact fetched (`gav`, `requested`, `repo`, files
  with SHA-256, checksum and signature, `age_days`, `override`) and every
  refusal (`requested`, `reason`) goes to the Session log as `maven_fetch`,
  and to `tools.fence()` (`maven`, `maven_fetches`) and `/fence`.
- **Tests:** `ae/tests/maven_test.ae` (coordinates, ranges by age, POMs,
  reachability over a local copy of the fixture repository, the allow-list,
  checksums and signatures against the fixtures, the fence settings),
  `ae/tests/tui_fence_test.ae` (the y/N), and
  `ae/tests/redteam/maven_broker.py`: the fixture repository
  (`ae/tests/maven_fixture`, regenerated by its `make.sh` with throwaway
  gpg keys) served on 127.0.0.1 with chosen `Last-Modified` dates, a second
  one naeb.ae does not allow (never asked), a fixture HOME; fetch ok, too
  young refused then `y` (and `n`) in the TUI, `ask --json` never asking,
  a range by age, an unknown repository, a coordinate in no POM, a bad
  checksum and a bad signature with nothing written, an unknown key
  recorded, a fenced command and `tools.write` unable to write
  `~/.m2/repository` while `MAVEN_ARGS=--offline`, planted directory and
  leaf symlinks not followed, a build extension (whose class would create
  a marker if loaded) fetched and never run, a keyring inside the project
  refused at start. No real Maven build runs in the tests: no `mvn` is
  installed and a Maven distribution would have to come from outside.
- **Not yet:** brokers for npm, Cargo, Go modules, uv/pip and Bundler (TODO.md);
  Gradle (it reads the same repository layout but has its own offline
  switch and module metadata); Maven's `maven-metadata-<repo>.xml` for
  ranges in offline builds; artifacts Maven resolves at run time without a
  POM naming them (surefire's providers, for instance) are refused as
  unreachable until a POM names them.

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

`ae/tests/redteam/escapes.py` attacks the same secrets, sockets and hosts by
other routes: symlinks, hard links, `..`, case (a component, and every
component), `/.vol` and firmlink spellings, inherited descriptors, a
check-then-use race on `tools.read` (a leaf swapped for a symlink) and
`tools.write` (a directory swapped for a symlink to `$HOME`), 600 tries
each, a FIFO and `/dev/fd/0` given to `tools.read`, daemons, `launchctl`
and `open`, other loopback spellings and proxy targets, a wildcard pair
whose name resolves to 127.0.0.1, DNS, loader variables and Unix socket
spellings. Its `KNOWN` list (holes the fence has, reported but not
failed) is empty.

The fixture project's policy (`naeb.ae`, allowing the allowed listener) is
built with `naeb build -y` into the fixture `HOME`. `ae/tests/redteam/attribution.py`
(run by `run.sh`) checks that each refusal reaches only the command that
caused it: a fetch, two concurrent commands, a background command and an
MCP server. `ae/tests/redteam/maven_broker.py` (run by `run.sh`) checks the
Maven broker (above). `ae/tests/redteam/naeb_policy.py` (also run by `run.sh`) checks
the policy's life: the default fence without `naeb.ae`, a refused changed
`naeb.ae`, `naeb build` with EOF or `n` changing nothing, two projects named
alike getting two keys, another interface refused (in the record and in the
library), a changed library refused, a library inside a writable root
refused, the templates, `set_env`, and a sub-agent loading the same policy.

Status (2026-11-15): every case refused, `escapes.py` included, with an
empty `KNOWN` list, on macOS 27.3, ae-x64 (Ubuntu
22.04, kernel 6.8, Landlock ABI 4: the seccomp path for Unix sockets) and
cachyos (kernel 7.3, ABI 11: `RESOLVE_UNIX`); the race cases also under
load (run.sh beside the other test scripts under `aeb .tests.ae`). Without a Fence (workspace
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
   executables). *Done.* The in-TUI approve, rebuild and reload loop.
   *Done* (no re-exec needed); `$EDITOR` to adjust a proposal: next.
6. Denial paths for children. *Done* (macOS unified log, Linux seccomp
   user notification).
7. Later: per-command scopes, Windows.

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
   (and on macOS `~/.CFUserTextEncoding`, which CoreFoundation programs
   such as curl read) are readable by default; everything else comes from templates. Too tight?
4. macOS loopback: keep it closed by default (tests binding localhost fail)
   or open it and accept local services as reachable?
5. Linux below Landlock ABI 9: refusing `socket(AF_UNIX)` breaks tools that
   talk to local daemons on purpose (ssh-agent, Docker). Acceptable?
7. Maven broker (experimental): should a signature by a key not in the
   keyring be refused by default (today it is recorded and allowed unless
   `maven_require_signatures`)? Central has no single key set, so
   requiring known keys means curating a keyring per project.
8. Maven broker: artifacts Maven resolves at run time with no POM naming
   them (surefire's JUnit provider, a plugin's dynamic dependencies) are
   refused as unreachable. Allow the groups of reachable plugins, or ask
   the user per coordinate as for a young version?
9. Maven broker: should the broker drop the policy's `allow_host` for its
   own repositories while it is on (so a build cannot download at all,
   offline flag or not)? Today the hosts stay as the policy has them; the
   read-only repository is what holds.
10. Maven broker: age is the `.pom`'s `Last-Modified`; a mirror that
   re-stamps files on sync makes everything look young. Trust another
   source (Central's search API, `maven-metadata.xml`'s `lastUpdated`)?
6. *(Settled 2026-11-15: a unified diff with y/N in the TUI now; opening the
   proposed change in `$EDITOR` to adjust it before applying comes later.)*
