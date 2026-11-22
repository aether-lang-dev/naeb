# naeb TODO

Work on the Aether port that goes beyond matching upstream nib. What the port
still owes upstream is in [PORT_STATUS.md](PORT_STATUS.md).

## The project fence: what is left (docs/naeb/adr/0001)

Landed 2026-11-15: `naeb.fence`, in-process checks, the egress proxy, Linux
namespace + Landlock + seccomp and macOS SBPL confinement of bash, hooks and
MCP stdio, Maven/Gradle/npm templates, `ae/tests/redteam/`; then one `naeb`
binary loading the project's `naeb.ae` as a policy library built by
`naeb build` (interface version 1, build record, location checks).

Landed 2026-11-15 too: the in-TUI approval loop (a `naeb.ae` diff offered
when a Turn ends, y/N, the policy rebuilt and loaded between Runs in the same
Session, grouped suggestions, the approval in the Session log).

- **Adjust a proposal in `$EDITOR`** (Paul, 2026-11-15): open the proposed
  `naeb.ae` change in `$EDITOR` before applying, then rebuild as the y/N path
  does. The y/N diff stays for the plain case.
- **Templates as suggestions:** offer `maven.apply(p)` (gradle, npm) when a
  cluster of refusals matches a template, instead of plain lines.
- **A write refused as a read:** `tools.write` into a closed directory of
  `$HOME` is refused as `read` (it opens the directory first), so the
  suggestion is `allow_read` and the write needs a second round. Name it a
  `write` with an `allow_write` suggestion.
- **`tools.fence_request({ lines, reason })`:** a model proposing lines up
  front, through the same y/N prompt with its reason shown as the model's
  words. Left out of the first cut.
- **Policy libraries on Windows:** `LoadLibrary` for `policy.dll` (and
  `--shared-runtime` questions there), once a Windows jail exists at all.
- **A prebuilt `naeb.policy`:** `naeb build` compiles against a naeb-code
  checkout; a release could ship `ae/policy_lib` beside the binary instead.
- **naeb confining itself** after start-up (Linux, file rules only), once
  the TUI's `open` and clipboard helpers start from an unconfined helper.
- **Per-command scopes** (e.g. Maven Central only for `mvn`): matched on
  command text, so convenience, not a boundary.
- **Maven's own proxy settings:** verify which Maven versions honour the
  JVM proxy properties; otherwise the template writes a settings file
  outside the project.

## Dependency brokers (experimental; docs/naeb/adr/0001, "The Maven broker")

Landed 2026-11-15, experimental: the Maven broker (`policy.maven_broker`,
`tools.maven_fetch`, naeb's own resolver in `ae/naeb/maven/`, the TUI's y/N
for a too-young version). Landed 2026-11-16, after Paul's petclinic run was
offered `allow_write ~/.m2`: no line for a forbidden path, single or grouped
(a note says why); `policy.maven_broker(p)` offered for a Maven project's
writes under `~/.m2`; the wrapper's Maven distribution fetched through the
broker into mvnw's directory; a no-Java hint. Still to do there:

- **An existing `~/.m2/settings.xml`:** Maven reads it whenever it exists,
  and the fence refuses that read (a secret). Unverified what Maven 3.9
  then does (an error, or a warning and on); if an error, pass
  `-s`/`--global-settings` of an empty settings file in `MAVEN_ARGS`.

- **A real Maven build in the tests:** a fixture project built offline by a
  Maven whose distribution comes from the fixture repository (none is
  installed here, and none may come from outside in tests).
- **Run-time artifacts no POM names** (surefire's providers, plugins'
  dynamic dependencies): refused as unreachable today (ADR open question 8).
- **`maven-metadata-<repo>.xml`** for version ranges in offline builds.
- **Provenance attestations** (Sigstore bundles, SLSA) beside the PGP
  result in each record.
- **Gradle:** the same repository layout, its own offline switch
  (`--offline`, `GRADLE_OPTS` does not carry it) and Gradle Module Metadata.

Per-ecosystem primers to write next, each a broker of the same shape
(offline fenced installs, a fetch tool, naeb's own resolver outside the
fence, reachability from the project's manifests, allowed registries,
integrity, signatures or provenance where the ecosystem has them, minimum
age, atomic writes into the shared cache). Listed, not built:

- **npm** (`package-lock.json`, the registry's `time` field, `integrity`
  hashes, npm provenance attestations; `npm ci --offline` against the cache).
- **Cargo** (`Cargo.lock`, the crates.io index, checksums in the lock file;
  `cargo build --offline` / `--frozen`).
- **Go modules** (`go.sum`, the checksum database, `GOFLAGS=-mod=mod`,
  `GOPROXY=off` inside the fence).
- **uv / pip** (`uv.lock` or hashes in requirements, PyPI's upload time and
  attestations; `uv sync --offline`).
- **Bundler** (`Gemfile.lock` checksums, rubygems.org's `created_at`;
  `bundle install --local`).

## Port mvdan/sh: a shell built into naeb, in Aether

**Deferred (Paul, 2026-11-15):** this and the Windows steps below wait behind
bigger goals.

[mvdan/sh](https://github.com/mvdan/sh) (Go, BSD-3-Clause) is a shell parser,
formatter and interpreter. The Task build tool embeds it so its command lines
run the same on every OS. Port it to Aether so naeb can run a model's command
lines with no system shell: on Windows, where there may be no bash, and
anywhere a predictable shell is wanted.

- **Scope:** the POSIX subset models actually write: sequences, `&&`/`||`,
  pipes, redirection, quoting, `VAR=x` prefixes, `$VAR` and globbing. Real
  programs run directly through the process runner, not through another shell.
- **Built-in commands**, in Aether: `ls`, `cp`, `mv`, `rm`, `mkdir`, `cat`,
  `diff`, and `sed` on Aether's `std.sed`. They behave the same everywhere and
  respect the workspace write roots without a jail.
- **Batch files:** on Windows, `.cmd`/`.bat` programs (`mvn`, `npm`,
  `gradlew`) can only run through `cmd.exe`, whose argument quoting is a
  known trap (the 2024 fixes in Rust, Node and Java). Check how Aether's
  process spawning handles them before relying on it.
- **Provenance:** a file-by-file port with attribution, as `std.sed` did from
  FreeBSD; mvdan/sh's own test suite ported as the gate.
- **Home:** decide whether it belongs in naeb or in Aether itself (a `std.sh`
  beside `std.sed`), so other Aether programs can use it.

Related, smaller steps first (2026-11-15):
- **Built-in file tools:** `copy`, `move`, `remove`, `mkdir`, `list`, `diff`
  as tools over `std.fs`, so file housekeeping needs no shell at all.
- **A `run` tool** taking a program and an argument list, no shell.
- **Git Bash on Windows:** use it as `bash` when present.
- **A Windows prompt variant**, through upstream's Profiles and prompt patches
  (ADR 0026 "tunings" once ported), saying which shell `bash` is and to prefer
  the built-in tools for files.
