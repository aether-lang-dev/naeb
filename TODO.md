# naeb TODO

Work on the Aether port that goes beyond matching upstream nib. What the port
still owes upstream is in [PORT_STATUS.md](PORT_STATUS.md).

## Port mvdan/sh: a shell built into naeb, in Aether

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
