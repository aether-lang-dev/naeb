# Confining a child to a project fence

**From:** naeb's project fence (docs/naeb/adr/0001), `naeb.fence` and
`tools/jail`.
**To:** aether, `std.sandbox` / `std.os` (0.916.0).
**Stand-in meanwhile:** `ae/naeb/tools/jail/landlock.c` (marked; extends the
one in [aether-landlock-write-roots.md](aether-landlock-write-roots.md)).

A fenced child gets reads, writes and the network cut down to what the
project's launcher declares. On Linux naeb does it in a helper it re-execs
itself as (`naeb __jail ...`), in C, because Aether has none of these:

1. **Landlock beyond writes.** `READ_FILE`/`READ_DIR` rules (ABI 1),
   `RESOLVE_UNIX` (ABI 9) to refuse connects to Unix sockets made outside
   the domain, and the ABI 6 scopes (abstract Unix sockets, signals). The
   attribute struct grows by ABI (`handled_access_net`, `scoped`); a std
   call would hide that.
2. **Entering an unprivileged user + mount + network namespace**:
   `unshare`, the uid/gid maps (`setgroups` deny first), a read-only bind
   mount (keeping the mount's locked flags, or the remount fails with
   EPERM), bringing `lo` up.
3. **A seccomp filter** refusing `socket(AF_UNIX, ...)` and
   `io_uring_setup` where Landlock is older than ABI 9.
4. **A pre-exec hook on spawn**, so the above can run between fork and exec
   in a std spawn instead of a helper re-exec of the whole binary.
5. **Scrubbing a process's initial environment.** A child of the same user
   reads its parent's initial environment on macOS through
   `KERN_PROCARGS2` (no SBPL operation stops it without breaking the
   child). naeb moves its environment to the heap and zeroes the original
   area. Pointers `os.getenv` handed out before then are zeroed too: a std
   `os.scrub_environ()` should document that, or `os.getenv` should return
   copies.
6. **The account's home** (`getpwuid(getuid())->pw_dir`): a child without
   `$HOME` falls back to it, so the fence closes it as well as `$HOME`.

Proposed: `std.sandbox.landlock_abi()`, a `std.sandbox.Confinement` built
in code (read/write rules, read-only paths, `unix: deny`, `network: none`)
applied by `spawn_confined(conf, prog, argv, env)` between fork and exec;
`os.scrub_environ()` and `os.account_home()`. std.sandbox's existing grant
lists are allow-only and enforced through std and LD_PRELOAD, so they cannot
express "$HOME closed except the project, secrets denied inside", nor hold
a statically linked child; the kernel layer is what a fence needs.

Separately, `std.http` has a reverse proxy but no forward (CONNECT) proxy
with a host allow-list; `tools/egress` is one in about 250 lines over
`std.tcp`, and could move to std if another program wants it.
