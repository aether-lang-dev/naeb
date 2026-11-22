# std.fs / std.net: decide on the opened file, *at calls, an address resolver

**From:** the naeb Aether port (`aether-port` branch of aether-lang-dev/naeb), naeb's project fence.
**To:** aether, `std.fs`, `std.dir` and `std.net`/`std.tcp` (0.917.0).
**Stand-in meanwhile:** `ae/naeb/tools/atomic_file/pathfd.c` and
`ae/naeb/tools/egress/resolve.c` (marked C; delete as each lands).

naeb's in-process tools (read, view, grep, glob, edit, write) used to check
a canonical path string and then open the file by name. That missed every
other spelling of the same file and every swap in between: a case-changed
spelling on a case-insensitive volume, `/.vol/<dev>/<ino>`, the
`/System/Volumes/Data` firmlink, `/dev/fd/<n>`, and a symlink swapped in
after the check (docs/naeb/adr/0001, "Path identity"; red-team cases
`i-case-*`, `i-volfs-read`, `i-firmlink-read`, `i-devfd`, `i-race-*` in
`ae/tests/redteam/escapes.py`). The fix opens first and decides on what was
opened; std.fs has none of the pieces:

1. **Open without side effects, and say what was opened.** An open that
   never blocks on a FIFO and never takes a controlling terminal
   (`O_NONBLOCK | O_NOCTTY | O_CLOEXEC`, optional `O_NOFOLLOW` and
   `O_DIRECTORY`), `fstat` of the descriptor, and the path the descriptor
   names: macOS `fcntl(F_GETPATH)` (gives the on-disk case and maps
   firmlinks and `/.vol` back), Linux `readlink("/proc/self/fd/N")`.
   Proposed: `fs.open_fd(path, flags) -> (fd, kind, msg)`,
   `fs.fd_stat(fd) -> (Stat, kind, msg)`, `fs.fd_path(fd) -> (string, kind, msg)`.
2. **Whether a volume folds case.** macOS `fpathconf(fd, _PC_CASE_SENSITIVE)`;
   Linux: vfat/exfat by `fstatfs`, ext4/f2fs casefold directories by
   `FS_IOC_GETFLAGS & FS_CASEFOLD_FL`. Proposed: `fs.fd_case_sensitive(fd) -> bool`.
3. **The *at family on a directory fd.** `openat` (with `O_NOFOLLOW`),
   `mkdirat`, `fstatat(AT_SYMLINK_NOFOLLOW)`, `renameat`, `unlinkat`, and
   `O_CREAT|O_EXCL` creation at a directory fd with a mode, so a write is
   created and renamed in a directory that was opened and verified, and a
   symlink swapped in later cannot redirect it. Proposed: `fs.openat`,
   `fs.mkdirat`, `fs.stat_at`, `fs.create_exclusive_at`, `fs.rename_at`,
   `fs.unlink_at`.
4. **Listing a directory by descriptor.** `fdopendir` on a dup, so a walk
   lists the directory it opened and checked, not whatever the name points
   to by then. Proposed: `dir.list_fd(fd)` with the same kinds `dir.list`
   gives.
5. **Read to EOF from an fd, binary-safe, with a limit.** `io.fd_read_n`
   loops to fill `n`; a whole-file read wants `fd_read_all(fd, limit)`.
6. **Marking inherited descriptors close-on-exec.** naeb marks every
   descriptor above 2 it inherited `FD_CLOEXEC` at start (`/proc/self/fd`
   or `/dev/fd`), so a fenced child never receives one (`c-devfd`).
   Proposed: `os.cloexec_inherited() -> int` (or `os.fd_set_cloexec(fd)`
   plus a descriptor listing).
7. **A resolver that returns addresses** (`std.net`): the egress proxy
   resolves a name itself, refuses loopback, private (RFC 1918, ULA),
   link-local, unspecified, multicast and reserved addresses (and the
   IPv4-mapped/NAT64 forms of them) unless the policy names the address,
   and connects to the vetted address with no second resolution
   (`c-rebind`, `i-fetch-rebind`). `tcp.connect_timeout(host, ...)`
   resolves internally. Proposed: `net.resolve(host) -> (list of numeric
   addresses, msg)` and `net.address_class(addr) -> string`.
