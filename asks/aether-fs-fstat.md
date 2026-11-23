# std.fs: stat of an open descriptor

**From:** naeb's paginated `read` (`ae/naeb/tools/files/module.ae`, port of
upstream nib-code ca62140).
**To:** aether, `std.fs` (0.936.0).
**Stand-in meanwhile:** `fs.stat(path, 1)` before the open and after the scan.

Upstream's read stats the open file before and after scanning it and fails with
`FileChangedDuringRead` when its inode, size or mtime moved, so a writer that
changed the file under the reader is noticed even though the page came from
one descriptor. `std.fs` has `fd_size(fd)` but no stat of a descriptor (inode,
mtime), so naeb compares the path's stat instead. The difference: a file
replaced by a rename during the read (a new inode at the same path) is reported
as changed although the descriptor still read one consistent old file.

Wanted: `fs.fd_stat(fd) -> (Stat, kind, msg)`, the same `Stat` as `fs.stat`
(`fstat(2)`; on Windows `GetFileInformationByHandle`).

Repro (shows the gap, not a bug):

```
import std.fs
main() {
    fd, _k, _m = fs.lock_open("/tmp/x")      // any open descriptor
    st, k, _msg = fs.fd_stat(fd)             // does not exist: only fs.fd_size(fd)
}
```
