/* Descriptor-relative file access for the in-process tools: open first,
 * then decide on the opened object (docs/naeb/adr/0001, "Path identity").
 * The path a descriptor really names (macOS fcntl(F_GETPATH): on-disk case,
 * firmlinks and /.vol mapped back; Linux /proc/self/fd), whether its volume
 * compares names case-insensitively, and the *at calls that create, rename
 * and list relative to a verified directory so a symlink swapped in later
 * cannot redirect them. A STAND-IN for Aether std.fs primitives
 * (asks/aether-fs-descriptor-paths.md). Errors are negative errno values. */
#ifdef __linux__
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __APPLE__
#include <sys/param.h>
#endif
#ifdef __linux__
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/vfs.h>
#endif

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* kind: 0 any object, 1 a directory. nofollow: refuse a symlink leaf.
 * Never blocks on a FIFO and never takes a controlling terminal. */
static int open_flags_(int kind, int nofollow) {
    int fl = O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOCTTY;
    if (kind == 1) fl |= O_DIRECTORY;
    if (nofollow) fl |= O_NOFOLLOW;
    return fl;
}

int naebfs_open(const char *path, int kind, int nofollow) {
    int fd = open(path, open_flags_(kind, nofollow));
    return fd < 0 ? -errno : fd;
}

int naebfs_openat(int dirfd, const char *name, int kind, int nofollow) {
    int fd = openat(dirfd, name, open_flags_(kind, nofollow));
    return fd < 0 ? -errno : fd;
}

int naebfs_close(int fd) { return close(fd) < 0 ? -errno : 0; }

/* 1 regular file, 2 directory, 3 symlink, 4 anything else; -errno. */
static int kind_of_(mode_t m) {
    if (S_ISREG(m)) return 1;
    if (S_ISDIR(m)) return 2;
    if (S_ISLNK(m)) return 3;
    return 4;
}

int naebfs_fd_kind(int fd) {
    struct stat st;
    if (fstat(fd, &st) < 0) return -errno;
    return kind_of_(st.st_mode);
}

/* The leaf `name` in `dirfd`, not followed: kind as above, 0 when absent. */
int naebfs_kind_at(int dirfd, const char *name) {
    struct stat st;
    if (fstatat(dirfd, name, &st, AT_SYMLINK_NOFOLLOW) < 0) return errno == ENOENT ? 0 : -errno;
    return kind_of_(st.st_mode);
}

/* Permission bits of `name` in `dirfd` (not followed), -errno. */
int naebfs_mode_at(int dirfd, const char *name) {
    struct stat st;
    if (fstatat(dirfd, name, &st, AT_SYMLINK_NOFOLLOW) < 0) return -errno;
    return (int)(st.st_mode & 07777);
}

/* 1 when `path` (followed) is the very file `fd` is open on. */
int naebfs_same(int fd, const char *path) {
    struct stat a, b;
    if (fstat(fd, &a) < 0 || stat(path, &b) < 0) return 0;
    return a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}

/* The absolute path `fd` names, verified to lead back to the same file;
 * "" when the OS cannot say or the answer is not that file. */
const char *naebfs_fd_path(int fd) {
    char buf[PATH_MAX + 1];
    buf[0] = 0;
#if defined(__APPLE__)
    if (fcntl(fd, F_GETPATH, buf) < 0) buf[0] = 0;
#elif defined(__linux__)
    char link[64];
    snprintf(link, sizeof link, "/proc/self/fd/%d", fd);
    ssize_t n = readlink(link, buf, PATH_MAX);
    buf[n > 0 ? n : 0] = 0;
#endif
    if (buf[0] != '/' || !naebfs_same(fd, buf)) buf[0] = 0;
    return strdup(buf);
}

/* 1 when the volume `fd` lies on compares names case-insensitively. */
int naebfs_fd_fold(int fd) {
#if defined(__APPLE__)
    return fpathconf(fd, _PC_CASE_SENSITIVE) == 0 ? 1 : 0;
#elif defined(__linux__)
    struct statfs sf;
    if (fstatfs(fd, &sf) == 0) {
        /* vfat/msdos, exfat */
        if ((unsigned long)sf.f_type == 0x4d44UL || (unsigned long)sf.f_type == 0x2011BAB0UL) return 1;
    }
#ifdef FS_CASEFOLD_FL
    int flags = 0;
    if (ioctl(fd, FS_IOC_GETFLAGS, &flags) == 0 && (flags & FS_CASEFOLD_FL)) return 1;
#endif
    return 0;
#else
    return 0;
#endif
}

int naebfs_mkdirat(int dirfd, const char *name, int mode) {
    if (mkdirat(dirfd, name, (mode_t)mode) < 0) return -errno;
    return 0;
}

/* A new file `name` in `dirfd` for writing, refused if anything (a
 * symlink included) is there. */
int naebfs_create_at(int dirfd, const char *name, int mode) {
    int fd = openat(dirfd, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, (mode_t)mode);
    return fd < 0 ? -errno : fd;
}

int naebfs_rename_at(int dirfd, const char *from, const char *to) {
    return renameat(dirfd, from, dirfd, to) < 0 ? -errno : 0;
}

int naebfs_unlink_at(int dirfd, const char *name) {
    return unlinkat(dirfd, name, 0) < 0 ? -errno : 0;
}

/* The entries of the directory `fd` (not consumed: a dup is listed) as
 * "<kind><name>/" each, kind f(ile) d(ir) l(ink) o(ther) u(nknown); "."
 * and ".." left out. NULL-free: a name never holds '/'. */
const char *naebfs_list(int fd) {
    int d = dup(fd);
    if (d < 0) return strdup("");
    DIR *dir = fdopendir(d);
    if (!dir) { close(d); return strdup(""); }
    rewinddir(dir);
    size_t cap = 4096, len = 0;
    char *out = malloc(cap);
    if (!out) { closedir(dir); return strdup(""); }
    struct dirent *e;
    while ((e = readdir(dir)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        char k = 'u';
#ifdef DT_REG
        if (e->d_type == DT_REG) k = 'f';
        else if (e->d_type == DT_DIR) k = 'd';
        else if (e->d_type == DT_LNK) k = 'l';
        else if (e->d_type != DT_UNKNOWN) k = 'o';
#endif
        size_t n = strlen(e->d_name);
        if (len + n + 3 > cap) {
            while (len + n + 3 > cap) cap *= 2;
            char *grown = realloc(out, cap);
            if (!grown) break;
            out = grown;
        }
        out[len++] = k;
        memcpy(out + len, e->d_name, n);
        len += n;
        out[len++] = '/';
    }
    out[len] = 0;
    closedir(dir);
    return out;
}

/* Zig's names for the errors the tools report. */
const char *naebfs_errname(int neg) {
    switch (-neg) {
    case ENOENT: return "FileNotFound";
    case EACCES: case EPERM: return "AccessDenied";
    case ENOTDIR: return "NotDir";
    case EISDIR: return "IsDir";
    case ELOOP: return "SymLinkLoop";
    case ENAMETOOLONG: return "NameTooLong";
    case EEXIST: return "PathAlreadyExists";
    case ENOSPC: return "NoSpaceLeft";
    case EXDEV: return "RenameAcrossMountPoints";
    case EROFS: return "ReadOnlyFileSystem";
    case EBUSY: return "DeviceBusy";
    case EFBIG: return "FileTooBig";
    case ENXIO: case EOPNOTSUPP: case ENODEV: return "NotFile";
    case EINVAL: return "InvalidArgument";
    default: return "Unexpected";
    }
}

/* Inherited descriptors above 2 become close-on-exec (docs/naeb/adr/0001,
 * "Inherited descriptors"): a fenced child must never receive one. Returns
 * how many it marked. */
int naebfs_cloexec_inherited(void) {
    int marked = 0;
#if defined(__linux__)
    DIR *d = opendir("/proc/self/fd");
#else
    DIR *d = opendir("/dev/fd");
#endif
    if (d) {
        int self = dirfd(d);
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
            int fd = atoi(e->d_name);
            if (fd <= 2 || fd == self) continue;
            int fl = fcntl(fd, F_GETFD);
            if (fl >= 0 && !(fl & FD_CLOEXEC) && fcntl(fd, F_SETFD, fl | FD_CLOEXEC) == 0) marked++;
        }
        closedir(d);
        return marked;
    }
    long max = sysconf(_SC_OPEN_MAX);
    if (max < 0 || max > 65536) max = 65536;
    for (int fd = 3; fd < max; fd++) {
        int fl = fcntl(fd, F_GETFD);
        if (fl >= 0 && !(fl & FD_CLOEXEC) && fcntl(fd, F_SETFD, fl | FD_CLOEXEC) == 0) marked++;
    }
    return marked;
}
