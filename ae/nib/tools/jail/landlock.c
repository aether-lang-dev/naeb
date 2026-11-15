/* Upstream src/tools/bash/jail.zig's Landlock mechanism (restrict, probe),
 * ported as C because Aether has no raw syscalls, plus naeb's project fence
 * (docs/naeb/adr/0001): read rules, a user + mount + network namespace with
 * read-only binds and a loopback relay to naeb's egress proxy, and a seccomp
 * refusal of AF_UNIX sockets where Landlock cannot mediate them (ABI < 9).
 * Called only by `nib __jail ... -- <command>...` in the child, never in
 * nib's own process. A STAND-IN for Aether primitives (asks/
 * aether-landlock-write-roots.md, asks/aether-fence-confinement.md). */
#ifdef __linux__
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <pwd.h>
#include <unistd.h>

extern char **environ;

/* The account's home directory from the user database, which a child
 * falls back to when $HOME is unset or points elsewhere; "" unknown. */
const char *nibjail_account_home(void) {
    struct passwd *pw = getpwuid(getuid());
    return pw && pw->pw_dir ? pw->pw_dir : "";
}

/* Moves every environment entry to the heap (setenv) and zeroes the
 * originals, which sit in the initial stack area another process of this
 * user can read: macOS's KERN_PROCARGS2, Linux's /proc/<pid>/environ.
 * naeb under a project fence calls it first thing. Returns how many
 * entries it moved. */
int nibjail_scrub_environ(void) {
    size_t n = 0;
    while (environ && environ[n]) n++;
    char **orig = (char **)malloc((n + 1) * sizeof(char *));
    if (!orig) return -1;
    for (size_t i = 0; i < n; i++) orig[i] = environ[i];
    orig[n] = NULL;
    int moved = 0;
    for (size_t i = 0; i < n; i++) {
        char *eq = strchr(orig[i], '=');
        if (!eq || eq == orig[i]) continue;
        size_t nl = (size_t)(eq - orig[i]);
        char *name = (char *)malloc(nl + 1);
        char *value = strdup(eq + 1);
        if (!name || !value) { free(name); free(value); continue; }
        memcpy(name, orig[i], nl);
        name[nl] = 0;
        if (setenv(name, value, 1) == 0) moved++;
        free(name);
        free(value);
    }
    for (size_t i = 0; i < n; i++) {
        int still = 0;
        for (size_t k = 0; environ && environ[k]; k++) if (environ[k] == orig[i]) still = 1;
        if (!still) memset(orig[i], 0, strlen(orig[i]));
    }
    free(orig);
    return moved;
}
#ifdef __linux__
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/mount.h>
#include <sys/statvfs.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#define __NR_landlock_add_rule 445
#define __NR_landlock_restrict_self 446
#endif
#define LL_CREATE_VERSION 1u
#define LL_RULE_PATH_BENEATH 1
#define LL_WRITE_FILE (1ull << 1)
#define LL_READ_FILE (1ull << 2)
#define LL_READ_DIR (1ull << 3)
#define LL_BASE_WRITE ((0x1ffull << 4) | LL_WRITE_FILE)
#define LL_REFER (1ull << 13)
#define LL_TRUNCATE (1ull << 14)
#define LL_RESOLVE_UNIX (1ull << 16)
#define LL_SCOPE_ABSTRACT_UNIX (1ull << 0)
#define LL_SCOPE_SIGNAL (1ull << 1)
#define NIB_RELAY_PORT 3128
struct nib_ll_attr { uint64_t handled_fs; uint64_t handled_net; uint64_t scoped; };
struct __attribute__((packed)) nib_ll_rule { uint64_t allowed; int32_t parent; };

static long nib_ll_abi(void) {
    return syscall(__NR_landlock_create_ruleset, NULL, 0, LL_CREATE_VERSION);
}

/* 0 available, 1 no Landlock, 2 disabled, 3 ABI below 2. */
int nibjail_probe(void) {
    long abi = nib_ll_abi();
    if (abi < 0) return errno == EOPNOTSUPP ? 2 : 1;
    return abi >= 2 ? 0 : 3;
}

/* The Landlock ABI (0 none, -1 disabled). */
int nibjail_abi(void) {
    long abi = nib_ll_abi();
    if (abi < 0) return errno == EOPNOTSUPP ? -1 : 0;
    return (int)abi;
}

/* 1 when an unprivileged user + mount + network namespace can be entered. */
int nibjail_probe_userns(void) {
    pid_t pid = fork();
    if (pid < 0) return 0;
    if (pid == 0) _exit(unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWNET) == 0 ? 0 : 1);
    int st = 0;
    if (waitpid(pid, &st, 0) < 0) return 0;
    return WIFEXITED(st) && WEXITSTATUS(st) == 0;
}

static void nib_add_rules(long fd, const char *list, uint64_t rights, uint64_t file_rights, int nofollow) {
    const char *p = list;
    char path[4096];
    while (p && *p) {
        const char *e = strchr(p, '\n');
        size_t n = e ? (size_t)(e - p) : strlen(p);
        if (n > 0 && n < sizeof path) {
            memcpy(path, p, n);
            path[n] = 0;
            int parent = open(path, O_PATH | O_CLOEXEC | (nofollow ? O_NOFOLLOW : 0));
            if (parent >= 0) {
                uint64_t tries[2] = { rights, file_rights };
                for (int i = 0; i < 2; i++) {
                    struct nib_ll_rule rule = { tries[i], parent };
                    if (tries[i] && syscall(__NR_landlock_add_rule, fd, LL_RULE_PATH_BENEATH, &rule, 0) == 0) break;
                }
                close(parent);
            }
        }
        if (!e) break;
        p = e + 1;
    }
}

/* roots: '\n'-separated canonical paths. 0 or -1. */
int nibjail_restrict(const char *roots) {
    long abi = nib_ll_abi();
    if (abi < 0) return -1;
    uint64_t handled = LL_BASE_WRITE;
    if (abi >= 2) handled |= LL_REFER;
    if (abi >= 3) handled |= LL_TRUNCATE;
    struct nib_ll_attr attr = { handled, 0, 0 };
    long fd = syscall(__NR_landlock_create_ruleset, &attr, sizeof(uint64_t), 0);
    if (fd < 0) return -1;
    nib_add_rules(fd, roots, handled, handled & (LL_WRITE_FILE | LL_TRUNCATE), 0);
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return -1;
    if (syscall(__NR_landlock_restrict_self, fd, 0) != 0) return -1;
    close((int)fd);
    return 0;
}

static int nib_write_file(const char *path, const char *text) {
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n = write(fd, text, strlen(text));
    close(fd);
    return n == (ssize_t)strlen(text) ? 0 : -1;
}

/* Locked flags of the mount holding `path`, which a remount must keep. */
static unsigned long nib_locked_flags(const char *path) {
    struct statvfs sv;
    unsigned long f = 0;
    if (statvfs(path, &sv) != 0) return 0;
    if (sv.f_flag & ST_NOSUID) f |= MS_NOSUID;
    if (sv.f_flag & ST_NODEV) f |= MS_NODEV;
    if (sv.f_flag & ST_NOEXEC) f |= MS_NOEXEC;
    if (sv.f_flag & ST_NOATIME) f |= MS_NOATIME;
    if (sv.f_flag & ST_NODIRATIME) f |= MS_NODIRATIME;
    if (sv.f_flag & ST_RELATIME) f |= MS_RELATIME;
    return f;
}

static int nib_readonly_binds(const char *list) {
    const char *p = list;
    char path[4096];
    while (p && *p) {
        const char *e = strchr(p, '\n');
        size_t n = e ? (size_t)(e - p) : strlen(p);
        if (n > 0 && n < sizeof path) {
            memcpy(path, p, n);
            path[n] = 0;
            if (access(path, F_OK) == 0) {
                if (mount(path, path, NULL, MS_BIND | MS_REC, NULL) != 0) return -1;
                if (mount(NULL, path, NULL, MS_REMOUNT | MS_BIND | MS_RDONLY | nib_locked_flags(path), NULL) != 0) return -1;
            }
        }
        if (!e) break;
        p = e + 1;
    }
    return 0;
}

static int nib_loopback_up(void) {
    int s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (s < 0) return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);
    int rc = ioctl(s, SIOCGIFFLAGS, &ifr);
    if (rc == 0) {
        ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
        rc = ioctl(s, SIOCSIFFLAGS, &ifr);
    }
    close(s);
    return rc;
}

static void nib_splice(int a, int b) {
    char buf[65536];
    struct pollfd p[2] = { { a, POLLIN, 0 }, { b, POLLIN, 0 } };
    for (;;) {
        if (poll(p, 2, -1) < 0) {
            if (errno == EINTR) continue;
            return;
        }
        for (int i = 0; i < 2; i++) {
            if (!(p[i].revents & (POLLIN | POLLHUP | POLLERR))) continue;
            ssize_t n = read(p[i].fd, buf, sizeof buf);
            if (n <= 0) return;
            int to = i == 0 ? b : a;
            ssize_t off = 0;
            while (off < n) {
                ssize_t w = write(to, buf + off, (size_t)(n - off));
                if (w <= 0) return;
                off += w;
            }
        }
    }
}

/* The parent of a fenced command: relays 127.0.0.1:3128 inside the
 * namespace to the proxy's Unix socket until the command exits, then exits
 * as it did. Never returns. */
static void nib_relay(pid_t child, int listener, const char *sock) {
    signal(SIGPIPE, SIG_IGN);
    for (;;) {
        int st = 0;
        pid_t w;
        while ((w = waitpid(-1, &st, WNOHANG)) > 0) {
            if (w == child) {
                if (WIFSIGNALED(st)) {
                    signal(WTERMSIG(st), SIG_DFL);
                    kill(getpid(), WTERMSIG(st));
                    _exit(128 + WTERMSIG(st));
                }
                _exit(WIFEXITED(st) ? WEXITSTATUS(st) : 1);
            }
        }
        struct pollfd p = { listener, POLLIN, 0 };
        if (poll(&p, 1, 100) <= 0) continue;
        int c = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
        if (c < 0) continue;
        pid_t k = fork();
        if (k == 0) {
            close(listener);
            int u = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
            struct sockaddr_un a;
            memset(&a, 0, sizeof a);
            a.sun_family = AF_UNIX;
            strncpy(a.sun_path, sock, sizeof a.sun_path - 1);
            if (u >= 0 && connect(u, (struct sockaddr *)&a, sizeof a) == 0) nib_splice(c, u);
            _exit(0);
        }
        close(c);
    }
}

static int nib_relay_listener(void) {
    int s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0) return -1;
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(NIB_RELAY_PORT);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(s, (struct sockaddr *)&a, sizeof a) != 0 || listen(s, 64) != 0) {
        close(s);
        return -1;
    }
    return s;
}

/* socket(AF_UNIX, ...) fails with EACCES, io_uring_setup with ENOSYS. */
static int nib_seccomp_unix(void) {
#if defined(__x86_64__)
    const uint32_t arch = AUDIT_ARCH_X86_64;
#elif defined(__aarch64__)
    const uint32_t arch = AUDIT_ARCH_AARCH64;
#else
    return -1;
#endif
#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup 425
#endif
    struct sock_filter f[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, arch, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_io_uring_setup, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_UNIX, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EACCES),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = { (unsigned short)(sizeof f / sizeof f[0]), f };
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0);
}

/* The project fence for this process (`nib __jail` with fence options):
 * writes: writable roots; wdeny: paths in them bound read-only; reads:
 * read grants ("" with reads_on: nothing readable); sock: the egress
 * proxy's Unix socket ("" when the network stays open). In the namespace
 * case the caller's process stays behind as the relay and only the forked
 * child returns. 0, or a negative step that failed:
 * -1 Landlock, -2 namespace, -3 mounts, -4 loopback, -5 relay, -6 seccomp. */
int nibjail_fence(const char *writes, const char *wdeny, const char *reads, int reads_on, const char *sock) {
    long abi = nib_ll_abi();
    if (abi < 1) return -1;
    int net = sock && *sock;
    int binds = wdeny && *wdeny;
    if (net || binds) {
        uid_t uid = getuid();
        gid_t gid = getgid();
        int flags = CLONE_NEWUSER | CLONE_NEWNS | (net ? CLONE_NEWNET : 0);
        if (unshare(flags) != 0) return -2;
        char m[64];
        nib_write_file("/proc/self/setgroups", "deny");
        snprintf(m, sizeof m, "%u %u 1", (unsigned)uid, (unsigned)uid);
        if (nib_write_file("/proc/self/uid_map", m) != 0) return -2;
        snprintf(m, sizeof m, "%u %u 1", (unsigned)gid, (unsigned)gid);
        if (nib_write_file("/proc/self/gid_map", m) != 0) return -2;
        if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) return -3;
        if (binds && nib_readonly_binds(wdeny) != 0) return -3;
        if (net) {
            if (nib_loopback_up() != 0) return -4;
            int listener = nib_relay_listener();
            if (listener < 0) return -5;
            pid_t child = fork();
            if (child < 0) return -5;
            if (child > 0) nib_relay(child, listener, sock);
            close(listener);
        }
    }
    uint64_t handled = LL_BASE_WRITE;
    if (abi >= 2) handled |= LL_REFER;
    if (abi >= 3) handled |= LL_TRUNCATE;
    uint64_t readr = reads_on ? (LL_READ_FILE | LL_READ_DIR) : 0;
    handled |= readr;
    if (net && abi >= 9) handled |= LL_RESOLVE_UNIX;
    struct nib_ll_attr attr = { handled, 0, 0 };
    size_t size = sizeof(uint64_t);
    if (abi >= 6) {
        attr.scoped = LL_SCOPE_ABSTRACT_UNIX | LL_SCOPE_SIGNAL;
        size = sizeof attr;
    }
    long fd = syscall(__NR_landlock_create_ruleset, &attr, size, 0);
    if (fd < 0) return -1;
    uint64_t wr = (handled & ~(LL_RESOLVE_UNIX | LL_READ_FILE | LL_READ_DIR)) | readr;
    nib_add_rules(fd, writes, wr, wr & (LL_WRITE_FILE | LL_TRUNCATE | LL_READ_FILE), 0);
    if (reads_on) nib_add_rules(fd, reads, readr, LL_READ_FILE, 1);
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return -1;
    if (syscall(__NR_landlock_restrict_self, fd, 0) != 0) return -1;
    close((int)fd);
    if (net && abi < 9 && nib_seccomp_unix() != 0) return -6;
    return 0;
}
#else
int nibjail_probe(void) { return 4; }
int nibjail_abi(void) { return 0; }
int nibjail_probe_userns(void) { return 0; }
int nibjail_restrict(const char *roots) { (void)roots; return -1; }
int nibjail_fence(const char *writes, const char *wdeny, const char *reads, int reads_on, const char *sock) {
    (void)writes; (void)wdeny; (void)reads; (void)reads_on; (void)sock;
    return -1;
}
#endif
