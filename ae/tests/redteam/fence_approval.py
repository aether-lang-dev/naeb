#!/usr/bin/env python3
"""The approval loop of naeb's TUI (docs/naeb/adr/0001, "Approval in the TUI").

Drives the built naeb (NAEB) on a pty through upstream's own PTY fixture
and mock provider (tests/test_interjections.py, used as a library), in a
fixture HOME of absolute fake paths with a fixture project whose policy is
built by `naeb build -y` against this checkout. The refused egress goes to a
listener on 127.0.0.1; the refused writes go to a directory of the fixture
HOME. No real home, secret, host or provider is touched.

    NAEB=target/build/bin/naeb python3 -I ae/tests/redteam/fence_approval.py

Cases: y (naeb.ae gains the lines and their comments, the policy is rebuilt
and loaded, the same command then succeeds in the same Session, the log has
the approval; many refused files are one line), n (nothing changes), naeb.ae
edited meanwhile (refused), a build that fails (naeb.ae restored, the old
policy still in force) and `ask --json` (reports, never asks). Prints
`ok   <case>` or `FAIL <case> ...`; the exit status is the number of failures.
"""
import atexit
import datetime
import hashlib
import http.server
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "scripts"))
import test_interjections as tui  # noqa: E402
from test_interjections import Mock, Reply, Terminal, screen  # noqa: E402

NAEB = Path(os.environ.get("NAEB", ROOT / "target/build/bin/naeb"))
tui.BIN = NAEB
LIB = "policy.dylib" if sys.platform == "darwin" else "policy.so"
POLICY = "import naeb.policy\n\nfence(p: ptr) {\n    policy.allow_host(p, \"allowed.invalid\", 443)\n}\n"

fails = 0


def check(name, held, why=""):
    global fails
    if held:
        print("ok   %s" % name)
    else:
        fails += 1
        print("FAIL %s %s" % (name, why))


def sha(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


class Body(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        data = b"approved-body"
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def wait(check_fn, what, timeout=180):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        v = check_fn()
        if v:
            return v
        time.sleep(.05)
    raise AssertionError("timed out: " + what)


class Case:
    """A fixture HOME with one project whose naeb.ae is built."""

    def __init__(self, work, name, port, src=None):
        self.home = os.path.realpath(os.path.join(work, name, "home"))
        self.nib_home = os.path.join(self.home, ".nib")
        self.project = os.path.join(self.home, "proj")
        os.makedirs(os.path.join(self.project, ".git"))
        os.makedirs(self.nib_home)
        for sub in ("x", "y"):
            os.makedirs(os.path.join(self.home, ".fixture-cache", "a", sub))
            for i in range(10):
                with open(os.path.join(self.home, ".fixture-cache", "a", sub, str(i)), "w") as f:
                    f.write("cached\n")
        self.policy = os.path.join(self.project, "naeb.ae")
        with open(self.policy, "w") as f:
            f.write(POLICY)
        self.port = port
        self.env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": self.home,
            "NIB_HOME": self.nib_home,
            "NAEB_SRC": str(ROOT),
            "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
            "LANG": "C.UTF-8",
            "TERM": "xterm-256color",
            "NIB_PROVIDER": "chat_completions",
            "NIB_API_KEY": "mock",
        }
        r = subprocess.run([str(NAEB), "build", "-y"], cwd=self.project, env=self.env, capture_output=True, text=True, timeout=600)
        if r.returncode != 0:
            raise AssertionError("naeb build: %s %s" % (r.stdout[-500:], r.stderr[-500:]))
        launchers = os.path.join(self.home, ".naeb", "launchers")
        self.dir = os.path.join(launchers, os.listdir(launchers)[0])
        if src is not None:
            self.env["NAEB_SRC"] = src

    def record(self):
        with open(os.path.join(self.dir, "policy.built")) as f:
            return dict(l.split("=", 1) for l in f.read().splitlines() if "=" in l)

    def state(self):
        return (open(self.policy, "rb").read(), sha(os.path.join(self.dir, LIB)), open(os.path.join(self.dir, "policy.built")).read())

    def code(self):
        reads = ";".join("n += await tools.read({path: %s}).then(() => 1, () => 0)" % json.dumps(os.path.join(self.home, ".fixture-cache", "a", sub, str(i)))
                         for sub in ("x", "y") for i in range(10))
        return "let n = 0; %s; const r = await tools.bash({command: 'curl -s --max-time 10 http://127.0.0.1:%d/'}); 'read=' + n + ' body=' + r.output" % (reads, self.port)

    def sessions(self):
        d = os.path.join(self.nib_home, "sessions")
        return sorted(p for p in os.listdir(d) if re.fullmatch(r"[0-9a-f]{32}\.jsonl", p)) if os.path.isdir(d) else []

    def records(self, member):
        out = []
        for name in self.sessions():
            for line in open(os.path.join(self.nib_home, "sessions", name), "rb").read().split(b"\n"):
                if line.strip():
                    rec = json.loads(line)
                    if member in rec:
                        out.append(rec[member])
        return out

    def tool_outputs(self):
        msgs = tui.history(Path(self.nib_home))
        return [m.get("content", "") for m in msgs if m.get("role") == "tool"]

    def tui(self, replies):
        return Session(self, replies)


class Session:
    def __init__(self, case, replies):
        self.case, self.replies = case, replies
        self.mock = Mock(replies)
        self.thread = threading.Thread(target=self.mock.serve_forever, daemon=True)
        self.thread.start()
        case.env["NIB_BASE_URL"] = "http://127.0.0.1:%d" % self.mock.server_port
        self.t = Terminal(case.project, case.env)

    def shown(self):
        return "\n".join(screen(self.t.read(), 120, 32))

    def until(self, text, timeout=180):
        return wait(lambda: text in self.shown(), repr(text) + "\n" + self.shown(), timeout)

    def close(self):
        try:
            self.t.close()
        finally:
            for r in self.replies:
                r.release.set()
            self.mock.shutdown()
            self.thread.join()


def approve(work, port):
    c = Case(work, "approve", port)
    before = c.record()
    code = c.code()
    s = c.tui([Reply("r1", code=code), Reply("first done"), Reply("r2", code=code), Reply("second done")])
    try:
        s.t.send("go\r")
        s.until("Allow? [y/N]")
        shown = s.shown()
        check("prompt-names-refusal", "refused egress 127.0.0.1:%d · b1" % port in shown, shown)
        check("prompt-collapses-files", "refused read under ~/.fixture-cache/a · 20 refusals · tool" in shown, shown)
        check("prompt-diff", "+    policy.allow_host(p, \"127.0.0.1\", %d)" % port in shown and "+++ naeb.ae (proposed)" in shown
              and "+    policy.allow_read(p, \"~/.fixture-cache/a\")" in shown, shown)
        sid = c.sessions()
        s.t.send("y")
        s.until("policy rebuilt and loaded")
        today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
        text = open(c.policy).read()
        check("naeb.ae-lines", ("    // Approved %s: refused egress 127.0.0.1:%d (b1)\n    policy.allow_host(p, \"127.0.0.1\", %d)\n" % (today, port, port)) in text
              and ("    // Approved %s: refused read under ~/.fixture-cache/a, 20 refusals (tool)\n    policy.allow_read(p, \"~/.fixture-cache/a\")\n" % today) in text
              and text.startswith(POLICY[:-2]) and text.endswith("}\n"), text)
        after = c.record()
        check("record-rebuilt", after["source_sha256"] == sha(c.policy) and after["library_sha256"] == sha(os.path.join(c.dir, LIB))
              and after["library_sha256"] != before["library_sha256"], "%r %r" % (before, after))
        left = [n for n in os.listdir(c.dir) if ".new-" in n] + [n for n in os.listdir(os.path.join(c.dir, "build")) if n.endswith(".ae") and n.startswith("policy-")]
        check("no-leftover-libraries", not left, repr(left))
        s.t.send("again\r")
        wait(lambda: tui.finished(Path(c.nib_home), "second done"), "second Turn")
        outs = c.tool_outputs()
        check("same-command-succeeds", len(outs) == 2 and "read=0 body=" in outs[0] and "approved-body" not in outs[0]
              and "read=20 body=approved-body" in outs[1], repr(outs)[-600:])
        check("same-session", c.sessions() == sid and len(sid) == 1, "%r then %r" % (sid, c.sessions()))
        log = c.records("fence_approval")
        check("log-approval", len(log) == 1 and log[0]["ok"] and log[0]["source_sha256_before"] == before["source_sha256"]
              and log[0]["source_sha256_after"] == after["source_sha256"] and log[0]["library_sha256_before"] == before["library_sha256"]
              and log[0]["library_sha256_after"] == after["library_sha256"] and "+++ naeb.ae (proposed)" in log[0]["diff"]
              and len(log[0]["lines"]) == 2, repr(log)[:800])
        s.t.send("/fence\r")
        s.until("Env set:", 30)
        check("fence-shows-new-policy", ("Hosts: allowed.invalid:443 · 127.0.0.1:%d" % port) in s.shown(), s.shown())
    finally:
        s.close()


def decline(work, port):
    c = Case(work, "decline", port)
    before = c.state()
    code = c.code()
    s = c.tui([Reply("r1", code=code), Reply("first done"), Reply("r2", code=code), Reply("second done")])
    try:
        s.t.send("go\r")
        s.until("Allow? [y/N]")
        s.t.send("n")
        s.until("Allow? [y/N] n")
        s.t.send("again\r")
        wait(lambda: tui.finished(Path(c.nib_home), "second done"), "second Turn")
        time.sleep(1)
        check("n-changes-nothing", c.state() == before and not c.records("fence_approval"), "naeb.ae or the build changed")
        open_q = [l for l in s.shown().splitlines() if l.strip() == "Allow? [y/N]"]
        check("n-not-offered-again", not open_q and "Allow the naeb.ae change" not in s.shown(), s.shown())
        outs = c.tool_outputs()
        check("n-still-refused", len(outs) == 2 and "approved-body" not in outs[1], repr(outs)[-400:])
    finally:
        s.close()


def edited(work, port):
    c = Case(work, "edited", port)
    code = c.code()
    s = c.tui([Reply("r1", code=code), Reply("first done")])
    try:
        s.t.send("go\r")
        s.until("Allow? [y/N]")
        with open(c.policy, "a") as f:
            f.write("// edited elsewhere\n")
        mine = open(c.policy, "rb").read()
        rec = c.record()
        s.t.send("y")
        s.until("naeb.ae not changed")
        check("edited-refused", "changed since the policy in force was built" in s.shown() and open(c.policy, "rb").read() == mine and c.record() == rec,
              s.shown())
    finally:
        s.close()


def broken(work, port):
    bad = os.path.join(work, "broken-src")
    shutil.copytree(ROOT / "ae" / "policy_lib", os.path.join(bad, "ae", "policy_lib"))
    with open(os.path.join(bad, "ae", "policy_lib", "naeb", "policy", "module.ae"), "a") as f:
        f.write("\nthis line is not Aether(\n")
    c = Case(work, "broken", port, src=bad)
    before = c.state()
    code = c.code()
    s = c.tui([Reply("r1", code=code), Reply("first done"), Reply("r2", code=code), Reply("second done")])
    try:
        s.t.send("go\r")
        s.until("Allow? [y/N]")
        s.t.send("y")
        wait(lambda: c.records("fence_approval"), "the failed approval logged")
        s.until("of the compiler's output", 30)
        check("broken-shown", "naeb.ae not changed · the policy did not compile" in s.shown(), s.shown())
        check("broken-restored", c.state() == before, "naeb.ae or the built policy changed")
        check("broken-no-leftovers", not [n for n in os.listdir(c.dir) if ".new-" in n], repr(os.listdir(c.dir)))
        s.t.send("again\r")
        wait(lambda: tui.finished(Path(c.nib_home), "second done"), "second Turn")
        outs = c.tool_outputs()
        check("broken-old-policy-in-force", len(outs) == 2 and "read=0 body=naeb: egress to 127.0.0.1:%d is not in the project fence" % port in outs[1], repr(outs)[-400:])
        log = c.records("fence_approval")
        check("broken-logged", len(log) == 1 and not log[0]["ok"] and "did not compile" in log[0]["error"], repr(log)[:400])
    finally:
        s.close()


def ask(work, port):
    c = Case(work, "ask", port)
    before = c.state()
    replies = [Reply("r1", code=c.code()), Reply("done")]
    mock = Mock(replies)
    th = threading.Thread(target=mock.serve_forever, daemon=True)
    th.start()
    try:
        env = dict(c.env, NIB_BASE_URL="http://127.0.0.1:%d" % mock.server_port)
        r = subprocess.run([str(NAEB), "ask", "--json", "go"], cwd=c.project, env=env, capture_output=True, text=True, timeout=300, stdin=subprocess.DEVNULL)
        check("ask-reports", r.returncode == 0 and "policy.allow_host(p, \\\"127.0.0.1\\\", %d)" % port in r.stdout, (r.stdout + r.stderr)[-600:])
        check("ask-never-asks", "Allow?" not in r.stdout + r.stderr and c.state() == before and not c.records("fence_approval"), (r.stdout + r.stderr)[-300:])
    finally:
        mock.shutdown()
        th.join()


def main():
    os.chdir(ROOT / "tests")
    scratch = ROOT / "target" / "redteam"
    scratch.mkdir(parents=True, exist_ok=True)
    work = tempfile.mkdtemp(prefix="approval-", dir=scratch)
    atexit.register(shutil.rmtree, work, True)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Body)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    only = sys.argv[1:]
    for case in (approve, decline, edited, broken, ask):
        if only and case.__name__ not in only:
            continue
        try:
            case(work, port)
        except Exception as e:  # a broken fixture fails its case, not the run
            check(case.__name__, False, "%s: %s" % (type(e).__name__, str(e)[-1500:]))
    server.shutdown()
    return fails


if __name__ == "__main__":
    sys.exit(main())
