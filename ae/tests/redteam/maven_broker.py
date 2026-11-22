#!/usr/bin/env python3
"""naeb's experimental Maven broker (docs/naeb/adr/0001, "The Maven broker").

Runs the built naeb (NAEB) in a fixture HOME (absolute fake paths under
target/redteam) whose project has the fixture pom.xml and a naeb.ae with
policy.maven_broker, built by `naeb build -y` against this checkout. The
repository is ae/tests/maven_fixture/repo served on 127.0.0.1 (serve.py)
with fixture Last-Modified dates; the keyring is the fixture's trusted
keys; a second fixture repository, which naeb.ae does not allow, is served
too and must never be asked. `naeb js` drives tools.maven_fetch directly
(no model); the TUI case runs on a pty with upstream's mock provider
(tests/test_interjections.py), and `ask --json` with the same mock. No real
~/.m2, home, host, key or provider is touched.

    NAEB=target/build/bin/naeb python3 -I ae/tests/redteam/maven_broker.py [case ...]

Prints `ok   <case>` or `FAIL <case> ...`; the exit status is the number of
failures.
"""
import atexit
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "ae" / "tests" / "maven_fixture"))
import test_interjections as tui  # noqa: E402
from test_interjections import Mock, Reply, Terminal, screen  # noqa: E402
from serve import Repo  # noqa: E402

NAEB = Path(os.environ.get("NAEB", ROOT / "target/build/bin/naeb"))
tui.BIN = NAEB
FIXTURE = ROOT / "ae" / "tests" / "maven_fixture"
FX = "invalid/naeb/fx"
G = "invalid.naeb.fx"
AGES = {FX + "/lib-young/": 2, FX + "/lib-range/1.9/": 2}
DIST_DIR = "org/apache/maven/apache-maven/3.9.16"
DIST_URL = "https://repo.naeb.invalid/maven2/%s/apache-maven-3.9.16-bin.zip" % DIST_DIR
DIST = "org.apache.maven:apache-maven:zip:bin:3.9.16"
PROPS = "wrapperVersion=3.3.4\ndistributionType=only-script\ndistributionUrl=%s\n" % DIST_URL


def java_hash(s):
    """mvnw's hash_string: Java's String.hashCode, unsigned, lower-case hex."""
    h = 0
    for c in s.encode("ascii"):
        h = (h * 31 + c) % 2 ** 32
    return "%x" % h

fails = 0


def check(name, held, why=""):
    global fails
    if held:
        print("ok   %s" % name)
    else:
        fails += 1
        print("FAIL %s %s" % (name, why))


def wait(fn, what, timeout=180):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        v = fn()
        if v:
            return v
        time.sleep(.05)
    raise AssertionError("timed out: " + what)


class Case:
    """A fixture HOME with the fixture project and a built naeb.ae."""

    def __init__(self, work, name, repo, other, policy_extra="", keyring="~/.naeb/maven/trusted.asc", wrapper=False, props=None,
                 policy=True):
        self.home = os.path.realpath(os.path.join(work, name, "home"))
        self.naeb_home = os.path.join(self.home, ".naeb")
        self.project = os.path.join(self.home, "proj")
        self.m2 = os.path.join(self.home, ".m2", "repository")
        os.makedirs(os.path.join(self.project, ".git"))
        os.makedirs(self.naeb_home)
        os.makedirs(os.path.join(self.home, ".naeb", "maven"))
        shutil.copy(FIXTURE / "keys" / "trusted.asc", os.path.join(self.home, ".naeb", "maven", "trusted.asc"))
        with open(FIXTURE / "project" / "pom.xml") as f:
            pom = f.read().replace("@OTHER@", other.url)
        with open(os.path.join(self.project, "pom.xml"), "w") as f:
            f.write(pom)
        if wrapper:
            # The Maven wrapper 3.3.4's own mvnw (only-script) and its properties.
            shutil.copy(FIXTURE / "project" / "mvnw", os.path.join(self.project, "mvnw"))
            os.chmod(os.path.join(self.project, "mvnw"), 0o755)
            os.makedirs(os.path.join(self.project, ".mvn", "wrapper"))
            with open(os.path.join(self.project, ".mvn", "wrapper", "maven-wrapper.properties"), "w") as f:
                f.write(props if props is not None else PROPS)
        self.marker = os.path.join(self.home, "extension-ran")
        self.policy = os.path.join(self.project, "naeb.ae")
        if policy:
            with open(self.policy, "w") as f:
                f.write("import naeb.policy\nimport naeb_templates.maven\n\nfence(p: ptr) {\n"
                        "    maven.apply(p)\n"
                        "    policy.maven_broker(p)\n"
                        "    policy.maven_repository(p, \"%s\")\n"
                        "    policy.maven_keyring(p, \"%s\")\n%s}\n" % (repo.url, keyring, policy_extra))
        self.env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": self.home,
            "NAEB_HOME": self.naeb_home,
            "NAEB_SRC": str(ROOT),
            "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
            "LANG": "C.UTF-8",
            "TERM": "xterm-256color",
            "NAEB_PROVIDER": "chat_completions",
            "NAEB_API_KEY": "mock",
            "NAEB_FX_MARKER": self.marker,
        }
        self.built = None
        if policy:
            self.built = subprocess.run([str(NAEB), "build", "-y"], cwd=self.project, env=self.env, capture_output=True, text=True, timeout=600)

    def require_built(self):
        if self.built is None or self.built.returncode != 0:
            raise AssertionError("naeb build: %s %s" % (self.built and self.built.stdout[-500:], self.built and self.built.stderr[-500:]))
        return self

    def bash(self, command):
        r, v = self.js("JSON.stringify(await tools.bash({command: %s, timeout_ms: 60000}))" % json.dumps(command))
        if not isinstance(v, dict):
            raise AssertionError("bash gave no JSON: %r %r" % (r.stdout[-800:], r.stderr[-800:]))
        return v

    def dist_home(self):
        return os.path.join(self.home, ".m2", "wrapper", "dists", "apache-maven-3.9.16", java_hash(DIST_URL))

    def js(self, code, timeout=300):
        r = subprocess.run([str(NAEB), "js", code], cwd=self.project, env=self.env, capture_output=True, text=True, timeout=timeout,
                           stdin=subprocess.DEVNULL)
        out = r.stdout.strip()
        try:
            v = json.loads(out)
        except ValueError:
            return r, None
        if isinstance(v, str) and v[:1] in ("{", "["):
            v = json.loads(v)
        return r, v

    def fetch(self, *gavs):
        r, v = self.js("JSON.stringify(await tools.maven_fetch({gavs: %s}))" % json.dumps(list(gavs)))
        if v is None:
            raise AssertionError("maven_fetch gave no JSON: %r %r" % (r.stdout[-800:], r.stderr[-800:]))
        return v

    def files(self, artifact=None):
        base = os.path.join(self.m2, *FX.split("/"))
        if artifact:
            base = os.path.join(base, artifact)
        out = []
        for d, _dirs, names in os.walk(base):
            out += [os.path.relpath(os.path.join(d, n), self.m2) for n in names]
        return sorted(out)

    def records(self, member):
        d = os.path.join(self.naeb_home, "sessions")
        out = []
        if not os.path.isdir(d):
            return out
        for name in sorted(os.listdir(d)):
            if not name.endswith(".jsonl"):
                continue
            for line in open(os.path.join(d, name), "rb").read().split(b"\n"):
                if line.strip():
                    rec = json.loads(line)
                    if member in rec:
                        out.append(rec[member])
        return out


def refused(v, gav):
    return [r for r in v.get("refused", []) if r["gav"] == gav]


def fetched(v):
    return [f["gav"] for f in v.get("fetched", [])]


def fetch_ok(c):
    v = c.fetch(G + ":lib-a:1.0")
    check("fetch-ok", v["ok"] and set(fetched(v)) == {G + ":lib-a:1.0", G + ":lib-b:1.0", G + ":parent:1.0"}, json.dumps(v)[:800])
    got = c.files()
    want = [FX + "/lib-a/1.0/lib-a-1.0.jar", FX + "/lib-a/1.0/lib-a-1.0.pom", FX + "/lib-b/1.0/lib-b-1.0.jar",
            FX + "/lib-b/1.0/lib-b-1.0.pom", FX + "/parent/1.0/parent-1.0.pom"]
    check("fetch-writes-closure", got == want, repr(got))
    same = all(open(os.path.join(c.m2, p), "rb").read() == open(FIXTURE / "repo" / p, "rb").read() for p in want)
    check("fetch-bytes-intact", same, "a written file differs from the repository's")
    sigs = {f["gav"]: f["signature"] for f in v["fetched"]}
    check("fetch-signatures", sigs[G + ":lib-a:1.0"].startswith("good ") and sigs[G + ":lib-b:1.0"].startswith("good "), repr(sigs))
    check("fetch-test-scope-skipped", not c.files("lib-test-only"), repr(c.files("lib-test-only")))
    again = c.fetch(G + ":lib-a:1.0")
    check("fetch-again-present", again["ok"] and not again["fetched"] and G + ":lib-a:1.0" in again["present"], json.dumps(again)[:400])


def young(c):
    v = c.fetch(G + ":lib-young:2.0")
    r = refused(v, G + ":lib-young:2.0")
    check("young-refused", not v["ok"] and r and "too young" in r[0]["reason"] and r[0]["young"] == [{"gav": G + ":lib-young:2.0", "age_days": 2}],
          json.dumps(v)[:600])
    check("young-denied-record", any(d.get("op") == "maven_age" for d in v.get("fence_denied", [])), json.dumps(v)[:600])
    check("young-nothing-written", not c.files("lib-young"), repr(c.files("lib-young")))


def range_by_age(c):
    v = c.fetch(G + ":lib-range:[1.0,2.0)")
    check("range-picks-newest-old-enough", v["ok"] and fetched(v) == [G + ":lib-range:1.5"], json.dumps(v)[:600])


def unknown_repo(c, other):
    before = len(other.hits)
    v = c.fetch(G + ":lib-elsewhere:1.0")
    r = refused(v, G + ":lib-elsewhere:1.0")
    check("unknown-repo-refused", r and "not found in the allowed repositories" in r[0]["reason"] and other.url in r[0]["reason"]
          and "policy.maven_repository" in r[0]["reason"], json.dumps(v)[:600])
    check("unknown-repo-never-asked", len(other.hits) == before == 0, repr(other.hits))
    check("unknown-repo-nothing-written", not c.files("lib-elsewhere"), repr(c.files("lib-elsewhere")))


def not_in_poms(c, repo):
    v = c.fetch(G + ":lib-unreached:1.0", G + ":lib-a:9.9")
    r = refused(v, G + ":lib-unreached:1.0")
    r2 = refused(v, G + ":lib-a:9.9")
    check("not-in-poms-refused", r and "not reachable from the project's POMs" in r[0]["reason"] and r2 and "not reachable" in r2[0]["reason"],
          json.dumps(v)[:600])
    check("not-in-poms-never-asked", not [h for h in repo.hits if "lib-unreached" in h or "/9.9/" in h], repr([h for h in repo.hits if "unreached" in h]))
    check("not-in-poms-nothing-written", not c.files("lib-unreached"), repr(c.files("lib-unreached")))


def bad_checksum(c):
    v = c.fetch(G + ":lib-badsum:1.0")
    r = refused(v, G + ":lib-badsum:1.0")
    check("bad-checksum-refused", r and "checksum mismatch" in r[0]["reason"], json.dumps(v)[:600])
    check("bad-checksum-nothing-written", not c.files("lib-badsum"), repr(c.files("lib-badsum")))


def bad_signature(c):
    v = c.fetch(G + ":lib-badsig:1.0")
    r = refused(v, G + ":lib-badsig:1.0")
    check("bad-signature-refused", r and "bad signature" in r[0]["reason"], json.dumps(v)[:600])
    check("bad-signature-nothing-written", not c.files("lib-badsig"), repr(c.files("lib-badsig")))


def unknown_key(c):
    v = c.fetch(G + ":lib-unknownkey:1.0")
    sig = [f["signature"] for f in v.get("fetched", [])]
    check("unknown-key-recorded", v["ok"] and sig and sig[0].startswith("unknown key "), json.dumps(v)[:600])


def offline_build(c):
    r, v = c.js("const b = await tools.bash({command: 'echo \"args=$MAVEN_ARGS\"; mkdir -p ~/.m2/repository/invalid; touch ~/.m2/repository/planted 2>&1; echo touch=$?; ls ~/.m2/repository'}); b.output")
    out = v if isinstance(v, str) else r.stdout
    check("offline-maven-args", "args=--offline" in out, out[-400:])
    check("offline-cannot-write-m2", "touch=0" not in out and not os.path.exists(os.path.join(c.m2, "planted")), out[-400:])
    r2, v2 = c.js("JSON.stringify((await tools.fence()).maven)")
    check("offline-fence-shows-broker", isinstance(v2, dict) and v2.get("broker") is True and v2.get("min_age_days") == 7, r2.stdout[-400:])
    r3, v3 = c.js("await tools.write({path: %s, content: 'x'}).then(() => 'wrote', e => 'refused')" % json.dumps(os.path.join(c.m2, "tool-planted"))
                  )
    check("offline-tool-cannot-write-m2", v3 == "refused" and not os.path.exists(os.path.join(c.m2, "tool-planted")), r3.stdout[-300:])


def symlinks(c):
    elsewhere = os.path.join(c.home, "elsewhere")
    os.makedirs(elsewhere)
    os.makedirs(os.path.join(c.m2, *FX.split("/")), exist_ok=True)
    os.symlink(elsewhere, os.path.join(c.m2, *FX.split("/"), "lib-managed"))
    v = c.fetch(G + ":lib-managed:1.3")
    r = refused(v, G + ":lib-managed:1.3")
    check("symlink-dir-refused", r and "not written" in r[0]["reason"], json.dumps(v)[:600])
    check("symlink-dir-not-redirected", os.listdir(elsewhere) == [], repr(os.listdir(elsewhere)))
    leaf_target = os.path.join(c.home, "leaf-target")
    with open(leaf_target, "w") as f:
        f.write("original\n")
    d = os.path.join(c.m2, *FX.split("/"), "lib-unknownkey", "1.0")
    os.makedirs(d)
    os.symlink(leaf_target, os.path.join(d, "lib-unknownkey-1.0.jar"))
    v2 = c.fetch(G + ":lib-unknownkey:1.0")
    r2 = refused(v2, G + ":lib-unknownkey:1.0")
    check("symlink-leaf-refused", r2 and "not a regular file" in r2[0]["reason"], json.dumps(v2)[:600])
    check("symlink-leaf-not-written-through", open(leaf_target).read() == "original\n" and os.path.islink(os.path.join(d, "lib-unknownkey-1.0.jar")),
          open(leaf_target).read())


def extension(c):
    v = c.fetch(G + ":fx-maven-plugin:1.0")
    check("extension-fetched", v["ok"] and fetched(v) == [G + ":fx-maven-plugin:1.0"], json.dumps(v)[:400])
    check("extension-never-run", not os.path.exists(c.marker), "the marker exists")


def keyring_in_root(work, repo, other):
    c = Case(work, "keyring", repo, other, keyring="~/proj/keys.asc")
    shutil.copy(FIXTURE / "keys" / "trusted.asc", os.path.join(c.project, "keys.asc"))
    r = subprocess.run([str(NAEB), "js", "1"], cwd=c.project, env=c.env, capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)
    check("keyring-in-root-refused", r.returncode == 2 and "Maven keyring" in r.stderr, "exit %d %r" % (r.returncode, r.stderr[-300:]))


def tui_override(work, repo, other):
    c = Case(work, "tui", repo, other)
    code = "const r = await tools.maven_fetch({gavs: [%s]}); JSON.stringify(r.refused)" % json.dumps(G + ":lib-young:2.0")
    replies = [Reply("r1", code=code), Reply("first done")]
    mock = Mock(replies)
    th = threading.Thread(target=mock.serve_forever, daemon=True)
    th.start()
    c.env["NAEB_BASE_URL"] = "http://127.0.0.1:%d" % mock.server_port
    t = Terminal(c.project, c.env)

    def shown():
        return "\n".join(screen(t.read(), 120, 32))
    try:
        t.send("build it\r")
        wait(lambda: "[y/N]" in shown(), "the prompt\n" + shown())
        s = shown()
        check("tui-prompt", "Maven broker refused %s:lib-young:2.0" % G in s and "published 2 days ago" in s and "Fetch it anyway" in s, s)
        check("tui-nothing-before-y", not c.files("lib-young"), repr(c.files("lib-young")))
        t.send("y")
        wait(lambda: "approved by you" in shown() or "nothing fetched" in shown(), "the fetch\n" + shown())
        check("tui-y-fetched", "Maven broker fetched %s:lib-young:2.0 · approved by you" % G in shown() and c.files("lib-young"), shown())
        log = c.records("maven_fetch")
        ov = [r for r in log if r.get("gav") == G + ":lib-young:2.0"]
        check("tui-log", ov and ov[0]["override"] is True and ov[0]["age_days"] == 2 and ov[0]["files"] and ov[0]["signature"].startswith("good ")
              and any(r.get("ok") is False and "too young" in r.get("reason", "") for r in log), json.dumps(log)[:800])
        t.send("/fence\r")
        wait(lambda: "Maven fetched:" in shown(), "/fence\n" + shown(), 30)
        s2 = shown()
        check("tui-fence-shows", "Maven broker: on" in s2 and "lib-young:2.0" in s2 and "override" in s2, s2)
    finally:
        try:
            t.close()
        finally:
            for r in replies:
                r.release.set()
            mock.shutdown()
            th.join()


def tui_decline(work, repo, other):
    c = Case(work, "tui-n", repo, other)
    code = "const r = await tools.maven_fetch({gavs: [%s]}); JSON.stringify(r.refused)" % json.dumps(G + ":lib-young:2.0")
    replies = [Reply("r1", code=code), Reply("first done")]
    mock = Mock(replies)
    th = threading.Thread(target=mock.serve_forever, daemon=True)
    th.start()
    c.env["NAEB_BASE_URL"] = "http://127.0.0.1:%d" % mock.server_port
    t = Terminal(c.project, c.env)

    def shown():
        return "\n".join(screen(t.read(), 120, 32))
    try:
        t.send("build it\r")
        wait(lambda: "[y/N]" in shown(), "the prompt\n" + shown())
        t.send("n")
        wait(lambda: "[y/N] n" in shown(), "the answer\n" + shown())
        time.sleep(1)
        check("tui-n-nothing-written", not c.files("lib-young") and "approved by you" not in shown(), shown())
    finally:
        try:
            t.close()
        finally:
            for r in replies:
                r.release.set()
            mock.shutdown()
            th.join()


def ask_json(work, repo, other):
    c = Case(work, "ask", repo, other)
    code = "const r = await tools.maven_fetch({gavs: [%s]}); JSON.stringify(r.refused)" % json.dumps(G + ":lib-young:2.0")
    replies = [Reply("r1", code=code), Reply("done")]
    mock = Mock(replies)
    th = threading.Thread(target=mock.serve_forever, daemon=True)
    th.start()
    try:
        env = dict(c.env, NAEB_BASE_URL="http://127.0.0.1:%d" % mock.server_port)
        r = subprocess.run([str(NAEB), "ask", "--json", "build it"], cwd=c.project, env=env, capture_output=True, text=True, timeout=300,
                           stdin=subprocess.DEVNULL)
        check("ask-reports", r.returncode == 0 and "maven_age" in r.stdout and "too young" in r.stdout, (r.stdout + r.stderr)[-800:])
        check("ask-never-asks", "[y/N]" not in r.stdout + r.stderr and not c.files("lib-young"), (r.stdout + r.stderr)[-300:])
        log = c.records("maven_fetch")
        check("ask-logged", any(x.get("ok") is False and "too young" in x.get("reason", "") for x in log), json.dumps(log)[:400])
    finally:
        mock.shutdown()
        th.join()


def under_m2(c, recs):
    m2 = os.path.join(c.home, ".m2")
    return [r for r in recs or [] if r.get("op") == "write" and (r.get("resource") == m2 or r.get("resource", "").startswith(m2 + "/"))]


def wrapper_dist(work, repo, other):
    """A fresh HOME (no ~/.m2), the broker on: mvnw is refused, the record
    points at maven_fetch; the fetch installs the fixture distribution where
    mvnw 3.3.4 looks; mvnw then runs it offline; ~/.m2 stays unwritable."""
    c = Case(work, "wrapper", repo, other, wrapper=True).require_built()
    check("wrapper-fresh-home", not os.path.exists(os.path.join(c.home, ".m2")), "~/.m2 exists before the run")
    b = c.bash("./mvnw -B verify")
    recs = under_m2(c, b.get("fence_denied"))
    check("wrapper-refused-record", recs and all("suggestion" not in r for r in recs)
          and any("tools.maven_fetch" in r.get("note", "") and DIST in r.get("note", "") for r in recs), json.dumps(b)[:1200])
    check("wrapper-m2-not-made", not os.path.exists(os.path.join(c.home, ".m2")), repr(os.listdir(c.home)))
    hits = len(repo.hits)
    v = c.fetch(DIST)
    f = [x for x in v.get("fetched", []) if x["gav"] == "org.apache.maven:apache-maven:3.9.16"]
    check("wrapper-fetched", v["ok"] and f and f[0].get("installed") == c.dist_home() and f[0]["signature"].startswith("good ")
          and {x["file"] for x in f[0]["files"]} == {"apache-maven-3.9.16.pom", "apache-maven-3.9.16-bin.zip"}, json.dumps(v)[:1200])
    asked = repo.hits[hits:]
    check("wrapper-only-the-fixture", asked and all(h.startswith("/maven2/%s/" % DIST_DIR) for h in asked), repr(asked))
    home = c.dist_home()
    mvn = os.path.join(home, "bin", "mvn")
    check("wrapper-installed-where-mvnw-looks", os.path.isfile(mvn) and os.access(mvn, os.X_OK)
          and open(os.path.join(home, "mvnw.url")).read() == DIST_URL + "\n"
          and os.path.isfile(os.path.join(home, "conf", "settings.xml"))
          and not os.access(os.path.join(home, "conf", "settings.xml"), os.X_OK), repr(os.listdir(home) if os.path.isdir(home) else None))
    parent = os.path.dirname(home)
    check("wrapper-no-staging-left", os.listdir(parent) == [os.path.basename(home)], repr(os.listdir(parent)))
    check("wrapper-not-in-repository", not os.path.exists(os.path.join(c.m2, "org", "apache")), "written into ~/.m2/repository")
    run = c.bash("./mvnw -B verify")
    check("wrapper-mvnw-runs-it", "fixture maven 3.9.16: MAVEN_ARGS=--offline args=-B verify" in run.get("output", ""), json.dumps(run)[:800])
    again = c.fetch("org.apache.maven:apache-maven:3.9.16:bin:zip")
    check("wrapper-again-present", again["ok"] and not again["fetched"] and DIST in again["present"], json.dumps(again)[:400])
    w = c.bash("touch ~/.m2/wrapper/planted; echo t=$?; mkdir ~/.m2/wrapper/dists/planted; echo m=$?; echo x > %s/bin/mvn; echo r=$?" % home)
    check("wrapper-read-only", "t=0" not in w.get("output", "") and "m=0" not in w.get("output", "") and "r=0" not in w.get("output", "")
          and not os.path.exists(os.path.join(c.home, ".m2", "wrapper", "planted")) and "fixture maven" in open(mvn).read(), json.dumps(w)[:800])
    r, t = c.js("await tools.write({path: %s, content: 'x'}).then(() => 'wrote', e => 'refused')" % json.dumps(os.path.join(c.home, ".m2", "wrapper", "tool-planted")))
    check("wrapper-tool-cannot-write", t == "refused" and not os.path.exists(os.path.join(c.home, ".m2", "wrapper", "tool-planted")), r.stdout[-300:])


def wrapper_refusals(work, repo, other):
    young_repo = Repo(FIXTURE / "repo", {"org/apache/maven/apache-maven/": 2})
    try:
        c = Case(work, "wrapper-young", young_repo, other, wrapper=True).require_built()
        v = c.fetch(DIST)
        r = refused(v, DIST)
        check("wrapper-young-refused", r and "too young" in r[0]["reason"] and r[0].get("young")
              and any(d.get("op") == "maven_age" and d.get("resource") == DIST for d in v.get("fence_denied", [])), json.dumps(v)[:600])
        check("wrapper-young-nothing-installed", not os.path.exists(os.path.join(c.home, ".m2", "wrapper", "dists", "apache-maven-3.9.16"))
              or not os.listdir(os.path.join(c.home, ".m2", "wrapper", "dists", "apache-maven-3.9.16")), "installed")
    finally:
        young_repo.close()
    c2 = Case(work, "wrapper-sum", repo, other, wrapper=True, props=PROPS + "distributionSha256Sum=" + "0" * 64 + "\n").require_built()
    v2 = c2.fetch(DIST)
    r2 = refused(v2, DIST)
    check("wrapper-sha256sum-checked", r2 and "distributionSha256Sum" in r2[0]["reason"] and not os.path.exists(c2.dist_home()), json.dumps(v2)[:600])
    v3 = c2.fetch("org.apache.maven:apache-maven:zip:bin:3.9.15")
    r3 = refused(v3, "org.apache.maven:apache-maven:zip:bin:3.9.15")
    check("wrapper-other-version-refused", r3 and "names " + DIST in r3[0]["reason"], json.dumps(v3)[:600])
    c3 = Case(work, "wrapper-none", repo, other).require_built()
    v4 = c3.fetch(DIST)
    r4 = refused(v4, DIST)
    check("wrapper-none-refused", r4 and "maven-wrapper.properties" in r4[0]["reason"], json.dumps(v4)[:600])


def tui_broker_offer(work, repo, other):
    """Paul's petclinic run, on fixtures: a Maven project with mvnw and no
    naeb.ae, a fresh HOME without ~/.m2. The fence refuses mvnw's mkdir of
    ~/.m2; the prompt offers policy.maven_broker(p), never allow_write ~/.m2;
    y writes it into a new naeb.ae and the policy is rebuilt with the broker."""
    c = Case(work, "fresh-tui", repo, other, wrapper=True, policy=False)
    code = "const b = await tools.bash({command: './mvnw -B clean verify'}); JSON.stringify(b)"
    replies = [Reply("r1", code=code), Reply("first done")]
    mock = Mock(replies)
    th = threading.Thread(target=mock.serve_forever, daemon=True)
    th.start()
    c.env["NAEB_BASE_URL"] = "http://127.0.0.1:%d" % mock.server_port
    t = Terminal(c.project, c.env)

    def shown():
        return "\n".join(screen(t.read(), 120, 40))
    try:
        t.send("build it\r")
        wait(lambda: "[y/N]" in shown(), "the prompt\n" + shown())
        s = shown()
        check("tui-broker-offered", "+    policy.maven_broker(p)" in s and "a Maven project: naeb's broker" in s and "--- /dev/null" in s, s)
        check("tui-never-allow-m2", "allow_write" not in s and "~/.m2\")" not in s, s)
        msgs = tui.history(Path(c.naeb_home))
        seen = json.dumps([m.get("content", "") for m in msgs if m.get("role") == "tool"])
        check("tui-model-told-broker", "policy.maven_broker(p)" in seen and "allow_write" not in seen, seen[-800:])
        t.send("y")
        wait(lambda: "policy rebuilt and loaded" in shown() or "naeb.ae not changed" in shown(), "the rebuild\n" + shown())
        text = open(c.policy).read() if os.path.exists(c.policy) else ""
        check("tui-broker-written", "policy rebuilt and loaded" in shown() and "    policy.maven_broker(p)\n" in text
              and "allow_write" not in text and "// Approved " in text, shown() + "\n" + text)
        check("tui-m2-untouched", not os.path.exists(os.path.join(c.home, ".m2")), repr(os.listdir(c.home)))
        t.send("/fence\r")
        wait(lambda: "Maven broker: on" in shown(), "/fence\n" + shown(), 30)
        check("tui-fence-has-broker", "Maven broker: on" in shown(), shown())
    finally:
        try:
            t.close()
        finally:
            for r in replies:
                r.release.set()
            mock.shutdown()
            th.join()


def main():
    os.chdir(ROOT / "tests")
    scratch = ROOT / "target" / "redteam"
    scratch.mkdir(parents=True, exist_ok=True)
    work = tempfile.mkdtemp(prefix="maven-", dir=scratch)
    atexit.register(shutil.rmtree, work, True)
    repo = Repo(FIXTURE / "repo", AGES)
    other = Repo(FIXTURE / "repo-other")
    only = sys.argv[1:]
    js_cases = [fetch_ok, young, range_by_age, unknown_repo, not_in_poms, bad_checksum, bad_signature, unknown_key, offline_build, symlinks, extension]
    shared = None
    for case in js_cases:
        if only and case.__name__ not in only:
            continue
        try:
            if shared is None:
                shared = Case(work, "js", repo, other)
                if shared.built.returncode != 0:
                    raise AssertionError("naeb build: %s %s" % (shared.built.stdout[-500:], shared.built.stderr[-500:]))
            c = shared
            if case is symlinks:
                c = Case(work, "symlinks", repo, other)
            if case is unknown_repo:
                case(c, other)
            elif case is not_in_poms:
                case(c, repo)
            else:
                case(c)
        except Exception as e:  # a broken fixture fails its case, not the run
            check(case.__name__, False, "%s: %s" % (type(e).__name__, str(e)[-1500:]))
    for case in (keyring_in_root, tui_override, tui_decline, ask_json, wrapper_dist, wrapper_refusals, tui_broker_offer):
        if only and case.__name__ not in only:
            continue
        try:
            case(work, repo, other)
        except Exception as e:
            check(case.__name__, False, "%s: %s" % (type(e).__name__, str(e)[-1500:]))
    repo.close()
    other.close()
    return fails


if __name__ == "__main__":
    sys.exit(main())
