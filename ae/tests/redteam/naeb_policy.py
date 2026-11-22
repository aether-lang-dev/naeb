#!/usr/bin/env python3
"""How naeb builds, checks and loads a project's policy (docs/naeb/adr/0001).

Drives naeb (NAEB) in a fixture HOME of absolute fake paths: `naeb build`
compiles each fixture project's naeb.ae against this checkout (NAEB_SRC) into
that HOME's ~/.naeb. No real home, secret, host or provider is touched; the
sub-agent case uses the local mock provider of tests/.

    NAEB=target/build/bin/naeb python3 -I ae/tests/redteam/naeb_policy.py

Prints `ok   <case>` or `FAIL <case> ...`; the exit status is the number of
failures.
"""
import atexit
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.join(ROOT, "tests"))
from mock_providers import Mock  # noqa: E402

NAEB = os.environ.get("NAEB", os.path.join(ROOT, "target/build/bin/naeb"))
LIB = "policy.dylib" if sys.platform == "darwin" else "policy.so"

fails = 0


def check(name, held, why):
    global fails
    if held:
        print("ok   %s" % name)
    else:
        fails += 1
        print("FAIL %s %s" % (name, why))


def sha(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def main():
    scratch = os.path.join(ROOT, "target", "redteam")
    os.makedirs(scratch, exist_ok=True)
    work = tempfile.mkdtemp(prefix="policy-", dir=scratch)
    atexit.register(shutil.rmtree, work, True)
    home = os.path.realpath(os.path.join(work, "home"))
    naeb_home = os.path.join(home, ".naeb")
    os.makedirs(naeb_home)
    os.makedirs(os.path.join(home, ".m2", "repository"))
    with open(os.path.join(home, ".m2", "settings.xml"), "w") as f:
        f.write("<settings>CANARY-m2</settings>\n")
    with open(os.path.join(home, "secret.txt"), "w") as f:
        f.write("CANARY-home\n")
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": home,
        "NAEB_HOME": naeb_home,
        "NAEB_SRC": ROOT,
        "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
        "LANG": "C.UTF-8",
    }

    def project(rel, policy=None):
        p = os.path.join(home, rel)
        os.makedirs(os.path.join(p, ".git"))
        if policy is not None:
            with open(os.path.join(p, "naeb.ae"), "w") as f:
                f.write(policy)
        return p

    def naeb(cwd, *args, stdin=subprocess.DEVNULL, extra=None):
        e = dict(env, **(extra or {}))
        return subprocess.run([NAEB, *args], cwd=cwd, env=e, stdin=stdin, capture_output=True, text=True, timeout=600)

    def js(cwd, code):
        r = naeb(cwd, "js", code)
        return r, r.stdout.strip().splitlines()[-1] if r.stdout.strip() else ""

    def launcher_dirs():
        d = os.path.join(home, ".naeb", "launchers")
        return sorted(os.listdir(d)) if os.path.isdir(d) else []

    basic = "import naeb.policy\n\nfence(p: ptr) {\n    policy.allow_host(p, \"allowed.invalid\", 443)\n}\n"

    # No naeb.ae: the default fence, said once.
    bare = project("bare")
    r, out = js(bare, "const a = await tools.read({path: %s}).then(x => JSON.stringify(x), e => 'ERR: ' + e.message); const b = await tools.fetch({url: 'https://allowed.invalid/', timeout_ms: 5000}).then(x => JSON.stringify(x), e => 'ERR: ' + e.message); JSON.stringify([a, b])" % json.dumps(os.path.join(home, "secret.txt")))
    check("no-policy-default-fence", r.returncode == 0 and "no naeb.ae" in r.stderr and "CANARY-home" not in out and "egress allowed.invalid:443" in out,
          "exit %d stderr %r out %r" % (r.returncode, r.stderr[-300:], out[:300]))

    # Built: the policy's host is allowed, naeb.ae is read-only to the fenced.
    a = project("a/app", basic)
    r = naeb(a, "build", "-y")
    check("build", r.returncode == 0 and LIB in r.stdout, "exit %d %s %s" % (r.returncode, r.stdout[-500:], r.stderr[-500:]))
    r, out = js(a, "const f = await tools.fetch({url: 'https://denied.invalid/', timeout_ms: 5000}).then(x => JSON.stringify(x), e => 'ERR: ' + e.message); const w = await tools.write({path: 'naeb.ae', content: '// widened\\n'}).then(x => JSON.stringify(x), e => 'ERR: ' + e.message); const b = await tools.bash({command: 'echo widened >> naeb.ae; cat naeb.ae'}); JSON.stringify([f, w, b.output])")
    check("policy-loaded", r.returncode == 0 and "no naeb.ae" not in r.stderr and "egress denied.invalid:443" in out, "exit %d stderr %r out %r" % (r.returncode, r.stderr[-300:], out[:300]))
    with open(os.path.join(a, "naeb.ae")) as f:
        check("policy-read-only", f.read() == basic, "naeb.ae was changed from inside the fence: %r" % out[:300])

    # Two projects named alike get two directories.
    b = project("b/app", basic)
    r = naeb(b, "js", "1")
    check("same-name-not-shared", r.returncode == 2 and "has not been built" in r.stderr, "b ran on a's build: exit %d %r" % (r.returncode, r.stderr[-300:]))
    naeb(b, "build", "-y")
    dirs = launcher_dirs()
    check("same-name-two-keys", len(dirs) == 2 and all(d.startswith("app-") for d in dirs), "launcher dirs %r" % dirs)
    adir = [os.path.join(home, ".naeb", "launchers", d) for d in dirs if open(os.path.join(home, ".naeb", "launchers", d, "policy.built")).read().find("project=%s\n" % a) >= 0][0]
    lib = os.path.join(adir, LIB)
    record = os.path.join(adir, "policy.built")

    # A changed naeb.ae: naeb will not start, and `naeb build` with no answer
    # (EOF) leaves the old policy in place.
    before = (sha(lib), sha(record), sha(os.path.join(adir, "naeb.ae")))
    with open(os.path.join(a, "naeb.ae"), "a") as f:
        f.write("// a pull brought this\n")
    r = naeb(a, "js", "1")
    check("changed-policy-refused", r.returncode == 2 and "changed since it was built" in r.stderr, "exit %d %r" % (r.returncode, r.stderr[-300:]))
    r = naeb(a, "build")
    check("build-eof-is-no", r.returncode == 1 and "a pull brought this" in r.stdout and (sha(lib), sha(record), sha(os.path.join(adir, "naeb.ae"))) == before,
          "exit %d out %r err %r" % (r.returncode, r.stdout[-300:], r.stderr[-300:]))
    r2 = subprocess.run([NAEB, "build"], cwd=a, env=env, input="n\n", capture_output=True, text=True, timeout=600)
    check("build-n-is-no", r2.returncode == 1 and (sha(lib), sha(record)) == before[:2], "exit %d %r" % (r2.returncode, r2.stderr[-300:]))
    r = subprocess.run([NAEB, "build"], cwd=a, env=env, input="y\n", capture_output=True, text=True, timeout=600)
    check("build-y-rebuilds", r.returncode == 0 and sha(record) != before[1] and naeb(a, "js", "1").returncode == 0, "exit %d %r" % (r.returncode, r.stderr[-300:]))

    # Another interface: in the record, or in the library itself.
    saved = open(record).read()
    with open(record, "w") as f:
        f.write(saved.replace("interface=2\n", "interface=0\n"))
    r = naeb(a, "js", "1")
    check("interface-record-refused", r.returncode == 2 and "interface 0" in r.stderr and "naeb build" in r.stderr, "exit %d %r" % (r.returncode, r.stderr[-300:]))
    other = os.path.join(work, "other")
    os.makedirs(other)
    with open(os.path.join(other, "v2.ae"), "w") as f:
        f.write("naeb_policy_interface() -> int { return 99 }\n\nnaeb_policy_v1(api: ptr, f: ptr) -> int { return 0 }\n")
    c = subprocess.run(["ae", "build", "--emit=lib", "v2.ae", "-o", "v2lib"], cwd=other, env=env, capture_output=True, text=True, timeout=600)
    built = [n for n in os.listdir(other) if n.startswith("v2lib")]
    if c.returncode != 0 or not built:
        check("interface-library-refused", False, "could not build the stand-in library: %s" % (c.stdout + c.stderr)[-300:])
    else:
        orig_lib = open(lib, "rb").read()
        shutil.copy(os.path.join(other, built[0]), lib)
        with open(record, "w") as f:
            f.write("\n".join("library_sha256=" + sha(lib) if l.startswith("library_sha256=") else l for l in saved.split("\n")))
        r = naeb(a, "js", "1")
        check("interface-library-refused", r.returncode == 2 and "built for interface 99" in r.stderr and "naeb build" in r.stderr, "exit %d %r" % (r.returncode, r.stderr[-300:]))
        with open(lib, "wb") as f:
            f.write(orig_lib)
    with open(record, "w") as f:
        f.write(saved)
    with open(lib, "ab") as f:
        f.write(b"\0")
    r = naeb(a, "js", "1")
    check("library-changed-refused", r.returncode == 2 and "not the one naeb build made" in r.stderr, "exit %d %r" % (r.returncode, r.stderr[-300:]))
    naeb(a, "build", "-y")
    check("rebuilt-runs", naeb(a, "js", "1").returncode == 0, "")

    # A policy that makes its own library writable: refused at start.
    w = project("w/app", "import naeb.policy\n\nfence(p: ptr) {\n    policy.allow_write(p, \"~/.naeb\")\n}\n")
    naeb(w, "build", "-y")
    r = naeb(w, "js", "1")
    check("library-in-root-refused", r.returncode == 2 and "lies inside a root" in r.stderr, "exit %d %r" % (r.returncode, r.stderr[-300:]))

    # Templates: a toolchain's cache, never its credentials.
    t = project("t/app", "import naeb.policy\nimport naeb_templates.maven\nimport naeb_templates.gradle\nimport naeb_templates.npm\n\nfence(p: ptr) {\n    maven.apply(p)\n    gradle.apply(p)\n    npm.apply(p)\n    policy.set_env(p, \"TOOL_HOME\", \"${policy.project_root(p)}/.tool\")\n}\n")
    r = naeb(t, "build", "-y")
    m2 = os.path.join(home, ".m2")
    r, out = js(t, "const s = await tools.read({path: %s}).then(x => JSON.stringify(x), e => 'ERR: ' + e.message); const w = await tools.write({path: %s, content: 'x'}).then(x => 'OK', e => 'ERR: ' + e.message); const g = await tools.write({path: %s, content: 'x'}).then(x => 'OK', e => 'ERR: ' + e.message); const e = await tools.bash({command: 'echo $TOOL_HOME'}); JSON.stringify([s, w, g, e.output])" % (json.dumps(os.path.join(m2, "settings.xml")), json.dumps(os.path.join(m2, "repository", "x.jar")), json.dumps(os.path.join(home, ".gradle", "init.d", "evil.gradle"))))
    try:
        s_, w_, g_, e_ = json.loads(json.loads(out)) if out.startswith('"') else json.loads(out)
    except Exception:
        s_ = w_ = g_ = e_ = ""
    check("templates", r.returncode == 0 and "CANARY-m2" not in s_ and w_ == "OK" and g_.startswith("ERR") and e_.strip() == os.path.join(t, ".tool"),
          "exit %d %r %r" % (r.returncode, out[:400], r.stderr[-300:]))

    # A sub-agent is naeb again: it loads the same policy and runs.
    mock = Mock("chat_completions")
    menv = {"NAEB_PROVIDER": "chat_completions", "NAEB_API_KEY": mock.key, "NAEB_BASE_URL": mock.url}
    r = naeb(a, "ask", "--json", "delegate", extra=menv)
    tool = [c["content"] for _, _, req in mock.requests for c in req.get("messages", []) if c.get("role") == "tool"]
    mock.close()
    check("sub-agent", r.returncode == 0 and any("child answer" in x for x in tool), "exit %d tool %r err %r" % (r.returncode, tool[:1], r.stderr[-300:]))

    print("%d failure(s)" % fails)
    return fails


if __name__ == "__main__":
    sys.exit(main())
