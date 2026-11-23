#!/usr/bin/env python3
"""The effective policy, visible (docs/naeb/adr/0001): tools.fence() returns
the fence in force as data, the same in a sub-agent, with the naeb.ae and
policy library it came from and their SHA-256s; the unfenced build has no tools.fence.

Local only: a fixture HOME of fake files, a fixture project whose naeb.ae
(allowing a host under `.invalid`) is built by `naeb build -y` against this
checkout (NAEB_SRC), the mock provider of tests/ for `ask`.

    NAEB=target/build/bin/naeb python3 -I ae/tests/redteam/fence_view.py

Prints `ok   <case>` or `FAIL <case> ...`; the exit status is the number of
failures (100 on a broken fixture).
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

POLICY = """import naeb.policy

fence(p: ptr) {
    policy.allow_host(p, "repo.example.invalid", 443)
    policy.allow_read(p, "~/.m2/repository")
    policy.allow_write(p, "~/.m2/repository")
    policy.deny_write(p, "generated")
    policy.pass_env(p, "FIXTURE_TOKENLESS")
    policy.set_env(p, "BUNDLE_USER_HOME", "${policy.project_root(p)}/.bundle/user")
}
"""

# The parent and its sub-agent (no tools.agent of its own) each print the fence.
AGENT_CODE = ("if (tools.agent) { await tools.agent({prompt: 'sub probe'}); }"
              " console.log('FENCE ' + JSON.stringify(await tools.fence()));")


def sha(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def main():
    scratch = os.path.join(ROOT, "target", "redteam")
    os.makedirs(scratch, exist_ok=True)
    work = tempfile.mkdtemp(prefix="fenceview-", dir=scratch)
    atexit.register(shutil.rmtree, work, True)
    home = os.path.realpath(os.path.join(work, "home"))
    proj = os.path.join(home, "work", "proj")
    naeb_home = os.path.join(home, ".naeb")
    os.makedirs(os.path.join(proj, ".git"))
    os.makedirs(os.path.join(proj, "generated"))
    os.makedirs(os.path.join(home, ".m2", "repository"))
    os.makedirs(os.path.join(home, ".ssh"))
    os.makedirs(naeb_home)
    with open(os.path.join(proj, "naeb.ae"), "w") as f:
        f.write(POLICY)
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": home,
        "NAEB_HOME": naeb_home,
        "NAEB_SRC": ROOT,
        "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
        "LANG": "C.UTF-8",
    }
    b = subprocess.run([NAEB, "build", "-y"], cwd=proj, env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=600)
    if b.returncode != 0:
        print("fixture broken: naeb build exited %d: %s %s" % (b.returncode, b.stdout[-800:], b.stderr[-800:]))
        return 100
    fails = 0

    def check(name, held, why):
        nonlocal fails
        if held:
            print("ok   %s" % name)
        else:
            fails += 1
            print("FAIL %s %s" % (name, why))

    p = subprocess.run([NAEB, "js", "JSON.stringify(await tools.fence())"], cwd=proj, env=env, capture_output=True, text=True, timeout=120)
    try:
        f = json.loads(json.loads(p.stdout.strip().splitlines()[-1]))
    except Exception:
        print("fixture broken: naeb js exited %d: %s %s" % (p.returncode, p.stdout[-800:], p.stderr[-800:]))
        return 100
    launchers = os.path.join(home, ".naeb", "launchers")
    key = os.listdir(launchers)[0]
    lib = [os.path.join(launchers, key, n) for n in os.listdir(os.path.join(launchers, key)) if n.startswith("policy.") and n != "policy.built"][0]
    pol = f.get("policy") or {}
    check("policy-origin", pol.get("file") == os.path.join(proj, "naeb.ae") and pol.get("sha256") == sha(os.path.join(proj, "naeb.ae"))
          and pol.get("library") == lib and pol.get("library_sha256") == sha(lib), "policy was %r (library %s)" % (pol, lib))
    check("hosts", f.get("hosts") == ["repo.example.invalid:443"], "hosts were %r" % f.get("hosts"))
    m2 = os.path.join(home, ".m2", "repository")
    check("reads-writes", m2 in f.get("reads", []) and m2 in f.get("writes", []) and proj in f.get("writes", []),
          "reads %r writes %r" % (f.get("reads"), f.get("writes")))
    check("read-denied", home in f.get("read_denied", []) and os.path.join(home, ".ssh") in f.get("read_denied", []) and f.get("home_open") is False,
          "read_denied %r" % f.get("read_denied"))
    check("read-only", os.path.join(proj, "naeb.ae") in f.get("read_only", []) and os.path.join(proj, "generated") in f.get("read_only", [])
          and os.path.join(proj, ".git", "hooks") in f.get("read_only", []), "read_only %r" % f.get("read_only"))
    check("env", "FIXTURE_TOKENLESS" in f.get("env_passed", []) and "PATH" in f.get("env_passed", [])
          and f.get("env_set") == ["BUNDLE_USER_HOME=%s/.bundle/user" % proj], "env %r %r" % (f.get("env_passed"), f.get("env_set")))
    check("loopback", f.get("loopback") is False and f.get("project") == proj, "loopback %r project %r" % (f.get("loopback"), f.get("project")))

    # The default fence (no naeb.ae) says so.
    other = os.path.join(home, "work", "other")
    os.makedirs(os.path.join(other, ".git"))
    p = subprocess.run([NAEB, "js", "JSON.stringify(await tools.fence())"], cwd=other, env=env, capture_output=True, text=True, timeout=120)
    d = json.loads(json.loads(p.stdout.strip().splitlines()[-1])) if p.returncode == 0 else {}
    check("default-fence", d.get("policy", "missing") is None and d.get("hosts") == [], "the default fence was %r" % d)

    # unfenced: no fence, no tools.fence.
    p = subprocess.run([NAEB, "--mode", "unfenced", "js", "typeof tools.fence"], cwd=proj, env=env, capture_output=True, text=True, timeout=120)
    check("naeb-has-none", p.stdout.strip().endswith('"undefined"'), "the unfenced build said %r" % p.stdout[-200:])

    # A sub-agent sees the same fence as its parent.
    mock = Mock("chat_completions", code=AGENT_CODE)
    menv = dict(env, NAEB_PROVIDER="chat_completions", NAEB_API_KEY=mock.key, NAEB_BASE_URL=mock.url)
    a = subprocess.run([NAEB, "ask", "--json", "probe"], cwd=proj, env=menv, capture_output=True, text=True, timeout=300)
    tool = [c["content"] for _, _, req in mock.requests for c in req.get("messages", []) if c.get("role") == "tool"]
    mock.close()
    seen = []
    for text in tool:
        for line in text.splitlines():
            if line.startswith("FENCE "):
                seen.append(json.loads(line[6:]))
    check("sub-agent-same", len(seen) == 2 and seen[0] == seen[1] == f, "saw %d fences (exit %d, %s)" % (len(seen), a.returncode, a.stderr[-300:]))
    shutil.rmtree(work, ignore_errors=True)
    print("%d failure(s)" % fails)
    return fails


if __name__ == "__main__":
    sys.exit(main())
