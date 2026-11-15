#!/usr/bin/env python3
"""A fence refusal is reported with the command that caused it (docs/naeb/adr/0001).

Drives naeb (NAEB) with `js`, and with `ask` against the
local mock provider of tests/ for an MCP stdio server, in a fixture HOME of
absolute fake paths, against hosts under `.invalid`: the proxy refuses them before
resolving anything, so nothing leaves the machine and no real home or secret
is touched. The fixture project has no naeb.ae, so naeb runs it inside the
default fence (no egress at all).

    NAEB=target/build/bin/naeb python3 -I ae/tests/redteam/attribution.py

Prints `ok   <case>` or `FAIL <case> ...`; the exit status is the number of
failures (100 on a broken fixture).
"""
import atexit
import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))), "tests"))
from mock_providers import Mock  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
NAEB = os.environ.get("NAEB", os.path.join(ROOT, "target/build/bin/naeb"))

SCRIPT = r'''
const out = {};
const show = (p) => p.then(r => JSON.stringify(r), e => 'ERR: ' + e.message);
const curl = (host) => 'curl -sS -m 5 -o /dev/null https://' + host + '/ 2>/dev/null; true';
// (a) a refused fetch, then a bash that makes no request
out.fetch = await show(tools.fetch({url: 'https://fetch-denied.invalid/intro.html', timeout_ms: 10000}));
out.after_fetch = await show(tools.bash({command: 'echo quiet', timeout_ms: 30000}));
// (b) two commands at once, each refused a different host; a's refusal lands while b runs
const [a, b] = await Promise.all([
  show(tools.bash({command: curl('a-denied.invalid') + '; sleep 3; echo a', timeout_ms: 30000})),
  show(tools.bash({command: 'sleep 1.5; ' + curl('b-denied.invalid') + '; echo b', timeout_ms: 30000})),
]);
out.concurrent_a = a;
out.concurrent_b = b;
// (c) a background command refused while a foreground one runs
out.background = await show(tools.bash({command: curl('bg-denied.invalid') + '; sleep 3; echo bg', background: true, timeout_ms: 30000}));
out.foreground = await show(tools.bash({command: 'sleep 2; echo fg', timeout_ms: 30000}));
JSON.stringify(out)
'''

# (d) an MCP stdio server refused a host; a later bash must not list it.
MCP_SERVER = r'''
import json, os, subprocess, sys
for line in sys.stdin:
    r = json.loads(line)
    i = r.get("id")
    if i is None:
        continue
    m = r.get("method")
    res = {"resultType": "complete"}
    if m == "server/discover":
        res.update(supportedVersions=["2026-07-28"], capabilities={"tools": {}}, serverInfo={"name": "attr", "version": "1"})
    elif m == "tools/list":
        res.update(tools=[{"name": "net", "description": "curl a refused host", "inputSchema": {"type": "object"}}])
    elif m == "tools/call":
        subprocess.run(["curl", "-sS", "-m", "5", "-o", "/dev/null", "https://mcp-denied.invalid/"], capture_output=True)
        res.update(content=[{"type": "text", "text": "tried"}])
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": i, "result": res}) + "\n")
    sys.stdout.flush()
'''

MCP_CODE = """console.log(JSON.stringify(await tools.mcp("attr.net", {})));
console.log(JSON.stringify(await tools.bash({command: 'echo after-mcp'})));"""


def denied_of(r):
    if r.startswith("ERR: "):
        return None
    return json.loads(r).get("fence_denied", [])


def main():
    scratch = os.path.join(ROOT, "target", "redteam")
    os.makedirs(scratch, exist_ok=True)
    work = tempfile.mkdtemp(prefix="attr-", dir=scratch)
    atexit.register(shutil.rmtree, work, True)
    home = os.path.realpath(os.path.join(work, "home"))
    proj = os.path.join(home, "work", "proj")
    nib_home = os.path.join(home, ".nib")
    os.makedirs(os.path.join(proj, ".git"))
    os.makedirs(nib_home)
    with open(os.path.join(proj, ".git", "HEAD"), "w") as f:
        f.write("ref: refs/heads/main\n")
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": home,
        "NIB_HOME": nib_home,
        "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
        "LANG": "C.UTF-8",
    }
    p = subprocess.run([NAEB, "js", SCRIPT], cwd=proj, env=env, capture_output=True, text=True, timeout=300)
    try:
        results = json.loads(p.stdout.strip().splitlines()[-1])
        if isinstance(results, str):
            results = json.loads(results)
    except Exception:
        print("fixture broken: naeb exited %d\nstdout: %s\nstderr: %s" % (p.returncode, p.stdout[-2000:], p.stderr[-2000:]))
        shutil.rmtree(work, ignore_errors=True)
        return 100
    fails = 0

    def check(name, held, why):
        nonlocal fails
        if held:
            print("ok   %s" % name)
        else:
            fails += 1
            print("FAIL %s %s" % (name, why))
        if os.environ.get("VERBOSE"):
            print("     %s" % json.dumps({k: v[:300] for k, v in results.items()}, indent=1))

    f = results.get("fetch", "")
    check("fetch-named", f.endswith("denied by the project fence: egress fetch-denied.invalid:443"), "fetch said %r" % f[:300])
    check("fetch-not-in-bash", denied_of(results.get("after_fetch", "")) == [], "the next bash got %r" % results.get("after_fetch", "")[:300])
    da = denied_of(results.get("concurrent_a", ""))
    db = denied_of(results.get("concurrent_b", ""))
    check("concurrent-a", da == ["egress a-denied.invalid:443"], "a got %r" % results.get("concurrent_a", "")[:300])
    check("concurrent-b", db == ["egress b-denied.invalid:443"], "b got %r" % results.get("concurrent_b", "")[:300])
    check("background-not-in-foreground", denied_of(results.get("foreground", "")) == [], "the foreground bash got %r (background: %r)" % (results.get("foreground", "")[:300], results.get("background", "")[:200]))

    server = os.path.join(proj, "attr_mcp.py")
    with open(server, "w") as f:
        f.write(MCP_SERVER)
    with open(os.path.join(nib_home, "config.toml"), "w") as f:
        f.write('[mcp]\nattr = true\n\n[mcp.attr]\ncommand = "python3"\nargs = ["-I", %s]\n' % json.dumps(server))
    mock = Mock("chat_completions", code=MCP_CODE)
    menv = dict(env, NIB_PROVIDER="chat_completions", NIB_API_KEY=mock.key, NIB_BASE_URL=mock.url)
    m = subprocess.run([NAEB, "ask", "--json", "probe"], cwd=proj, env=menv, capture_output=True, text=True, timeout=120)
    tool = [c["content"] for _, _, req in mock.requests for c in req.get("messages", []) if c.get("role") == "tool"]
    mock.close()
    lines = tool[0].splitlines() if tool else []
    mres = json.loads(lines[0]) if len(lines) > 1 else {}
    after = json.loads(lines[1]) if len(lines) > 1 else {}
    check("mcp-ran", mres.get("ok") is True and after.get("output") == "after-mcp\n", "the run said %r (exit %d, %s)" % (tool[:1], m.returncode, m.stderr[-300:]))
    check("mcp-not-in-bash", after.get("output") == "after-mcp\n" and "fence_denied" not in after, "the bash after the MCP call got %r" % after)
    shutil.rmtree(work, ignore_errors=True)
    print("%d failure(s)" % fails)
    return fails


if __name__ == "__main__":
    sys.exit(main())
