#!/usr/bin/env python3
"""A fenced child's file refusals are named (docs/naeb/adr/0001, "Denials
reaching the model"): a bash command, a hook and an MCP stdio server list
under `fence_denied` the paths the OS refused them because of the fence, and
nothing for an ordinary permission failure or another command's refusal.

Local only: a fixture HOME of fake files (a fake key, never the real
~/.ssh), a fixture project with no naeb.ae (the default fence), the mock
provider of tests/ for `ask`. No real home, secret, host or provider.

    NAEB=target/build/bin/naeb python3 -I ae/tests/redteam/named_denials.py

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

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.join(ROOT, "tests"))
from mock_providers import Mock  # noqa: E402

NAEB = os.environ.get("NAEB", os.path.join(ROOT, "target/build/bin/naeb"))

SCRIPT = r'''
const out = {};
const show = (p) => p.then(r => JSON.stringify(r), e => 'ERR: ' + e.message);
out.read = await show(tools.bash({command: 'cat ~/.ssh/id_fake; echo done', timeout_ms: 30000}));
out.write = await show(tools.bash({command: 'echo x > ~/planted; mkdir ~/planted-dir; echo done', timeout_ms: 30000}));
out.hook = await show(tools.bash({command: 'echo x >> .git/hooks/pre-commit; echo done', timeout_ms: 30000}));
out.ordinary = await show(tools.bash({command: 'cat locked.txt; echo done', timeout_ms: 30000}));
out.clean = await show(tools.bash({command: 'echo clean', timeout_ms: 30000}));
out.curl = await show(tools.bash({command: 'curl -sS -m 5 -o /dev/null https://curl-denied.invalid/ 2>/dev/null; echo done', timeout_ms: 30000}));
const [a, b] = await Promise.all([
  show(tools.bash({command: 'sleep 1; cat ~/.ssh/id_fake; sleep 1; echo a', timeout_ms: 30000})),
  show(tools.bash({command: 'sleep 0.5; echo b; sleep 2', timeout_ms: 30000})),
]);
out.concurrent_a = a;
out.concurrent_b = b;
JSON.stringify(out)
'''

MCP_SERVER = r'''
import json, os, sys
for line in sys.stdin:
    r = json.loads(line)
    i = r.get("id")
    if i is None:
        continue
    m = r.get("method")
    res = {"resultType": "complete"}
    if m == "server/discover":
        res.update(supportedVersions=["2026-07-28"], capabilities={"tools": {}}, serverInfo={"name": "nd", "version": "1"})
    elif m == "tools/list":
        res.update(tools=[{"name": "peek", "description": "read the fake key", "inputSchema": {"type": "object"}}])
    elif m == "tools/call":
        try:
            open(os.path.expanduser("~/.ssh/id_fake")).read()
            text = "read it"
        except OSError as e:
            text = "refused: %s" % e.strerror
        res.update(content=[{"type": "text", "text": text}])
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": i, "result": res}) + "\n")
    sys.stdout.flush()
'''

MCP_CODE = """console.log(JSON.stringify(await tools.mcp("nd.peek", {})));
console.log(JSON.stringify(await tools.mcp("nd.peek", {})));"""

HOOK_CODE = """await tools.write({path: "touched.txt", content: "x\\n"}); console.log("wrote");"""


def entries(r):
    """What a result names under fence_denied, as "op resource" strings."""
    if not isinstance(r, dict):
        return None
    out = []
    for e in r.get("fence_denied", []):
        out.append(e if isinstance(e, str) else "%s %s" % (e.get("op"), e.get("resource")))
    return out


def parsed(text):
    if not text or text.startswith("ERR: "):
        return None
    return json.loads(text)


def main():
    scratch = os.path.join(ROOT, "target", "redteam")
    os.makedirs(scratch, exist_ok=True)
    work = tempfile.mkdtemp(prefix="named-", dir=scratch)
    atexit.register(shutil.rmtree, work, True)
    home = os.path.realpath(os.path.join(work, "home"))
    proj = os.path.join(home, "work", "proj")
    nib_home = os.path.join(home, ".nib")
    os.makedirs(os.path.join(proj, ".git", "hooks"))
    os.makedirs(os.path.join(home, ".ssh"))
    os.makedirs(nib_home)
    with open(os.path.join(proj, ".git", "HEAD"), "w") as f:
        f.write("ref: refs/heads/main\n")
    key = os.path.join(home, ".ssh", "id_fake")
    with open(key, "w") as f:
        f.write("FAKE-KEY-NOT-A-SECRET\n")
    locked = os.path.join(proj, "locked.txt")
    with open(locked, "w") as f:
        f.write("ordinary\n")
    os.chmod(locked, 0)
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
        return 100
    fails = 0

    def check(name, held, why):
        nonlocal fails
        if held:
            print("ok   %s" % name)
        else:
            fails += 1
            print("FAIL %s %s" % (name, why))

    def got(k):
        return entries(parsed(results.get(k, "")))

    read = got("read")
    check("child-read-named", read is not None and "read %s" % key in read, "the command was told %r" % results.get("read", "")[:400])
    write = got("write")
    check("child-write-named", write is not None and "write %s" % os.path.join(home, "planted") in write and "write %s" % os.path.join(home, "planted-dir") in write,
          "the command was told %r" % results.get("write", "")[:400])
    hookw = got("hook")
    check("child-read-only-named", hookw is not None and "write %s" % os.path.realpath(os.path.join(proj, ".git", "hooks", "pre-commit")) in hookw,
          "the command was told %r" % results.get("hook", "")[:400])
    ordinary = parsed(results.get("ordinary", ""))
    check("ordinary-permission-not-named", ordinary is not None and "ermission denied" in ordinary.get("output", "") and "fence_denied" not in ordinary,
          "an ordinary EACCES was told %r" % results.get("ordinary", "")[:400])
    clean = parsed(results.get("clean", ""))
    check("clean-unchanged", clean == {"exit_code": 0, "output": "clean\n"}, "a clean command got %r" % results.get("clean", "")[:300])
    # CoreFoundation's text-encoding preference (~/.CFUserTextEncoding, of
    # the account's home) is not a secret; a fenced curl must not report it.
    curl = got("curl")
    check("cf-text-encoding-not-named", curl is not None and not [e for e in curl if e.endswith("/.CFUserTextEncoding")],
          "a fenced curl reported reads %r" % results.get("curl", "")[:400])
    ca = got("concurrent_a")
    cb = parsed(results.get("concurrent_b", ""))
    check("concurrent-own-refusal", ca is not None and "read %s" % key in ca, "a got %r" % results.get("concurrent_a", "")[:300])
    check("concurrent-not-other", cb is not None and "fence_denied" not in cb, "b got %r" % results.get("concurrent_b", "")[:300])

    # A failing after_edit hook names what it was refused in its payload.
    with open(os.path.join(nib_home, "config.toml"), "w") as f:
        f.write('[hooks]\nafter_edit = ["cat ~/.ssh/id_fake"]\n')
    mock = Mock("chat_completions", code=HOOK_CODE)
    menv = dict(env, NIB_PROVIDER="chat_completions", NIB_API_KEY=mock.key, NIB_BASE_URL=mock.url)
    m = subprocess.run([NAEB, "ask", "--json", "probe"], cwd=proj, env=menv, capture_output=True, text=True, timeout=120)
    tool = [c["content"] for _, _, req in mock.requests for c in req.get("messages", []) if c.get("role") == "tool"]
    mock.close()
    payload = None
    for t in tool:
        for line in t.splitlines():
            at = line.find('{"hook"')
            if at >= 0:
                payload = json.loads(line[at:])["hook"]
    check("hook-named", payload is not None and "read %s" % key in (entries(payload) or []),
          "the hook payload was %r (tool output %r, exit %d, %s)" % (payload, tool[:1], m.returncode, m.stderr[-300:]))

    # An MCP stdio server: each call names what the server was refused since the last.
    server = os.path.join(proj, "nd_mcp.py")
    with open(server, "w") as f:
        f.write(MCP_SERVER)
    with open(os.path.join(nib_home, "config.toml"), "w") as f:
        f.write('[mcp]\nnd = true\n\n[mcp.nd]\ncommand = "python3"\nargs = ["-I", %s]\n' % json.dumps(server))
    mock = Mock("chat_completions", code=MCP_CODE)
    menv = dict(env, NIB_PROVIDER="chat_completions", NIB_API_KEY=mock.key, NIB_BASE_URL=mock.url)
    m = subprocess.run([NAEB, "ask", "--json", "probe"], cwd=proj, env=menv, capture_output=True, text=True, timeout=120)
    tool = [c["content"] for _, _, req in mock.requests for c in req.get("messages", []) if c.get("role") == "tool"]
    mock.close()
    lines = tool[0].splitlines() if tool else []
    first = json.loads(lines[0]) if len(lines) > 1 else {}
    check("mcp-named", "refused" in first.get("content", "") and "read %s" % key in (entries(first) or []),
          "the MCP call returned %r (exit %d, %s)" % (lines[:2], m.returncode, m.stderr[-300:]))
    shutil.rmtree(work, ignore_errors=True)
    print("%d failure(s)" % fails)
    return fails


if __name__ == "__main__":
    sys.exit(main())
