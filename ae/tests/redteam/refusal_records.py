#!/usr/bin/env python3
"""One refusal record everywhere (docs/naeb/adr/0001, "Denials reaching the
model"): in-process tools, bash, hooks, MCP stdio servers and sub-agents all
report a fence refusal as {op, resource, layer, command_id?, reason?, suggestion?,
note?}, the suggestion a naeb.ae line as text, the note why there is none (a
secret is never offered); without a fence (unfenced) the shapes are upstream's.

Local only: a fixture HOME of fake files, a fixture project with no naeb.ae
(the default fence), hosts under `.invalid` (the proxy refuses them before
resolving anything), the mock provider of tests/ for `ask`.

    NAEB=target/build/bin/naeb python3 -I ae/tests/redteam/refusal_records.py

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
UNFENCED = os.environ.get("NAEB_UNFENCED", os.path.join(os.path.dirname(NAEB), "naeb-unfenced"))
SECRET_NOTE = "not offered: naeb keeps ~/.ssh closed; open it only by editing naeb.ae yourself"

SCRIPT = r'''
const out = {};
const show = (p) => p.then(r => JSON.stringify(r), e => JSON.stringify({error: e.message, fence_denied: e.fence_denied}));
out.read = await show(tools.bash({command: 'cat ~/.ssh/id_fake; echo x > ~/planted; echo x >> .git/hooks/pre-commit; true', timeout_ms: 30000}));
out.egress = await show(tools.bash({command: 'curl -sS -m 5 -o /dev/null https://bash-denied.invalid/ 2>/dev/null; true', timeout_ms: 30000}));
out.tool_read = await show(tools.read({path: '~/.ssh/id_fake'.replace('~', HOME)}));
out.tool_fetch = await show(tools.fetch({url: 'https://fetch-denied.invalid/', timeout_ms: 10000}));
out.tool_other = await show(tools.read({path: 'missing.txt'}));
out.tool_write = await show(tools.write({path: '.git/hooks/post-commit', content: 'x'}));
out.clean = await show(tools.bash({command: 'echo clean'}));
JSON.stringify(out)
'''

# The parent delegates; the sub-agent (no tools.agent of its own) runs bash.
AGENT_CODE = ("if (tools.agent) console.log(JSON.stringify(await tools.agent({prompt: 'sub probe'})));"
              " else console.log(JSON.stringify(await tools.bash({command: 'cat ~/.ssh/id_fake; true'})));")

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
        res.update(supportedVersions=["2026-07-28"], capabilities={"tools": {}}, serverInfo={"name": "rr", "version": "1"})
    elif m == "tools/list":
        res.update(tools=[{"name": "peek", "description": "read the fake key", "inputSchema": {"type": "object"}}])
    elif m == "tools/call":
        try:
            open(os.path.expanduser("~/.ssh/id_fake")).read()
        except OSError:
            pass
        res.update(content=[{"type": "text", "text": "tried"}])
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": i, "result": res}) + "\n")
    sys.stdout.flush()
'''


def main():
    scratch = os.path.join(ROOT, "target", "redteam")
    os.makedirs(scratch, exist_ok=True)
    work = tempfile.mkdtemp(prefix="records-", dir=scratch)
    atexit.register(shutil.rmtree, work, True)
    home = os.path.realpath(os.path.join(work, "home"))
    proj = os.path.join(home, "work", "proj")
    naeb_home = os.path.join(home, ".naeb")
    os.makedirs(os.path.join(proj, ".git", "hooks"))
    os.makedirs(os.path.join(home, ".ssh"))
    os.makedirs(naeb_home)
    with open(os.path.join(proj, ".git", "HEAD"), "w") as f:
        f.write("ref: refs/heads/main\n")
    key = os.path.join(home, ".ssh", "id_fake")
    with open(key, "w") as f:
        f.write("FAKE-KEY-NOT-A-SECRET\n")
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": home,
        "NAEB_HOME": naeb_home,
        "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
        "LANG": "C.UTF-8",
    }
    script = "const HOME = %s;\n%s" % (json.dumps(home), SCRIPT)

    def js(binary):
        p = subprocess.run([binary, "js", script], cwd=proj, env=env, capture_output=True, text=True, timeout=300)
        try:
            r = json.loads(p.stdout.strip().splitlines()[-1])
            return json.loads(r) if isinstance(r, str) else r
        except Exception:
            print("fixture broken: %s exited %d\nstdout: %s\nstderr: %s" % (binary, p.returncode, p.stdout[-2000:], p.stderr[-2000:]))
            return None

    results = js(NAEB)
    if results is None:
        return 100
    fails = 0

    def check(name, held, why):
        nonlocal fails
        if held:
            print("ok   %s" % name)
        else:
            fails += 1
            print("FAIL %s %s" % (name, why))

    def get(k):
        try:
            return json.loads(results.get(k, ""))
        except Exception:
            return {}

    def find(recs, op, resource):
        for r in recs or []:
            if isinstance(r, dict) and r.get("op") == op and r.get("resource") == resource:
                return r
        return None

    planted = os.path.join(home, "planted")
    hook = os.path.realpath(os.path.join(proj, ".git", "hooks", "pre-commit"))
    r = get("read")
    rec = find(r.get("fence_denied"), "read", key)
    check("bash-read-record", rec == {"op": "read", "resource": key, "layer": "child", "command_id": rec and rec.get("command_id"),
                                      "note": SECRET_NOTE} and str(rec.get("command_id", "")).startswith("b"),
          "the record was %r" % r.get("fence_denied"))
    rec = find(r.get("fence_denied"), "write", planted)
    check("bash-write-record", rec is not None and rec.get("suggestion") == 'policy.allow_write(p, "~/planted")', "the records were %r" % r.get("fence_denied"))
    rec = find(r.get("fence_denied"), "write", hook)
    check("bash-read-only-no-suggestion", rec is not None and "suggestion" not in rec, "the records were %r" % r.get("fence_denied"))
    e = get("egress")
    rec = find(e.get("fence_denied"), "egress", "bash-denied.invalid:443")
    check("bash-egress-record", rec is not None and rec.get("layer") == "child" and rec.get("suggestion") == 'policy.allow_host(p, "bash-denied.invalid", 443)',
          "the records were %r" % e.get("fence_denied"))
    t = get("tool_read")
    check("tool-read-record", t.get("error") == "read: denied by the project fence: read %s" % key and
          t.get("fence_denied") == [{"op": "read", "resource": key, "layer": "tool", "note": SECRET_NOTE}],
          "the error was %r" % t)
    t = get("tool_fetch")
    check("tool-fetch-record", t.get("error") == "fetch: denied by the project fence: egress fetch-denied.invalid:443" and
          t.get("fence_denied") == [{"op": "egress", "resource": "fetch-denied.invalid:443", "layer": "tool", "suggestion": 'policy.allow_host(p, "fetch-denied.invalid", 443)'}],
          "the error was %r" % t)
    t = get("tool_write")
    hook2 = os.path.realpath(os.path.join(proj, ".git", "hooks")) + "/post-commit"
    check("tool-write-record", t.get("error", "").endswith("denied by the project fence: write %s" % hook2) and
          t.get("fence_denied") == [{"op": "write", "resource": hook2, "layer": "tool"}], "the error was %r" % t)
    t = get("tool_other")
    check("tool-other-error-plain", t.get("error", "").startswith("read: ") and t.get("fence_denied") is None, "the error was %r" % t)

    # An uncaught refusal shows its records in the Run's error text.
    p = subprocess.run([NAEB, "js", "await tools.read({path: %s})" % json.dumps(key)], cwd=proj, env=env, capture_output=True, text=True, timeout=120)
    check("uncaught-shows-records", "fence_denied: [{" in p.stdout + p.stderr and '"layer":"tool"' in p.stdout + p.stderr,
          "the Run said %r" % (p.stdout + p.stderr)[-500:])

    # Without a fence (unfenced): upstream's shapes.
    plain = js(UNFENCED)
    pr = json.loads(plain.get("read", "{}")) if plain else {}
    pt = json.loads(plain.get("tool_other", "{}")) if plain else {}
    check("naeb-unchanged", plain is not None and "fence_denied" not in pr and set(pr) == {"exit_code", "output"} and pt.get("fence_denied") is None,
          "the unfenced build returned %r / %r" % (pr, pt))

    # A hook's payload, an MCP server's result, a sub-agent's result.
    with open(os.path.join(naeb_home, "config.toml"), "w") as f:
        f.write('[hooks]\nafter_edit = ["cat ~/.ssh/id_fake"]\n')
    mock = Mock("chat_completions", code='await tools.write({path: "touched.txt", content: "x\\n"}); console.log("wrote");')
    menv = dict(env, NAEB_PROVIDER="chat_completions", NAEB_API_KEY=mock.key, NAEB_BASE_URL=mock.url)
    subprocess.run([NAEB, "ask", "--json", "probe"], cwd=proj, env=menv, capture_output=True, text=True, timeout=120)
    tool = [c["content"] for _, _, req in mock.requests for c in req.get("messages", []) if c.get("role") == "tool"]
    system = [c["content"] for _, _, req in mock.requests for c in req.get("messages", []) if c.get("role") == "system"]
    tools_desc = json.dumps([req.get("tools") for _, _, req in mock.requests])
    mock.close()
    payload = None
    for text in tool:
        at = text.find('{"hook"')
        if at >= 0:
            payload = json.loads(text[at:].splitlines()[0])["hook"]
    rec = find((payload or {}).get("fence_denied"), "read", key)
    check("hook-record", rec is not None and rec.get("command_id") == "hook:after_edit" and rec.get("layer") == "child", "the payload was %r" % payload)
    docs = "".join(system) + tools_desc
    check("docs-name-the-field", "fence_denied: [{ op, resource, layer, command_id?, reason?, suggestion?, note? }]" in docs, "the model was not told about fence_denied")

    server = os.path.join(proj, "rr_mcp.py")
    with open(server, "w") as f:
        f.write(MCP_SERVER)
    with open(os.path.join(naeb_home, "config.toml"), "w") as f:
        f.write('[mcp]\nrr = true\n\n[mcp.rr]\ncommand = "python3"\nargs = ["-I", %s]\n' % json.dumps(server))
    mock = Mock("chat_completions", code='console.log(JSON.stringify(await tools.mcp("rr.peek", {})));')
    menv = dict(env, NAEB_PROVIDER="chat_completions", NAEB_API_KEY=mock.key, NAEB_BASE_URL=mock.url)
    subprocess.run([NAEB, "ask", "--json", "probe"], cwd=proj, env=menv, capture_output=True, text=True, timeout=120)
    tool = [c["content"] for _, _, req in mock.requests for c in req.get("messages", []) if c.get("role") == "tool"]
    mock.close()
    mres = {}
    for text in tool:
        for line in text.splitlines():
            if line.startswith('{"ok"'):
                mres = json.loads(line)
    rec = find(mres.get("fence_denied"), "read", key)
    check("mcp-record", rec is not None and rec.get("command_id") == "mcp:rr" and rec.get("layer") == "child", "the MCP result was %r" % mres)

    os.remove(os.path.join(naeb_home, "config.toml"))
    mock = Mock("chat_completions", code=AGENT_CODE)
    menv = dict(env, NAEB_PROVIDER="chat_completions", NAEB_API_KEY=mock.key, NAEB_BASE_URL=mock.url)
    a = subprocess.run([NAEB, "ask", "--json", "probe"], cwd=proj, env=menv, capture_output=True, text=True, timeout=300)
    tool = [c["content"] for _, _, req in mock.requests for c in req.get("messages", []) if c.get("role") == "tool"]
    mock.close()
    ares = None
    for text in tool:
        for line in text.splitlines():
            if line.startswith('{"ok"') and '"changes"' in line:
                ares = json.loads(line)
    rec = find((ares or {}).get("fence_denied"), "read", key)
    check("sub-agent-record", rec is not None and rec.get("layer") == "child" and rec.get("note") == SECRET_NOTE and "suggestion" not in rec,
          "the agent result was %r (exit %d, %s)" % (ares, a.returncode, a.stderr[-300:]))
    shutil.rmtree(work, ignore_errors=True)
    print("%d failure(s)" % fails)
    return fails


if __name__ == "__main__":
    sys.exit(main())
