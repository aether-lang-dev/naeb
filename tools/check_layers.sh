#!/bin/sh
# tools/check_layers.sh — the reach of each module of the Aether port is its
# import list (sae's tests/check_layers.sh is the model). This pins the
# imports of every module (ae/naeb_main.ae and each ae/naeb module; an unpinned one
# fails), so widening one is a reviewed change here, and checks the rules a
# single import list cannot: who may start a process, who may embed QuickJS,
# who may use the marked stand-in, who reaches the network, and that the
# sandbox's host functions keep their `hide` veto line. Who may start a
# program is the compiler's (`import std.os hiding (...)`); this checks the
# hiding lists. The TUI's two exceptions (tui/open's launch,
# auth/models' GET) are each named with what they may do and why.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
fail=0

PINNED=""
expect_imports() {   # expect_imports FILE "a|b|..."
    PINNED="$PINNED $1"
    got=$(grep -E '^import ' "$1" | sed -e 's/^import //' -e 's/ hiding .*//' | sort | tr '\n' '|')
    want=$(printf '%s' "$2" | tr '|' '\n' | sort | tr '\n' '|')
    if [ "$got" = "$want" ]; then
        echo "ok   $1"
    else
        echo "FAIL $1 imports changed:"
        echo "       expected: $want"
        echo "       found:    $got"
        fail=1
    fi
}

T=ae/naeb/tools
expect_imports ae/naeb/jsonx/module.ae "std.json|std.strbuilder|std.string"
expect_imports ae/naeb/lock/module.ae "std.sync"
expect_imports ae/naeb/fserr/module.ae "std.fs"
expect_imports ae/naeb/sysenv/module.ae "std.list|std.os|std.string"
expect_imports ae/naeb/sandbox/module.ae "contrib.quickjs|naeb.jsonx|naeb.sandbox.console|naeb.sandbox.record|naeb.sandbox.timing|std.intarr|std.list|std.os|std.strbuilder|std.string|std.sync|std.worker"
# The calls sidecar (record) writes one file under its own flock; replay runs the sandbox with no tools.
expect_imports ae/naeb/sandbox/record/module.ae "naeb.jsonx|naeb.lock|std.cryptography|std.fs|std.io|std.list|std.map|std.os|std.strbuilder|std.string"
expect_imports ae/naeb/sandbox/replay/module.ae "naeb.jsonx|naeb.sandbox|std.intarr|std.json|std.list|std.string|std.sync"
expect_imports ae/naeb/sandbox/console/module.ae "std.list|std.strbuilder|std.string"
expect_imports ae/naeb/sandbox/timing/module.ae "naeb.jsonx|std.list|std.os|std.string"
# Pure logic: no file system, process or network.
expect_imports $T/policy/module.ae "std.list|std.strbuilder|std.string"
expect_imports $T/secrets/module.ae "std.list|std.string"
expect_imports $T/diff/module.ae "std.list|std.string"
expect_imports $T/html/module.ae "std.strbuilder|std.string"
expect_imports $T/changes/module.ae "naeb.tools.diff|std.list|std.strbuilder|std.string"
expect_imports $T/registry/module.ae "naeb.jsonx|naeb.lock|std.list|std.os|std.string|std.sync"
expect_imports $T/progress/module.ae "naeb.jsonx|naeb.lock|std.list|std.os|std.string"
expect_imports $T/background/module.ae "naeb.jsonx|naeb.lock|std.list|std.string|std.sync|std.worker"
# File system, no process.
expect_imports $T/atomic_file/module.ae "naeb.fserr|std.cryptography|std.fs|std.io|std.list|std.os|std.string"
expect_imports $T/file_state/module.ae "naeb.fserr|naeb.lock|std.cryptography|std.fs|std.io|std.list|std.map|std.string|std.sync"
expect_imports $T/files/module.ae "naeb.fserr|naeb.jsonx|naeb.tools.atomic_file|naeb.tools.file_state|naeb.tools.rules|naeb.tools.undo|std.fs|std.io|std.list|std.strbuilder|std.string|std.sync"
expect_imports $T/undo/module.ae "naeb.fserr|naeb.jsonx|naeb.tools.atomic_file|naeb.tools.file_state|naeb.tools.registry|std.cryptography|std.dir|std.fs|std.list|std.string|std.strbuilder|std.sync"
expect_imports $T/walk/module.ae "naeb.tools.atomic_file|naeb.tools.rules|std.dir|std.fs|std.list|std.strbuilder|std.string|std.sync"
expect_imports $T/grep/module.ae "contrib.quickjs|naeb.tools.atomic_file|naeb.tools.rules|naeb.tools.walk|std.fs|std.list|std.strbuilder|std.string|std.sync"
expect_imports $T/search/module.ae "naeb.jsonx|naeb.tools.grep|naeb.tools.walk|std.json|std.list|std.strbuilder|std.string"
# Processes.
expect_imports $T/process/module.ae "naeb.sysenv|std.cryptography|std.fs|std.io|std.ipc|std.list|std.os|std.string|std.sync|std.worker"
expect_imports $T/bash/module.ae "naeb.fence|naeb.jsonx|naeb.tools.denials|naeb.tools.egress|naeb.tools.jail|naeb.tools.policy|naeb.tools.process|naeb.tools.progress|naeb.tools.registry|naeb.tools.secrets|std.list|std.os|std.string|std.sync"
# Images: file system only (store, read, hash, base64), no network or process.
expect_imports ae/naeb/image/module.ae "naeb.fserr|naeb.jsonx|naeb.lock|naeb.tools.atomic_file|std.bytes|std.cryptography|std.encoding|std.fs|std.list|std.strbuilder|std.string"
expect_imports $T/view/module.ae "naeb.image|naeb.jsonx|naeb.tools.atomic_file|naeb.tools.rules|std.list|std.string"
expect_imports $T/jail/module.ae "naeb.tools.atomic_file|naeb.tools.rules|std.dir|std.fs|std.list|std.os|std.string"
# The project fence (docs/naeb/adr/0001): its read rules are pure logic; the
# Fence resolves paths (file system) into a jail.Spec; the egress proxy is
# the fenced children's and tools.fetch's only way out.
expect_imports $T/rules/module.ae "std.list|std.string"
expect_imports ae/naeb/fence/module.ae "naeb.fence.proposal|naeb.jsonx|naeb.maven.wrapper|naeb.tools.atomic_file|naeb.tools.jail|naeb.tools.rules|std.fs|std.list|std.string"
# naeb.ae: built by `naeb build` (diff, then `ae build --emit=lib` through
# tools/process), checked against its record and dlopened at start (policy_host.c).
# The naeb.ae lines the TUI offers after refusals, where they go, the diff: pure text.
expect_imports ae/naeb/fence/proposal/module.ae "std.list|std.string"
expect_imports ae/naeb/fence/policy/module.ae "naeb.build_info|naeb.fence|naeb.fence.proposal|naeb.jsonx|naeb.tools.atomic_file|naeb.tools.jail|naeb.tools.process|std.cryptography|std.fs|std.io|std.list|std.os|std.string"
# A fenced child's refusals, named: the macOS sandbox's reports through one
# `log stream` and a sentinel (tools/process), the Linux helper's report file.
expect_imports $T/denials/module.ae "naeb.jsonx|naeb.lock|naeb.tools.egress|naeb.tools.process|std.fs|std.ipc|std.list|std.os|std.string|std.sync|std.worker"
expect_imports $T/egress/module.ae "naeb.fence|naeb.lock|std.fs|std.list|std.string|std.sync|std.tcp|std.worker"
expect_imports $T/agent_sessions/module.ae "naeb.lock|std.list|std.string"
expect_imports $T/agent_input/module.ae "naeb.jsonx|naeb.provider.types|std.json|std.list|std.strbuilder|std.string"
# A subagent is a child naeb started through tools/process.
expect_imports $T/agent/module.ae "naeb.jsonx|naeb.lock|naeb.provider.types|naeb.tools.agent_input|naeb.tools.agent_sessions|naeb.tools.process|naeb.tools.progress|naeb.tools.secrets|std.json|std.list|std.os|std.strbuilder|std.string|std.sync"
expect_imports ae/naeb/session/hooks/module.ae "naeb.jsonx|naeb.session.instructions|naeb.tools.jail|naeb.tools.process|naeb.tools.secrets|std.list|std.os|std.string|std.sync"
expect_imports ae/naeb/build_info/module.ae ""
expect_imports ae/naeb/session/fork_history/module.ae "naeb.msg|naeb.provider.types|std.list|std.string"
expect_imports $T/web/module.ae "naeb.jsonx|naeb.tools.html|std.http.client|std.json|std.string|std.sync|std.worker"
expect_imports $T/llm_call/module.ae "naeb.jsonx|naeb.lock|naeb.msg|naeb.provider|naeb.provider.sink|naeb.provider.types|std.json|std.list|std.strbuilder|std.string|std.sync"
expect_imports $T/web_search/module.ae "naeb.jsonx|naeb.lock|naeb.provider.sse|naeb.provider.types|std.http.client|std.json|std.list|std.string|std.sync|std.time|std.worker"
# naeb's Maven broker (experimental; docs/naeb/adr/0001, "The Maven broker"):
# coordinates, POMs and OpenPGP are pure logic; repo is its one GET; the
# broker writes only into ~/.m2/repository and ~/.m2/wrapper/dists (atomic_file;
# std.zip only reads the wrapper's distribution in memory) and starts no process.
expect_imports ae/naeb/maven/gav/module.ae "std.list|std.string|std.time"
expect_imports ae/naeb/maven/pom/module.ae "std.list|std.string|std.xml"
expect_imports ae/naeb/maven/pgp/module.ae "std.bytes|std.cryptography|std.cryptography.ed25519|std.cryptography.rsa|std.encoding|std.list|std.string"
expect_imports ae/naeb/maven/repo/module.ae "std.http.client|std.string"
expect_imports ae/naeb/maven/wrapper/module.ae "std.string"
expect_imports ae/naeb/maven/broker/module.ae "naeb.jsonx|naeb.lock|naeb.maven.gav|naeb.maven.pgp|naeb.maven.pom|naeb.maven.repo|naeb.maven.wrapper|naeb.tools.atomic_file|std.cryptography|std.fs|std.list|std.map|std.string|std.time|std.zip"
expect_imports $T/module.ae "std.json|naeb.fence|naeb.image|naeb.jsonx|naeb.lock|naeb.maven.broker|naeb.provider.types|naeb.sandbox|naeb.sysenv|naeb.tools.agent|naeb.tools.agent_input|naeb.tools.agent_sessions|naeb.tools.atomic_file|naeb.tools.background|naeb.tools.bash|naeb.tools.changes|naeb.tools.denials|naeb.tools.egress|naeb.tools.file_state|naeb.tools.files|naeb.tools.jail|naeb.tools.llm_call|naeb.tools.mcp_tool|naeb.tools.progress|naeb.tools.registry|naeb.tools.search|naeb.tools.undo|naeb.tools.view|naeb.tools.web|naeb.tools.web_search|std.list|std.os|std.strbuilder|std.string|std.sync"

# The Session + provider slice.
expect_imports ae/naeb/auth/module.ae "naeb.auth.store|naeb.config|naeb.config.env|naeb.provider.types|std.list|std.string"
expect_imports ae/naeb/auth/store/module.ae "naeb.jsonx|naeb.tools.atomic_file|std.fs|std.json|std.string"
expect_imports ae/naeb/config/env/module.ae "naeb.sysenv|std.list|std.string"
expect_imports ae/naeb/config/module.ae "naeb.auth.store|naeb.config.env|naeb.jsonx|naeb.provider.types|naeb.session.tuning|naeb.tools.atomic_file|std.fs|std.list|std.string"
expect_imports ae/naeb/msg/module.ae "naeb.jsonx|naeb.provider.types|std.json|std.list|std.string"
expect_imports ae/naeb/provider/anthropic/module.ae "naeb.image|naeb.jsonx|naeb.msg|naeb.provider.http|naeb.provider.sink|naeb.provider.sse|naeb.provider.types|std.json|std.list|std.strbuilder|std.string"
expect_imports ae/naeb/provider/http/module.ae "naeb.lock|naeb.provider.timing|std.http.client|std.list|std.string|std.sync|std.time|std.worker"
expect_imports ae/naeb/provider/module.ae "naeb.provider.anthropic|naeb.provider.timing|naeb.provider.openai|naeb.provider.responses|naeb.provider.sink|naeb.provider.types|std.list|std.string|std.sync"
expect_imports ae/naeb/provider/openai/module.ae "naeb.image|naeb.jsonx|naeb.msg|naeb.provider.http|naeb.provider.sink|naeb.provider.sse|naeb.provider.types|std.json|std.list|std.strbuilder|std.string"
expect_imports ae/naeb/provider/responses/module.ae "naeb.image|naeb.jsonx|naeb.msg|naeb.provider.http|naeb.provider.sink|naeb.provider.sse|naeb.provider.types|std.json|std.list|std.strbuilder|std.string"
expect_imports ae/naeb/provider/sink/module.ae "naeb.provider.http|naeb.provider.timing"
expect_imports ae/naeb/provider/timing/module.ae "naeb.jsonx|naeb.provider.types|std.list|std.longarr|std.os|std.string"
expect_imports ae/naeb/provider/sse/module.ae "naeb.provider.http|std.string"
expect_imports ae/naeb/provider/types/module.ae "naeb.jsonx|std.list|std.string"
expect_imports ae/naeb/session/compact/module.ae "naeb.image|naeb.jsonx|naeb.msg|naeb.provider.types|std.json|std.list|std.string"
expect_imports ae/naeb/session/instructions/module.ae "std.fs|std.strbuilder|std.string"
expect_imports ae/naeb/session/log/module.ae "naeb.fserr|naeb.jsonx|naeb.lock|naeb.msg|naeb.provider.types|std.dir|std.fs|std.io|std.json|std.list|std.string|std.time"
expect_imports ae/naeb/session/module.ae "naeb.session.tuning|naeb.build_info|naeb.image|naeb.jsonx|naeb.lock|naeb.mcp|naeb.msg|naeb.provider|naeb.provider.timing as modeltiming|naeb.provider.sink|naeb.provider.types|naeb.sandbox|naeb.sandbox.record|naeb.sandbox.timing|naeb.session.compact|naeb.session.fork_history|naeb.session.hooks|naeb.session.instructions|naeb.session.log|naeb.session.output|naeb.session.profile|naeb.session.prompt|naeb.session.skills|naeb.session.tool_summary|naeb.tools|naeb.tools.agent_input|naeb.tools.agent_sessions|naeb.tools.atomic_file|naeb.tools.background|naeb.tools.diff|naeb.tools.progress|std.cryptography|std.fs|std.json|std.list|std.os|std.string|std.sync|std.worker"
# `naeb replay`: reads the two Session files, replays through naeb.sandbox.replay; no tools, no provider.
expect_imports ae/naeb/run_replay/module.ae "naeb.jsonx|naeb.sandbox|naeb.sandbox.replay|naeb.session.output|std.fs|std.json|std.list|std.map|std.strbuilder|std.string"
# Saves a truncated Run's whole output to a file (f7ed5ea): atomic_file writes it.
expect_imports ae/naeb/session/output/module.ae "naeb.sandbox|naeb.sandbox.console|naeb.tools.atomic_file|std.cryptography|std.fs|std.list|std.strbuilder|std.string"
expect_imports ae/naeb/session/profile/module.ae "std.string"
expect_imports ae/naeb/session/skills/module.ae "naeb.jsonx|std.dir|std.fs|std.list|std.os|std.strbuilder|std.string"
expect_imports ae/naeb/session/tuning/module.ae "naeb.jsonx|naeb.session.profile|std.json|std.string"
expect_imports ae/naeb/session/prompt/module.ae "naeb.sandbox|naeb.session.output|naeb.session.profile|naeb.session.tuning|std.cryptography|std.list|std.strbuilder|std.string"
expect_imports ae/naeb/session/tool_summary/module.ae "naeb.jsonx|naeb.sandbox.timing|std.list|std.strbuilder|std.string"

# The MCP client (not yet in the Session): pure index/header logic, then the transport (the only reach to MCP servers: a child through tools/process, or HTTP).
expect_imports ae/naeb/mcp/mcp_index/module.ae "naeb.jsonx|std.json|std.list|std.strbuilder|std.string"
expect_imports ae/naeb/mcp/mcp_headers/module.ae "naeb.jsonx|std.encoding|std.json|std.list|std.string"
expect_imports ae/naeb/mcp/mcp_transport/module.ae "naeb.build_info|naeb.fence|naeb.jsonx|naeb.lock|naeb.mcp.mcp_headers|naeb.provider.sse|naeb.provider.types|naeb.tools.denials|naeb.tools.egress|naeb.tools.jail|naeb.tools.process|naeb.tools.secrets|std.fs|std.http.client|std.ipc|std.json|std.list|std.os|std.string|std.sync|std.worker"
expect_imports ae/naeb/mcp/module.ae "naeb.jsonx|naeb.lock|naeb.mcp.mcp_headers|naeb.mcp.mcp_index|naeb.mcp.mcp_transport|naeb.provider.types|std.json|std.list|std.string|std.sync"
expect_imports $T/mcp_tool/module.ae "naeb.image|naeb.jsonx|naeb.mcp|std.encoding|std.json|std.list|std.string"

# The TUI (ae/term underneath; no network, no process of its own except the
# exceptions named in the rules below).
U=ae/naeb/tui
expect_imports ae/naeb_main.ae "naeb.app"
# The binary's body: ae/naeb_main.ae runs it with the project's fence, or with none under --mode unfenced.
expect_imports ae/naeb/app/module.ae "naeb.auth|naeb.build_info|naeb.config|naeb.config.env|naeb.fence|naeb.fence.policy|naeb.jsonx|naeb.provider.types|naeb.run_replay|naeb.sandbox|naeb.session|naeb.tools|naeb.tools.agent_input|naeb.tools.background|naeb.tools.jail|naeb.tui|naeb.tui.clock|naeb.tui.live|std.fs|std.io|std.list|std.os|std.signal|std.string|std.sync|std.worker|term|term.input"
# `/model`'s listing (src/auth/models.zig): one GET of the provider's /models.
expect_imports ae/naeb/auth/models/module.ae "naeb.jsonx|std.http.client|std.json|std.list|std.string|std.time"
expect_imports $U/module.ae "naeb.auth|naeb.auth.models|naeb.config|naeb.config.env|naeb.image|naeb.jsonx|naeb.provider.types|naeb.session.skills|naeb.session.tool_summary|naeb.tools.changes|naeb.tools.diff|naeb.tui.agent_tree|naeb.tui.app_queue|naeb.tui.bill|naeb.tui.clipboard|naeb.tui.clock|naeb.tui.commands|naeb.tui.editor|naeb.tui.entry|naeb.tui.fence_offer|naeb.tui.format|naeb.tui.frames|naeb.tui.long_text|naeb.tui.menu|naeb.tui.mode|naeb.tui.open|naeb.tui.paths|naeb.tui.port|naeb.tui.prediction|naeb.tui.provider_flow|naeb.tui.reflect|naeb.tui.sel_history|naeb.tui.selection|naeb.tui.status|naeb.tui.tasks|naeb.tui.title|naeb.tui.transcript|naeb.tui.tui_view|naeb.tui.turn|naeb.tui.turn_changes|naeb.tui.turn_summary|naeb.tui.viewport|std.fs|std.json|std.list|std.os|std.strbuilder|std.string|std.sync|term|term.input|term.screen"
# The Session's live port: the only TUI module that imports naeb.session.
expect_imports $U/live/module.ae "naeb.config|naeb.fence|naeb.fence.policy|naeb.jsonx|naeb.mcp|naeb.msg|naeb.provider|naeb.provider.sink as psink|naeb.provider.types|naeb.sandbox|naeb.session|naeb.session.instructions|naeb.session.log|naeb.session.skills|naeb.tools|naeb.tools.background|naeb.tools.changes|naeb.tools.diff|naeb.tools.jail|naeb.tools.progress|naeb.sysenv|naeb.tui.app_queue|naeb.tui.port|naeb.tui.prediction|naeb.tui.turn|std.list|std.os|std.string|std.sync|std.time|std.worker"
expect_imports $U/port/module.ae "naeb.jsonx|naeb.provider.types|naeb.tui.app_queue|std.list|std.string|std.sync"
expect_imports $U/turn/module.ae "naeb.jsonx|naeb.tui.app_queue|std.sync"
expect_imports $U/app_queue/module.ae "naeb.lock"
expect_imports $U/clock/module.ae "term"
expect_imports $U/frames/module.ae ""
expect_imports $U/mode/module.ae ""
# Drawing and text: no file system, process or network.
expect_imports $U/agent_tree/module.ae "naeb.jsonx|naeb.tools.progress|naeb.tui.format|naeb.tui.long_text|std.json|std.list|std.strbuilder|std.string|term.screen"
expect_imports $U/bill/module.ae "naeb.tui.format|naeb.tui.turn_summary|std.string|term.screen"
expect_imports $U/commands/module.ae "naeb.provider.types|naeb.tui.mode|std.strbuilder|std.string"
expect_imports $U/editor/module.ae "naeb.tui.format|naeb.tui.long_text|naeb.tui.paths|std.strbuilder|std.string|term.input|term.screen"
expect_imports $U/entry/module.ae "naeb.session.tool_summary|naeb.tui.agent_tree|naeb.tui.bill|naeb.tui.format|naeb.tui.label|naeb.tui.long_text|naeb.tui.markdown|naeb.tui.run_details|naeb.tui.smooth|naeb.tui.turn_changes|std.list|std.strbuilder|std.string|term.screen"
expect_imports $U/format/module.ae "std.string|term.screen"
expect_imports $U/intraline/module.ae "std.string|term.screen"
expect_imports $U/label/module.ae "naeb.session.tool_summary|std.list|std.strbuilder|std.string"
expect_imports $U/long_text/module.ae "std.string|term.screen"
expect_imports $U/markdown/module.ae "naeb.tui.syntax|std.strbuilder|std.string|term.screen"
expect_imports $U/menu/module.ae "naeb.config|naeb.jsonx|naeb.provider.types|naeb.session.skills|naeb.tui.commands|naeb.tui.editor|naeb.tui.paths|naeb.tui.port|std.list|std.string"
expect_imports $U/sel_history/module.ae "naeb.tui.entry|naeb.tui.viewport|std.strbuilder|std.string|term.screen"
expect_imports $U/selection/module.ae "naeb.tui.entry|naeb.tui.sel_history|std.strbuilder|std.string|term|term.input|term.screen"
expect_imports $U/smooth/module.ae "std.string|term.screen"
expect_imports $U/status/module.ae "naeb.provider.types|naeb.tui.format|naeb.tui.label|naeb.tui.turn_summary|std.strbuilder|std.string|term.screen"
expect_imports $U/syntax/module.ae "std.string|term.screen"
expect_imports $U/tasks/module.ae "naeb.tui.agent_tree|naeb.tui.format|std.strbuilder|std.string"
expect_imports $U/transcript/module.ae "naeb.jsonx|naeb.msg|naeb.sandbox.timing|naeb.session.tool_summary|naeb.tools.changes|naeb.tools.diff|naeb.tui.agent_tree|naeb.tui.entry|naeb.tui.label|naeb.tui.long_text|naeb.tui.smooth|naeb.tui.turn_changes|naeb.tui.viewport|std.json|std.list|std.strbuilder|std.string"
expect_imports $U/tui_view/module.ae "naeb.provider.types|naeb.tui.commands|naeb.tui.editor|naeb.tui.entry|naeb.tui.format|naeb.tui.sel_history|naeb.tui.status|naeb.tui.viewport|std.string|term.screen"
expect_imports $U/turn_changes/module.ae "naeb.tools.changes|naeb.tools.diff|std.list|std.strbuilder|std.string|term.screen"
# The expanded part of a Run: its disclosures and file rows, drawn from facts the entry hands over.
expect_imports $U/run_details/module.ae "naeb.tui.intraline|naeb.tui.turn_changes|std.string|term.screen"
expect_imports $U/fence_offer/module.ae "naeb.jsonx|std.json|std.list|std.string"
expect_imports $U/turn_summary/module.ae "naeb.jsonx|std.string"
expect_imports $U/viewport/module.ae "naeb.tui.entry|term.screen"
# File system (the @ completion walk, the title's git branch).
expect_imports $U/paths/module.ae "naeb.lock|naeb.tools.walk|std.fs|std.list|std.string|std.sync|std.worker"
expect_imports $U/title/module.ae "std.fs|std.strbuilder|std.string"
# The model calls are closures the app passes in (prediction) or the /model listing (provider_flow).
expect_imports $U/prediction/module.ae "naeb.msg|naeb.tui.editor|std.list|std.strbuilder|std.string|std.sync|std.worker"
expect_imports $U/provider_flow/module.ae "naeb.auth.models|naeb.config|std.list|std.strbuilder|std.string|std.sync|std.worker"
# Processes through tools/process: pbcopy/osascript/xclip and friends (clipboard read and write), gh (reflect).
expect_imports $U/clipboard/module.ae "naeb.image|naeb.tools.process|std.list|std.string|std.worker"
expect_imports $U/reflect/module.ae "naeb.fserr|naeb.jsonx|naeb.tools.process|std.cryptography|std.fs|std.io|std.json|std.list|std.os|std.strbuilder|std.string|std.sync|std.worker"
# A clicked path's `open` command, detached (see the exception below).
expect_imports $U/open/module.ae "std.fs|std.list|std.map|std.os|std.strbuilder|std.string|std.worker"

# Every module is pinned: a new one needs its line above.
for f in ae/naeb_main.ae $(find ae/naeb -name '*.ae' | sort); do
    case " $PINNED " in
        *" $f "*) ;;
        *) echo "FAIL $f has no expect_imports line"; fail=1 ;;
    esac
done

rule() {   # rule "what" "pattern" "allowed path regex"
    hits=$(grep -rnE "$2" --include='*.ae' ae/naeb ae/naeb_main.ae 2>/dev/null \
          | grep -vE "^($3)" | grep -vE '^[^:]+:[0-9]+:[[:space:]]*//' || true)
    if [ -n "$hits" ]; then
        echo "FAIL $1:"
        echo "$hits" | sed 's/^/       /'
        fail=1
    else
        echo "ok   $1"
    fi
}

# Who may start a program is the compiler's rule (Aether 0.911.0's
# `import ns hiding (...)`, aether #3653; a use is E0304): every file that
# imports std.os outside tools/process and tools/jail (the Landlock probe and
# the `naeb __jail` exec helper) hides each std.os member that starts a
# program. The list is std.os's as of 0.912.0; a new such member must join it.
PROC="exec run_capture run_pipe run_pipe_drain_and_wait run_socket run_stdio run_full run_supervised spawn_proc spawn_proc_to os_system os_exec_raw os_execv os_run os_run_capture_raw os_run_capture_status_raw os_run_pipe_raw os_run_pipe_drain_and_wait_raw os_run_socket_raw os_run_stdio_raw os_run_full_raw os_run_supervised_raw os_spawn_raw os_spawn_to_raw"
# The one exception: tui/open launches the user's `open` command for a
# clicked path, detached, stdio to /dev/null (upstream open.zig). tools/process
# ties a child to a Run (output capture, deadline, kill on cancel); a click is
# outside any Run. So tui/open alone keeps spawn_proc_to (and os.wait on its
# own worker to reap the child).
for f in $(grep -rlE '^import std\.os( |$)' --include='*.ae' ae/naeb ae/naeb_main.ae | sort); do
    case $f in $T/process/*|$T/jail/*) continue ;; esac
    stmt=$(awk '/^import std\.os( |$)/ { on = 1 } on { printf "%s ", $0; if ($0 ~ /\)/ || $0 ~ /^import std\.os$/) exit }' "$f")
    keep=""
    [ "$f" = "$U/open/module.ae" ] && keep=spawn_proc_to
    bad=""
    for n in $PROC; do
        [ "$n" = "$keep" ] && continue
        case "$stmt" in *hiding*[\(\ ]"$n"[,\)]*) ;; *) bad="$bad $n" ;; esac
    done
    if [ -n "$keep" ]; then
        case "$stmt" in *[\(\ ]"$keep"[,\)]*) bad="$bad (hides $keep: the exception is gone, drop it here)" ;; esac
    fi
    if [ -n "$bad" ]; then
        echo "FAIL $f: its std.os import does not hide:$bad"
        fail=1
    else
        echo "ok   $f hides std.os's program starts${keep:+ but $keep}"
    fi
done
only_calls() {   # only_calls FILE MODULE "allowed members|..." "why"
    used=$(grep -oE "(^|[^A-Za-z0-9_.])$2\.[a-z_]+[[:space:]]*\(" "$1" | sed -E "s/.*$2\.([a-z_]+).*/\1/" | sort -u | tr '\n' ' ')
    bad=""
    for m in $used; do
        case "|$3|" in *"|$m|"*) ;; *) bad="$bad $m" ;; esac
    done
    if [ -n "$bad" ]; then
        echo "FAIL $1 calls $2.(${bad# }) ($4 allows only: $(printf '%s' "$3" | sed 's/|/, /g'))"
        fail=1
    else
        echo "ok   $1 calls only $2.($(printf '%s' "$3" | sed 's/|/, /g')): $4"
    fi
}
rule "QuickJS is embedded only by the sandbox and grep's private matcher" \
    '^import contrib\.quickjs' "ae/naeb/sandbox/module.ae|$T/grep/"
# - auth/models lists the provider's models for `/model` (upstream
#   auth/models.zig): one GET, with the key the Session would send.
rule "only provider/http (the model request), auth/models (the /model listing), mcp_transport (Streamable HTTP MCP servers) tools/web_search (the search request), tools/web (tools.fetch), tools/egress (a fence's proxy) and maven/repo (the Maven broker's GET, naeb's own) reach the network" \
    '^import std\.(http|net|tcp|udp)' "ae/naeb/provider/http/|ae/naeb/auth/models/|ae/naeb/mcp/mcp_transport/|$T/web/|$T/web_search/|$T/egress/|ae/naeb/maven/repo/"
if grep -nE 'client\.request\(' ae/naeb/auth/models/module.ae | grep -vqE 'client\.request\("GET", '; then
    echo "FAIL ae/naeb/auth/models sends something other than a GET"; fail=1
else
    echo "ok   ae/naeb/auth/models only GETs"
fi
if grep -nE 'client\.request\(' ae/naeb/maven/repo/module.ae | grep -vqE 'client\.request\("GET", '; then
    echo "FAIL ae/naeb/maven/repo sends something other than a GET"; fail=1
else
    echo "ok   ae/naeb/maven/repo only GETs"
fi
rule "the Maven broker is reached only from the tools" \
    '^import naeb\.maven\.broker' "$T/module.ae"
rule "the /model listing is reached only from the TUI's app and its provider flow" \
    '^import naeb\.auth\.models' "$U/module.ae|$U/provider_flow/"
rule "the TUI reaches the Session only through its live port" \
    '^import naeb\.session$' "$U/live/|ae/naeb/app/|ae/naeb/tools/agent/|ae/naeb/session/"

# A project's policy library is compiled against ae/policy_lib alone: its
# modules import nothing of naeb (no copy of naeb's layouts) and nothing with a
# capability (--emit=lib refuses those anyway).
if grep -rnE '^import ' ae/policy_lib | grep -vE ':import (naeb\.policy|std\.(string|list|map|math))$' >/dev/null; then
    echo "FAIL ae/policy_lib imports beyond naeb.policy and pure std:"; grep -rnE '^import ' ae/policy_lib | grep -vE ':import (naeb\.policy|std\.(string|list|map|math))$' | sed 's/^/       /'; fail=1
else
    echo "ok   ae/policy_lib imports only naeb.policy and pure std"
fi

# ae/term stands alone: nothing of naeb.
if grep -rnE '^import naeb\.' ae/term >/dev/null 2>&1; then echo "FAIL ae/term imports naeb"; fail=1; else echo "ok   ae/term imports nothing of naeb"; fi

# The sandbox's host functions open with the veto line.
n=$(grep -c 'hide os, worker, dispatch_, work_' ae/naeb/sandbox/module.ae || true)
if [ "$n" -ge 2 ]; then echo "ok   the sandbox's host functions keep their hide line"; else echo "FAIL the sandbox's host functions lost their hide line"; fail=1; fi

exit $fail
