"""Run one of upstream's test files (tests/test_*.py), unchanged on disk,
leaving out the tests the port excludes by policy or has not reached yet.

The file on disk is never edited. A few of upstream's assertions pin the
program name `nib` in a message, or `.nib` as the default home, where naeb says
naeb: SUBS lists each such text and what naeb has in its place, and the run
fails if a listed text is not found, so the list cannot go stale unnoticed.

    cd tests && python3 ../ae/tests/run_upstream.py test_agent.py [SKIP ...]

Each SKIP is a substring of a test's id (Class.method); a matching test is
not run. ae/tests/upstream-e2e.sh holds the list and the reason for each.
"""
import types
import os
import sys
import unittest


# file name -> [(upstream's text, naeb's text)]
SUBS = {
    "test_cli.py": [
        ('"nib: Unknown option: --x \u00b7 run nib --help\\n"', '"naeb: Unknown option: --x \u00b7 run naeb --help\\n"'),
    ],
    "test_background_bash.py": [
        ('"refused by nib"', '"refused by naeb"'),
    ],
    "test_model.py": [
        ('b"NIB_PROVIDER overrides at startup"', 'b"NAEB_PROVIDER overrides at startup"'),
    ],
    "test_session.py": [
        ('"NIB_API_KEY" in message', '"NAEB_API_KEY" in message'),
        ('(tmp / ".nib/sessions" /', '(tmp / ".naeb/sessions" /'),
    ],
}
# Files that are a script rather than a unittest module: run as __main__.
SCRIPTS = {"test_session.py", "test_model.py"}


def source(path):
    text = open(path, encoding="utf-8").read()
    for old, new in SUBS.get(os.path.basename(path), []):
        if old not in text:
            sys.exit(f"{path}: the text {old!r} is no longer in upstream's file; update SUBS")
        text = text.replace(old, new)
    return text


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


def main():
    path, skips = sys.argv[1], sys.argv[2:]
    sys.path.insert(0, os.getcwd())
    name = os.path.splitext(os.path.basename(path))[0]
    if os.path.basename(path) in SCRIPTS:
        exec(compile(source(path), path, "exec"), {"__name__": "__main__", "__file__": os.path.abspath(path)})
        return
    module = types.ModuleType(name)
    module.__file__ = os.path.abspath(path)
    sys.modules[name] = module
    exec(compile(source(path), path, "exec"), module.__dict__)
    loaded = unittest.defaultTestLoader.loadTestsFromModule(module)
    kept, skipped = unittest.TestSuite(), []
    for test in flatten(loaded):
        test_id = test.id().split(".", 1)[-1]
        if any(s in test_id for s in skips):
            skipped.append(test_id)
        else:
            kept.addTest(test)
    print(f"excluded {len(skipped)}: {', '.join(skipped) or '-'}", flush=True)
    result = unittest.TextTestRunner(verbosity=2).run(kept)
    sys.exit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
