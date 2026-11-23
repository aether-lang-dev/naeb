# An array literal cannot be returned from a function or be a `const` initialiser

**From:** the naeb Aether port (`aether-port` branch of aether-lang-dev/naeb).
**To:** aether, ae 0.936.0.
**Workaround meanwhile:** none needed once the right spelling is known:
`const NAMES[] = [...]` (naeb: `TOOL_NAMES` in `ae/naeb/tools/module.ae`). Until
that was found the port built slices with `make([]T, 0)` and `push` (the pairs
of sentences `ae/naeb/session/prompt` used to rewrite; that code is gone) and
kept a literal in a local of the function that indexed it.

Two small programs, `ae build a.ae` and `ae build b.ae` with ae 0.936.0:

```
a.ae:  names() -> string[] {
           return ["a", "b"]
       }
       main() { print(names()[0]) }

b.ae:  const NAMES = ["a", "b"]
       main() { print(NAMES[0]) }
```

```
error[E0900]: 'names' returns a slice of its own storage (an array literal): the storage ends when 'names' returns, so the slice would view memory that is gone
  --> a.ae:2:12
2 |     return ["a", "b"]
  |            ^ help: copy the elements into storage that lives as long as the slice (a `make([]T, n)` buffer), declare a literal of constants as `const NAMES[] = [...]` (static storage, in the function or at module level), or use the slice only while the function runs

error[E0200]: const initializer must be a compile-time constant expression, function calls are inlined at each use site, which would re-evaluate the call (and re-allocate / re-side-effect) on every reference. Use a regular assignment in main() (or std.config / std.actors for process-global state) instead.
  --> b.ae:1:1
1 | const NAMES = ["a", "b"]
  | ^ help: ensure types are compatible or add explicit type conversion
```

The first message is right and its help names the working form, which this
port missed for a while: `const NAMES[] = ["a", "b"]` is static storage, and a
function may return `NAMES` (checked: `names()[1]` prints `b`). So what is left
to ask is small:

1. The second message is the wrong diagnosis for `const NAMES = [...]`. It
   talks about function calls, but the initialiser is a literal; the fix is the
   `const NAMES[] = [...]` spelling the first message already knows. Pointing
   at it from E0200 when the initialiser is an array literal would have saved
   the workaround above.
2. The form is documented (`docs/compile-time-eval.md`), but the E0200 text
   above never sends a reader there.
