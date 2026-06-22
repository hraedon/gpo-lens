# Work Item: SYSVOL path helpers (case-insensitive resolution)

## Dependencies

- `interface_ref`: none at runtime — stdlib-only (`pathlib`).
- Consumer: `ingest.augment_blocked_registry_from_pol` (resolves
  `Machine/Registry.pol` / `User/Registry.pol` case-insensitively),
  `detection._walk_gpp_xml` (resolves `Preferences/*.xml`).
- Reference: there is **no dedicated plan file** for `paths.py`. It was
  factored out of `ingest.py` / `detection.py` when the
  `augment_blocked_registry_from_pol` integration (Plan 018-adjacent
  gap fix) needed the same case-insensitive resolution that
  `_walk_gpp_xml` already did ad-hoc. This spec is the first formal
  contract; `docs/spec/export-format.md` documents the underlying
  SYSVOL shape.

## Notes

This module hosts two path helpers that resolve Windows-cased SYSVOL
paths on a case-sensitive (Linux) analysis host. It is a **core
module** (`tests/_arch.py::CORE_MODULES`); no `narration`/`web`
imports, fully stdlib-only (just `pathlib`).

### Why this exists

A copied SYSVOL keeps Windows' original casing, which varies in the
wild:

- The default GPOs (`Default Domain Policy`, `Default Domain
  Controllers Policy`) ship with upper-case side dirs: `MACHINE/`,
  `USER/`.
- Most other GPOs use Title Case: `Machine/`, `User/`.
- Some tooling emits mixed case (`machine/`, `UsEr/`).

On Windows (case-insensitive FS) `base / "Machine"` resolves any of
these. On Linux (case-sensitive FS, the deployment target for
gpo-lens), a literal `base / "Machine"` silently misses the upper-case
default-GPO shape. These helpers close that gap by trying the literal
name first (fast path, also correct on case-insensitive hosts) then
falling back to a case-insensitive scan.

### Drift / known simplifications

- **`OSError` from `iterdir()` is swallowed silently.** A copied
  SYSVOL can contain directories the analysis account cannot enter
  (permission-denied). `ci_child` returns `None` rather than raising,
  so a missing side dir is indistinguishable from an unreadable one.
  The caller (`augment_blocked_registry_from_pol`) treats both as
  "cannot resolve" and surfaces the gap (the blocked placeholder is
  kept). This matches the AGENTS.md "Coverage honesty" stance — flag,
  don't paper over.
- **The fast path uses `Path.exists()`, not `Path.is_dir()`.** A
  regular file named `Machine` at the base would short-circuit the
  scan and be returned, then fail downstream when the caller tries to
  list it. Real SYSVOLs don't have such files; the trade-off is speed
  over strictness.
- **The fallback scan uses `child.name.lower() == target.lower()`**,
  not Unicode case-folding. Windows file names are typically ASCII;
  `str.lower()` is sufficient. A name with non-ASCII characters whose
  lowercase form differs under locale-aware comparison could
  theoretically miss, but this is not a real-world SYSVOL concern.
- **`ci_path` is `ci_child` composed.** Each segment is resolved
  independently; a missing segment aborts the whole chain and returns
  `None`. There is no partial-resolution return — callers cannot
  recover "we got this far, then ran out of path."
- **No `__all__`.** Public exports: `ci_child`, `ci_path`.

## Module map

`src/gpo_lens/paths.py` — stdlib-only (`pathlib.Path`). Core module
(`tests/_arch.py`); no I/O outside the explicit `Path` argument, no
model calls.

| Public surface | Role |
|----------------|------|
| `ci_child(parent: Path, name: str) -> Path \| None` | Case-insensitive single-segment child resolution. |
| `ci_path(base: Path, *parts: str) -> Path \| None` | Multi-segment chain resolution (composes `ci_child`). |

---

## AC-01: Module purity

`paths.py` is a core module. Imports: `pathlib.Path` only. Must never
import `gpo_lens.narration` or `gpo_lens.web`
(`tests/_arch.py::forbidden_imports_in("paths")`). No `gpo_lens.*`
imports at all — fully standalone. No I/O outside the `Path` argument
(`exists()`, `iterdir()` are the only fs touches). Read-only: no
mutation of the filesystem.

## AC-02: `ci_child` — single-segment resolution

```python
def ci_child(parent: Path, name: str) -> Path | None: ...
```

Resolution order:

1. **Fast path**: `direct = parent / name`. If `direct.exists()` is
   True, return `direct`. This is correct on case-insensitive hosts
   (Windows, macOS default FS) and on case-sensitive hosts when the
   casing happens to match.
2. **Fallback scan**: `target = name.lower()`. Iterate
   `parent.iterdir()`. For each child, if `child.name.lower() ==
   target`, return that child. First match wins (iteration order is OS-
   dependent; if two children differ only by case, the result is
   implementation-defined — Windows disallows this, Linux allows it
   but real SYSVOLs don't have such collisions).
3. **No match**: return `None`.
4. **`OSError` at any point** (unreadable parent, permission denied):
   return `None` (see Notes — silently swallowed).

`Path.exists()` follows symlinks. A symlink whose target is missing
returns False from `exists()`, so the literal path is treated as
missing and the scan runs.

## AC-03: `ci_path` — multi-segment chain

```python
def ci_path(base: Path, *parts: str) -> Path | None: ...
```

Initialize `cur = base`. For each `part` in `parts` (in order):

- `nxt = ci_child(cur, part)`.
- If `nxt is None`: return `None` immediately (no partial resolution —
  see Notes).
- Else `cur = nxt`.

Return `cur` after all parts resolve. Empty `parts` returns `base`
itself (no resolution performed — `base` may not exist; the function
does not validate).

The chain semantics make `ci_path(base, "Machine", "Registry.pol")`
equivalent to two `ci_child` calls. A failure at any segment
short-circuits the whole resolution.

## AC-04: Determinism and read-only invariant

- All filesystem access is read-only (`exists()`, `iterdir()`). The
  module never writes, creates, or deletes anything.
- Resolution is deterministic given the same on-disk state. Iteration
  order from `iterdir()` is OS-dependent but stable for a given FS
  state; the first-case-insensitive-match wins.
- `OSError` is the only caught exception. Other exceptions
  (e.g. `ValueError` from a malformed path) propagate — these
  indicate programmer error, not an unreadable path.
- No time, no randomness, no environment reads, no model calls
  (`tests/_arch.py`).
