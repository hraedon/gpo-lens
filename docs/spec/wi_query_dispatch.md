# Work Item: Query dispatch table (CLI / web ask single source of truth)

## Dependencies

- `interface_ref`: `queries` (every dispatched query is a `queries.*`
  function — except `principal_resultant`, which is lazily imported
  from `merge`).
- `interface_ref`: `merge.principal_resultant` (imported as
  `from gpo_lens import merge as _merge` at module top; the dispatch lambda
  calls `_merge.principal_resultant` — see AC-04 / Notes).
- Consumer: `narration.route_question` (LLM-driven ask), `web/app.py`
  `/ask` route (programmatic + LLM ask), `cli/_narration.py` (CLI ask
  subcommand). All three call `validate_params` then `dispatch_query`.
- Reference: there is **no dedicated plan file** for `query_dispatch.py`.
  It was factored out of `narration.py` when the web `/ask` route
  needed the same query-name → callable mapping. This spec is the first
  formal contract. The routing corpus that exercises every query is in
  `tests/test_routing_corpus.py`.

## Notes

This module is the **single source of truth** for which queries the
LLM-routing layer (and the programmatic `/ask` endpoint) can dispatch
to. It is a **core module** (`tests/_arch.py::CORE_MODULES`); no
`narration`/`web` imports. The core-imports-only rule means
`query_dispatch` may import `queries` and (lazily) `merge`, but never
`narration` or `web` — those modules import *it*, not the reverse.

### Why a dispatch table (and not direct calls)

Before this module existed, `narration.route_question` had its own
inline mapping from query name to callable. When the web `/ask` route
was added (Plan 012), it needed the same mapping. Duplicating it in
two places risked drift — the LLM might route to a query the web layer
didn't know about, or vice versa. The dispatch table centralizes:

1. The name → callable mapping (`_QUERY_DISPATCH`).
2. The human-readable description per query
   (`_QUERY_DESCRIPTIONS` — fed to the LLM as the routing menu).
3. The required parameters per query (`QUERY_REQUIRED_PARAMS`).
4. The parameter type validators (`_PARAM_VALIDATORS`).

`VALID_QUERIES` is the public frozenset of names; narration re-exports
it as `_VALID_QUERIES` and rejects any LLM-proposed query not in the
set (`test_route_question_unknown_query_raises`).

### Drift / known simplifications

- **`principal_resultant` is imported lazily via `__import__`.** All
  other queries are direct `queries.*` attribute lookups inside the
  lambda. The lazy import for `merge.principal_resultant` avoids
  importing `merge` (a heavy module with deep `topology`/`detection`/
  `authz` transitive deps) at module-load time — the import happens
  only when `principal_resultant` is actually dispatched. This keeps
  `query_dispatch`'s import footprint minimal. If `merge` ever
  becomes cheap to import, replace the `__import__` with a direct
  module-level import.
- **`validate_params` silently drops unknown parameter keys.** It does
  not raise on extras; it filters them out (AC-03). This is deliberate
  — the LLM may emit extra context keys (`"reasoning"`, `"confidence"`)
  that the dispatch layer ignores. Stricter validation would force the
  LLM prompt to be more precise, at the cost of more false rejections.
- **The error message for a missing required param names only one
  parameter**, even if multiple are missing (`missing.pop()`). This is
  a presentation choice; if a future query requires two params, the
  error reports whichever `set.pop()` happened to yield.
- **`dispatch_query(name, **kwargs)` raises `KeyError` for unknown
  names** — it does not call `validate_params`. Callers that need the
  friendlier `ValueError` from validation must call `validate_params`
  first (the narration / web paths do; a direct `dispatch_query` call
  skips validation). The two paths have different failure modes.
- **Every dispatched query takes an `estate` kwarg.** The validators
  pass `estate` through unvalidated (AC-03) — it can be any object.
  The query implementations assume it's a `model.Estate`, but the
  dispatch layer does not enforce the type. A caller passing a
  non-Estate gets a runtime `AttributeError` from inside the query.
- **The dispatch lambdas extract kwargs by name (`kw["estate"]`,
  `kw["ou_path"]`, etc.) with no defaults.** A missing required kwarg
  raises `KeyError` at dispatch time, not a friendly message. This is
  why `validate_params` exists — it translates the missing-key
  `KeyError` into a `ValueError("Query 'X' requires parameter 'Y'")`.
- **No `__all__`.** Public exports are: `VALID_QUERIES`,
  `QUERY_REQUIRED_PARAMS`, `validate_params`, `dispatch_query`. The
  `_QUERY_DISPATCH`, `_QUERY_DESCRIPTIONS`, `_PARAM_VALIDATORS` dicts
  are private but load-bearing.

## Module map

`src/gpo_lens/query_dispatch.py` — stdlib-only (`typing`) plus
`gpo_lens.queries` and a lazy `gpo_lens.merge` import. Core module
(`tests/_arch.py`).

| Public surface | Role |
|----------------|------|
| `VALID_QUERIES: frozenset[str]` | The set of routable query names. |
| `QUERY_REQUIRED_PARAMS: dict[str, list[str]]` | Required non-`estate` params per query. |
| `validate_params(query_name, params) -> dict[str, object]` | Filter + type-check + required-check; raises `ValueError`. |
| `dispatch_query(name, **kwargs) -> Any` | Invoke the named query's lambda. Raises `KeyError` on unknown name. |

Private load-bearing: `_QUERY_DISPATCH` (name → callable),
`_QUERY_DESCRIPTIONS` (name → human description, fed to the LLM),
`_PARAM_VALIDATORS` (name → `{param_name: type}`).

---

## AC-01: Module purity and the import boundary

`query_dispatch.py` is a core module. Imports at module load:
`typing`, `gpo_lens.queries`. The `gpo_lens.merge` import is **lazy**
(inside the `principal_resultant` lambda via `__import__`), so it is
not in the module's import graph until that query is dispatched. Must
never import `gpo_lens.narration` or `gpo_lens.web`
(`tests/_arch.py::forbidden_imports_in("query_dispatch")`).

The architecture rule is one-way: `narration` and `web` may import
`query_dispatch`, but `query_dispatch` may not import them. This keeps
the routing vocabulary in the deterministic core, with the LLM/web
layers as consumers.

## AC-02: `_QUERY_DISPATCH` — the 19 routable queries

`_QUERY_DISPATCH` is a `dict[str, Callable[..., Any]]` with exactly
these keys (validated by `test_all_valid_queries_are_covered`, which
asserts the corpus covers `_VALID_QUERIES`):

| Query name | Lambda body |
|------------|-------------|
| `estate_summary` | `queries.estate_summary(kw["estate"])` |
| `estate_doctor` | `queries.estate_doctor(kw["estate"])` |
| `cpassword_scan` | `queries.cpassword_scan(kw["estate"])` |
| `unlinked_gpos` | `queries.unlinked_gpos(kw["estate"])` |
| `empty_gpos` | `queries.empty_gpos(kw["estate"])` |
| `version_skew` | `queries.version_skew(kw["estate"])` |
| `broken_refs` | `queries.broken_refs(kw["estate"])` |
| `enforced_links` | `queries.enforced_links(kw["estate"])` |
| `dangling_links` | `queries.dangling_links(kw["estate"])` |
| `ms16_072_vulnerable` | `queries.ms16_072_vulnerable(kw["estate"])` |
| `topology_crosscheck` | `queries.topology_crosscheck(kw["estate"])` |
| `disabled_but_populated` | `queries.disabled_but_populated(kw["estate"])` |
| `settings_at_som` | `queries.settings_at_som(kw["estate"], kw["ou_path"])` |
| `effective_scope` | `queries.effective_scope(kw["estate"], kw["gpo_id"])` |
| `orphaned_wmi_filters` | `queries.orphaned_wmi_filters(kw["estate"])` |
| `broken_wmi_refs` | `queries.broken_wmi_refs(kw["estate"])` |
| `stale_gpos` | `queries.stale_gpos(kw["estate"])` |
| `danger_findings` | `queries.danger_findings(kw["estate"])` |
| `principal_resultant` | `__import__("gpo_lens.merge", fromlist=["principal_resultant"]).principal_resultant(kw["estate"], kw["principal_sid"])` |

17 of 19 take only `estate`. The three with extra required params are
`settings_at_som` (`ou_path`), `effective_scope` (`gpo_id`), and
`principal_resultant` (`principal_sid`). These three are also the only
entries in `QUERY_REQUIRED_PARAMS` and `_PARAM_VALIDATORS`.

`_QUERY_DESCRIPTIONS` mirrors `_QUERY_DISPATCH` exactly — every key in
the dispatch table has a description entry (and vice versa). The
descriptions are the routing menu fed to the LLM in
`narration.route_question`.

## AC-03: `validate_params` — filtering and validation

```python
def validate_params(
    query_name: str, params: dict[str, object],
) -> dict[str, object]: ...
```

Algorithm:

1. If `query_name not in _QUERY_DISPATCH`: raise
   `ValueError(f"Unknown query: {query_name}")`.
2. `required = set(QUERY_REQUIRED_PARAMS.get(query_name, []))`.
3. `expected = {"estate", *required}` — the set of accepted param
   names. Anything else is silently dropped (see Notes).
4. `schema = _PARAM_VALIDATORS.get(query_name, {})` — the per-param
   type map.
5. For each `(key, value)` in `params.items()`:
   - If `key == "estate"`: copy through unvalidated (AC-01 / Notes —
     any object).
   - Else if `key not in expected`: skip (drop the extra).
   - Else: look up `expected_type = schema.get(key)`. If non-None and
     `not isinstance(value, expected_type)`: raise
     `ValueError(f"Parameter '{key}' must be {expected_type.__name__},
     got {type(value).__name__}")`. Otherwise copy through.
6. `missing = required - set(validated.keys())`. If non-empty: raise
   `ValueError(f"Query '{query_name}' requires parameter
   '{missing.pop()}'")`. Note: only one missing name is reported (see
   Notes).
7. Return `validated`.

The function never returns `None` — on success it returns a dict that
is a subset of `params` (extras dropped). The return value is the
input to `dispatch_query(name, **validated)`.

## AC-04: `dispatch_query` — direct invocation

```python
def dispatch_query(name: str, **kwargs: Any) -> Any: ...
```

Returns `_QUERY_DISPATCH[name](**kwargs)`. Raises `KeyError` if `name`
is unknown — there is no friendly error message and no validation
(see Notes). Callers that need validation must call `validate_params`
first; the narration and web paths do exactly this:

```
validated = validate_params(name, params)   # raises ValueError on bad input
result = dispatch_query(name, **validated)  # raises KeyError only on programmer error
```

For `principal_resultant`, the dispatch triggers the lazy
`__import__("gpo_lens.merge", ...)` — the first call pays the import
cost; subsequent calls reuse Python's module cache. The lazy import is
the only deferred-cost path in the module.

## AC-05: `VALID_QUERIES` and `QUERY_REQUIRED_PARAMS` — public constants

`VALID_QUERIES: frozenset[str] = frozenset(_QUERY_DISPATCH.keys())` —
the immutable set of routable query names. Re-exported by
`narration.py` as `_VALID_QUERIES` and used to reject LLM-proposed
unknown queries (`test_route_question_unknown_query_raises`).

`QUERY_REQUIRED_PARAMS: dict[str, list[str]]` has exactly three
entries:

| Query | Required params (excl. `estate`) |
|-------|----------------------------------|
| `settings_at_som` | `["ou_path"]` |
| `effective_scope` | `["gpo_id"]` |
| `principal_resultant` | `["principal_sid"]` |

Every other query has no required params (besides the implicit
`estate`). `estate` itself is never listed in `QUERY_REQUIRED_PARAMS`
— it is always required and always passed through unvalidated (AC-03).

`_PARAM_VALIDATORS` mirrors `QUERY_REQUIRED_PARAMS` exactly, with each
param mapped to `str`:

```
{"settings_at_som": {"ou_path": str},
 "effective_scope": {"gpo_id": str},
 "principal_resultant": {"principal_sid": str}}
```

The three dicts (`_QUERY_DISPATCH`, `_QUERY_DESCRIPTIONS`,
`QUERY_REQUIRED_PARAMS`, `_PARAM_VALIDATORS`) must stay in lockstep —
adding a query requires updating all four, or the routing corpus test
will fail.

## AC-06: Determinism

- All dispatch calls are pure functions of `(name, kwargs)`. No
  randomness, no time, no environment reads, no model calls
  (`tests/_arch.py`).
- The dispatch table is a module-level constant; iteration order
  follows insertion order (CPython 3.7+). `VALID_QUERIES` is a
  `frozenset` — unordered, but membership checks are O(1).
- `_QUERY_DESCRIPTIONS` is consumed verbatim by the LLM prompt
  constructor in `narration.route_question`. Editing a description
  changes the routing menu and may shift LLM routing behavior — treat
  description text as part of the contract.
- The lazy `__import__` for `principal_resultant` is deterministic:
  Python caches imported modules, so the second call reuses the cached
  `gpo_lens.merge` module. No re-import overhead per call.

## AC-07: REST API surface (WI-057)

The dispatch table is also exposed as a versioned JSON REST API under
`/api/v1/`. The API is a thin layer: it validates params, loads the
estate, dispatches the query, serializes via `serialize_result`, and
returns JSON. The API runs the deterministic core only — no LLM calls
(it never imports `narration`).

### Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/` | none | Endpoint listing (self-documenting) |
| GET | `/api/v1/queries` | `VIEW` | List all available queries with descriptions and required params |
| GET | `/api/v1/query/{query_name}` | `VIEW` | Execute a named query |
| GET | `/api/v1/health` | none | Health check (version + DB basename) |
| GET | `/api/v1/snapshots` | `VIEW` | List saved snapshots |

### Query execution contract

`GET /api/v1/query/{query_name}` accepts required parameters as URL
query string params (e.g. `?ou_path=OU=Servers,DC=example,DC=com`).
The endpoint:

1. Checks `query_name in VALID_QUERIES` — 404 if not.
2. Collects required params (`QUERY_REQUIRED_PARAMS`) from the query
   string.
3. Validates via `validate_params` — 400 with the `ValueError` message
   if validation fails (missing required param, type mismatch).
4. Loads the estate from the DB via `store.load_estate`.
5. Dispatches via `dispatch_query`.
6. For `cpassword_scan`, masks cpassword values via
   `detection.mask_cpassword` (never surfaces raw secrets).
7. Serializes via `display.serialize_result` and returns `{"status":
   "ok", "data": <result>}`.

### Error response format

All error responses use a consistent envelope:

```
{"status": "error", "detail": "<human-readable message>"}
```

| Status | When |
|--------|------|
| 400 | Validation failure (missing required param, type mismatch, estate load error) |
| 401 | Missing/invalid auth token (when `GPO_LENS_AUTH_TOKEN` is configured) |
| 404 | Unknown query name |

### Auth

The API uses the same auth system as the web UI (`web.auth`). Endpoints
requiring `Permission.VIEW` accept a `Bearer` token via the
`Authorization` header (when `GPO_LENS_AUTH_TOKEN` is set) or allow
loopback without a token (local dev mode). The `/api/v1/health` and
`/api/v1/` endpoints are exempt — no auth required — so monitoring and
load balancers can poll without credentials.

### Versioning

All endpoints are under `/api/v1/` for future compatibility. A v2
surface (if needed) would mount under `/api/v2/` without breaking v1
consumers.

### Read-only

All API endpoints are `GET`. No `POST`/`PUT`/`DELETE` — the API never
mutates estate data or triggers ingest.
