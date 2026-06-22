# Work Item: Event sinks (NDJSON file + Splunk HEC)

## Dependencies

- `interface_ref`: `events.query_events` (the replay path queries the
  event store and pipes results to `emit_events`).
- Consumer: `cli/_estate.py::_emit_ingest_events` (the post-ingest
  emit path; wires up the optional NDJSON file + optional HEC sink via
  env vars), `web/app.py` (no direct use today — sinks are CLI-only).
- Reference: `plans/016-splunk-change-attribution.md` (the "why" — sinks
  drain the local event store to external systems for SIEM correlation
  and long-term retention). There is **no dedicated plan file** for
  `sinks.py`; this spec is the first formal contract.

## Notes

This module hosts the **external event sinks**: an NDJSON file sink and
a Splunk HEC sender. It is a **core module**
(`tests/_arch.py::CORE_MODULES`); no `narration`/`web` imports.
Stdlib-only (`json`, `os`, `ssl`, `sys`, `threading`, `urllib`) — the
Splunk client uses `urllib.request`, not `requests` or `aiohttp`, so
the core stays dependency-free and air-gappable.

The two sinks are intentionally **independent failure domains**. The
local NDJSON file is the durable fallback; the Splunk HEC sender is the
optional SIEM integration. `emit_events` runs them sequentially and
reports each sink's success separately — an HEC outage never prevents
the local file from being written.

### Design stance — never raise

Both sinks **never raise** from the public surface. Every network /
IO / SSL failure is caught, printed to `stderr` as a `Warning:` line,
and surfaces as a `False` return value. This matches the project's
"local-first, deterministic core" stance: an external sink failure is
observable (return value + stderr) but never aborts an ingest. Callers
that need to react to failure must inspect the `dict[str, bool]` from
`emit_events`.

### Drift / known simplifications vs Plan 016

- **The HEC endpoint is `/services/collector/event`, not `/raw`.**
  `send_batch` joins individual event JSON objects with newlines and
  POSTs them to the *event* endpoint, which accepts newline-delimited
  JSON event objects. This is the documented Splunk HEC batch-event
  format. Do not "fix" this to `/raw` — the payload shape would no
  longer parse.
- **`HecSink._post` returns True only on HTTP 200.** Splunk HEC may
  return `201 Created` or `202 Accepted` for accepted batches — those
  are reported as `False`. This is conservative; in practice Splunk
  returns `200` for the JSON event endpoint.
- **`HecSink.send_batch([])` returns `True` without a network call.**
  Empty-list short-circuit. Useful for "send if we have anything"
  call sites.
- **`HecSink.verify_tls=False` disables all TLS verification.** When
  set, `ssl.create_default_context()` is configured with
  `check_hostname=False` and `verify_mode=ssl.CERT_NONE`. This is the
  "lab CA / self-signed HEC" escape hatch. Production should leave
  `verify_tls=True`.
- **`GPO_LENS_HEC_VERIFY_TLS` is matched as `.lower() != "false"`.**
  So `"False"`, `"FALSE"`, `"false"` all disable TLS verification;
  every other value (including `"0"`, `"no"`, `""`) keeps it on. The
  default when the env var is unset is `"true"` (verify on).
- **`HecSink.from_env()` returns `None` silently** when `GPO_LENS_HEC_URL`
  or `GPO_LENS_HEC_TOKEN` is unset or empty. The caller is expected to
  treat `None` as "no HEC sink configured" and skip HEC emission.
- **`NdjsonSink` opens the file in append mode (`"a"`).** A new
  process append continues after an old process's lines; the file is
  never truncated. `__enter__` uses `newline="\n"` so LF is enforced
  even on Windows (CRLF would corrupt NDJSON consumers that split on
  `\n` and leave a trailing `\r`).
- **`NdjsonSink.write` and `write_batch` raise outside a `with` block.**
  Both check `self._fh is None` and raise `RuntimeError("… use 'with'
  block")`. The `__enter__`/`__exit__` contract is load-bearing — there
  is no fallback path that lazily opens the file.
- **`NdjsonSink.__enter__` re-opens if already open** — closes the
  existing fh first, then opens fresh. This "reset" semantic means a
  second `with` block on the same sink instance truncates the in-memory
  state but never truncates the file (still append mode).
- **Errors print to `stderr`, not the `logging` framework.** Consistent
  with the stdlib-only, no-deps stance. A caller that wants structured
  failure handling must read the `dict[str, bool]` return, not parse
  stderr.
- **No `__all__`.** Public exports: `NdjsonSink`, `HecSink`,
  `emit_events`.

## Module map

`src/gpo_lens/sinks.py` — stdlib-only (`json`, `os`, `ssl`, `sys`,
`threading`, `urllib`, `typing`). Core module (`tests/_arch.py`); no
`narration`/`web` imports.

| Public surface | Role |
|----------------|------|
| `NdjsonSink` (class) | Append-mode, thread-safe, context-managed NDJSON writer. |
| `HecSink` (class) | Splunk HEC v1 sender; stdlib urllib + ssl. |
| `emit_events(events, *, ndjson_path=None, hec_sink=None) -> dict[str, bool]` | Fan-out helper. Runs both sinks, reports each result. |

`HecSink.from_env()` is a `@classmethod` factory. `NdjsonSink` /
`HecSink` instance methods: `write`, `write_batch` (NdjsonSink);
`send`, `send_batch` (HecSink).

---

## AC-01: Module purity and import boundary

`sinks.py` is a core module. Imports: stdlib only (`json`, `os`, `ssl`,
`sys`, `threading`, `urllib.error`, `urllib.request`, `typing`). Must
never import `gpo_lens.narration` or `gpo_lens.web`
(`tests/_arch.py::forbidden_imports_in("sinks")`). No `gpo_lens.*`
imports at runtime — the module is fully standalone.

## AC-02: `NdjsonSink` — context-manager lifecycle

```python
class NdjsonSink:
    def __init__(self, path: str) -> None: ...
    def __enter__(self) -> NdjsonSink: ...
    def __exit__(self, *args: object) -> None: ...
```

- `__init__` stores `self.path`, creates a `threading.Lock`, sets
  `self._closed = False`, `self._fh = None`. Does NOT open the file.
- `__enter__`:
  - If `self._fh is not None and not self._closed`: close the existing
    fh first (reset semantic — see Notes).
  - Set `self._closed = False`.
  - `self._fh = open(self.path, "a", encoding="utf-8", newline="\n")`
    — append mode, UTF-8, LF newlines even on Windows.
  - Return `self`.
- `__exit__(*args)`: calls `self.close()` regardless of whether an
  exception was raised.

`close()` is idempotent: takes the lock, if `self._closed` returns;
else sets `self._closed = True` and closes the fh if non-None.

## AC-03: `NdjsonSink.write` and `write_batch`

```python
def write(self, event: dict[str, Any]) -> None: ...
def write_batch(self, events: list[dict[str, Any]]) -> None: ...
```

Both check `self._closed` first (return immediately if closed) and
`self._fh is None` (raise `RuntimeError("NdjsonSink.write() called
outside context manager; use 'with' block")` — same message for
`write_batch`, see Notes). Then:

- `write`: serialize `event` via `json.dumps(event, sort_keys=True)`,
  take the lock, double-check `self._closed`/`self._fh` under the lock,
  write `line + "\n"`, flush.
- `write_batch`: take the lock, double-check, then for each event
  `self._fh.write(json.dumps(event, sort_keys=True) + "\n")`, flush
  once at the end.

Both flush after writing — the on-disk file is up-to-date as soon as
the call returns. JSON serialization uses `sort_keys=True` (canonical
key order; deterministic file content for diff/replay testing).

## AC-04: `NdjsonSink` thread safety

A single `threading.Lock` (`self._lock`) guards every fh mutation. The
"check, then act" pattern is repeated under the lock — `write` checks
`self._closed` outside the lock for fast-path return, then re-checks
inside the lock before touching the fh. This makes `close()`
race-safe against concurrent `write`/`write_batch`: a writer that
loses the race to `close()` returns silently (no exception) instead of
writing to a closed fh (`test_thread_safety`).

## AC-05: `HecSink` — construction and `from_env`

```python
class HecSink:
    def __init__(
        self, url: str, token: str, *,
        verify_tls: bool = True, timeout: int = 30,
    ) -> None: ...
    @classmethod
    def from_env(cls) -> HecSink | None: ...
```

`__init__`:
- `self.url = url.rstrip("/")` — strip trailing slashes so endpoint
  construction is deterministic.
- `self.token = token`, `self.verify_tls = verify_tls`,
  `self.timeout = timeout`.

`from_env()`:
- `hec_url = os.environ.get("GPO_LENS_HEC_URL")`,
  `hec_token = os.environ.get("GPO_LENS_HEC_TOKEN")`.
- If either is empty/missing: return `None` (silent — caller treats as
  "no HEC configured").
- `verify = os.environ.get("GPO_LENS_HEC_VERIFY_TLS", "true").lower()
  != "false"` — only the literal `"false"` (any case) disables TLS
  verification; everything else (including `"0"`, unset) leaves it on.
- Return `cls(url=hec_url, token=hec_token, verify_tls=verify)`.

## AC-06: `HecSink.send` — single-event POST

```python
def send(self, event: dict[str, Any]) -> bool: ...
```

- `payload = json.dumps({"event": event, "sourcetype":
  "gpo_lens:change"})`. The sourcetype is **hardcoded** — every event
  from gpo-lens arrives at Splunk with sourcetype `gpo_lens:change`.
- Return `self._post(payload)`.

`_post(payload: str) -> bool`:
- Endpoint: `f"{self.url}/services/collector/event"`.
- Body: `payload.encode("utf-8")`.
- Headers: `{"Authorization": f"Splunk {self.token}",
  "Content-Type": "application/json"}`.
- Method: `POST`.
- If `not self.verify_tls`: build an `ssl.create_default_context()`
  with `check_hostname=False` and `verify_mode=ssl.CERT_NONE`, pass as
  `context=ctx`. Else `ctx=None`.
- `urllib.request.urlopen(req, timeout=self.timeout, [context=ctx])`.
- Return `resp.getcode() == 200` — True only on HTTP 200 (see Notes).
- On `ssl.SSLError` / `OSError`: print
  `f"Warning: HEC SSL/socket error: {exc}"` to stderr, return False.
- On `urllib.error.HTTPError`: print
  `f"Warning: HEC returned HTTP {exc.code}"`, return False.
- On `urllib.error.URLError`: print
  `f"Warning: HEC transport error: {exc.reason}"`, return False.
- On `TimeoutError`: print `"Warning: HEC request timed out"`, return
  False.

The function never raises.

## AC-07: `HecSink.send_batch` — newline-joined event POST

```python
def send_batch(self, events: list[dict[str, Any]]) -> bool: ...
```

- If `not events`: return `True` without a network call (empty-list
  short-circuit — see Notes).
- `payload = "\n".join(json.dumps({"event": e, "sourcetype":
  "gpo_lens:change"}) for e in events)` — newline-delimited JSON event
  objects (the Splunk HEC event endpoint accepts this batch format).
- Return `self._post(payload)`.

Same exception handling and 200-only success rule as `send` (AC-06).

## AC-08: `emit_events` — fan-out helper

```python
def emit_events(
    events: list[dict[str, Any]],
    *,
    ndjson_path: str | None = None,
    hec_sink: HecSink | None = None,
) -> dict[str, bool]: ...
```

- Initialize `results = {"ndjson": False, "hec": False}`.
- If `ndjson_path` is non-None:
  - Try `with NdjsonSink(ndjson_path) as sink: sink.write_batch(events)`.
    On success: `results["ndjson"] = True`.
  - On any `Exception`: print `f"Warning: NDJSON sink failed: {exc}"`
    to stderr, leave `results["ndjson"] = False`.
- If `hec_sink` is non-None:
  - Try `results["hec"] = hec_sink.send_batch(events)`.
  - On any `Exception`: print `f"Warning: HEC sink failed: {exc}"` to
    stderr, leave `results["hec"] = False`.
- Return `results`.

**NDJSON runs before HEC.** The local file is the durable fallback; an
HEC outage never blocks it. The two sinks are independent — one's
failure does not skip the other (`test_emit_continues_on_sink_failure`).

## AC-09: Replay contract — `query_events` output is `emit_events` input

The dict shape returned by `events.query_events` (`{id, timestamp,
event_type, schema_version, payload}`) is exactly the dict shape
`emit_events` / `NdjsonSink.write` / `HecSink.send` consume. A replay
is a one-liner: `emit_events(query_events(conn, limit=N),
ndjson_path=path)`. The serialized NDJSON line is
`json.dumps(event_dict, sort_keys=True)`, so the on-disk representation
is canonical and diffable across runs
(`tests/test_sinks.py::TestReplay`).

## AC-10: Determinism and "never raise" invariant

- All JSON serialization uses `sort_keys=True` — canonical output
  regardless of dict construction order.
- `NdjsonSink` flushes after every `write` / `write_batch` — the file
  is durable up to the OS page cache as soon as the call returns.
- Every public method on `HecSink` and `NdjsonSink`, plus
  `emit_events`, returns normally on every code path. Failures surface
  as `False` returns (HecSink / emit_events) or silent no-ops
  (NdjsonSink after `close()`); the only raised exception is
  `NdjsonSink.write`/`write_batch` outside a `with` block (programmer
  error, not a runtime failure mode).
- No time-based decisions outside the explicit `timeout` on
  `HecSink._post` (`urlopen` honors it). No randomness.
- The hardcoded sourcetype `"gpo_lens:change"` and endpoint suffix
  `/services/collector/event` are wire-protocol contracts — changing
  either breaks Splunk-side parsing.
