# Work Item: Narration Layer (Tier 3 — LLM-powered explanation)

## Dependencies

- `interface_ref`: `queries` (DoctorFinding JSON), `cli` (subcommand wiring)

## Charter constraints

1. **No AI in the truth path.** The deterministic core (model, normalize, ingest,
   store, queries) must produce identical output with or without this module.
   The narration layer may never be imported by a core module.
2. **Degrade to facts.** When no API key is configured, narration surfaces print
   the raw deterministic output unchanged and exit 0. Never block, never error.
3. **Provenance.** Every narrated claim must be traceable to an input fact (a
   DoctorFinding field, a Setting identity, etc.). The prompt construction must
   include the raw facts verbatim; the narration merely restates them in plain
   English.
4. **Optional transport.** Default endpoint is the Anthropic Messages API.
   Configurable via `GPO_LENS_LLM_ENDPOINT` and `GPO_LENS_LLM_MODEL` env vars.
   Core stays stdlib-only; narration may use `urllib.request` (stdlib) or
   optional `httpx`/`requests` if available.

## Architecture boundary

```
src/gpo_lens/
    model.py          # core — must NOT import narration
    normalize.py      # core
    ingest.py         # core
    store.py          # core
    queries.py        # core
    admx_parser.py    # core
    cli.py            # thin shell — MAY import narration (guarded)
    display.py        # core
    report.py         # core
    narration.py      # Tier 3 — may import model, queries; must NOT be imported by core
```

An architecture test must assert: none of the core modules (`model`, `normalize`,
`ingest`, `store`, `queries`, `admx_parser`, `display`, `report`) contain the
string `"narration"` in any `import` statement.

## Transport contract

```python
def call_llm(
    system_prompt: str,
    user_prompt: str,
    *,
    api_key: str | None = None,
    endpoint: str | None = None,
    model: str | None = None,
    max_tokens: int = 2048,
    timeout: int = 30,
) -> str:
    ...
```

- `api_key`: read from `GPO_LENS_API_KEY` env var if not passed.
- `endpoint`: read from `GPO_LENS_LLM_ENDPOINT` env var; defaults to
  `https://api.anthropic.com/v1/messages`.
- `model`: read from `GPO_LENS_LLM_MODEL`; defaults to `claude-sonnet-4-20250514`.
- Returns the assistant's text content.
- Raises `NarrationUnavailable` (a custom exception) if no key or on any
  transport error. Callers catch this and degrade to raw output.

## Narration targets

### WI-C.2: `doctor --explain`

**Input:** the JSON array already produced by `estate_doctor` (list of dicts with
severity, category, gpo_id, gpo_name, summary, detail).

**Prompt strategy:**
1. System prompt: "You are a Group Policy security analyst. Explain each finding
   in plain English: what it means, why it matters, and what to do. Preserve the
   severity ordering. Reference GPO names, not GUIDs."
2. User prompt: the full JSON findings array, verbatim.
3. Output: Markdown-structured explanation (one section per severity tier).

**CLI wiring:** `doctor` subcommand gains an `--explain` flag. When set:
1. Run `estate_doctor` as normal.
2. If `GPO_LENS_API_KEY` is set, call the narration layer and print the result.
3. If not set, print the standard text/JSON output with a footer:
   "Set GPO_LENS_API_KEY to enable AI-powered explanations."

**AC-C2-01:** `doctor --explain` with a valid API key produces Markdown narration
         that mentions at least one GPO name from the findings.
**AC-C2-02:** `doctor --explain` without an API key prints standard doctor output
         plus a "set API key" footer, exits 0.
**AC-C2-03:** `doctor --explain --json` with a valid API key adds a top-level
         `"narration"` key containing the LLM output alongside the `"findings"` array.
**AC-C2-04:** Architecture test: core modules have zero imports of `narration`.
**AC-C2-05:** When the LLM call fails (timeout, 429, etc.), output degrades to
         standard doctor output with no traceback.

### WI-C.3: `gpo-lens ask` (NL query routing)

**Input:** a free-text question in English.

**Routing strategy:**
1. System prompt describes the available query primitives and their parameters:
   - `estate_summary` → estate overview
   - `estate_doctor` → health findings
   - `settings_at_som` (needs: OU path) → settings applied to an OU
   - `cpassword_scan` → cpassword findings
   - `unlinked_gpos` → unlinked GPOs
   - `empty_gpos` → empty GPOs
   - `version_skew` → version-skew GPOs
   - `broken_refs` → broken references
   - `baseline_diff` (needs: baseline path) → baseline comparison
   - `enforced_links` → enforced links
   - `dangling_links` → dangling links
   - `ms16_072_vulnerable` → MS16-072 vulnerable GPOs
   - `topology_crosscheck` → topology discrepancies
   - `disabled_but_populated` → disabled-but-populated sides
2. User prompt: the question.
3. LLM responds with a JSON object: `{"query": "<name>", "params": {...}}` or
   `{"error": "cannot_route"}` if the question doesn't map.
4. The CLI validates the response, calls the named query function with the
   extracted params, and prints results (optionally narrated).

**CLI wiring:** new `ask` subcommand with a positional `question` argument and
optional `--no-narrate` flag (just show raw query output).

**AC-C3-01:** A test corpus of ~20 NL questions routes to the correct query
         primitive with correct parameters.
**AC-C3-02:** Unroutable questions produce `{"error": "cannot_route"}`, not
         hallucinated answers.
**AC-C3-03:** `ask` without API key prints an error message and exits non-zero
         (unlike `doctor --explain`, this command cannot function without the LLM).
**AC-C3-04:** Routed query results are printed using existing display helpers
         when `--no-narrate` is set.

## Test strategy

- **Unit tests** mock `call_llm` to return canned text. No network calls.
- **Architecture test** scans core module source for `import.*narration`.
- **Integration marker** (`tests/test_narration_integration.py`): skips unless
  `GPO_LENS_API_KEY` is set. Hits the real endpoint with a small prompt.
- **Routing corpus** (`tests/test_routing_corpus.py`): 20 question/answer pairs
  that validate the NL→query mapping. Mocks the LLM to return the expected JSON.

## File layout

```
src/gpo_lens/
    narration.py              # call_llm, explain_findings, route_question
tests/
    test_narration.py         # unit tests (mocked LLM)
    test_narration_integration.py  # integration (skips without API key)
    test_routing_corpus.py    # NL routing corpus
```
