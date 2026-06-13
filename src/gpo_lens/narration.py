"""Tier 3 narration layer — LLM-powered explanations (optional)."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from gpo_lens.query_dispatch import VALID_QUERIES as _VALID_QUERIES


class NarrationUnavailable(Exception):
    """Raised when narration cannot be produced (no API key, transport error, etc.)."""


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
    key = api_key or os.environ.get("GPO_LENS_API_KEY")
    if not key:
        raise NarrationUnavailable("No API key configured")
    url = endpoint or os.environ.get(
        "GPO_LENS_LLM_ENDPOINT",
        "https://api.anthropic.com/v1/messages",
    )
    model_name = model or os.environ.get(
        "GPO_LENS_LLM_MODEL",
        "claude-sonnet-4-20250514",
    )
    payload = json.dumps({
        "model": model_name,
        "max_tokens": max_tokens,
        "system": system_prompt,
        "messages": [{"role": "user", "content": user_prompt}],
    }).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body: dict[str, object] = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise NarrationUnavailable(
            f"LLM API returned HTTP {exc.code}: {exc.reason}"
        ) from exc
    except urllib.error.URLError as exc:
        raise NarrationUnavailable(f"LLM transport error: {exc.reason}") from exc
    except json.JSONDecodeError as exc:
        raise NarrationUnavailable(f"Malformed response: {exc}") from exc
    content = body.get("content")
    if not isinstance(content, list) or not content:
        raise NarrationUnavailable("Unexpected response: missing or empty content")
    first = content[0]
    if not isinstance(first, dict) or "text" not in first:
        raise NarrationUnavailable("Unexpected response: first content block has no text")
    text: str = first["text"]
    return text


_ROUTING_SYSTEM_PROMPT = """You are a routing assistant for a Group Policy analysis tool.
Given a user's question, determine which query function best answers it.

Available query functions:
- estate_summary: Overview of the estate (GPO count, domain, etc.)
- estate_doctor: Health/hygiene findings (cpassword, MS16-072, version skew, etc.)
- settings_at_som: Settings applied to a specific OU (requires param: "ou_path")
- cpassword_scan: GPOs containing encrypted cpasswords
- unlinked_gpos: GPOs with no links (apply nowhere)
- empty_gpos: GPOs with no settings
- version_skew: GPOs where AD and SYSVOL versions differ
- broken_refs: GPOs with broken references (UNC paths, missing scripts)
- enforced_links: GPO links that are enforced (override block-inheritance)
- dangling_links: Links to GPOs that no longer exist
- ms16_072_vulnerable: GPOs vulnerable to MS16-072 (missing Authenticated Users Read)
- topology_crosscheck: Discrepancies between OU gp_link data and SOM data
- disabled_but_populated: GPO sides that are disabled but still have settings

Respond with ONLY a JSON object:
- If routeable: {"query": "<function_name>", "params": {"param_name": "value"}}
- If not routeable: {"error": "cannot_route", "reason": "brief explanation"}

Do NOT include any other text."""


def route_question(question: str) -> dict[str, object]:
    result = call_llm(_ROUTING_SYSTEM_PROMPT, question)
    try:
        parsed: dict[str, object] = json.loads(result)
    except json.JSONDecodeError as exc:
        raise NarrationUnavailable(
            f"Routing LLM returned non-JSON: {exc}"
        ) from exc
    if not isinstance(parsed, dict):
        raise NarrationUnavailable("Routing LLM returned non-object")
    if "error" in parsed:
        return {
            "error": str(parsed.get("error", "cannot_route")),
            "reason": str(parsed.get("reason", "")),
        }
    query_name = parsed.get("query")
    if not isinstance(query_name, str) or query_name not in _VALID_QUERIES:
        raise NarrationUnavailable(
            f"Unknown query function: {query_name!r}"
        )
    params = parsed.get("params")
    if params is None:
        params = {}
    if not isinstance(params, dict):
        raise NarrationUnavailable("Routing returned non-dict params")
    return {"query": query_name, "params": params}


_SYSTEM_PROMPT = (
    "You are a Group Policy security analyst. Explain each finding in "
    "plain English: what it means, why it matters, and what to do. "
    "Preserve the severity ordering. Reference GPO names, not GUIDs. "
    "Format output as Markdown with sections for each severity tier."
)


def explain_findings(findings_json: list[dict[str, str]]) -> str:
    if not findings_json:
        return "No issues detected — the estate looks healthy."
    user_prompt = json.dumps(findings_json, indent=2)
    return call_llm(_SYSTEM_PROMPT, user_prompt)
