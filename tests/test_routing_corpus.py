"""Corpus tests for NL -> query routing in the ask command.

These tests validate the JSON-parse and validation path inside route_question()
by mocking call_llm to return pre-determined routing JSON.  They do NOT validate
that an actual LLM would pick the right query for a given question — that
requires the integration tests in test_narration_integration.py with a live
API key.  What they do verify:
  - route_question() correctly parses well-formed LLM responses
  - every query in _VALID_QUERIES has at least one corpus entry
  - malformed responses (bad JSON, unknown query, non-dict params) are rejected
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from gpo_lens.narration import _VALID_QUERIES, NarrationUnavailable, route_question

_CORPUS: list[tuple[str, str, dict[str, object] | None]] = [
    # Estate summary
    (
        "How many GPOs are in my estate?",
        "estate_summary",
        None,
    ),
    (
        "Give me an overview of my domain",
        "estate_summary",
        None,
    ),
    # Estate doctor
    (
        "What health issues does my estate have?",
        "estate_doctor",
        None,
    ),
    (
        "Run a hygiene check on my GPOs",
        "estate_doctor",
        None,
    ),
    # Settings at SOM with OU path
    (
        "What settings apply to OU=Workstations,DC=test,DC=local?",
        "settings_at_som",
        {"ou_path": "ou=workstations,dc=test,dc=local"},
    ),
    (
        "Show me the effective settings for OU=Servers,DC=corp,DC=local",
        "settings_at_som",
        {"ou_path": "ou=servers,dc=corp,dc=local"},
    ),
    # Settings at SOM without OU path
    (
        "What settings apply to this OU?",
        "settings_at_som",
        None,
    ),
    (
        "Show effective settings for the Workstations OU",
        "settings_at_som",
        None,
    ),
    # cpassword scan
    (
        "Which GPOs have cpasswords?",
        "cpassword_scan",
        None,
    ),
    (
        "Find encrypted passwords in my GPOs",
        "cpassword_scan",
        None,
    ),
    # Unlinked GPOs
    (
        "Which GPOs are not linked anywhere?",
        "unlinked_gpos",
        None,
    ),
    (
        "Find orphaned GPOs",
        "unlinked_gpos",
        None,
    ),
    # Empty GPOs
    (
        "Which GPOs have no settings?",
        "empty_gpos",
        None,
    ),
    (
        "Find empty GPOs",
        "empty_gpos",
        None,
    ),
    # Version skew
    (
        "Which GPOs have version mismatches?",
        "version_skew",
        None,
    ),
    (
        "Find GPOs where AD and SYSVOL versions differ",
        "version_skew",
        None,
    ),
    # Broken refs
    (
        "Which GPOs have broken references?",
        "broken_refs",
        None,
    ),
    (
        "Find missing scripts or bad UNC paths in GPOs",
        "broken_refs",
        None,
    ),
    # Enforced links
    (
        "Which GPO links are enforced?",
        "enforced_links",
        None,
    ),
    (
        "Show me NoOverride links",
        "enforced_links",
        None,
    ),
    # Dangling links
    (
        "Which links point to non-existent GPOs?",
        "dangling_links",
        None,
    ),
    (
        "Find dangling references to deleted GPOs",
        "dangling_links",
        None,
    ),
    # MS16-072 vulnerable
    (
        "Which GPOs are vulnerable to MS16-072?",
        "ms16_072_vulnerable",
        None,
    ),
    (
        "Find GPOs missing Authenticated Users read",
        "ms16_072_vulnerable",
        None,
    ),
    # Topology crosscheck
    (
        "Are there discrepancies between OU tree and SOM data?",
        "topology_crosscheck",
        None,
    ),
    (
        "Check OU vs SOM topology",
        "topology_crosscheck",
        None,
    ),
    # Disabled but populated
    (
        "Which disabled GPO sides still have settings?",
        "disabled_but_populated",
        None,
    ),
    (
        "Find GPOs with settings on disabled sides",
        "disabled_but_populated",
        None,
    ),
    # Scope honesty
    (
        "What is the effective scope of the Default Domain Policy?",
        "effective_scope",
        {"gpo_id": "Default Domain Policy"},
    ),
    (
        "Who does the lockdown GPO apply to?",
        "effective_scope",
        {"gpo_id": "lockdown"},
    ),
    (
        "Are there any orphaned WMI filters nobody is using?",
        "orphaned_wmi_filters",
        None,
    ),
    (
        "Which GPOs reference a WMI filter that doesn't exist?",
        "broken_wmi_refs",
        None,
    ),
    (
        "Show me GPOs that haven't been touched in years",
        "stale_gpos",
        None,
    ),
    (
        "Which GPOs carry dangerous configurations?",
        "danger_findings",
        None,
    ),
    (
        "What's the effective policy for user S-1-5-21-123-456-789-1001?",
        "principal_resultant",
        {"principal_sid": "S-1-5-21-123-456-789-1001"},
    ),
    (
        "How does my estate compare to the golden backup?",
        "golden_diff",
        None,
    ),
    (
        "Which ADMX policies are actually used by my GPOs?",
        "admx_coverage",
        None,
    ),
    (
        "Who can edit GPOs in this domain?",
        "delegation_rollup",
        None,
    ),
]

_UNROUTABLE: list[tuple[str, str]] = [
    (
        "What's the weather today?",
        "not a GPO question",
    ),
    (
        "Who won the World Cup?",
        "not a GPO question",
    ),
    (
        "Tell me a joke",
        "not a GPO question",
    ),
    (
        "How do I configure Azure AD?",
        "not a GPO question",
    ),
    (
        "What is the meaning of life?",
        "not a GPO question",
    ),
]


def _expected_result(query: str, params: dict[str, object] | None) -> dict[str, object]:
    if params is None:
        params = {}
    return {"query": query, "params": params}


def _mock_llm_response(
    query: str, params: dict[str, object] | None
) -> str:
    return json.dumps(_expected_result(query, params))


def _mock_llm_error(reason: str) -> str:
    return json.dumps({"error": "cannot_route", "reason": reason})


class TestRoutingCorpus:
    @pytest.mark.parametrize(
        "question,expected_query,expected_params",
        _CORPUS,
    )
    def test_route_question_maps_to_correct_query(
        self,
        question: str,
        expected_query: str,
        expected_params: dict[str, object] | None,
    ) -> None:
        mock_resp = _mock_llm_response(expected_query, expected_params)
        with patch("gpo_lens.narration.call_llm", return_value=mock_resp):
            result = route_question(question)

        assert result == _expected_result(expected_query, expected_params)

    @pytest.mark.parametrize(
        "question,reason",
        _UNROUTABLE,
    )
    def test_route_question_returns_error_for_unroutable(
        self,
        question: str,
        reason: str,
    ) -> None:
        mock_resp = _mock_llm_error(reason)
        with patch("gpo_lens.narration.call_llm", return_value=mock_resp):
            result = route_question(question)

        assert result == {"error": "cannot_route", "reason": reason}

    def test_all_valid_queries_are_covered(self) -> None:
        covered = {q for _, q, _ in _CORPUS}
        missing = _VALID_QUERIES - covered
        assert not missing, f"Missing query coverage for: {missing}"

    def test_route_question_unknown_query_raises(self) -> None:
        mock_resp = json.dumps({"query": "not_a_real_query", "params": {}})
        with patch("gpo_lens.narration.call_llm", return_value=mock_resp):
            with pytest.raises(NarrationUnavailable, match="Unknown query"):
                route_question("something weird")

    def test_route_question_invalid_json_raises(self) -> None:
        with patch("gpo_lens.narration.call_llm", return_value="not json"):
            with pytest.raises(NarrationUnavailable, match="non-JSON"):
                route_question("something")

    def test_route_question_non_dict_params_raises(self) -> None:
        mock_resp = json.dumps({"query": "estate_summary", "params": []})
        with patch("gpo_lens.narration.call_llm", return_value=mock_resp):
            with pytest.raises(NarrationUnavailable, match="non-dict params"):
                route_question("summary")
