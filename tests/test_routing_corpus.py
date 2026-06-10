"""Tests for route_question JSON parser — validates that route_question()
correctly parses LLM responses and dispatches to the right query.

Note: these tests mock call_llm, so they validate the *parser* logic, not
the LLM's routing ability. The LLM never runs; the mock supplies the JSON."""

from __future__ import annotations

import json
import os
import unittest.mock

import pytest

from gpo_lens.narration import NarrationUnavailable, route_question

ROUTING_CORPUS = [
    (
        "How many GPOs are in the estate?",
        {"query": "estate_summary", "params": {}},
    ),
    (
        "Are there any cpasswords?",
        {"query": "cpassword_scan", "params": {}},
    ),
    (
        "Which GPOs are unlinked?",
        {"query": "unlinked_gpos", "params": {}},
    ),
    (
        "Show me empty GPOs",
        {"query": "empty_gpos", "params": {}},
    ),
    (
        "Are there version skew issues?",
        {"query": "version_skew", "params": {}},
    ),
    (
        "Any broken references?",
        {"query": "broken_refs", "params": {}},
    ),
    (
        "What health issues exist?",
        {"query": "estate_doctor", "params": {}},
    ),
    (
        "Which GPOs have enforced links?",
        {"query": "enforced_links", "params": {}},
    ),
    (
        "Are there dangling links?",
        {"query": "dangling_links", "params": {}},
    ),
    (
        "Check for MS16-072 vulnerable GPOs",
        {"query": "ms16_072_vulnerable", "params": {}},
    ),
    (
        "Are there topology discrepancies?",
        {"query": "topology_crosscheck", "params": {}},
    ),
    (
        "Which GPO sides are disabled but have settings?",
        {"query": "disabled_but_populated", "params": {}},
    ),
    (
        "What settings apply to OU=Servers,DC=test,DC=local?",
        {
            "query": "settings_at_som",
            "params": {"ou_path": "OU=Servers,DC=test,DC=local"},
        },
    ),
    (
        "Any GPOs with disabled sides that still have settings?",
        {"query": "disabled_but_populated", "params": {}},
    ),
    (
        "Run a health check",
        {"query": "estate_doctor", "params": {}},
    ),
    (
        "Give me an estate overview",
        {"query": "estate_summary", "params": {}},
    ),
    (
        "Find GPOs with cpassword in them",
        {"query": "cpassword_scan", "params": {}},
    ),
    (
        "Show version mismatches between AD and SYSVOL",
        {"query": "version_skew", "params": {}},
    ),
    (
        "What's the weather like?",
        {"error": "cannot_route", "reason": "not a GPO question"},
    ),
    (
        "Delete all GPOs",
        {"error": "cannot_route", "reason": "destructive action not supported"},
    ),
]


@pytest.mark.parametrize(
    "question,expected",
    ROUTING_CORPUS,
    ids=[f"q{i}" for i in range(len(ROUTING_CORPUS))],
)
def test_routing_corpus(
    question: str, expected: dict[str, object]
) -> None:
    response_text = json.dumps(expected)
    with unittest.mock.patch.dict(
        os.environ, {"GPO_LENS_API_KEY": "test-key"}
    ):
        with unittest.mock.patch(
            "gpo_lens.narration.call_llm", return_value=response_text
        ):
            result = route_question(question)
    if "error" in expected:
        assert "error" in result
        assert result["error"] == expected["error"]
    else:
        assert result["query"] == expected["query"]
        assert result["params"] == expected["params"]


def test_route_question_no_api_key_raises() -> None:
    with unittest.mock.patch.dict(os.environ, {}, clear=True):
        with pytest.raises(NarrationUnavailable, match="No API key"):
            route_question("How many GPOs?")


def test_route_question_malformed_response() -> None:
    with unittest.mock.patch.dict(
        os.environ, {"GPO_LENS_API_KEY": "test-key"}
    ):
        with unittest.mock.patch(
            "gpo_lens.narration.call_llm", return_value="this is not json"
        ):
            with pytest.raises(NarrationUnavailable, match="non-JSON"):
                route_question("How many GPOs?")


def test_route_question_unknown_query() -> None:
    bad = json.dumps({"query": "nonexistent", "params": {}})
    with unittest.mock.patch.dict(
        os.environ, {"GPO_LENS_API_KEY": "test-key"}
    ):
        with unittest.mock.patch(
            "gpo_lens.narration.call_llm", return_value=bad
        ):
            with pytest.raises(NarrationUnavailable, match="Unknown query"):
                route_question("something weird")
