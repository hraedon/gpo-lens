"""Integration tests for the narration layer — hits real LLM endpoint.

These tests are skipped unless GPO_LENS_API_KEY is set.  They validate that
the real LLM endpoint responds sensibly, complementing the unit tests that
mock call_llm.
"""

from __future__ import annotations

import os
import sqlite3

import pytest

from gpo_lens import model, store

_SKIP_REASON = "GPO_LENS_API_KEY not set"


@pytest.fixture
def db_with_findings(tmp_path):
    db = tmp_path / "narration_int.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)
    estate = model.Estate(
        domain="test.local",
        gpos=[
            model.Gpo(
                id="aaa-bbb",
                name="GPO Alpha",
                domain="test.local",
                created=None,
                modified=None,
                read=None,
                computer_enabled=True,
                user_enabled=True,
                computer_ver_ds=1,
                computer_ver_sysvol=2,
                user_ver_ds=0,
                user_ver_sysvol=0,
                sddl=None,
                owner="BUILTIN\\Admins",
                filter_data_available=False,
                wmi_filter=None,
                sysvol_path=None,
            ),
        ],
    )
    store.save_estate(conn, estate)
    conn.close()
    return db


@pytest.mark.skipif(
    not os.environ.get("GPO_LENS_API_KEY"),
    reason=_SKIP_REASON,
)
class TestRealEndpoint:
    def test_call_llm_real_endpoint(self) -> None:
        from gpo_lens.narration import call_llm

        result = call_llm(
            "You are a helpful assistant. Reply with exactly: hello",
            "Say hello.",
            max_tokens=32,
        )
        assert isinstance(result, str)
        assert len(result) > 0

    def test_route_question_real_routes_correctly(self) -> None:
        from gpo_lens.narration import _VALID_QUERIES, route_question

        result = route_question("How many GPOs are in my estate?")
        assert isinstance(result, dict)
        assert "query" in result
        assert isinstance(result["query"], str)
        assert result["query"] in _VALID_QUERIES, (
            f"LLM routed to unknown query: {result['query']}"
        )
        assert "params" in result
        assert isinstance(result["params"], dict)

    def test_route_question_real_cpassword(self) -> None:
        from gpo_lens.narration import route_question

        result = route_question("Which GPOs contain encrypted passwords?")
        assert isinstance(result, dict)
        assert result.get("query") == "cpassword_scan"

    def test_route_question_real_unroutable(self) -> None:
        from gpo_lens.narration import route_question

        result = route_question("What is the capital of France?")
        assert isinstance(result, dict)
        assert "error" in result
