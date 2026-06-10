"""Tests for the Tier 3 narration layer."""

from __future__ import annotations

import json
import os
import re
from unittest.mock import patch

import pytest

from gpo_lens.narration import NarrationUnavailable, call_llm, explain_findings


class TestCallLlm:
    def test_call_llm_reads_env_key(self) -> None:
        with patch.dict(os.environ, {"GPO_LENS_API_KEY": "test-key-123"}):
            with patch("gpo_lens.narration.urllib.request.urlopen") as mock_urlopen:
                mock_resp = mock_urlopen.return_value.__enter__.return_value
                mock_resp.read.return_value = json.dumps({
                    "content": [{"type": "text", "text": "hello"}],
                }).encode("utf-8")
                result = call_llm("sys", "user")
                assert result == "hello"
                req = mock_urlopen.call_args[0][0]
                assert req.get_header("X-api-key") == "test-key-123"

    def test_call_llm_no_key_raises(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(NarrationUnavailable, match="No API key"):
                call_llm("sys", "user")

    def test_call_llm_http_error_raises(self) -> None:
        import urllib.error

        with patch.dict(os.environ, {"GPO_LENS_API_KEY": "k"}):
            with patch("gpo_lens.narration.urllib.request.urlopen") as mock_urlopen:
                mock_urlopen.side_effect = urllib.error.HTTPError(
                    "http://x", 500, "Server Error", {}, None,
                )
                with pytest.raises(NarrationUnavailable):
                    call_llm("sys", "user")

    def test_call_llm_timeout_raises(self) -> None:
        import urllib.error

        with patch.dict(os.environ, {"GPO_LENS_API_KEY": "k"}):
            with patch("gpo_lens.narration.urllib.request.urlopen") as mock_urlopen:
                mock_urlopen.side_effect = urllib.error.URLError("timed out")
                with pytest.raises(NarrationUnavailable):
                    call_llm("sys", "user")


class TestExplainFindings:
    def test_explain_findings_returns_narration(self) -> None:
        canned = "## CRITICAL\nGPO Alpha has a cpassword issue."
        with patch("gpo_lens.narration.call_llm", return_value=canned):
            findings = [
                {
                    "severity": "critical",
                    "category": "cpassword",
                    "gpo_id": "aaa",
                    "gpo_name": "GPO Alpha",
                    "summary": "cpassword found",
                    "detail": "encrypted password in preferences",
                },
            ]
            result = explain_findings(findings)
            assert result == canned

    def test_explain_findings_no_api_key(self) -> None:
        with patch(
            "gpo_lens.narration.call_llm",
            side_effect=NarrationUnavailable("No API key"),
        ):
            with pytest.raises(NarrationUnavailable):
                explain_findings([{"severity": "info", "category": "test",
                                   "gpo_id": "x", "gpo_name": "Y",
                                   "summary": "s", "detail": ""}])


    def test_cli_does_not_import_narration_at_module_level(self) -> None:
        import ast

        import gpo_lens.cli as cli_mod

        filepath = cli_mod.__file__
        with open(filepath) as fh:
            tree = ast.parse(fh.read())
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert "narration" not in alias.name
            elif isinstance(node, ast.ImportFrom):
                assert "narration" not in (node.module or "")


class TestArchitecture:
    @pytest.mark.parametrize("module_name", [
        "model",
        "normalize",
        "ingest",
        "store",
        "queries",
        "admx_parser",
        "display",
        "report",
    ])
    def test_core_modules_do_not_import_narration(self, module_name: str) -> None:
        import gpo_lens

        pkg_dir = os.path.dirname(gpo_lens.__file__)
        filepath = os.path.join(pkg_dir, f"{module_name}.py")
        if not os.path.exists(filepath):
            pytest.skip(f"{filepath} not found")
        with open(filepath) as fh:
            source = fh.read()
        assert not re.search(r"import.*narration", source), (
            f"{module_name}.py contains a narration import"
        )
