from __future__ import annotations

import re
import subprocess
import sys
import tomllib
from pathlib import Path

from gpo_lens import __version__


def test_version_sync() -> None:
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    pyproject_version = tomllib.loads(pyproject.read_text(encoding="utf-8"))[
        "project"
    ]["version"]
    assert __version__ == pyproject_version, (
        f"__init__.__version__={__version__!r} != pyproject.toml version={pyproject_version!r}"
    )


def test_changelog_top_version_matches() -> None:
    changelog = Path(__file__).resolve().parent.parent / "CHANGELOG.md"
    text = changelog.read_text(encoding="utf-8")
    match = re.search(r"^## v(\S+)", text, re.MULTILINE)
    assert match, "No version header found in CHANGELOG.md"
    changelog_version = match.group(1)
    assert __version__ == changelog_version, (
        f"__init__.__version__={__version__!r} != CHANGELOG top version={changelog_version!r}"
    )


def test_cli_version_flag() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "gpo_lens", "--version"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"Exit code {result.returncode}: {result.stderr}"
    assert __version__ in result.stdout.strip(), (
        f"CLI --version output {result.stdout.strip()!r} does not contain {__version__!r}"
    )
