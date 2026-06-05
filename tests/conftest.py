"""Test fixtures.

Sample-backed fixtures extract the three artifacts the Tier-1 ingest needs
(`AllGPOs.xml`, `gp-inheritance.json`, `gpo-metadata.json`) from the gitignored
zips in ``samples/`` into a tmp dir, then build an ``Estate`` via
``ingest.load_estate``. They skip cleanly when ``samples/`` is absent, so the
suite runs anywhere — but the calibration numbers (which prove the parser against
reality) only assert when the real exports are present.

Sample identity: WORK-DOMAIN.local = work (the 129-GPO mess); lab.example.com = lab.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
_NEEDED = ("AllGPOs.xml", "gp-inheritance.json", "gpo-metadata.json")


def _find_zip(substr: str) -> Path | None:
    hits = sorted(SAMPLES.glob(f"*{substr}*.zip"))
    return hits[0] if hits else None


def _extract(zip_path: Path, dest: Path) -> Path:
    with zipfile.ZipFile(zip_path) as z:
        present = set(z.namelist())
        for name in _NEEDED:
            if name in present:
                z.extract(name, dest)
    return dest


def _estate(substr: str, label: str, tmp_factory):
    zip_path = _find_zip(substr)
    if zip_path is None:
        pytest.skip(f"{label} sample ({substr}) not present in samples/")
    src = _extract(zip_path, tmp_factory.mktemp(label))
    from gpo_lens.ingest import load_estate

    return load_estate(src)


@pytest.fixture(scope="session")
def work_estate(tmp_path_factory):
    """WORK-DOMAIN.local — the messy work domain."""
    return _estate("WORKDOMAIN", "work", tmp_path_factory)


@pytest.fixture(scope="session")
def lab_estate(tmp_path_factory):
    """lab.example.com — the clean lab domain."""
    return _estate("LABDOMAIN", "lab", tmp_path_factory)
