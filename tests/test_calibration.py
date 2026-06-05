"""Calibration: the parser must reproduce numbers measured from the real exports.

These are the acceptance bar for ingest + queries. Numbers are observed facts
about the two sample domains (work = WORK-DOMAIN.local, lab = lab.example.com), not
targets to fit. Marked ``samples`` — they skip when the exports are absent.
"""

from __future__ import annotations

import json

import pytest

pytestmark = pytest.mark.samples


# ---- GPO counts ---------------------------------------------------------------

def test_work_gpo_count(work_estate):
    assert len(work_estate.gpos) == 129


def test_lab_gpo_count(lab_estate):
    assert len(lab_estate.gpos) == 12


def test_no_duplicate_display_names(work_estate, lab_estate):
    for estate in (work_estate, lab_estate):
        names = [g.name for g in estate.gpos]
        assert len(names) == len(set(names))


# ---- Topology -----------------------------------------------------------------

def test_work_som_counts(work_estate):
    assert len(work_estate.soms) == 1551
    assert sum(1 for s in work_estate.soms if s.inheritance_blocked) == 12


def test_lab_som_counts(lab_estate):
    assert len(lab_estate.soms) == 28
    assert sum(1 for s in lab_estate.soms if s.inheritance_blocked) == 3


# ---- Hygiene signals (queries) ------------------------------------------------

def test_disabled_but_populated(work_estate, lab_estate):
    from gpo_lens.queries import disabled_but_populated

    assert len(disabled_but_populated(work_estate)) == 6
    assert disabled_but_populated(lab_estate) == []


def test_enforced_flag_is_boolean(work_estate):
    # LinksTo/NoOverride -> GpoLink.enforced; ensure links parsed and typed.
    links = [link for g in work_estate.gpos for link in g.links]
    assert links
    assert all(isinstance(link.enforced, bool) for link in links)


# ---- Security clean (MS14-025 / structured CSE) -------------------------------

def test_loopback_is_present_somewhere(work_estate):
    # Work has loopback configured (31 raw hits). It must survive ingest, whether
    # via a parsed display field or preserved in `raw`.
    from gpo_lens.queries import who_sets

    def raw_has(term: str) -> bool:
        term = term.lower()
        return any(
            term in json.dumps(s.raw).lower()
            for g in work_estate.gpos
            for s in g.settings
        )

    assert who_sets(work_estate, "loopback") or raw_has("loopback")


# ---- Smoke: every query runs and returns a list -------------------------------

def test_queries_smoke(work_estate):
    from gpo_lens import queries

    assert isinstance(queries.unlinked_gpos(work_estate), list)
    assert isinstance(queries.empty_gpos(work_estate), list)
    assert isinstance(queries.conflicts(work_estate), list)
    assert isinstance(queries.blocked_extensions(work_estate), list)
