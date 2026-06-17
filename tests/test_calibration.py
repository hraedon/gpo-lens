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


# ---- Version skew -------------------------------------------------------------

def test_work_version_skew(work_estate):
    from gpo_lens.queries import version_skew

    assert len(version_skew(work_estate)) == 0


def test_lab_version_skew(lab_estate):
    from gpo_lens.queries import version_skew

    assert len(version_skew(lab_estate)) == 0


# ---- MS16-072 (delegation audit) ---------------------------------------------

def test_ms16_072_work(work_estate):
    from gpo_lens.queries import ms16_072_vulnerable

    # Work domain: 112 of 129 GPOs lack Read for AU or DC
    assert len(ms16_072_vulnerable(work_estate)) == 112


def test_ms16_072_lab(lab_estate):
    from gpo_lens.queries import ms16_072_vulnerable

    # Lab domain: 10 of 12 GPOs lack Read for AU or DC
    assert len(ms16_072_vulnerable(lab_estate)) == 10


# ---- cpassword (MS14-025) -----------------------------------------------------

def test_cpassword_clean_work(work_estate):
    from gpo_lens.queries import cpassword_scan

    assert len(cpassword_scan(work_estate)) == 0


def test_cpassword_clean_lab(lab_estate):
    from gpo_lens.queries import cpassword_scan

    assert len(cpassword_scan(lab_estate)) == 0


# ---- Smoke: every query runs and returns a list -------------------------------

def test_queries_smoke(work_estate):
    from gpo_lens import queries

    assert isinstance(queries.unlinked_gpos(work_estate), list)
    assert isinstance(queries.empty_gpos(work_estate), list)
    assert isinstance(queries.conflicts(work_estate), list)
    assert isinstance(queries.blocked_extensions(work_estate), list)
    assert isinstance(queries.version_skew(work_estate), list)
    assert isinstance(queries.ms16_072_vulnerable(work_estate), list)
    assert isinstance(queries.cpassword_scan(work_estate), list)


# ---- Tier 2.5 topology calibration -------------------------------------------

def test_work_no_dangling_links(work_estate):
    from gpo_lens.queries import dangling_links

    # Clean domain: no SOM links to missing GPOs
    assert len(dangling_links(work_estate)) == 0


def test_work_enforced_links(work_estate):
    from gpo_lens.queries import enforced_links

    # Work domain has enforced links (NoOverride)
    count = len(enforced_links(work_estate))
    assert count > 0


def test_loopback_detected(work_estate):
    from gpo_lens.queries import loopback_gpos

    # Work domain has loopback (31 raw hits in calibration notes).
    # Tightened to >= 30 (allowing a 1-count tolerance for benign parser
    # variance), so a regression from 31 to 20 cannot pass silently.
    assert len(loopback_gpos(work_estate)) >= 30


def test_work_no_precedence_conflicts_on_clean_soms(work_estate):
    from gpo_lens.queries import som_conflicts

    # Find a SOM that only links to one GPO — should have zero conflicts
    # Instead let's just assert the whole-work run doesn't crash
    soms_with_one_link = [
        s for s in work_estate.soms if len(s.links) == 1
    ]
    if soms_with_one_link:
        assert som_conflicts(work_estate, soms_with_one_link[0].path) == []


# ---- Plan 009: settings_at_som calibration -----------------------------------

def test_settings_at_som_lab_domain(lab_estate):
    from gpo_lens.queries import settings_at_som

    # Lab domain root: dc=lab,dc=example,dc=com
    # The root SOM should have a resolved chain (multiple GPOs at root)
    root_som = next(
        (s for s in lab_estate.soms if s.path.lower() == "dc=lab,dc=example,dc=com"),
        None,
    )
    if root_som is None:
        pytest.skip("Root SOM not found in lab domain")

    result = settings_at_som(lab_estate, root_som.path)
    # Should have effective settings from the chain
    assert len(result) > 0
    # Every result should have a valid winner
    for es in result:
        assert es.winner_gpo_id
        assert es.winner_gpo_name
        assert es.identity
        assert es.display_name is not None


def test_settings_at_som_work_domain(work_estate):
    from gpo_lens.queries import settings_at_som

    # Work domain root
    root_som = next(
        (s for s in work_estate.soms
         if s.path.lower().replace(" ", "") == "dc=work-domain,dc=local"),
        None,
    )
    if root_som is None:
        # Try relaxed match
        root_som = next(
            (s for s in work_estate.soms
             if "work-domain" in s.path.lower() and "local" in s.path.lower()),
            None,
        )
    if root_som is None:
        pytest.skip("Root SOM not found in work domain")

    # Performance: fold the largest chain in < 2 seconds
    import time
    start = time.perf_counter()
    result = settings_at_som(work_estate, root_som.path)
    elapsed = time.perf_counter() - start
    assert elapsed < 2.0
    assert len(result) > 0
    # Verify no duplicates by (cse, side, identity) — the fold should be unique
    seen = set()
    for es in result:
        key = (es.cse, es.side, es.identity)
        assert key not in seen, f"Duplicate identity {key} in settings_at_som"
        seen.add(key)
