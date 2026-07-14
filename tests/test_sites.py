"""AD site-linked GPO support (Plan 014)."""
from __future__ import annotations

import shutil
from pathlib import Path

from gpo_lens import ingest, queries
from gpo_lens.ingest import _parse_gplink, parse_sites

FIXTURES = Path(__file__).parent / "fixtures"


# --- gPLink parsing ---------------------------------------------------------

def test_parse_gplink_flags():
    raw = (
        "[LDAP://CN={11111111-1111-1111-1111-111111111111},...;0]"  # enabled
        "[LDAP://CN={22222222-2222-2222-2222-222222222222},...;1]"  # disabled
        "[LDAP://CN={33333333-3333-3333-3333-333333333333},...;2]"  # enforced
        "[LDAP://CN={44444444-4444-4444-4444-444444444444},...;3]"  # disabled+enforced
    )
    links = _parse_gplink(raw, "CN=Site,...")
    assert [(link.enabled, link.enforced) for link in links] == [
        (True, False),
        (False, False),
        (True, True),
        (False, True),
    ]
    assert [link.order for link in links] == [1, 2, 3, 4]
    assert links[0].gpo_id == "11111111111111111111111111111111"


def test_parse_gplink_empty():
    assert _parse_gplink("", "x") == []
    assert _parse_gplink(None, "x") == []


# --- ingest -----------------------------------------------------------------

def test_parse_sites_produces_site_soms():
    soms = parse_sites(FIXTURES / "sites.json")
    assert {s.name for s in soms} == {"Default-First-Site-Name", "Branch-Office"}
    assert all(s.container_type == "site" for s in soms)
    branch = next(s for s in soms if s.name == "Branch-Office")
    assert len(branch.links) == 1
    assert branch.links[0].enforced is True


def test_load_estate_includes_sites():
    estate = ingest.load_estate(FIXTURES)
    sites = [s for s in estate.soms if s.container_type == "site"]
    assert len(sites) == 2


def test_load_estate_without_sites_json_is_backward_compatible(tmp_path):
    dest = tmp_path / "export"
    shutil.copytree(
        FIXTURES, dest, ignore=shutil.ignore_patterns("*.sqlite3*", "__pycache__")
    )
    (dest / "sites.json").unlink()
    estate = ingest.load_estate(dest)
    assert [s for s in estate.soms if s.container_type == "site"] == []
    assert queries.has_site_links(estate) is False


# --- queries ----------------------------------------------------------------

def test_site_scopes_resolves_gpo_names():
    estate = ingest.load_estate(FIXTURES)
    scopes = queries.site_scopes(estate)
    branch = next(s for s in scopes if s.name == "Branch-Office")
    assert branch.links[0].gpo_name != branch.links[0].gpo_id  # resolved to a name
    assert branch.links[0].enforced is True


def test_has_site_links():
    estate = ingest.load_estate(FIXTURES)
    assert queries.has_site_links(estate) is True


# --- sites excluded from OU-centric views -----------------------------------

def test_sites_excluded_from_som_count_and_counted_separately():
    summary = queries.estate_summary(ingest.load_estate(FIXTURES))
    assert summary.som_count == 2          # OU/domain SOMs only
    assert summary.linked_site_count == 1  # one site with an enabled link


def test_sites_excluded_from_precedence_conflicts():
    estate = ingest.load_estate(FIXTURES)
    soms = [som for som, _ in queries.precedence_conflicts(estate)]
    assert all(som.container_type != "site" for som in soms)


# --- OU caveat --------------------------------------------------------------

def test_site_caveat_present_in_ou_scope():
    estate = ingest.load_estate(FIXTURES)
    caveats = queries.scope_caveats(estate, "dc=fakefixture,dc=local")
    assert any("site link" in c.lower() for c in caveats)


def test_no_site_caveat_without_sites(tmp_path):
    dest = tmp_path / "export"
    shutil.copytree(
        FIXTURES, dest, ignore=shutil.ignore_patterns("*.sqlite3*", "__pycache__")
    )
    (dest / "sites.json").unlink()
    estate = ingest.load_estate(dest)
    caveats = queries.scope_caveats(estate, "dc=fakefixture,dc=local")
    assert not any("site link" in c.lower() for c in caveats)
