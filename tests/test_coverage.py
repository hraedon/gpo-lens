"""Coverage reconciliation — naming GPOs the collector could not read (Plan 015)."""
from __future__ import annotations

import json
import shutil
import sqlite3
from pathlib import Path

from gpo_lens import ingest, queries, store

FIXTURES = Path(__file__).parent / "fixtures"
STRIPPED = "{DEADBEEF-0000-0000-0000-000000000001}"  # a GUID not in the fixture estate


def _export_with(tmp_path, *, inventory=None, errors=None) -> Path:
    dest = tmp_path / "export"
    shutil.copytree(FIXTURES, dest)
    if inventory is not None:
        (dest / "gpo-inventory.json").write_text(json.dumps(inventory))
    if errors is not None:
        (dest / "collection-errors.json").write_text(json.dumps(errors))
    return dest


def test_no_manifests_means_no_gaps(tmp_path):
    # Backward compatible: an export without the manifests reconciles to nothing.
    est = ingest.load_estate(_export_with(tmp_path))
    assert est.coverage_gaps == []


def test_inventory_reconciliation_flags_inaccessible(tmp_path):
    base = ingest.load_estate(FIXTURES)
    inventory = [{"Id": g.id, "DisplayName": g.name} for g in base.gpos]
    inventory.append({"Id": STRIPPED, "DisplayName": "Stripped GPO"})
    est = ingest.load_estate(_export_with(tmp_path, inventory=inventory))
    gaps = [g for g in est.coverage_gaps if g.kind == "inaccessible"]
    assert len(gaps) == 1
    assert gaps[0].gpo_id == "deadbeef-0000-0000-0000-000000000001"
    assert gaps[0].display_name == "Stripped GPO"


def test_collection_errors_flagged(tmp_path):
    errors = [{"GpoId": "{CAFE0000-0000-0000-0000-000000000002}",
               "DisplayName": "Failed GPO", "Stage": "report", "Error": "Access is denied"}]
    est = ingest.load_estate(_export_with(tmp_path, errors=errors))
    gaps = [g for g in est.coverage_gaps if g.kind == "collection_error"]
    assert len(gaps) == 1
    assert "denied" in gaps[0].detail.lower()


def test_error_for_a_collected_gpo_is_not_a_gap(tmp_path):
    base = ingest.load_estate(FIXTURES)
    collected_id = next(iter(base.gpos)).id
    errors = [{"GpoId": collected_id, "Stage": "report", "Error": "stale"}]
    est = ingest.load_estate(_export_with(tmp_path, errors=errors))
    assert all(g.gpo_id != collected_id for g in est.coverage_gaps)


def test_inventory_entry_for_collected_gpo_is_not_a_gap(tmp_path):
    base = ingest.load_estate(FIXTURES)
    inventory = [{"Id": g.id, "DisplayName": g.name} for g in base.gpos]  # all readable
    est = ingest.load_estate(_export_with(tmp_path, inventory=inventory))
    assert est.coverage_gaps == []


def test_store_roundtrip(tmp_path):
    inventory = [{"Id": STRIPPED, "DisplayName": "Stripped"}]
    est = ingest.load_estate(_export_with(tmp_path, inventory=inventory))
    db = tmp_path / "c.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)
    store.save_estate(conn, est)
    est2 = store.load_estate(conn)
    conn.close()
    assert {(g.gpo_id, g.kind) for g in est2.coverage_gaps} == \
           {(g.gpo_id, g.kind) for g in est.coverage_gaps}
    assert est2.coverage_gaps


def test_doctor_and_summary_surface_gaps(tmp_path):
    inventory = [{"Id": STRIPPED, "DisplayName": "Stripped"}]
    est = ingest.load_estate(_export_with(tmp_path, inventory=inventory))
    assert queries.estate_summary(est).coverage_gap_count == 1
    findings = queries.estate_doctor(est)
    cov = [f for f in findings if f.category == "coverage_gap"]
    assert len(cov) == 1
    assert cov[0].severity == "high"
