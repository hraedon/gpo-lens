"""Unit tests for the report builder."""

from __future__ import annotations

from pathlib import Path

import pytest

from gpo_lens import model, queries
from gpo_lens.ingest import load_estate
from gpo_lens.report import generate_report, write_report

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture(scope="session")
def fixture_estate():
    return load_estate(FIXTURE_DIR)


def test_report_md_contains_summary(fixture_estate):
    report = generate_report(fixture_estate, format="md")
    assert "# Estate Report: fakefixture.local" in report
    assert "## Summary" in report
    assert "| Domain | fakefixture.local |" in report


def test_report_md_contains_doctor_findings(fixture_estate):
    report = generate_report(fixture_estate, format="md")
    assert "## Doctor Findings" in report
    findings = queries.estate_doctor(fixture_estate)
    # critical and high findings should be present
    critical = [f for f in findings if f.severity == "critical"]
    high = [f for f in findings if f.severity == "high"]
    if critical:
        assert "### CRITICAL" in report
    if high:
        assert "### HIGH" in report


def test_report_html_contains_css(fixture_estate):
    report = generate_report(fixture_estate, format="html")
    assert "<!DOCTYPE html>" in report
    assert "<style>" in report
    assert "@media print" in report
    assert "Estate Report: fakefixture.local" in report


def test_report_with_baseline(fixture_estate):
    # Build a simple baseline from one setting in the estate
    baseline = [
        queries.BaselineSetting(
            side="Computer",
            cse="Registry",
            identity=r"HKLM\Software\Fake:BadValue",
            display_name="FakeBadValue",
            expected_value="wrong_value",
        ),
    ]
    report = generate_report(
        fixture_estate, baseline=queries.baseline_diff(fixture_estate, baseline), format="md"
    )
    assert "## Baseline Compliance" in report
    assert "Compliance:" in report


def test_report_with_changelog(tmp_path):
    import sqlite3

    from gpo_lens import store

    db = tmp_path / "changelog.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)
    estate = model.Estate(
        domain="test.local",
        gpos=[
            model.Gpo(
                id="aaa-bbb", name="GPO A", domain="test.local",
                created=None, modified=None, read=None,
                computer_enabled=True, user_enabled=True,
                computer_ver_ds=1, computer_ver_sysvol=2,
                user_ver_ds=0, user_ver_sysvol=0,
                sddl=None, owner=None, filter_data_available=False,
                wmi_filter=None, sysvol_path=None,
                settings=[
                    model.Setting(
                        gpo_id="aaa-bbb", side="Computer", cse="Registry",
                        identity="Setting1", display_name="Setting1",
                        display_value="old", raw={}, from_disabled_side=False,
                    ),
                ],
            ),
        ],
    )
    sid_a = store.save_estate(conn, estate)
    # mutate
    estate.gpos[0].settings[0] = model.Setting(
        gpo_id="aaa-bbb", side="Computer", cse="Registry",
        identity="Setting1", display_name="Setting1",
        display_value="new", raw={}, from_disabled_side=False,
    )
    sid_b = store.save_estate(conn, estate)
    changelog = queries.snapshot_changelog(conn, sid_a, sid_b)
    conn.close()

    report = generate_report(
        estate, changelog_entries=changelog, format="md"
    )
    assert "## Change Log" in report
    assert "GPO A" in report


def test_report_file_written(tmp_path, fixture_estate):
    out = tmp_path / "report.md"
    write_report(fixture_estate, out, format="md")
    assert out.exists()
    text = out.read_text()
    assert "# Estate Report:" in text


def test_report_html_file_written(tmp_path, fixture_estate):
    out = tmp_path / "report.html"
    write_report(fixture_estate, out, format="html")
    assert out.exists()
    text = out.read_text()
    assert "<!DOCTYPE html>" in text
