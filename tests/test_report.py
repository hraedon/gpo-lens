"""Unit tests for the report builder."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from gpo_lens import model, queries
from gpo_lens.ingest import load_estate
from gpo_lens.report import (
    _md_code,
    generate_html,
    generate_markdown,
    generate_report,
    write_report,
)

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture(scope="session")
def fixture_estate():
    return load_estate(FIXTURE_DIR)


def test_generate_markdown_contains_summary(fixture_estate):
    report = generate_markdown(fixture_estate)
    assert "# Estate Report: fakefixture.local" in report
    assert "## Executive Summary" in report
    assert "| Domain | fakefixture.local |" in report


def test_generate_markdown_contains_hygiene_findings(fixture_estate):
    report = generate_markdown(fixture_estate)
    assert "## Hygiene Findings" in report
    findings = queries.estate_doctor(fixture_estate)
    critical = [f for f in findings if f.severity == "critical"]
    high = [f for f in findings if f.severity == "high"]
    if critical:
        assert "### CRITICAL" in report
    if high:
        assert "### HIGH" in report


def test_generate_markdown_contains_per_gpo_detail(fixture_estate):
    report = generate_markdown(fixture_estate)
    assert "## Per-GPO Detail" in report
    for gpo in fixture_estate.gpos:
        assert gpo.name in report
        assert gpo.id in report


def test_generate_markdown_per_gpo_settings(fixture_estate):
    report = generate_markdown(fixture_estate)
    gpo_with_settings = next(g for g in fixture_estate.gpos if g.settings)
    assert "**Settings**" in report
    first_setting = gpo_with_settings.settings[0]
    assert first_setting.identity in report


def test_generate_markdown_per_gpo_links(fixture_estate):
    report = generate_markdown(fixture_estate)
    assert "**Links:**" in report


def test_generate_markdown_per_gpo_delegation(fixture_estate):
    report = generate_markdown(fixture_estate)
    gpo_with_delegation = next(
        (g for g in fixture_estate.gpos if g.delegation), None
    )
    if gpo_with_delegation:
        assert "**Delegation:**" in report


def test_generate_markdown_per_gpo_version_status(fixture_estate):
    report = generate_markdown(fixture_estate)
    assert "Computer version:" in report or "User version:" in report


def test_generate_markdown_version_skew_flagged(fixture_estate):
    report = generate_markdown(fixture_estate)
    skew_gpos = [g for g in fixture_estate.gpos if g.computer_version_skew or g.user_version_skew]
    if skew_gpos:
        assert "SKEW" in report


def test_generate_markdown_precedence_conflicts(fixture_estate):
    report = generate_markdown(fixture_estate)
    prec = queries.precedence_conflicts(fixture_estate)
    if prec:
        assert "## Precedence Conflicts" in report


def test_generate_html_contains_css(fixture_estate):
    report = generate_html(fixture_estate)
    assert "<!DOCTYPE html>" in report
    assert "<style>" in report
    assert "@media print" in report
    assert "Estate Report: fakefixture.local" in report


def test_generate_html_contains_per_gpo(fixture_estate):
    report = generate_html(fixture_estate)
    assert "<h2>Per-GPO Detail</h2>" in report
    for gpo in fixture_estate.gpos:
        assert gpo.name in report


def test_generate_html_escaping():
    gpo = model.Gpo(
        id="test-id", name="GPO <script>alert(1)</script>",
        domain="test.local",
        created=None, modified=None, read=None,
        computer_enabled=True, user_enabled=True,
        computer_ver_ds=None, computer_ver_sysvol=None,
        user_ver_ds=None, user_ver_sysvol=None,
        sddl=None, owner=None, filter_data_available=False,
        wmi_filter=None, sysvol_path=None,
        settings=[
            model.Setting(
                gpo_id="test-id", side="Computer", cse="Registry",
                identity="HKLM\\Software\\Foo & Bar",
                display_name="Foo & Bar",
                display_value="<val>", raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate = model.Estate(domain="test.local", gpos=[gpo])
    report = generate_html(estate)
    assert "<script>" not in report
    assert "&lt;script&gt;" in report
    assert "&amp;" in report
    assert "&lt;val&gt;" in report


def test_generate_markdown_escaping():
    """Markdown report must escape HTML in user-controlled values to prevent
    XSS when the Markdown is rendered to HTML."""
    gpo = model.Gpo(
        id="test-id", name="GPO <script>alert(1)</script>",
        domain="<b>evil</b>.local",
        created=None, modified=None, read=None,
        computer_enabled=True, user_enabled=True,
        computer_ver_ds=None, computer_ver_sysvol=None,
        user_ver_ds=None, user_ver_sysvol=None,
        sddl=None, owner="Owner <img src=x onerror=alert(1)>",
        filter_data_available=False,
        wmi_filter=None, sysvol_path=None,
        description="Desc <iframe src=evil>",
        settings=[
            model.Setting(
                gpo_id="test-id", side="Computer", cse="Registry",
                identity="HKLM\\Software\\Foo & Bar",
                display_name="Foo & Bar",
                display_value="<val>", raw={},
                from_disabled_side=False,
            ),
        ],
        delegation=[
            model.DelegationEntry(
                gpo_id="test-id", trustee="TRUSTEE<script>",
                trustee_sid=None, permission="READ", allowed=True,
            ),
        ],
    )
    estate = model.Estate(domain="<b>evil</b>.local", gpos=[gpo])
    report = generate_markdown(estate)
    assert "<script>" not in report
    assert "<script>alert" not in report
    assert "<img src=x" not in report
    assert "<b>evil</b>" not in report
    assert "<iframe" not in report
    assert "&lt;script&gt;" in report
    assert "&lt;val&gt;" in report
    assert "&amp;" in report


def test_generate_markdown_pipe_escaping():
    """Markdown table cells must escape pipe characters."""
    gpo = model.Gpo(
        id="test-id", name="GPO|Name",
        domain="test|local",
        created=None, modified=None, read=None,
        computer_enabled=True, user_enabled=True,
        computer_ver_ds=None, computer_ver_sysvol=None,
        user_ver_ds=None, user_ver_sysvol=None,
        sddl=None, owner=None, filter_data_available=False,
        wmi_filter=None, sysvol_path=None,
    )
    estate = model.Estate(domain="test|local", gpos=[gpo])
    report = generate_markdown(estate)
    # The summary table should have escaped pipes in the domain value
    assert "test\\|local" in report


def test_md_code_no_double_escaping():
    """_md_code must not HTML-escape — CommonMark renderers escape code span
    content automatically, so escaping here would double-escape (``<`` →
    ``&lt;`` → ``&amp;lt;`` in the rendered output).  Only backticks are
    escaped (to prevent breaking out of the code span)."""
    assert _md_code("<val>") == "<val>"
    assert _md_code("a & b") == "a & b"
    assert _md_code("a ` b") == "a &#96; b"
    assert _md_code("<script>") == "<script>"


def test_generate_html_precedence_conflicts(fixture_estate):
    report = generate_html(fixture_estate)
    prec = queries.precedence_conflicts(fixture_estate)
    if prec:
        assert "<h2>Precedence Conflicts</h2>" in report


def test_report_with_baseline(fixture_estate):
    baseline = [
        queries.BaselineSetting(
            side="Computer",
            cse="Registry",
            identity=r"HKLM\Software\Fake:BadValue",
            display_name="FakeBadValue",
            expected_value="wrong_value",
        ),
    ]
    report = generate_markdown(
        fixture_estate,
        baseline=queries.baseline_diff(fixture_estate, baseline),
    )
    assert "## Baseline Compliance" in report
    assert "Compliance:" in report


def test_report_baseline_html(fixture_estate):
    baseline = [
        queries.BaselineSetting(
            side="Computer",
            cse="Registry",
            identity=r"HKLM\Software\Fake:BadValue",
            display_name="FakeBadValue",
            expected_value="wrong_value",
        ),
    ]
    report = generate_html(
        fixture_estate,
        baseline=queries.baseline_diff(fixture_estate, baseline),
    )
    assert "<h2>Baseline Compliance</h2>" in report


def test_report_with_changelog(tmp_path):
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
    estate.gpos[0].settings[0] = model.Setting(
        gpo_id="aaa-bbb", side="Computer", cse="Registry",
        identity="Setting1", display_name="Setting1",
        display_value="new", raw={}, from_disabled_side=False,
    )
    sid_b = store.save_estate(conn, estate)
    changelog = queries.snapshot_changelog(conn, sid_a, sid_b)
    conn.close()

    report = generate_markdown(estate, changelog_entries=changelog)
    assert "## Change Log" in report
    assert "GPO A" in report


def test_report_changelog_html(tmp_path):
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
    estate.gpos[0].settings[0] = model.Setting(
        gpo_id="aaa-bbb", side="Computer", cse="Registry",
        identity="Setting1", display_name="Setting1",
        display_value="new", raw={}, from_disabled_side=False,
    )
    sid_b = store.save_estate(conn, estate)
    changelog = queries.snapshot_changelog(conn, sid_a, sid_b)
    conn.close()

    report = generate_html(estate, changelog_entries=changelog)
    assert "<h2>Change Log</h2>" in report


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


def test_generate_report_dispatches_md(fixture_estate):
    report = generate_report(fixture_estate, format="md")
    assert "# Estate Report:" in report
    assert "<!DOCTYPE html>" not in report


def test_generate_report_dispatches_html(fixture_estate):
    report = generate_report(fixture_estate, format="html")
    assert "<!DOCTYPE html>" in report


def test_generate_markdown_empty_estate():
    estate = model.Estate(domain="empty.local", gpos=[], soms=[])
    report = generate_markdown(estate)
    assert "# Estate Report: empty.local" in report
    assert "## Per-GPO Detail" in report
    assert "No issues detected" in report


def test_generate_html_empty_estate():
    estate = model.Estate(domain="empty.local", gpos=[], soms=[])
    report = generate_html(estate)
    assert "<!DOCTYPE html>" in report
    assert "empty.local" in report


def test_cli_report_stdout(tmp_path, fixture_estate):
    import subprocess
    import sys

    r = subprocess.run(
        [sys.executable, "-m", "gpo_lens.cli", "report", str(FIXTURE_DIR)],
        capture_output=True, text=True,
    )
    assert r.returncode == 0
    assert "# Estate Report:" in r.stdout


def test_cli_report_html_stdout(tmp_path, fixture_estate):
    import subprocess
    import sys

    r = subprocess.run(
        [sys.executable, "-m", "gpo_lens.cli", "report", str(FIXTURE_DIR),
         "--format", "html"],
        capture_output=True, text=True,
    )
    assert r.returncode == 0
    assert "<!DOCTYPE html>" in r.stdout


def test_cli_report_output_file(tmp_path, fixture_estate):
    import subprocess
    import sys

    out = tmp_path / "out.md"
    r = subprocess.run(
        [sys.executable, "-m", "gpo_lens.cli", "report", str(FIXTURE_DIR),
         "--output", str(out)],
        capture_output=True, text=True,
    )
    assert r.returncode == 0
    assert out.exists()
    assert "# Estate Report:" in out.read_text()


def test_cli_report_html_output_file(tmp_path, fixture_estate):
    import subprocess
    import sys

    out = tmp_path / "out.html"
    r = subprocess.run(
        [sys.executable, "-m", "gpo_lens.cli", "report", str(FIXTURE_DIR),
         "--format", "html", "--output", str(out)],
        capture_output=True, text=True,
    )
    assert r.returncode == 0
    assert out.exists()
    assert "<!DOCTYPE html>" in out.read_text()


def test_markdown_effective_settings_surface_scope_caveats(fixture_estate):
    report = generate_markdown(fixture_estate)
    assert "## Per-OU Effective Settings" in report
    assert "Scope caveats" in report
    assert "flagged, not simulated" in report


def test_html_effective_settings_surface_scope_caveats(fixture_estate):
    report = generate_html(fixture_estate)
    assert "Per-OU Effective Settings" in report
    assert "Scope caveats" in report
    assert "flagged, not simulated" in report
    assert 'class="caveats"' in report
