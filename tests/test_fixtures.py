"""Round-trip test: generator output must match committed fixtures.

Pure unit tests — no samples required, always run.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

from gpo_lens.ingest import load_estate

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fixtures.build_fixture import write_all

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"


def _canonical_xmltext(path: Path) -> str:
    """Strip non-semantic whitespace from fixture XML for comparison."""
    raw = path.read_text(encoding="utf-8")
    lines = [ln.strip() for ln in raw.splitlines()]
    return "\n".join(ln for ln in lines if ln)


def _canonical_json(path: Path) -> str:
    """Re-serialise JSON so formatting differences are ignored."""
    text = path.read_text(encoding="utf-8-sig")
    data = json.loads(text)
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


class TestBuildFixtureRoundTrip:
    def test_generator_produces_equivalent_estate(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            write_all(target=tmp)
            generated = load_estate(tmp)
            committed = load_estate(FIXTURE_DIR)

            assert generated.domain == committed.domain
            assert len(generated.gpos) == len(committed.gpos)

            gen_by_id = {g.id: g for g in generated.gpos}
            com_by_id = {g.id: g for g in committed.gpos}
            assert set(gen_by_id) == set(com_by_id)

            for gid in gen_by_id:
                g = gen_by_id[gid]
                c = com_by_id[gid]
                assert g.name == c.name
                assert g.computer_enabled == c.computer_enabled
                assert g.user_enabled == c.user_enabled
                assert g.computer_ver_ds == c.computer_ver_ds
                assert g.computer_ver_sysvol == c.computer_ver_sysvol
                assert g.user_ver_ds == c.user_ver_ds
                assert g.user_ver_sysvol == c.user_ver_sysvol
                assert g.wmi_filter == c.wmi_filter
                gen_paths = [link.som_path for link in g.links]
                com_paths = [link.som_path for link in c.links]
                assert gen_paths == com_paths
                gen_enf = [link.enforced for link in g.links]
                com_enf = [link.enforced for link in c.links]
                assert gen_enf == com_enf
                gen_settings = {(s.cse, s.side, s.identity, s.display_value) for s in g.settings}
                com_settings = {(s.cse, s.side, s.identity, s.display_value) for s in c.settings}
                assert gen_settings == com_settings, f"Settings differ for GPO {gid}"
                assert len(g.delegation) == len(c.delegation)

            assert len(generated.soms) == len(committed.soms)
            assert len(generated.wmi_filters) == len(committed.wmi_filters)
            assert len(generated.ou_tree) == len(committed.ou_tree)

    def test_all_gpos_xml_content_equivalent(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            write_all(target=tmp)
            gen_xml = _canonical_xmltext(tmp / "AllGPOs.xml")
            com_xml = _canonical_xmltext(FIXTURE_DIR / "AllGPOs.xml")
            assert gen_xml == com_xml

    def test_json_fixtures_content_equivalent(self) -> None:
        names = ("ou-tree.json", "gp-inheritance.json", "gpo-metadata.json", "wmi-filters.json")
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            write_all(target=tmp)
            for name in names:
                gen = _canonical_json(tmp / name)
                com = _canonical_json(FIXTURE_DIR / name)
                assert gen == com, f"{name} differs"

    def test_sysvol_groups_xml_content_equivalent(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            write_all(target=tmp)
            gen = _canonical_xmltext(
                tmp
                / "SYSVOL-Policies"
                / "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}"
                / "Machine"
                / "Preferences"
                / "Groups.xml"
            )
            com = _canonical_xmltext(
                FIXTURE_DIR
                / "SYSVOL-Policies"
                / "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}"
                / "Machine"
                / "Preferences"
                / "Groups.xml"
            )
            assert gen == com

    def test_ou_tree_has_utf8_bom(self) -> None:
        raw = (FIXTURE_DIR / "ou-tree.json").read_bytes()
        assert raw[:3] == b"\xef\xbb\xbf"
