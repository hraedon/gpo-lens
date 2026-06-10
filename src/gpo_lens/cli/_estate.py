from __future__ import annotations

import argparse
import sqlite3

from gpo_lens import ingest, queries, store
from gpo_lens.cli._helpers import _get_estate, _render_json


def cmd_summary(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    s = queries.estate_summary(estate)
    if args.json:
        _render_json({
            "domain": s.domain,
            "gpo_count": s.gpo_count,
            "som_count": s.som_count,
            "wmi_filter_count": s.wmi_filter_count,
            "unlinked_count": s.unlinked_count,
            "empty_count": s.empty_count,
            "disabled_but_populated_count": s.disabled_but_populated_count,
            "conflict_count": s.conflict_count,
            "blocked_extension_count": s.blocked_extension_count,
            "version_skew_count": s.version_skew_count,
            "ms16_072_vulnerable_count": s.ms16_072_vulnerable_count,
            "cpassword_hit_count": s.cpassword_hit_count,
            "loopback_gpo_count": s.loopback_gpo_count,
            "wmi_filtered_gpo_count": s.wmi_filtered_gpo_count,
            "enforced_link_count": s.enforced_link_count,
            "dangling_link_count": s.dangling_link_count,
            "broken_ref_count": s.broken_ref_count,
            "admx_gap_count": s.admx_gap_count,
            "total_settings": s.total_settings,
            "total_delegation_entries": s.total_delegation_entries,
        })
    else:
        print(f"Domain: {s.domain}")
        print(f"GPOs: {s.gpo_count}  |  SOMs: {s.som_count}  |  WMI filters: {s.wmi_filter_count}")
        print(f"Settings: {s.total_settings}  |  Delegation entries: {s.total_delegation_entries}")
        print()
        issues = []
        if s.unlinked_count:
            issues.append(f"  Unlinked GPOs:           {s.unlinked_count}")
        if s.empty_count:
            issues.append(f"  Empty GPOs:              {s.empty_count}")
        if s.disabled_but_populated_count:
            issues.append(f"  Disabled-but-populated:  {s.disabled_but_populated_count}")
        if s.conflict_count:
            issues.append(f"  Setting conflicts:       {s.conflict_count}")
        if s.blocked_extension_count:
            issues.append(f"  Blocked extensions:      {s.blocked_extension_count}")
        if s.version_skew_count:
            issues.append(f"  Version skew:            {s.version_skew_count}")
        if s.ms16_072_vulnerable_count:
            issues.append(f"  MS16-072 vulnerable:     {s.ms16_072_vulnerable_count}")
        if s.cpassword_hit_count:
            issues.append(f"  cpassword hits (MS14-025): {s.cpassword_hit_count}")
        if s.loopback_gpo_count:
            issues.append(f"  Loopback GPOs:           {s.loopback_gpo_count}")
        if s.wmi_filtered_gpo_count:
            issues.append(f"  WMI-filtered GPOs:       {s.wmi_filtered_gpo_count}")
        if s.enforced_link_count:
            issues.append(f"  Enforced links:          {s.enforced_link_count}")
        if s.dangling_link_count:
            issues.append(f"  Dangling links:          {s.dangling_link_count}")
        if s.broken_ref_count:
            issues.append(f"  Broken references:       {s.broken_ref_count}")
        if s.admx_gap_count:
            issues.append(f"  ADMX gaps (raw reg keys): {s.admx_gap_count}")
        if issues:
            print("Hygiene & security:")
            for line in issues:
                print(line)
        else:
            print("No issues detected.")


def _latest_snapshot_before(conn: sqlite3.Connection, sid: int) -> int | None:
    row = conn.execute(
        "SELECT id FROM snapshot WHERE id < ? ORDER BY id DESC LIMIT 1", (sid,)
    ).fetchone()
    return row[0] if row else None


def cmd_ingest(args: argparse.Namespace) -> None:
    estate = ingest.load_estate(args.sample_dir)
    conn = sqlite3.connect(args.db)
    try:
        store.init_db(conn)
        sid = store.save_estate(conn, estate)
        domain = estate.domain or "unknown"
        msg = f"{domain}, {len(estate.gpos)} GPOs, {len(estate.soms)} SOMs, snapshot={sid}"
        if args.json:
            out = {
                "domain": domain,
                "gpo_count": len(estate.gpos),
                "som_count": len(estate.soms),
                "snapshot_id": sid,
            }
            if args.diff_latest:
                prev = _latest_snapshot_before(conn, sid)
                if prev:
                    entries = queries.snapshot_changelog(conn, prev, sid)
                    out["changelog"] = [
                        {
                            "gpo_id": e.gpo_id,
                            "gpo_name": e.gpo_name,
                            "kind": e.kind,
                            "side": e.side,
                            "summary": e.summary,
                        }
                        for e in entries
                    ]
            _render_json(out)
        else:
            print(msg)
            if args.diff_latest:
                prev = _latest_snapshot_before(conn, sid)
                if prev:
                    entries = queries.snapshot_changelog(conn, prev, sid)
                    if entries:
                        print("\nChanges since previous snapshot:")
                        for e in entries:
                            prefix = "[DETAIL]" if e.kind == "settings_detail" else "[META]"
                            print(f"  {prefix} {e.gpo_name} — {e.summary}")
                            for sc in e.setting_changes:
                                print(f"    [{sc.side}/{sc.cse}] {sc.identity}: {sc.change_type}")
                    else:
                        print("\nNo changes since previous snapshot.")
                else:
                    print("\nNo previous snapshot to diff against.")
    finally:
        conn.close()
