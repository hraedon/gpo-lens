"""Flat settings dump and two-file settings diff."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, cast

from gpo_lens.model import Side

if TYPE_CHECKING:
    from gpo_lens.model import Estate


@dataclass(frozen=True)
class SettingsDumpRow:
    """One row in the flat settings export."""

    gpo_id: str
    gpo_name: str
    side: Side
    cse: str
    identity: str
    display_name: str
    display_value: str
    from_disabled_side: bool
    source_state: str = "normal"  # "normal" | "blocked" (<Blocked/> extension)


@dataclass(frozen=True)
class SettingsDiffRow:
    gpo_id: str
    gpo_name: str
    side: Side
    cse: str
    identity: str
    display_name: str
    change_type: str
    old_value: str | None
    new_value: str | None


class _SettingsDiffResult(list[SettingsDiffRow]):
    """list subclass carrying a skipped_count attribute."""

    skipped_count: int = 0


def settings_diff(
    file_a: str | Path,
    file_b: str | Path,
    *,
    side: str | None = None,
    cse: str | None = None,
    gpo_id: str | None = None,
) -> _SettingsDiffResult:
    from gpo_lens.normalize import canonical_guid, load_json

    _REQUIRED_KEYS = {"gpo_id", "side", "cse", "identity"}

    def _index(
        data: list[dict[str, object]],
    ) -> tuple[dict[tuple[str, str, str, str], dict[str, object]], int]:
        idx: dict[tuple[str, str, str, str], dict[str, object]] = {}
        skipped = 0
        for row in data:
            missing = _REQUIRED_KEYS - row.keys()
            if missing:
                skipped += 1
                continue
            try:
                gid = canonical_guid(str(row["gpo_id"]))
            except ValueError:
                skipped += 1
                continue
            key = (gid, str(row["side"]), str(row["cse"]), str(row["identity"]))
            idx[key] = row
        return idx, skipped

    data_a = load_json(file_a)
    data_b = load_json(file_b)

    index_a, skipped_a = _index(data_a)
    index_b, skipped_b = _index(data_b)

    all_keys = set(index_a) | set(index_b)

    side_exact = side if side else None
    cse_lower = cse.lower() if cse else None
    gpo_lower = gpo_id.lower() if gpo_id else None

    results = _SettingsDiffResult()
    for key in sorted(all_keys):
        gid, side_val, cse_val, identity = key

        a_row = index_a.get(key)
        b_row = index_b.get(key)

        if side_exact or cse_lower or gpo_lower:
            row = a_row or b_row
            if row is None:
                continue
            if side_exact and side_val != side_exact:
                continue
            if cse_lower and cse_lower not in cse_val.lower():
                continue
            if gpo_lower and gpo_lower not in gid:
                continue

        if a_row is None and b_row is not None:
            results.append(SettingsDiffRow(
                gpo_id=gid, gpo_name=str(b_row.get("gpo_name", "")),
                side=cast(Side, side_val), cse=cse_val, identity=identity,
                display_name=str(b_row.get("display_name", "")),
                change_type="added", old_value=None, new_value=str(b_row.get("display_value", "")),
            ))
        elif a_row is not None and b_row is None:
            results.append(SettingsDiffRow(
                gpo_id=gid, gpo_name=str(a_row.get("gpo_name", "")),
                side=cast(Side, side_val), cse=cse_val, identity=identity,
                display_name=str(a_row.get("display_name", "")),
                change_type="removed",
                old_value=str(a_row.get("display_value", "")),
                new_value=None,
            ))
        elif a_row is not None and b_row is not None:
            old_v = str(a_row.get("display_value", ""))
            new_v = str(b_row.get("display_value", ""))
            if old_v != new_v:
                results.append(SettingsDiffRow(
                    gpo_id=gid, gpo_name=str(b_row.get("gpo_name", "")),
                    side=cast(Side, side_val), cse=cse_val, identity=identity,
                    display_name=str(b_row.get("display_name", "")),
                    change_type="modified", old_value=old_v, new_value=new_v,
                ))

    results.skipped_count = skipped_a + skipped_b
    return results


def settings_dump(
    estate: Estate,
    *,
    side: str | None = None,
    cse: str | None = None,
    gpo_name: str | None = None,
) -> list[SettingsDumpRow]:
    """Flat export of all settings, optionally filtered."""
    side_lower = side.lower() if side else None
    cse_lower = cse.lower() if cse else None
    gpo_lower = gpo_name.lower() if gpo_name else None

    results: list[SettingsDumpRow] = []
    for g in estate.gpos:
        if gpo_lower and gpo_lower not in g.name.lower():
            continue
        for s in g.settings:
            if side_lower and side_lower not in s.side.lower():
                continue
            if cse_lower and cse_lower not in s.cse.lower():
                continue
            results.append(SettingsDumpRow(
                gpo_id=g.id, gpo_name=g.name,
                side=s.side, cse=s.cse, identity=s.identity,
                display_name=s.display_name, display_value=s.display_value,
                from_disabled_side=s.from_disabled_side,
                source_state=s.source_state,
            ))
    results.sort(key=lambda r: (r.gpo_id, r.side, r.cse, r.identity.lower()))
    return results
