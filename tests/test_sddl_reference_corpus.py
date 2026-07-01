"""Differential regression corpus: parse_sddl vs Windows' own SDDL decoder.

``fixtures/sddl/corpus.json`` holds real GPMC-emitted SDDL strings from the
lab estate plus synthetic strings covering the grammar (aliases, object/deny/
audit ACEs, ACL control flags, hex rights masks, SW adjacency, empty DACLs,
conditional ACEs). ``fixtures/sddl/reference_decode.json`` is the same corpus
decoded by .NET ``System.Security.AccessControl.RawSecurityDescriptor`` on a
real Windows host (the authoritative implementation).

The tests assert field-level agreement between ``gpo_lens.authz.parse_sddl``
and the reference: ACE count and order, ACE type, inheritance/audit flags,
trustee SID, decoded rights, the read-or-apply and write verdict sets, and
owner/group/control-flags. The rights bit table below is written out
independently (from sddl.h / iads.h) so a wrong entry in
``authz._HEX_RIGHTS_MAP`` cannot hide by being used on both sides.

Regenerating the reference (only needed when the corpus changes): feed the
corpus strings to ``RawSecurityDescriptor`` on any Windows host and dump
owner/group/control plus per-ACE type/flags/mask/sid/object-GUIDs — see this
file's git history or plans/ for the original generation script.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from gpo_lens.authz import canonical_sddl_sid, parse_sddl, parse_sddl_rights

_FIXTURE_DIR = Path(__file__).parent / "fixtures" / "sddl"

# Independent sddl.h / iads.h rights table (deliberately NOT imported from
# gpo_lens.authz).
_BIT_TO_CODE = (
    (0x80000000, "GR"), (0x40000000, "GW"), (0x20000000, "GX"), (0x10000000, "GA"),
    (0x00080000, "WO"), (0x00040000, "WD"), (0x00020000, "RC"), (0x00010000, "SD"),
    (0x00000100, "CR"), (0x00000080, "LO"), (0x00000040, "DT"), (0x00000020, "WP"),
    (0x00000010, "RP"), (0x00000008, "SW"), (0x00000004, "LC"), (0x00000002, "DC"),
    (0x00000001, "CC"),
)
_READ_OR_APPLY = frozenset({"GA", "GR", "CR", "RP"})
_WRITE = frozenset({"GA", "GW", "WD", "WO", "SD", "DT", "WP", "DC", "CC"})

# .NET AceType -> gpo_lens ace_type
_TYPE_MAP = {
    "AccessAllowed": "allow",
    "AccessDenied": "deny",
    "AccessAllowedObject": "object_allow",
    "AccessDeniedObject": "object_deny",
    "AccessAllowedCallback": "allow",
    "AccessDeniedCallback": "deny",
    "SystemAudit": "audit_success",
    "SystemAuditObject": "audit_object",
}

# .NET AceFlags names -> SDDL ACE-flag codes (as kept in SddlAce.flags)
_ACEFLAG_MAP = {
    "ObjectInherit": "OI",
    "ContainerInherit": "CI",
    "NoPropagateInherit": "NP",
    "InheritOnly": "IO",
    "Inherited": "ID",
    "SuccessfulAccess": "SA",
    "FailedAccess": "FA",
}


def _mask_to_codes(mask: int) -> frozenset[str]:
    m = mask & 0xFFFFFFFF
    return frozenset(code for bit, code in _BIT_TO_CODE if m & bit)


def _sddl_flag_codes(flags: str) -> frozenset[str]:
    """Split an SDDL ACE-flags field ('CIIO') into 2-letter codes."""
    f = flags.strip().upper()
    return frozenset(f[i:i + 2] for i in range(0, len(f) - 1, 2))


def _ref_flag_codes(ref_flags: str) -> frozenset[str]:
    if ref_flags == "None":
        return frozenset()
    out = set()
    for name in ref_flags.split(", "):
        code = _ACEFLAG_MAP.get(name)
        if code is not None:
            out.add(code)
    return out


def _domain_sid_of(entry: dict) -> str | None:
    """Best-effort domain SID for canonicalizing domain-relative aliases."""
    for a in entry["DiscretionaryAcl"] + entry["SystemAcl"]:
        if a["sid"].startswith("S-1-5-21-"):
            return a["sid"].lower().rsplit("-", 1)[0]
    owner = entry.get("owner") or ""
    if owner.startswith("S-1-5-21-"):
        return owner.lower().rsplit("-", 1)[0]
    return None


def _load_reference() -> list[dict]:
    return json.loads((_FIXTURE_DIR / "reference_decode.json").read_text())


def _corpus_ids() -> list[str]:
    ref = _load_reference()
    return [e["sddl"][:60] for e in ref]


@pytest.fixture(scope="module")
def reference() -> list[dict]:
    return _load_reference()


def test_corpus_and_reference_in_sync(reference: list[dict]):
    corpus = json.loads((_FIXTURE_DIR / "corpus.json").read_text())
    corpus_strings = corpus["lab"] + corpus["synthetic"]
    assert [e["sddl"] for e in reference] == corpus_strings


@pytest.mark.parametrize("idx", range(27), ids=_corpus_ids())
def test_parse_sddl_agrees_with_windows_reference(
    reference: list[dict], idx: int
):
    entry = reference[idx]
    sddl = entry["sddl"]
    acl = parse_sddl(sddl)
    dom = _domain_sid_of(entry)

    # Owner / group (canonicalized: reference resolved aliases to full SIDs).
    for py_val, ref_val in (
        (acl.owner_sid, entry.get("owner")),
        (acl.group_sid, entry.get("group")),
    ):
        py_c = canonical_sddl_sid(py_val, dom) if py_val else None
        assert py_c == (ref_val.lower() if ref_val else None)

    # DACL protected flag: SDDL "P" (always leading) <-> control
    # DiscretionaryAclProtected.
    assert acl.dacl_flags.startswith("P") == (
        "DiscretionaryAclProtected" in entry["control"]
    )

    for section, ref_key in (("dacl", "DiscretionaryAcl"), ("sacl", "SystemAcl")):
        py_aces = getattr(acl, section)
        ref_aces = entry[ref_key]
        assert len(py_aces) == len(ref_aces), f"{section} ACE count"
        for pa, ra in zip(py_aces, ref_aces, strict=True):
            assert pa.ace_type == _TYPE_MAP[ra["type"]]
            assert _sddl_flag_codes(pa.flags) == _ref_flag_codes(ra["flags"])
            assert canonical_sddl_sid(pa.trustee_sid, dom) == ra["sid"].lower()
            ref_codes = _mask_to_codes(ra["mask"])
            py_codes = frozenset(parse_sddl_rights(pa.rights))
            assert py_codes == ref_codes, (
                f"rights disagree for {pa.rights!r}: "
                f"py-only={sorted(py_codes - ref_codes)} "
                f"ref-only={sorted(ref_codes - py_codes)}"
            )
            # Verdict-level agreement (what detection/topology/danger act on).
            assert bool(py_codes & _READ_OR_APPLY) == bool(ref_codes & _READ_OR_APPLY)
            assert bool(py_codes & _WRITE) == bool(ref_codes & _WRITE)
