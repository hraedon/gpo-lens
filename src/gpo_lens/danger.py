"""Dangerous-configuration detectors — curated, cited, AI-free (Plan 018 Phase B).

Two buckets, matched to their mechanics (B.1):

* **Bucket 2 — structural / attack-path** (typed detectors reusing the
  existing SDDL/delegation/GPP parse): :func:`gpo_writable_by_nonadmin`,
  :func:`local_admin_push`, :func:`overbroad_apply_group_policy`.
* **Bucket 1 — setting-value dangers** (a small cited data table + one pure
  evaluator): :func:`evaluate_danger_rules` over :class:`DangerRule` instances
  loaded from ``danger_rules.toml``.

Both emit one typed :class:`DangerFinding` carrying a required ``reference``.
Findings are *facts about the GPO* (B.3 "Flag, don't simulate"), not claims
about per-principal effective state. The module is a core module: it never
imports ``narration`` or ``web`` and makes zero model calls (AC-8).
"""

from __future__ import annotations

import os
import tomllib
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from gpo_lens.authz import is_allow_ace_type, parse_sddl, parse_sddl_rights, resolve_principal
from gpo_lens.detection import (
    _has_write_right,
    _is_default_writer_sid,
    scan_local_groups,
)
from gpo_lens.model import SEVERITY_ORDER

if TYPE_CHECKING:
    from gpo_lens.model import AdmxResolver, Estate

__all__ = [
    "DangerFinding",
    "DangerRule",
    "danger_findings",
    "evaluate_danger_rules",
    "gpo_writable_by_nonadmin",
    "load_danger_rules",
    "local_admin_push",
    "overbroad_apply_group_policy",
]


_SEVERITY_ORDER = SEVERITY_ORDER


@dataclass(frozen=True)
class DangerFinding:
    """One dangerous-configuration finding from a curated, cited check."""

    check_id: str
    severity: str
    title: str
    gpo_id: str
    gpo_name: str
    detail: str
    reference: str


@dataclass(frozen=True)
class DangerRule:
    """One cited danger rule from the shipped TOML data table."""

    id: str
    title: str
    severity: str
    applies: str
    identity: str
    predicate: str
    value: str
    reference: str


# ---------------------------------------------------------------------------
# Bucket 2 — structural / attack-path detectors
# ---------------------------------------------------------------------------

_GPO_MODIFY_REF = "https://attack.mitre.org/techniques/T1484/001/"
_LOCAL_ADMIN_REF = "https://attack.mitre.org/techniques/T1078/003/"
_APPLY_GP_REF = (
    "https://learn.microsoft.com/en-us/troubleshoot/"
    "windows-server/group-policy/security-filtering-group-policy"
)

# "Apply Group Policy" granted to these SIDs means any authenticated or
# anonymous user receives the GPO — an over-broad apply scope.
_BROAD_APPLY_SIDS = {"s-1-1-0", "s-1-5-7", "wd", "an"}
_APPLY_RIGHTS = {"GA", "GR", "CC", "CR", "RP"}


def _format_trustee(estate: Estate, sid: str) -> str:
    """Resolve *sid* to ``"name (sid)"`` when resolved, else the raw SID.

    The SID is always present (Plan 020, decision 2); the name is omitted when
    unresolved to avoid the redundant ``sid (sid)`` form.
    """
    rp = resolve_principal(estate, sid)
    if rp.resolved:
        return f"{rp.name} ({sid})"
    return sid


def gpo_writable_by_nonadmin(estate: Estate) -> list[DangerFinding]:
    """Flag GPOs whose DACL grants write rights to a non-default-writer trustee,
    or whose Owner is a non-default-writer SID.

    Reuses the existing SDDL parse and the ``_is_default_writer_sid`` /
    ``_has_write_right`` helpers — no new ACL evaluator (AC-7). Emits one
    finding per (GPO, trustee) pair for DACL write ACEs, plus one finding
    per GPO with a non-admin Owner (the Owner implicitly holds WRITE_DAC
    and can escalate to full control — a GPO-hijack primitive).
    """
    findings: list[DangerFinding] = []
    for g in estate.gpos:
        if not g.sddl:
            continue
        acl = parse_sddl(g.sddl)

        if acl.owner_sid and not _is_default_writer_sid(acl.owner_sid):
            owner_display = _format_trustee(estate, acl.owner_sid)
            findings.append(DangerFinding(
                check_id="gpo_owner_nonadmin",
                severity="high",
                title="GPO owned by a non-admin trustee",
                gpo_id=g.id,
                gpo_name=g.name,
                detail=(
                    f"GPO Owner is {owner_display} — the Owner implicitly "
                    f"holds WRITE_DAC and can escalate to full control"
                ),
                reference=_GPO_MODIFY_REF,
            ))

        for ace in acl.dacl:
            if not is_allow_ace_type(ace.ace_type):
                continue
            if not _has_write_right(ace.rights):
                continue
            sid = ace.trustee_sid
            if not sid or _is_default_writer_sid(sid):
                continue
            trustee_display = _format_trustee(estate, sid)
            findings.append(DangerFinding(
                check_id="gpo_writable_nonadmin",
                severity="high",
                title="GPO writable by a non-admin trustee",
                gpo_id=g.id,
                gpo_name=g.name,
                detail=(
                    f"Trustee {trustee_display} has write access ({ace.rights}) "
                    f"to this GPO — a GPO-hijack primitive"
                ),
                reference=_GPO_MODIFY_REF,
            ))
    return findings


def local_admin_push(estate: Estate) -> list[DangerFinding]:
    """Flag GPOs that push members into the local Administrators group.

    Reuses :func:`detection.scan_local_groups` (no new GPP parse). Emits one
    finding per GPO (deduplicated across groups). Adds via Restricted Groups
    or GPP LocalUsersAndGroups to the local Administrators (SID S-1-5-32-544
    or a name containing "admin") are flagged as a privilege-escalation path.
    """
    findings: list[DangerFinding] = []
    for g in estate.gpos:
        pushes: list[str] = []
        for mod in scan_local_groups(g):
            is_admin = (
                (mod.group_sid and mod.group_sid.upper() == "S-1-5-32-544")
                or "ADMIN" in (mod.group_name or "").upper()
            )
            if not is_admin or not mod.members_added:
                continue
            pushes.append(
                f"adds {', '.join(mod.members_added)} to '{mod.group_name}'"
            )
        if pushes:
            findings.append(DangerFinding(
                check_id="local_admin_push",
                severity="high",
                title="GPO pushes local Administrators membership",
                gpo_id=g.id,
                gpo_name=g.name,
                detail="; ".join(pushes),
                reference=_LOCAL_ADMIN_REF,
            ))
    return findings


def overbroad_apply_group_policy(estate: Estate) -> list[DangerFinding]:
    """Flag GPOs whose 'Apply Group Policy' is granted to Everyone/Anonymous.

    Checks ``gpo.delegation`` entries first. When delegation is empty (common
    when the collector only has SDDL), falls back to parsing ``gpo.sddl`` for
    allow ACEs granting apply/read rights to Everyone (S-1-1-0) or Anonymous
    (S-1-5-7). Everyone or Anonymous receiving Apply Group Policy means any
    authenticated/anonymous user gets the GPO applied — an over-broad scope.
    """
    findings: list[DangerFinding] = []
    for g in estate.gpos:
        found = False
        for d in g.delegation:
            if not d.allowed:
                continue
            if "apply group policy" not in (d.permission or "").lower():
                continue
            sid = (d.trustee_sid or "").lower()
            if sid not in _BROAD_APPLY_SIDS:
                continue
            findings.append(DangerFinding(
                check_id="overbroad_apply_gp",
                severity="medium",
                title="GPO apply scope is over-broad (Everyone/Anonymous)",
                gpo_id=g.id,
                gpo_name=g.name,
                detail=(
                    f"'Apply Group Policy' granted to {d.trustee or sid} ({sid})"
                ),
                reference=_APPLY_GP_REF,
            ))
            found = True
            break

        if found:
            continue

        if not g.delegation and g.sddl:
            acl = parse_sddl(g.sddl)
            for ace in acl.dacl:
                if not is_allow_ace_type(ace.ace_type):
                    continue
                sid = (ace.trustee_sid or "").lower()
                if sid not in _BROAD_APPLY_SIDS:
                    continue
                rights = set(parse_sddl_rights(ace.rights))
                if not (rights & _APPLY_RIGHTS):
                    continue
                trustee_display = _format_trustee(estate, ace.trustee_sid)
                findings.append(DangerFinding(
                    check_id="overbroad_apply_gp",
                    severity="medium",
                    title="GPO apply scope is over-broad (Everyone/Anonymous)",
                    gpo_id=g.id,
                    gpo_name=g.name,
                    detail=(
                        f"SDDL grants apply rights to {trustee_display} "
                        f"({ace.rights})"
                    ),
                    reference=_APPLY_GP_REF,
                ))
                break
    return findings


# ---------------------------------------------------------------------------
# Bucket 1 — setting-value dangers (data table + pure evaluator)
# ---------------------------------------------------------------------------

_REGISTRY_CSES = ("Registry", "Windows Registry")


def _resolve_display_name(admx: AdmxResolver, identity: str) -> str | None:
    """Resolve a setting identity to an ADMX policy display name.

    Returns ``None`` when the resolver has no match, so name-keyed
    rules degrade to identity-keyed only (AC-9 — no crash, no silent all-match).
    """
    result = admx.resolve_display_name(identity)
    return result if isinstance(result, str) else None


def _predicate_matches(rule: DangerRule, value: str) -> bool:
    v = (value or "").strip()
    if rule.predicate == "equals":
        return v.lower() == rule.value.strip().lower()
    if rule.predicate == "in":
        wanted = {x.strip().lower() for x in rule.value.split(",") if x.strip()}
        return v.lower() in wanted
    if rule.predicate == "present":
        return True
    if rule.predicate == "min":
        try:
            return float(v) >= float(rule.value)
        except ValueError:
            return False
    if rule.predicate == "max":
        try:
            return float(v) <= float(rule.value)
        except ValueError:
            return False
    return False


def _side_matches(rule_applies: str, setting_side: str) -> bool:
    if rule_applies == "Both":
        return True
    want = "Computer" if rule_applies == "Machine" else "User"
    return setting_side == want


def _identity_matches(
    rule: DangerRule,
    setting_identity: str,
    admx: AdmxResolver | None,
) -> bool:
    if setting_identity.lower() == rule.identity.lower():
        return True
    if admx is None:
        return False
    resolved = _resolve_display_name(admx, setting_identity)
    return resolved is not None and resolved == rule.identity


def evaluate_danger_rules(
    estate: Estate, rules: list[DangerRule], admx: AdmxResolver | None = None
) -> list[DangerFinding]:
    """Evaluate setting-value danger rules against estate Registry settings.

    For each rule, scan all GPO Registry CSE settings where the side matches
    ``rule.applies`` and the identity matches ``rule.identity`` (raw registry
    path, case-insensitive) *or* the ADMX-resolved display name matches
    ``rule.identity`` (policy-name-keyed). When *admx* is ``None``, name-keyed
    rules produce no matches (graceful degradation, AC-9).

    The ``absent`` predicate is estate-wide: a finding is emitted when *no*
    GPO carries a setting matching the rule's identity.
    """
    present_findings: list[DangerFinding] = []
    absent_rules = [r for r in rules if r.predicate == "absent"]
    active_rules = [r for r in rules if r.predicate != "absent"]

    for rule in active_rules:
        for g in estate.gpos:
            for s in g.settings:
                if s.source_state == "blocked":
                    continue
                if s.cse not in _REGISTRY_CSES:
                    continue
                if not _side_matches(rule.applies, s.side):
                    continue
                if not _identity_matches(rule, s.identity, admx):
                    continue
                if _predicate_matches(rule, s.display_value):
                    present_findings.append(DangerFinding(
                        check_id=rule.id,
                        severity=rule.severity,
                        title=rule.title,
                        gpo_id=g.id,
                        gpo_name=g.name,
                        detail=f"{s.identity} = {s.display_value}",
                        reference=rule.reference,
                    ))

    absent_findings: list[DangerFinding] = []
    for rule in absent_rules:
        found_any = False
        for g in estate.gpos:
            for s in g.settings:
                if s.cse not in _REGISTRY_CSES:
                    continue
                if _identity_matches(rule, s.identity, admx):
                    found_any = True
                    break
            if found_any:
                break
        if not found_any:
            absent_findings.append(DangerFinding(
                check_id=rule.id,
                severity=rule.severity,
                title=rule.title,
                gpo_id="",
                gpo_name="",
                detail=f"Expected setting not found estate-wide: {rule.identity}",
                reference=rule.reference,
            ))

    return present_findings + absent_findings


_VALID_PREDICATES = frozenset({
    "equals", "in", "min", "max", "present", "absent",
})

_REQUIRED_RULE_FIELDS = frozenset({
    "id", "title", "severity", "applies", "identity", "reference",
})


def _load_rules_file(path: Path) -> list[DangerRule]:
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError):
        return []
    raw_rules = data.get("rules", [])
    if not isinstance(raw_rules, list):
        warnings.warn(
            f"Skipping danger rules in {path.name} ('rules' must be an array)",
            stacklevel=1,
        )
        return []
    rules: list[DangerRule] = []
    for entry in raw_rules:
        if not isinstance(entry, dict):
            warnings.warn(
                f"Skipping non-table entry in {path.name} (got {type(entry).__name__})",
                stacklevel=1,
            )
            continue
        predicate = entry.get("predicate", "")
        if predicate not in _VALID_PREDICATES:
            continue
        missing = _REQUIRED_RULE_FIELDS - entry.keys()
        if missing:
            warnings.warn(
                f"Skipping danger rule in {path.name} (missing: {sorted(missing)})",
                stacklevel=1,
            )
            continue
        rules.append(DangerRule(
            id=entry["id"],
            title=entry["title"],
            severity=entry["severity"],
            applies=entry["applies"],
            identity=entry["identity"],
            predicate=predicate,
            value=str(entry.get("value", "")),
            reference=entry["reference"],
        ))
    return rules


def load_danger_rules(rules_path: Path | None = None) -> list[DangerRule]:
    """Load danger rules from a TOML file.

    Falls back to the shipped ``danger_rules.toml``. When
    ``GPO_LENS_DANGER_RULES_DIR`` is set, additional ``.toml`` files in that
    directory are loaded and merged by ``id`` (drop-in overrides — B.2).
    """
    if rules_path is not None:
        return _load_rules_file(rules_path)

    shipped = _load_rules_file(Path(__file__).resolve().parent / "danger_rules.toml")

    env_dir = os.environ.get("GPO_LENS_DANGER_RULES_DIR")
    if not env_dir:
        return shipped

    env_path = Path(env_dir)
    if not env_path.is_dir():
        return shipped

    merged: dict[str, DangerRule] = {}
    for r in shipped:
        merged[r.id] = r
    for toml_file in sorted(env_path.glob("*.toml")):
        for r in _load_rules_file(toml_file):
            merged[r.id] = r
    return list(merged.values())


# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------

def danger_findings(
    estate: Estate, *, admx: AdmxResolver | None = None, rules: list[DangerRule] | None = None
) -> list[DangerFinding]:
    """Run all danger detectors (Bucket 1 + Bucket 2) and return sorted findings."""
    if rules is None:
        rules = load_danger_rules()
    findings: list[DangerFinding] = []
    findings.extend(gpo_writable_by_nonadmin(estate))
    findings.extend(local_admin_push(estate))
    findings.extend(overbroad_apply_group_policy(estate))
    findings.extend(evaluate_danger_rules(estate, rules, admx))
    findings.sort(
        key=lambda f: (_SEVERITY_ORDER.get(f.severity, 99), f.check_id, f.gpo_id)
    )
    return findings
