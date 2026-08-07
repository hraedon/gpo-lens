"""Contract: every GPO-less detector finding declares a stable subject.

``DoctorFinding.subject_key`` is documented as *required* for GPO-less
findings, but nothing enforced it. When it is omitted, the candidate adapter
has nothing to key identity on but the prose summary, so the fingerprint moves
whenever the wording does — falsely resolving the real finding and minting a
"new" one. That is the WI-1.1 failure class, one layer up: WI-1.1 stopped
*dimensions* being parsed from prose; this stops *subject_key* being prose.

The adapter now marks such candidates ``subject_stable=False`` so they surface
as ``snapshot_scoped`` rather than silently churning. That is the safety net.
This test is the guardrail that keeps the net unused: it fails when a new
GPO-less detector forgets its ``subject_key``, at the point the detector is
written rather than after an operator's acknowledgement has quietly detached.
"""

from __future__ import annotations

import ast
from pathlib import Path

DOCTOR_SRC = (
    Path(__file__).resolve().parent.parent
    / "src" / "gpo_lens" / "queries" / "_doctor.py"
)


def _literal_empty_gpo_id(call: ast.Call) -> bool:
    """True when the call passes ``gpo_id=""`` as a literal."""
    for kw in call.keywords:
        if kw.arg == "gpo_id":
            return isinstance(kw.value, ast.Constant) and kw.value.value == ""
    return False


def _declares_subject_key(call: ast.Call) -> bool:
    return any(kw.arg == "subject_key" for kw in call.keywords)


def _doctor_finding_calls() -> list[ast.Call]:
    tree = ast.parse(DOCTOR_SRC.read_text(encoding="utf-8"))
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "DoctorFinding"
    ]


def test_gpo_less_doctor_findings_declare_subject_key() -> None:
    calls = _doctor_finding_calls()
    assert calls, "found no DoctorFinding constructions — did _doctor.py move?"

    offenders = [
        call.lineno
        for call in calls
        if _literal_empty_gpo_id(call) and not _declares_subject_key(call)
    ]
    assert not offenders, (
        "GPO-less DoctorFinding(s) at _doctor.py line(s) "
        f"{offenders} declare no subject_key. Their identity would key on the "
        "prose summary and churn on every rewording. Declare a subject_key "
        "built from stable identifiers (SIDs, GUIDs, paths, names) — not from "
        "summary/detail text."
    )


def test_contract_detects_a_missing_subject_key() -> None:
    """The guardrail must actually fail when the invariant is broken.

    A contract test that cannot fail is worse than no test: it reports safety
    it never checked. Parse a synthetic offender and assert both predicates
    fire, so the assertion above is known to be load-bearing.
    """
    tree = ast.parse('DoctorFinding(severity="low", gpo_id="", summary="x")')
    call = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
    )
    assert _literal_empty_gpo_id(call)
    assert not _declares_subject_key(call)
