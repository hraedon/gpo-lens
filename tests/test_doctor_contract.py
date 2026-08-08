"""Contract: every GPO-less detector finding declares a stable subject.

``DoctorFinding.subject_key`` is documented as *required* for GPO-less
findings, but nothing enforced it. When it is omitted, the candidate adapter
has nothing to key identity on but the prose summary, so the fingerprint moves
whenever the wording does — falsely resolving the real finding and minting a
"new" one. That is the WI-1.1 failure class, one layer up: WI-1.1 stopped
*dimensions* being parsed from prose; this stops *subject_key* being prose.

The adapter now marks such candidates ``subject_stable=False`` so they surface
as ``snapshot_scoped`` rather than silently churning. That is the safety net.
These tests are the guardrail that keeps the net unused: they fail when a new
GPO-less detector forgets its ``subject_key``, at the point the detector is
written rather than after an operator's acknowledgement has quietly detached.

Two layers, because the static one alone was not enough. The AST scan below
only recognises a *literal* ``gpo_id=""``, and the first version of this file
shipped with a hole because of it: ``estate_doctor`` re-wraps every
``DangerFinding`` as ``DoctorFinding(gpo_id=df.gpo_id, ...)`` — an attribute,
not a literal — with no ``subject_key``. An ``absent``-predicate danger rule
produces ``gpo_id=""`` at runtime, so that wrapper reached the prose branch
while this scan reported all clear. The runtime test is therefore the
authoritative one: it drives real detector output through the real adapter,
where the values are values rather than syntax.
"""

from __future__ import annotations

import ast
import os
import tempfile
from pathlib import Path

import pytest

DOCTOR_SRC = Path(__file__).resolve().parent.parent / "src" / "gpo_lens" / "queries" / "_doctor.py"


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
        n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
    )
    assert _literal_empty_gpo_id(call)
    assert not _declares_subject_key(call)


# ---------------------------------------------------------------------------
# Runtime layer — the authoritative one. Values, not syntax.
# ---------------------------------------------------------------------------


@pytest.fixture
def absent_rule_dir():
    """A drop-in danger rule using the ``absent`` predicate.

    ``absent`` is the only rule shape that emits an estate-scoped
    ``DangerFinding`` (``gpo_id=""``, danger.py). No shipped rule uses it, so
    without this fixture the estate-scoped path is never exercised — which is
    exactly why the original hole survived a full green suite.
    """
    with tempfile.TemporaryDirectory() as d:
        Path(d, "absent.toml").write_text(
            "[[rules]]\n"
            'id = "test_absent_rule"\n'
            'title = "A setting that must exist estate-wide"\n'
            'severity = "high"\n'
            'applies = "Machine"\n'
            'identity = "HKLM\\\\Software\\\\Test:Value"\n'
            'predicate = "absent"\n'
            'reference = "test"\n'
            'remediation = "set it"\n',
            encoding="utf-8",
        )
        prev = os.environ.get("GPO_LENS_DANGER_RULES_DIR")
        os.environ["GPO_LENS_DANGER_RULES_DIR"] = d
        try:
            yield d
        finally:
            if prev is None:
                os.environ.pop("GPO_LENS_DANGER_RULES_DIR", None)
            else:
                os.environ["GPO_LENS_DANGER_RULES_DIR"] = prev


def _empty_estate():
    from gpo_lens.model import Estate

    return Estate(
        gpos=[],
        soms=[],
        wmi_filters=[],
        ou_tree=[],
        principals={},
        group_members={},
        coverage_gaps=[],
    )


def test_no_detector_output_reaches_the_prose_subject_fallback(absent_rule_dir) -> None:
    """Every real candidate must carry a stable subject.

    This is the assertion the AST scan cannot make. It fails if any detector —
    doctor, danger, or a wrapper between them — produces a candidate the
    adapter had to key on prose.
    """
    from gpo_lens.findings import candidates_from_estate

    candidates = candidates_from_estate(_empty_estate(), snapshot_id=1)
    assert candidates, "fixture produced no candidates — the guard would be vacuous"

    unstable = [(c.detector_id, c.subject_key) for c in candidates if not c.subject_stable]
    assert not unstable, (
        f"{len(unstable)} candidate(s) fell back to a prose subject_key: "
        f"{unstable}. Give the detector a subject_key built from stable "
        "identifiers, or stop routing it through the doctor wrapper."
    )


def test_danger_findings_produce_exactly_one_candidate_each(absent_rule_dir) -> None:
    """A danger finding must not be converted twice.

    ``estate_doctor`` re-wraps danger findings for its own display list. If
    ``candidates_from_estate`` converts those wrappers too, one real problem
    becomes two occurrences with different fingerprints — the wrapper carries
    neither ``dimensions`` nor a ``subject_key``.
    """
    from gpo_lens.danger import danger_findings
    from gpo_lens.finding_model import compute_fingerprint
    from gpo_lens.findings import candidates_from_estate

    estate = _empty_estate()
    danger = danger_findings(estate)
    assert any(d.gpo_id == "" for d in danger), (
        "fixture did not produce an estate-scoped danger finding"
    )

    candidates = candidates_from_estate(estate, snapshot_id=1)
    danger_cands = [c for c in candidates if c.detector_id.startswith("danger:")]

    assert len(danger_cands) == len(danger), (
        f"{len(danger)} danger finding(s) produced {len(danger_cands)} "
        "candidate(s) — expected one each"
    )
    fingerprints = {compute_fingerprint(c) for c in danger_cands}
    assert len(fingerprints) == len(danger_cands), (
        "two danger candidates share a fingerprint — they would collapse into one occurrence"
    )


def test_snapshot_scoped_occurrence_refuses_acknowledgement() -> None:
    """The guard the fix's justification depends on.

    Marking a finding ``snapshot_scoped`` only *labels* the hazard. What the
    commit actually promises — that an acknowledgement cannot silently detach —
    requires refusing the decision, because the next evaluation resolves this
    occurrence and mints a new one under a different fingerprint.
    """
    import sqlite3

    from gpo_lens.findings import append_triage_event, run_evaluation
    from gpo_lens.store import init_db

    conn = sqlite3.connect(":memory:")
    try:
        init_db(conn)
        conn.execute(
            "INSERT INTO snapshot (id, domain, taken_at) "
            "VALUES (1, 'test', '2025-01-01T00:00:00+00:00')"
        )
        from gpo_lens.finding_model import FindingCandidate
        from gpo_lens.findings import create_evaluation_run

        run_id = create_evaluation_run(conn, 1)
        run_evaluation(
            conn,
            run_id,
            [
                FindingCandidate(
                    detector_id="unstable",
                    detector_version="1",
                    category="unstable",
                    severity="high",
                    subject_type="estate",
                    subject_key=("some prose",),
                    summary="some prose",
                    subject_stable=False,
                ),
                FindingCandidate(
                    detector_id="stable",
                    detector_version="1",
                    category="stable",
                    severity="high",
                    subject_type="gpo",
                    subject_key=("gpo-1",),
                    summary="stable finding",
                ),
            ],
        )
        rows = dict(conn.execute("SELECT detector_id, id FROM finding").fetchall())
        unstable_id, stable_id = rows["unstable"], rows["stable"]

        for action in ("acknowledged", "accepted_risk"):
            with pytest.raises(ValueError, match="snapshot_scoped"):
                append_triage_event(
                    conn,
                    unstable_id,
                    action,
                    "admin",  # type: ignore[arg-type]
                    rationale="because",
                )

        # A note is still allowed — it claims nothing about future runs.
        append_triage_event(conn, unstable_id, "commented", "admin", note="looked at it")

        # And the guard must not touch stable occurrences.
        append_triage_event(conn, stable_id, "acknowledged", "admin")
    finally:
        conn.close()
