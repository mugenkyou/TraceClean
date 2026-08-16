"""Unit tests for pure deterministic Provenance Exposure Score formula."""

from __future__ import annotations

from provenance.schema import Finding, FindingCategory, FindingConfidence, FindingSeverity, VerificationStatus
from provenance.scoring import compute_provenance_exposure_score


def test_zero_findings_not_detected():
    score_obj = compute_provenance_exposure_score([], VerificationStatus.NOT_DETECTED.value)
    assert score_obj.score == 0.0
    assert score_obj.verified_clean is True
    assert score_obj.verification_status == "not_detected"


def test_inconclusive_missing_tools_refuses_zero_score():
    score_obj = compute_provenance_exposure_score(
        findings=[],
        verification_status=VerificationStatus.INCONCLUSIVE.value,
        missing_tools=["c2patool", "exiftool"],
    )
    assert score_obj.score is None
    assert score_obj.verified_clean is False
    assert score_obj.verification_status == "inconclusive"
    assert "unavailable" in score_obj.derivation


def test_score_reproducibility():
    findings = [
        Finding(
            id="f1",
            scan_id="s1",
            category=FindingCategory.C2PA.value,
            signal="C2PA_MANIFEST",
            confidence=FindingConfidence.CONFIRMED.value,
            severity=FindingSeverity.CRITICAL.value,
            location="APP11 box",
            evidence={},
        )
    ]

    score1 = compute_provenance_exposure_score(findings, VerificationStatus.DETECTED.value)
    score2 = compute_provenance_exposure_score(findings, VerificationStatus.DETECTED.value)

    assert score1.score is not None
    assert score1.score == score2.score
    assert score1.score > 0.0
    assert score1.score <= 100.0
    assert score1.components == score2.components
