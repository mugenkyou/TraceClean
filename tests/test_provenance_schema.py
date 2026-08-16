"""Unit tests for Finding Schema v1.0 and Data Models."""

from __future__ import annotations

from provenance.schema import (
    Finding,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    ProvenanceScanResult,
    ProvenanceScore,
    VerificationStatus,
)


def test_finding_dataclass_serialization():
    finding = Finding(
        id="find_test123",
        scan_id="scan_abc",
        category=FindingCategory.INVISIBLE_TEXT.value,
        signal="ZERO_WIDTH_SPACE",
        confidence=FindingConfidence.CONFIRMED.value,
        severity=FindingSeverity.HIGH.value,
        location="Codepoint U+200B at offset 12",
        evidence={"codepoint": "U+200B", "count": 5},
        removable=True,
    )

    d = finding.to_dict()
    assert d["id"] == "find_test123"
    assert d["category"] == "invisible_text"
    assert d["signal"] == "ZERO_WIDTH_SPACE"
    assert d["confidence"] == "confirmed"
    assert d["severity"] == "high"
    assert d["removable"] is True

    restored = Finding.from_dict(d)
    assert restored.id == finding.id
    assert restored.category == finding.category
    assert restored.signal == finding.signal


def test_provenance_score_serialization():
    score = ProvenanceScore(
        score=45.2,
        score_version="1.0",
        verification_status=VerificationStatus.DETECTED.value,
        verified_clean=False,
        components={"c2pa": 40.0, "invisible_text": 12.0},
        derivation="Raw total 52.0 mapped to Exposure Score 45.2.",
        limitations=["Diagnostic only"],
    )

    d = score.to_dict()
    assert d["score"] == 45.2
    assert d["verification_status"] == "detected"
    assert d["components"]["c2pa"] == 40.0
