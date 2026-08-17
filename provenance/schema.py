"""Unified Finding Schema v1.0 and Data Models for TraceClean."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

SCHEMA_VERSION = "1.0"


class FindingCategory(str, Enum):
    INVISIBLE_TEXT = "invisible_text"
    STATISTICAL_TEXT = "statistical_text"
    C2PA = "c2pa"
    IMAGE_METADATA = "image_metadata"
    DOCUMENT_METADATA = "document_metadata"


class FindingConfidence(str, Enum):
    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    INFORMATIONAL = "informational"
    LIKELY_FALSE_POSITIVE = "likely_false_positive"


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VerificationStatus(str, Enum):
    DETECTED = "detected"
    NOT_DETECTED = "not_detected"
    INCONCLUSIVE = "inconclusive"


@dataclass
class Finding:
    """Normalized provenance signal finding."""

    id: str
    scan_id: str
    category: str
    signal: str
    confidence: str
    severity: str
    location: str
    evidence: dict[str, Any] = field(default_factory=dict)
    removable: bool = True
    removed: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "category": self.category,
            "signal": self.signal,
            "confidence": self.confidence,
            "severity": self.severity,
            "location": self.location,
            "evidence": self.evidence,
            "removable": self.removable,
            "removed": self.removed,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        return cls(
            id=data.get("id", f"find_{uuid.uuid4().hex[:8]}"),
            scan_id=data.get("scan_id", ""),
            category=data.get("category", FindingCategory.INVISIBLE_TEXT.value),
            signal=data.get("signal", "UNKNOWN_SIGNAL"),
            confidence=data.get("confidence", FindingConfidence.PROBABLE.value),
            severity=data.get("severity", FindingSeverity.MEDIUM.value),
            location=data.get("location", "unknown"),
            evidence=data.get("evidence", {}),
            removable=bool(data.get("removable", True)),
            removed=data.get("removed"),
        )


@dataclass
class ProvenanceScore:
    """Diagnostic aggregate exposure score."""

    score: float | None  # 0.0 to 100.0, or None if inconclusive
    score_version: str = SCHEMA_VERSION
    verification_status: str = VerificationStatus.INCONCLUSIVE.value
    verified_clean: bool = False
    components: dict[str, float] = field(default_factory=dict)
    derivation: str = ""
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "score_version": self.score_version,
            "verification_status": self.verification_status,
            "verified_clean": self.verified_clean,
            "components": self.components,
            "derivation": self.derivation,
            "limitations": self.limitations,
        }


@dataclass
class ProvenanceScanResult:
    """Complete provenance inspection result wrapping normalized findings & score."""

    scan_id: str
    original_filename: str
    kind: str
    size: int
    created_at: float
    verification_status: str
    verified_clean: bool
    missing_tools: list[str]
    findings: list[Finding]
    score: ProvenanceScore
    status_reason: str = ""
    raw_report: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "original_filename": self.original_filename,
            "kind": self.kind,
            "size": self.size,
            "created_at": self.created_at,
            "verification_status": self.verification_status,
            "verified_clean": self.verified_clean,
            "missing_tools": self.missing_tools,
            "status_reason": self.status_reason,
            "findings": [f.to_dict() for f in self.findings],
            "score": self.score.to_dict(),
            "raw_report": self.raw_report,
        }
