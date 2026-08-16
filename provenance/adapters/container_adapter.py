"""Container detector adapter normalizing PDF, DOCX, ODT, HTML & Markdown metadata findings."""

from __future__ import annotations

import uuid
from typing import Any

from provenance.adapters.base import BaseAdapter
from provenance.schema import Finding, FindingCategory, FindingConfidence, FindingSeverity


class ContainerAdapter(BaseAdapter):
    """Adapts document container inspection reports into normalized Findings."""

    def adapt(self, raw_report: dict[str, Any], scan_id: str) -> list[Finding]:
        findings: list[Finding] = []
        fmt = str(raw_report.get("format", "container")).upper()

        # 1. Top-Level C2PA Manifest
        if raw_report.get("has_c2pa"):
            findings.append(
                Finding(
                    id=f"find_{uuid.uuid4().hex[:8]}",
                    scan_id=scan_id,
                    category=FindingCategory.C2PA.value,
                    signal="C2PA_CONTAINER_MANIFEST",
                    confidence=FindingConfidence.CONFIRMED.value,
                    severity=FindingSeverity.CRITICAL.value,
                    location=f"{fmt} C2PA metadata stream",
                    evidence={"format": fmt},
                    removable=True,
                )
            )

        # 2. AI Metadata Fields
        if raw_report.get("has_ai_metadata"):
            findings.append(
                Finding(
                    id=f"find_{uuid.uuid4().hex[:8]}",
                    scan_id=scan_id,
                    category=FindingCategory.DOCUMENT_METADATA.value,
                    signal="DOCUMENT_AI_PROPERTIES",
                    confidence=FindingConfidence.CONFIRMED.value,
                    severity=FindingSeverity.HIGH.value,
                    location=f"{fmt} document properties / XMP stream",
                    evidence={"format": fmt},
                    removable=True,
                )
            )

        # 3. Individual Container Findings
        for item in raw_report.get("findings", []):
            msg = str(item)
            if "c2pa" in msg.lower() and raw_report.get("has_c2pa"):
                continue

            findings.append(
                Finding(
                    id=f"find_{uuid.uuid4().hex[:8]}",
                    scan_id=scan_id,
                    category=FindingCategory.DOCUMENT_METADATA.value,
                    signal="CONTAINER_METADATA_ELEMENT",
                    confidence=FindingConfidence.CONFIRMED.value,
                    severity=FindingSeverity.MEDIUM.value,
                    location=f"{fmt} structural element",
                    evidence={"description": msg},
                    removable=True,
                )
            )

        # 4. Embedded Layer A Text Hits inside Container
        layer_a_total = raw_report.get("layer_a_total", 0)
        if layer_a_total > 0 and not any(f.category == FindingCategory.INVISIBLE_TEXT.value for f in findings):
            findings.append(
                Finding(
                    id=f"find_{uuid.uuid4().hex[:8]}",
                    scan_id=scan_id,
                    category=FindingCategory.INVISIBLE_TEXT.value,
                    signal="EMBEDDED_TEXT_INVISIBLE_CONTROL",
                    confidence=FindingConfidence.PROBABLE.value,
                    severity=FindingSeverity.HIGH.value,
                    location=f"Embedded text spans in {fmt}",
                    evidence={"count": layer_a_total},
                    removable=True,
                )
            )

        return findings
