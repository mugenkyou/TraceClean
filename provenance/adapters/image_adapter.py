"""Image detector adapter normalizing C2PA and EXIF/XMP metadata findings."""

from __future__ import annotations

import uuid
from typing import Any

from provenance.adapters.base import BaseAdapter
from provenance.schema import Finding, FindingCategory, FindingConfidence, FindingSeverity


class ImageAdapter(BaseAdapter):
    """Adapts image inspection reports (C2PA, EXIF, XMP, ISOBMFF) into normalized Findings."""

    def adapt(self, raw_report: dict[str, Any], scan_id: str) -> list[Finding]:
        findings: list[Finding] = []
        fmt = str(raw_report.get("format", "image")).upper()

        # 1. C2PA / JUMBF Manifest
        if raw_report.get("has_c2pa"):
            findings.append(
                Finding(
                    id=f"find_{uuid.uuid4().hex[:8]}",
                    scan_id=scan_id,
                    category=FindingCategory.C2PA.value,
                    signal="C2PA_JUMBF_MANIFEST",
                    confidence=FindingConfidence.CONFIRMED.value,
                    severity=FindingSeverity.CRITICAL.value,
                    location=f"{fmt} header / JUMBF box / C2PA manifest",
                    evidence={
                        "format": fmt,
                        "c2pa_details": raw_report.get("c2pa_report", {}),
                    },
                    removable=True,
                )
            )

        # 2. AI Generator / Prompt Metadata Fields
        if raw_report.get("has_ai_metadata"):
            findings.append(
                Finding(
                    id=f"find_{uuid.uuid4().hex[:8]}",
                    scan_id=scan_id,
                    category=FindingCategory.IMAGE_METADATA.value,
                    signal="EXIF_AI_GENERATOR_TAG",
                    confidence=FindingConfidence.CONFIRMED.value,
                    severity=FindingSeverity.HIGH.value,
                    location=f"{fmt} EXIF/XMP metadata header",
                    evidence={
                        "format": fmt,
                        "ai_fields": raw_report.get("ai_fields", []),
                        "exif_ai_tags": raw_report.get("exif_ai_tags", []),
                    },
                    removable=True,
                )
            )

        # 3. Individual Text Findings
        for item in raw_report.get("findings", []):
            if isinstance(item, str):
                msg = item
                conf = FindingConfidence.CONFIRMED.value
            elif isinstance(item, dict):
                msg = item.get("description", item.get("label", str(item)))
                conf = item.get("confidence", FindingConfidence.CONFIRMED.value)
            else:
                msg = str(item)
                conf = FindingConfidence.CONFIRMED.value

            # Deduplicate if already covered by C2PA or AI metadata top-level
            if "c2pa" in msg.lower() and raw_report.get("has_c2pa"):
                continue

            findings.append(
                Finding(
                    id=f"find_{uuid.uuid4().hex[:8]}",
                    scan_id=scan_id,
                    category=FindingCategory.IMAGE_METADATA.value,
                    signal="IMAGE_METADATA_HEADER",
                    confidence=conf,
                    severity=FindingSeverity.MEDIUM.value,
                    location=f"{fmt} metadata field",
                    evidence={"description": msg},
                    removable=True,
                )
            )

        return findings
