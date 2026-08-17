"""Text detector adapter normalizing Layer A Unicode & stylometry findings."""

from __future__ import annotations

import uuid
from typing import Any

from provenance.adapters.base import BaseAdapter
from provenance.schema import Finding, FindingCategory, FindingConfidence, FindingSeverity


class TextAdapter(BaseAdapter):
    """Adapts text unicode hits and stylometry scores into normalized Findings."""

    def adapt(self, raw_report: dict[str, Any], scan_id: str) -> list[Finding]:
        findings: list[Finding] = []

        # 1. Layer A Unicode Hits
        hits = raw_report.get("hits", [])
        for h in hits:
            kind = h.get("kind", "strip")
            codepoint = h.get("codepoint", "U+0000")
            label = h.get("label", "")
            count = h.get("count", 1)
            conf = h.get("confidence", FindingConfidence.PROBABLE.value)

            # Signal classification
            if kind == "tag_chars":
                signal = "TAG_CHARACTERS"
                severity = FindingSeverity.CRITICAL.value
            elif kind == "bidi":
                signal = "BIDI_OVERRIDE_CONTROL"
                severity = FindingSeverity.HIGH.value
            elif kind == "zwj_family":
                signal = "ZERO_WIDTH_CONTROL"
                severity = FindingSeverity.HIGH.value
            elif kind == "variation_selector":
                signal = "VARIATION_SELECTOR"
                severity = FindingSeverity.MEDIUM.value
            elif kind == "space":
                signal = "SPACE_HOMOGLYPH"
                severity = FindingSeverity.LOW.value
            else:
                signal = "INVISIBLE_UNICODE_CONTROL"
                severity = FindingSeverity.MEDIUM.value

            find_id = f"find_{uuid.uuid4().hex[:8]}"
            findings.append(
                Finding(
                    id=find_id,
                    scan_id=scan_id,
                    category=FindingCategory.INVISIBLE_TEXT.value,
                    signal=signal,
                    confidence=conf,
                    severity=severity,
                    location=f"Codepoint {codepoint} ({label}) x{count}",
                    evidence={
                        "codepoint": codepoint,
                        "label": label,
                        "count": count,
                        "kind": kind,
                        "sample_offsets": h.get("sample_offsets", []),
                    },
                    removable=True,
                )
            )

        # 2. Text Stylometry Signals
        sty = raw_report.get("stylometry", {})
        if isinstance(sty, dict) and sty.get("score", 0.0) >= 0.65:
            score = sty.get("score", 0.0)
            findings.append(
                Finding(
                    id=f"find_{uuid.uuid4().hex[:8]}",
                    scan_id=scan_id,
                    category=FindingCategory.STATISTICAL_TEXT.value,
                    signal="STYLOMETRY_AI_PATTERN",
                    confidence=FindingConfidence.PROBABLE.value,
                    severity=FindingSeverity.MEDIUM.value,
                    location="Text prose structural features",
                    evidence={
                        "score": score,
                        "findings": sty.get("findings", []),
                        "n_tokens": sty.get("n_tokens", 0),
                    },
                    removable=False,  # Statistical text requires Layer B LLM rewrite pass
                )
            )

        return findings
