"""Pure, deterministic backend scoring function for TraceClean Provenance Exposure Score."""

from __future__ import annotations

import math
from typing import Any

from provenance.schema import (
    SCHEMA_VERSION,
    Finding,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    ProvenanceScore,
    VerificationStatus,
)

CATEGORY_WEIGHTS: dict[str, float] = {
    FindingCategory.C2PA.value: 40.0,
    FindingCategory.IMAGE_METADATA.value: 25.0,
    FindingCategory.DOCUMENT_METADATA.value: 25.0,
    FindingCategory.INVISIBLE_TEXT.value: 30.0,
    FindingCategory.STATISTICAL_TEXT.value: 15.0,
}

SEVERITY_MULTIPLIERS: dict[str, float] = {
    FindingSeverity.CRITICAL.value: 1.0,
    FindingSeverity.HIGH.value: 0.8,
    FindingSeverity.MEDIUM.value: 0.5,
    FindingSeverity.LOW.value: 0.25,
    FindingSeverity.INFO.value: 0.0,
}

CONFIDENCE_MULTIPLIERS: dict[str, float] = {
    FindingConfidence.CONFIRMED.value: 1.0,
    FindingConfidence.PROBABLE.value: 0.75,
    FindingConfidence.INFORMATIONAL.value: 0.3,
    FindingConfidence.LIKELY_FALSE_POSITIVE.value: 0.0,
}

SCORE_LIMITATIONS: list[str] = [
    "Measures physical metadata signals and steganographic carriers only.",
    "NOT an AI-generated content probability estimator.",
    "Score 0.0 indicates no known signals detected; it is not a universal cleanliness guarantee.",
    "Inconclusive assessments due to missing tools refuse to output a zero score.",
]


def compute_provenance_exposure_score(
    findings: list[Finding],
    verification_status: str,
    missing_tools: list[str] | None = None,
) -> ProvenanceScore:
    """Compute pure deterministic Provenance Exposure Score (0.0 to 100.0).

    Returns ProvenanceScore object. If verification is inconclusive and no marks were found,
    score is set to None to prevent false clean claims.
    """
    missing = missing_tools or []

    # Inconclusive Rule: If required tools are missing and 0 marks were found by basic parsers,
    # we refuse to calculate a false 0 score.
    if verification_status == VerificationStatus.INCONCLUSIVE.value and not findings and missing:
        tool_str = ", ".join(missing)
        return ProvenanceScore(
            score=None,
            score_version=SCHEMA_VERSION,
            verification_status=VerificationStatus.INCONCLUSIVE.value,
            verified_clean=False,
            components={},
            derivation=f"Verification inconclusive because required tool(s) ({tool_str}) were unavailable.",
            limitations=SCORE_LIMITATIONS,
        )

    components: dict[str, float] = {cat.value: 0.0 for cat in FindingCategory}

    for f in findings:
        cat_w = CATEGORY_WEIGHTS.get(f.category, 10.0)
        sev_m = SEVERITY_MULTIPLIERS.get(f.severity, 0.5)
        conf_c = CONFIDENCE_MULTIPLIERS.get(f.confidence, 0.5)
        contrib = cat_w * sev_m * conf_c
        components[f.category] = components.get(f.category, 0.0) + contrib

    raw_total = sum(components.values())

    if raw_total <= 0.0:
        final_score: float | None = 0.0
        verified_clean = (verification_status == VerificationStatus.NOT_DETECTED.value)
        status = VerificationStatus.NOT_DETECTED.value if verified_clean else verification_status
        derivation = "0.0 Exposure Score: No provenance marks or signals detected."
    else:
        # Saturation curve: 100 * (1 - exp(-raw_total / 50))
        calculated = 100.0 * (1.0 - math.exp(-raw_total / 50.0))
        final_score = round(min(100.0, max(0.0, calculated)), 1)
        verified_clean = False
        status = VerificationStatus.DETECTED.value
        top_cats = [f"{cat}: {val:.1f}" for cat, val in components.items() if val > 0]
        derivation = f"Raw total {raw_total:.1f} mapped via saturation curve to Exposure Score {final_score:.1f}. Contributed by: {', '.join(top_cats)}."

    return ProvenanceScore(
        score=final_score,
        score_version=SCHEMA_VERSION,
        verification_status=status,
        verified_clean=verified_clean,
        components={k: round(v, 2) for k, v in components.items() if v > 0},
        derivation=derivation,
        limitations=SCORE_LIMITATIONS,
    )
