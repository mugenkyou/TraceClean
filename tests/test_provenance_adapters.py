"""Unit tests for detector adapters normalizing raw reports into Findings."""

from __future__ import annotations

from pathlib import Path

from provenance.adapters.registry import normalize_findings
from provenance.schema import FindingCategory

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def test_text_adapter_with_sample_watermarked():
    sample_txt = FIXTURES_DIR / "sample_watermarked.txt"
    assert sample_txt.exists()
    text = sample_txt.read_text(encoding="utf-8")

    from text_unicode import inspect_text
    report = inspect_text(text).to_dict()

    findings = normalize_findings(report, "text", "scan_test_txt")
    assert len(findings) > 0
    assert any(f.category == FindingCategory.INVISIBLE_TEXT.value for f in findings)
    assert all(f.scan_id == "scan_test_txt" for f in findings)


def test_container_adapter_with_sample_meta_svg():
    sample_svg = FIXTURES_DIR / "sample_meta.svg"
    assert sample_svg.exists()

    from container_meta import inspect_container
    report = inspect_container(sample_svg).to_dict()

    findings = normalize_findings(report, "container", "scan_test_svg")
    assert len(findings) > 0
    assert any(f.category in (FindingCategory.DOCUMENT_METADATA.value, FindingCategory.C2PA.value) for f in findings)
