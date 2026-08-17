"""Unit tests for SQLite scan history persistence and isolation."""

from __future__ import annotations

import tempfile
import time
from pathlib import Path

from provenance.db import get_scan, init_db, list_scans, save_scan
from provenance.schema import Finding, FindingCategory, FindingConfidence, FindingSeverity, ProvenanceScanResult, ProvenanceScore


def test_sqlite_persistence_lifecycle():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "test_contenttrace.db"
        init_db(db_path)

        score = ProvenanceScore(score=35.0, verification_status="detected")
        finding = Finding(
            id="f_db_1",
            scan_id="scan_db_100",
            category=FindingCategory.INVISIBLE_TEXT.value,
            signal="ZERO_WIDTH_SPACE",
            confidence=FindingConfidence.CONFIRMED.value,
            severity=FindingSeverity.HIGH.value,
            location="Offset 10",
        )

        scan_res = ProvenanceScanResult(
            scan_id="scan_db_100",
            original_filename="sample.txt",
            kind="text",
            size=1024,
            created_at=time.time(),
            verification_status="detected",
            verified_clean=False,
            missing_tools=[],
            findings=[finding],
            score=score,
        )

        save_scan(scan_res, db_path=db_path, file_bytes=b"sample secret content")

        retrieved = get_scan("scan_db_100", db_path=db_path)
        assert retrieved is not None
        assert retrieved.original_filename == "sample.txt"
        assert retrieved.score.score == 35.0
        assert len(retrieved.findings) == 1
        assert retrieved.findings[0].signal == "ZERO_WIDTH_SPACE"

        scans_list = list_scans(db_path=db_path)
        assert len(scans_list) == 1
        assert scans_list[0]["scan_id"] == "scan_db_100"
