"""Batch scanner and orchestration for multi-file/directory audits."""

from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

# Insert service/scripts into path
import sys
SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "service" / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from common import MAX_INPUT_BYTES
from engine import clean_bytes, inspect_bytes
from provenance.adapters.registry import normalize_findings
from provenance.schema import ProvenanceScanResult
from provenance.scoring import compute_provenance_exposure_score

DEFAULT_SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
    ".tox", ".mypy_cache", ".pytest_cache", "dist", "build", ".next", "target", ".cache"
}


@dataclass
class BatchScanResult:
    """Aggregate result of a batch scan operation."""

    batch_id: str
    total_files: int
    scanned_files: int
    failed_files: int
    items: list[dict[str, Any]] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)
    average_score: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "batch_id": self.batch_id,
            "total_files": self.total_files,
            "scanned_files": self.scanned_files,
            "failed_files": self.failed_files,
            "average_score": self.average_score,
            "items": self.items,
            "errors": self.errors,
        }


def run_batch_scan(
    files: list[tuple[str, bytes]],
    progress_cb: Callable[[int, int, dict[str, Any]], None] | None = None,
) -> BatchScanResult:
    """Run batch inspection over a list of (filename, file_bytes) tuples."""
    batch_id = f"batch_{uuid.uuid4().hex[:8]}"
    total = len(files)
    scanned = 0
    failed = 0
    items: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    scores: list[float] = []

    for i, (name, data_bytes) in enumerate(files, 1):
        if not data_bytes or len(data_bytes) > MAX_INPUT_BYTES:
            err = {"filename": name, "reason": "empty or exceeds size cap"}
            errors.append(err)
            failed += 1
            if progress_cb:
                progress_cb(i, total, err)
            continue

        try:
            scan_id = f"scan_{uuid.uuid4().hex[:8]}"
            inspect_res = inspect_bytes(data_bytes, name)
            findings = normalize_findings(inspect_res["report"], inspect_res["kind"], scan_id)
            score_obj = compute_provenance_exposure_score(
                findings,
                inspect_res["verification_status"],
                inspect_res.get("missing_tools"),
            )

            full_res = ProvenanceScanResult(
                scan_id=scan_id,
                original_filename=name,
                kind=inspect_res["kind"],
                size=len(data_bytes),
                created_at=time.time(),
                verification_status=inspect_res["verification_status"],
                verified_clean=inspect_res["verified_clean"],
                missing_tools=inspect_res.get("missing_tools", []),
                status_reason=inspect_res.get("status_reason", ""),
                findings=findings,
                score=score_obj,
                raw_report=inspect_res["report"],
            )

            item_dict = full_res.to_dict()
            items.append(item_dict)
            scanned += 1
            if score_obj.score is not None:
                scores.append(score_obj.score)

            if progress_cb:
                progress_cb(i, total, item_dict)

        except Exception as e:
            err = {"filename": name, "reason": str(e)}
            errors.append(err)
            failed += 1
            if progress_cb:
                progress_cb(i, total, err)

    avg_score = round(sum(scores) / len(scores), 1) if scores else None

    return BatchScanResult(
        batch_id=batch_id,
        total_files=total,
        scanned_files=scanned,
        failed_files=failed,
        items=items,
        errors=errors,
        average_score=avg_score,
    )
