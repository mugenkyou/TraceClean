"""ZIP export packager for batch scanning & cleaning artifacts."""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path
from typing import Any

from provenance.batch import BatchScanResult


def build_batch_zip(
    batch_result: BatchScanResult,
    cleaned_files: list[tuple[str, bytes]] | None = None,
) -> bytes:
    """Build a secure ZIP archive containing batch report, cleaned files, and per-file reports."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        # 1. Aggregate JSON report
        z.writestr("batch_summary.json", json.dumps(batch_result.to_dict(), indent=2, ensure_ascii=False))

        # 2. Per-file reports directory
        for item in batch_result.items:
            fname = Path(item.get("original_filename", "file")).name
            safe_name = f"reports/report_{fname}.json"
            z.writestr(safe_name, json.dumps(item, indent=2, ensure_ascii=False))

        # 3. Cleaned files directory (if provided)
        if cleaned_files:
            for fname, file_bytes in cleaned_files:
                safe_name = f"cleaned/{Path(fname).name}"
                z.writestr(safe_name, file_bytes)

    return buf.getvalue()
