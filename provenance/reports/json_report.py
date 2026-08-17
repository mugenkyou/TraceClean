"""JSON Report Generator for TraceClean Phase 2."""

from __future__ import annotations

import json
from typing import Any

from provenance.schema import ProvenanceScanResult


def generate_json_report(scan_result: ProvenanceScanResult, clean_report: dict[str, Any] | None = None) -> str:
    """Generate machine-readable versioned JSON report string."""
    data = scan_result.to_dict()
    if clean_report:
        data["clean_report"] = clean_report

    return json.dumps(data, indent=2, ensure_ascii=False)
