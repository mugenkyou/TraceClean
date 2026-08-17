"""Adapter registry for dispatching raw detector reports to normalized Finding objects."""

from __future__ import annotations

from typing import Any

from provenance.adapters.container_adapter import ContainerAdapter
from provenance.adapters.image_adapter import ImageAdapter
from provenance.adapters.text_adapter import TextAdapter
from provenance.schema import Finding

_TEXT_ADAPTER = TextAdapter()
_IMAGE_ADAPTER = ImageAdapter()
_CONTAINER_ADAPTER = ContainerAdapter()


def normalize_findings(raw_report: dict[str, Any], kind: str, scan_id: str) -> list[Finding]:
    """Dispatch raw detector output to appropriate adapter based on file kind.

    Never mutates or discards raw evidence. Normalizes into unified Finding objects.
    """
    if not isinstance(raw_report, dict):
        return []

    if kind == "text":
        return _TEXT_ADAPTER.adapt(raw_report, scan_id)
    elif kind == "image":
        return _IMAGE_ADAPTER.adapt(raw_report, scan_id)
    else:
        return _CONTAINER_ADAPTER.adapt(raw_report, scan_id)
