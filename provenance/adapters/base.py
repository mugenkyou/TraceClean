"""Base detector adapter interface for TraceClean."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from provenance.schema import Finding


class BaseAdapter(ABC):
    """Abstract base class for converting raw detector reports into normalized Findings."""

    @abstractmethod
    def adapt(self, raw_report: dict[str, Any], scan_id: str) -> list[Finding]:
        """Convert raw detector report into normalized Finding objects."""
        pass
