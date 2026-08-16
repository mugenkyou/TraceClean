"""Temporary FileSession management for TraceClean Web Application.

Provides isolated filesystem session storage for uploaded and cleaned artifacts,
enforcing path traversal protection, non-guessable UUIDs, and automatic TTL expiration.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any

# Base temporary directory for TraceClean web sessions
SESSION_BASE_DIR = Path(tempfile.gettempdir()) / "traceclean_web_sessions"
DEFAULT_TTL_SECONDS = 3600  # 1 hour TTL


def _safe_basename(filename: str) -> str:
    """Sanitize filename to prevent path traversal."""
    name = Path(filename.replace("\\", "/")).name
    if not name or name in (".", ".."):
        return "file"
    return name


class FileSession:
    """Represents an isolated user upload/inspection/cleaning session."""

    def __init__(self, session_id: str, session_dir: Path):
        self.session_id = session_id
        self.session_dir = session_dir
        self.meta_file = session_dir / "session.json"
        self._data: dict[str, Any] = {}
        if self.meta_file.exists():
            try:
                self._data = json.loads(self.meta_file.read_text(encoding="utf-8"))
            except Exception:
                self._data = {}

    @classmethod
    def create(cls, file_bytes: bytes, filename: str, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> FileSession:
        """Create a new isolated FileSession directory and write initial input bytes."""
        SESSION_BASE_DIR.mkdir(parents=True, exist_ok=True)
        session_id = uuid.uuid4().hex
        session_dir = SESSION_BASE_DIR / session_id
        session_dir.mkdir(parents=True, exist_ok=False)

        safe_name = _safe_basename(filename)
        input_path = session_dir / f"original_{safe_name}"
        input_path.write_bytes(file_bytes)

        now = time.time()
        meta = {
            "session_id": session_id,
            "original_filename": safe_name,
            "size": len(file_bytes),
            "input_filename": input_path.name,
            "created_at": now,
            "expires_at": now + ttl_seconds,
            "inspect_report": None,
            "cleaned_filename": None,
            "clean_report": None,
            "detected_kind": None,
            "suspicious": False,
        }

        meta_file = session_dir / "session.json"
        meta_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")

        obj = cls(session_id, session_dir)
        obj._data = meta
        return obj

    @classmethod
    def get(cls, session_id: str) -> FileSession | None:
        """Retrieve an active FileSession if it exists and has not expired."""
        if not session_id or not isinstance(session_id, str):
            return None
        # Sanitize session_id to alphanumeric UUID hex
        safe_id = "".join(c for c in session_id if c.isalnum() or c in ("-", "_"))
        if not safe_id:
            return None

        session_dir = SESSION_BASE_DIR / safe_id
        if not session_dir.is_dir():
            return None

        session = cls(safe_id, session_dir)
        if session.is_expired():
            session.delete()
            return None
        return session

    def _save(self) -> None:
        self.meta_file.write_text(json.dumps(self._data, indent=2), encoding="utf-8")

    @property
    def original_filename(self) -> str:
        return self._data.get("original_filename", "file")

    @property
    def size(self) -> int:
        return self._data.get("size", 0)

    @property
    def created_at(self) -> float:
        return self._data.get("created_at", 0.0)

    @property
    def expires_at(self) -> float:
        return self._data.get("expires_at", 0.0)

    @property
    def detected_kind(self) -> str | None:
        return self._data.get("detected_kind")

    @property
    def suspicious(self) -> bool:
        return bool(self._data.get("suspicious"))

    @property
    def verification_status(self) -> str:
        return self._data.get("verification_status", "detected" if self.suspicious else "not_detected")

    @property
    def status_reason(self) -> str:
        return self._data.get("status_reason", "")

    @property
    def missing_tools(self) -> list[str]:
        return self._data.get("missing_tools", [])

    @property
    def verified_clean(self) -> bool:
        return bool(self._data.get("verified_clean", False))

    @property
    def cleaned_size(self) -> int:
        return self._data.get("cleaned_size", 0)

    @property
    def size_delta(self) -> int:
        return self._data.get("size_delta", 0)

    @property
    def size_delta_pct(self) -> float:
        return self._data.get("size_delta_pct", 0.0)

    @property
    def inspect_report(self) -> dict[str, Any] | None:
        return self._data.get("inspect_report")

    @property
    def clean_report(self) -> dict[str, Any] | None:
        return self._data.get("clean_report")

    @property
    def post_clean_inspect(self) -> dict[str, Any] | None:
        return self._data.get("post_clean_inspect")

    def input_path(self) -> Path:
        filename = self._data.get("input_filename", "input")
        return self.session_dir / filename

    def cleaned_path(self) -> Path | None:
        filename = self._data.get("cleaned_filename")
        if not filename:
            return None
        p = self.session_dir / filename
        return p if p.exists() else None

    def read_input_bytes(self) -> bytes:
        return self.input_path().read_bytes()

    def read_cleaned_bytes(self) -> bytes | None:
        p = self.cleaned_path()
        return p.read_bytes() if p else None

    def save_inspect_result(self, res: dict[str, Any]) -> None:
        """Store inspect pipeline output."""
        self._data["detected_kind"] = res.get("kind")
        self._data["suspicious"] = res.get("suspicious", False)
        self._data["verification_status"] = res.get("verification_status", "detected" if res.get("suspicious") else "not_detected")
        self._data["status_reason"] = res.get("status_reason", "")
        self._data["missing_tools"] = res.get("missing_tools", [])
        self._data["verified_clean"] = res.get("verified_clean", False)
        self._data["inspect_report"] = res.get("report")
        self._save()

    def save_clean_result(self, cleaned_bytes: bytes, res: dict[str, Any], post_inspect_res: dict[str, Any] | None = None) -> Path:
        """Save cleaned file bytes, size deltas, and report metadata."""
        suffix = Path(self.original_filename).suffix
        stem = Path(self.original_filename).stem
        cleaned_name = f"cleaned_{stem}{suffix}"
        cleaned_path = self.session_dir / cleaned_name
        cleaned_path.write_bytes(cleaned_bytes)

        orig_size = self.size
        cleaned_size = len(cleaned_bytes)
        delta = cleaned_size - orig_size
        delta_pct = (delta / orig_size * 100.0) if orig_size > 0 else 0.0

        self._data["cleaned_filename"] = cleaned_name
        self._data["cleaned_size"] = cleaned_size
        self._data["size_delta"] = delta
        self._data["size_delta_pct"] = round(delta_pct, 2)
        self._data["clean_report"] = res.get("report")

        if post_inspect_res:
            self._data["post_clean_inspect"] = post_inspect_res
            self._data["post_verification_status"] = post_inspect_res.get("verification_status")
            self._data["post_verified_clean"] = post_inspect_res.get("verified_clean", False)

        self._save()
        return cleaned_path

    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    def delete(self) -> None:
        """Remove session directory and all its temporary files."""
        if self.session_dir.exists():
            shutil.rmtree(self.session_dir, ignore_errors=True)


def cleanup_expired_sessions() -> int:
    """Scans SESSION_BASE_DIR and deletes all expired session folders."""
    if not SESSION_BASE_DIR.exists():
        return 0

    removed = 0
    now = time.time()
    for child in SESSION_BASE_DIR.iterdir():
        if child.is_dir():
            meta = child / "session.json"
            expired = False
            if meta.exists():
                try:
                    data = json.loads(meta.read_text(encoding="utf-8"))
                    if now > data.get("expires_at", 0):
                        expired = True
                except Exception:
                    expired = True
            else:
                # If created > 1 hour ago without meta
                if now - child.stat().st_mtime > DEFAULT_TTL_SECONDS:
                    expired = True

            if expired:
                shutil.rmtree(child, ignore_errors=True)
                removed += 1
    return removed


class _JanitorThread(threading.Thread):
    def __init__(self, interval_seconds: int = 300):
        super().__init__(daemon=True, name="SessionJanitor")
        self.interval = interval_seconds
        self._stop_event = threading.Event()

    def run(self):
        while not self._stop_event.is_set():
            try:
                cleanup_expired_sessions()
            except Exception:
                pass
            self._stop_event.wait(self.interval)

    def stop(self):
        self._stop_event.set()


_JANITOR: _JanitorThread | None = None


def start_janitor(interval_seconds: int = 300) -> None:
    """Start background janitor thread for period cleanup if not already running."""
    global _JANITOR
    if _JANITOR is None or not _JANITOR.is_alive():
        _JANITOR = _JanitorThread(interval_seconds=interval_seconds)
        _JANITOR.start()
