"""Local SQLite database manager for TraceClean scan history and normalized findings.

Persists scan metadata, scores, and normalized findings in `contenttrace.db`.
DOES NOT store uploaded or cleaned file bytes.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

from provenance.schema import Finding, ProvenanceScanResult, ProvenanceScore

DB_PATH = Path(__file__).resolve().parent.parent / "contenttrace.db"


def get_connection(db_path: Path = DB_PATH) -> sqlite3.Connection:
    """Open or create a SQLite database connection with row factory."""
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Path = DB_PATH) -> None:
    """Initialize database tables for scans and findings."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = get_connection(db_path)
    try:
        with conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    original_filename TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    file_hash TEXT,
                    created_at REAL NOT NULL,
                    score REAL,
                    score_version TEXT,
                    finding_count INTEGER NOT NULL,
                    verification_status TEXT NOT NULL,
                    verified_clean INTEGER NOT NULL,
                    missing_tools_json TEXT,
                    status_reason TEXT,
                    score_derivation TEXT
                )
                """
            )

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    category TEXT NOT NULL,
                    signal TEXT NOT NULL,
                    confidence TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    location TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    removable INTEGER NOT NULL,
                    removed INTEGER,
                    FOREIGN KEY (scan_id) REFERENCES scans (scan_id) ON DELETE CASCADE
                )
                """
            )

            conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_created ON scans (created_at DESC)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings (scan_id)")
    finally:
        conn.close()


def save_scan(result: ProvenanceScanResult, db_path: Path = DB_PATH, file_bytes: bytes | None = None) -> None:
    """Persist a scan result and its normalized findings to SQLite."""
    init_db(db_path)
    file_hash = hashlib.sha256(file_bytes).hexdigest() if file_bytes else ""

    conn = get_connection(db_path)
    try:
        with conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO scans (
                    scan_id, original_filename, kind, size, file_hash, created_at,
                    score, score_version, finding_count, verification_status, verified_clean,
                    missing_tools_json, status_reason, score_derivation
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.scan_id,
                    result.original_filename,
                    result.kind,
                    result.size,
                    file_hash,
                    result.created_at,
                    result.score.score,
                    result.score.score_version,
                    len(result.findings),
                    result.verification_status,
                    1 if result.verified_clean else 0,
                    json.dumps(result.missing_tools),
                    result.status_reason,
                    result.score.derivation,
                ),
            )

            for f in result.findings:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO findings (
                        id, scan_id, category, signal, confidence, severity,
                        location, evidence_json, removable, removed
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        f.id,
                        f.scan_id,
                        f.category,
                        f.signal,
                        f.confidence,
                        f.severity,
                        f.location,
                        json.dumps(f.evidence, ensure_ascii=False),
                        1 if f.removable else 0,
                        1 if f.removed is True else (0 if f.removed is False else None),
                    ),
                )
    finally:
        conn.close()


def get_scan(scan_id: str, db_path: Path = DB_PATH) -> ProvenanceScanResult | None:
    """Retrieve a full scan result with normalized findings from SQLite."""
    if not db_path.exists():
        return None

    conn = get_connection(db_path)
    try:
        scan_row = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
        if not scan_row:
            return None

        finding_rows = conn.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_id,)).fetchall()
        findings: list[Finding] = []
        for r in finding_rows:
            findings.append(
                Finding(
                    id=r["id"],
                    scan_id=r["scan_id"],
                    category=r["category"],
                    signal=r["signal"],
                    confidence=r["confidence"],
                    severity=r["severity"],
                    location=r["location"],
                    evidence=json.loads(r["evidence_json"] or "{}"),
                    removable=bool(r["removable"]),
                    removed=True if r["removed"] == 1 else (False if r["removed"] == 0 else None),
                )
            )

        missing_tools = json.loads(scan_row["missing_tools_json"] or "[]")
        score = ProvenanceScore(
            score=scan_row["score"],
            score_version=scan_row["score_version"] or "1.0",
            verification_status=scan_row["verification_status"],
            verified_clean=bool(scan_row["verified_clean"]),
            derivation=scan_row["score_derivation"] or "",
        )

        return ProvenanceScanResult(
            scan_id=scan_row["scan_id"],
            original_filename=scan_row["original_filename"],
            kind=scan_row["kind"],
            size=scan_row["size"],
            created_at=scan_row["created_at"],
            verification_status=scan_row["verification_status"],
            verified_clean=bool(scan_row["verified_clean"]),
            missing_tools=missing_tools,
            status_reason=scan_row["status_reason"] or "",
            findings=findings,
            score=score,
        )
    finally:
        conn.close()


def list_scans(limit: int = 50, db_path: Path = DB_PATH) -> list[dict[str, Any]]:
    """List recent scan summary records."""
    if not db_path.exists():
        return []

    conn = get_connection(db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def delete_scan(scan_id: str, db_path: Path = DB_PATH) -> bool:
    """Delete a scan record and its findings."""
    if not db_path.exists():
        return False

    conn = get_connection(db_path)
    try:
        with conn:
            cursor = conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
            return cursor.rowcount > 0
    finally:
        conn.close()
