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
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Path = DB_PATH) -> None:
    """Initialize database tables for scans, findings, experiments, runs, metrics, and benchmarks."""
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

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS experiments (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    configuration_json TEXT NOT NULL,
                    created_at REAL NOT NULL
                )
                """
            )

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS experiment_runs (
                    id TEXT PRIMARY KEY,
                    experiment_id TEXT NOT NULL,
                    started_at REAL NOT NULL,
                    finished_at REAL,
                    status TEXT NOT NULL,
                    device TEXT,
                    input_hash TEXT,
                    configuration_hash TEXT NOT NULL,
                    error TEXT,
                    reproducibility_json TEXT NOT NULL,
                    FOREIGN KEY (experiment_id) REFERENCES experiments (id) ON DELETE CASCADE
                )
                """
            )

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    value REAL,
                    unit TEXT NOT NULL,
                    FOREIGN KEY (run_id) REFERENCES experiment_runs (id) ON DELETE CASCADE
                )
                """
            )

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS benchmarks (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    version TEXT NOT NULL,
                    description TEXT,
                    config_json TEXT NOT NULL
                )
                """
            )

            conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_created ON scans (created_at DESC)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings (scan_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_runs_experiment ON experiment_runs (experiment_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_metrics_run ON metrics (run_id)")
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


# =====================================================================
# Phase 3 — Watermark Lab CRUD Helpers
# =====================================================================

def save_experiment(
    exp_id: str,
    name: str,
    configuration_json: str,
    created_at: float,
    db_path: Path = DB_PATH,
) -> None:
    """Insert or replace an experiment definition."""
    init_db(db_path)
    conn = get_connection(db_path)
    try:
        with conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO experiments (id, name, configuration_json, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (exp_id, name, configuration_json, created_at),
            )
    finally:
        conn.close()


def get_experiment(exp_id: str, db_path: Path = DB_PATH) -> dict[str, Any] | None:
    """Retrieve an experiment definition."""
    init_db(db_path)
    conn = get_connection(db_path)
    try:
        row = conn.execute("SELECT * FROM experiments WHERE id = ?", (exp_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def list_experiments(db_path: Path = DB_PATH) -> list[dict[str, Any]]:
    """List all experiment definitions ordered by created_at DESC."""
    init_db(db_path)
    conn = get_connection(db_path)
    try:
        rows = conn.execute("SELECT * FROM experiments ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def delete_experiment(exp_id: str, db_path: Path = DB_PATH) -> bool:
    """Delete an experiment and its runs (cascading)."""
    if not db_path.exists():
        return False
    conn = get_connection(db_path)
    try:
        with conn:
            cursor = conn.execute("DELETE FROM experiments WHERE id = ?", (exp_id,))
            return cursor.rowcount > 0
    finally:
        conn.close()


def save_experiment_run(
    run_id: str,
    experiment_id: str,
    started_at: float,
    finished_at: float | None,
    status: str,
    device: str | None,
    input_hash: str | None,
    configuration_hash: str,
    error: str | None,
    reproducibility_json: str,
    db_path: Path = DB_PATH,
) -> None:
    """Insert or replace an experiment run record."""
    init_db(db_path)
    conn = get_connection(db_path)
    try:
        with conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO experiment_runs (
                    id, experiment_id, started_at, finished_at, status, device,
                    input_hash, configuration_hash, error, reproducibility_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    experiment_id,
                    started_at,
                    finished_at,
                    status,
                    device,
                    input_hash,
                    configuration_hash,
                    error,
                    reproducibility_json,
                ),
            )
    finally:
        conn.close()


def get_experiment_run(run_id: str, db_path: Path = DB_PATH) -> dict[str, Any] | None:
    """Retrieve a single experiment run."""
    init_db(db_path)
    conn = get_connection(db_path)
    try:
        row = conn.execute("SELECT * FROM experiment_runs WHERE id = ?", (run_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def list_experiment_runs(
    experiment_id: str | None = None,
    db_path: Path = DB_PATH,
) -> list[dict[str, Any]]:
    """List experiment runs, optionally filtered by experiment_id."""
    init_db(db_path)
    conn = get_connection(db_path)
    try:
        if experiment_id:
            rows = conn.execute(
                "SELECT * FROM experiment_runs WHERE experiment_id = ? ORDER BY started_at DESC",
                (experiment_id,),
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM experiment_runs ORDER BY started_at DESC").fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def delete_experiment_run(run_id: str, db_path: Path = DB_PATH) -> bool:
    """Delete an individual experiment run."""
    if not db_path.exists():
        return False
    conn = get_connection(db_path)
    try:
        with conn:
            cursor = conn.execute("DELETE FROM experiment_runs WHERE id = ?", (run_id,))
            return cursor.rowcount > 0
    finally:
        conn.close()


def save_run_metrics(
    run_id: str,
    metrics: list[dict[str, Any]],
    db_path: Path = DB_PATH,
) -> None:
    """Save a list of metric data points for a specific run."""
    init_db(db_path)
    conn = get_connection(db_path)
    try:
        with conn:
            # Clear existing metrics for the run to avoid duplicates on re-saves
            conn.execute("DELETE FROM metrics WHERE run_id = ?", (run_id,))
            for m in metrics:
                conn.execute(
                    """
                    INSERT INTO metrics (run_id, name, value, unit)
                    VALUES (?, ?, ?, ?)
                    """,
                    (run_id, m["name"], m.get("value"), m["unit"]),
                )
    finally:
        conn.close()


def get_run_metrics(run_id: str, db_path: Path = DB_PATH) -> list[dict[str, Any]]:
    """Retrieve all metrics recorded for a specific run."""
    init_db(db_path)
    conn = get_connection(db_path)
    try:
        rows = conn.execute("SELECT * FROM metrics WHERE run_id = ?", (run_id,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def save_benchmark(
    bench_id: str,
    name: str,
    version: str,
    description: str | None,
    config_json: str,
    db_path: Path = DB_PATH,
) -> None:
    """Insert or replace a benchmark record."""
    init_db(db_path)
    conn = get_connection(db_path)
    try:
        with conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO benchmarks (id, name, version, description, config_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (bench_id, name, version, description, config_json),
            )
    finally:
        conn.close()


def list_benchmarks(db_path: Path = DB_PATH) -> list[dict[str, Any]]:
    """List all registered benchmarks."""
    init_db(db_path)
    conn = get_connection(db_path)
    try:
        rows = conn.execute("SELECT * FROM benchmarks ORDER BY id").fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()

