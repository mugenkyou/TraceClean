"""Flask Web Application for TraceClean (Phase 1 Web MVP).

Provides a polished, forensic-grade web interface on top of the TraceClean engine.
Delegates file inspection and cleaning directly to service/scripts/engine.py in-process.
"""

from __future__ import annotations

import io
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

from flask import (
    Flask,
    Response,
    abort,
    make_response,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

# Insert service/scripts and root into path
ROOT_DIR = Path(__file__).resolve().parent.parent
SERVICE_SCRIPTS = ROOT_DIR / "service" / "scripts"
if str(SERVICE_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SERVICE_SCRIPTS))
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from common import MAX_INPUT_BYTES
from engine import capabilities, clean_bytes, inspect_bytes
from session import FileSession, start_janitor

from provenance.batch import run_batch_scan
from provenance.db import delete_scan as delete_db_scan, get_scan as get_db_scan, list_scans as list_db_scans, save_scan as save_db_scan
from provenance.reports.html_report import generate_html_report
from provenance.reports.json_report import generate_json_report
from provenance.reports.zip_export import build_batch_zip
from provenance.schema import Finding, ProvenanceScanResult, ProvenanceScore

app = Flask(
    __name__,
    template_folder="templates",
    static_folder="static",
)

# 256 MB max upload cap at Flask layer
app.config["MAX_CONTENT_LENGTH"] = MAX_INPUT_BYTES
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", os.urandom(24))

# Start background janitor for session TTL cleanup (every 5 mins)
start_janitor(interval_seconds=300)


def session_to_scan_result(session: FileSession) -> ProvenanceScanResult:
    """Convert an in-memory FileSession to a unified ProvenanceScanResult model."""
    score_dict = session.score or {}
    score_obj = ProvenanceScore(
        score=score_dict.get("score"),
        score_version=score_dict.get("score_version", "1.0"),
        verification_status=score_dict.get("verification_status", "inconclusive"),
        verified_clean=bool(score_dict.get("verified_clean", False)),
        derivation=score_dict.get("derivation", ""),
    )
    findings = [Finding.from_dict(fd) for fd in session.normalized_findings]
    return ProvenanceScanResult(
        scan_id=session.session_id,
        original_filename=session.original_filename,
        kind=session.detected_kind or "unknown",
        size=session.size,
        created_at=session.created_at,
        verification_status=session.verification_status,
        verified_clean=session.verified_clean,
        missing_tools=session.missing_tools,
        status_reason=session.status_reason,
        findings=findings,
        score=score_obj,
        raw_report=session.inspect_report or {},
    )


def build_single_session_zip(session: FileSession) -> bytes:
    """Build a secure single-audit ZIP archive containing cleaned file, HTML, and JSON reports."""
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        scan_res = session_to_scan_result(session)
        
        # 1. JSON report
        json_rep = generate_json_report(scan_res, clean_report=session.clean_report)
        z.writestr(f"report_{Path(session.original_filename).stem}.json", json_rep)
        
        # 2. HTML report
        html_rep = generate_html_report(scan_res)
        z.writestr(f"report_{Path(session.original_filename).stem}.html", html_rep)
        
        # 3. Cleaned file if exists
        cleaned_bytes = session.read_cleaned_bytes()
        if cleaned_bytes is not None:
            z.writestr(f"cleaned_{session.original_filename}", cleaned_bytes)
        else:
            z.writestr(f"original_{session.original_filename}", session.read_input_bytes())
    return buf.getvalue()


@app.context_processor
def inject_capabilities() -> dict[str, Any]:
    """Inject server engine capabilities into all Jinja templates."""
    try:
        caps = capabilities()
    except Exception:
        caps = None
    return {"capabilities": caps}


@app.route("/", methods=["GET"])
def index() -> str:
    """Landing and drag-and-drop file upload UI."""
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload_file() -> Response | str:
    """Handle file upload, validate format & size, create session, and run inspection."""
    if "file" not in request.files:
        return render_template("error.html", error="No file submitted in upload request."), 400

    uploaded_file = request.files["file"]
    filename = uploaded_file.filename or ""
    if not filename.strip():
        return render_template("error.html", error="No filename provided."), 400

    file_bytes = uploaded_file.read()
    if not file_bytes:
        return render_template("error.html", error="Uploaded file is empty (0 bytes)."), 400

    if len(file_bytes) > MAX_INPUT_BYTES:
        return render_template(
            "error.html",
            error=f"File exceeds maximum allowed size of {MAX_INPUT_BYTES // (1024 * 1024)} MB.",
        ), 413

    # Run inspection in-process
    try:
        inspect_res = inspect_bytes(file_bytes, filename)
    except ValueError as err:
        return render_template("error.html", error=str(err)), 400
    except Exception as err:
        return render_template("error.html", error=f"Inspection engine error: {err}"), 500

    # Create isolated FileSession and store results
    session = FileSession.create(file_bytes, filename)
    session.save_inspect_result(inspect_res)

    return redirect(url_for("inspect_session", session_id=session.session_id))


@app.route("/session/<session_id>/inspect", methods=["GET"])
def inspect_session(session_id: str) -> str:
    """Display categorized inspection findings and cleaning options for a session."""
    session = FileSession.get(session_id)
    if session is None:
        return render_template("error.html", error="Session missing, expired, or invalid."), 440

    return render_template("inspect.html", session=session)


@app.route("/session/<session_id>/clean", methods=["POST"])
def clean_session(session_id: str) -> Response | str:
    """Run deterministic clean on the session file and store results."""
    session = FileSession.get(session_id)
    if session is None:
        return render_template("error.html", error="Session missing or expired."), 440

    # Collect form options
    options: dict[str, Any] = {}
    if request.form.get("nfkc") == "1":
        options["nfkc"] = True
    if request.form.get("aggressive_homoglyphs") == "1":
        options["aggressive_homoglyphs"] = True
    if request.form.get("keep_non_ai_metadata") == "1":
        options["keep_non_ai_metadata"] = True
    if request.form.get("also_layer_a_text") == "1":
        options["also_layer_a_text"] = True

    try:
        cleaned_bytes, clean_res = clean_bytes(
            session.read_input_bytes(),
            session.original_filename,
            options=options,
        )
        post_inspect_res = None
        try:
            post_inspect_res = inspect_bytes(cleaned_bytes, session.original_filename)
        except Exception:
            pass
    except ValueError as err:
        return render_template("error.html", error=str(err)), 400
    except Exception as err:
        return render_template("error.html", error=f"Cleaning engine failure: {err}"), 500

    session.save_clean_result(cleaned_bytes, clean_res, post_inspect_res=post_inspect_res)
    return redirect(url_for("result_session", session_id=session.session_id))


@app.route("/session/<session_id>/result", methods=["GET"])
def result_session(session_id: str) -> Response | str:
    """Show before/after summary and download links."""
    session = FileSession.get(session_id)
    if session is None:
        return render_template("error.html", error="Session missing or expired."), 440

    if session.cleaned_path() is None:
        return redirect(url_for("inspect_session", session_id=session_id))

    return render_template("result.html", session=session)


@app.route("/session/<session_id>/download/cleaned", methods=["GET"])
def download_cleaned(session_id: str) -> Response:
    """Safely download cleaned file artifact."""
    session = FileSession.get(session_id)
    if session is None:
        return make_response(render_template("error.html", error="Session missing or expired."), 440)

    cleaned_p = session.cleaned_path()
    if cleaned_p is None or not cleaned_p.exists():
        return make_response(render_template("error.html", error="Cleaned file not found."), 404)

    download_name = f"cleaned_{session.original_filename}"
    response = send_file(
        cleaned_p,
        as_attachment=True,
        download_name=download_name,
        mimetype="application/octet-stream",
    )
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.route("/session/<session_id>/download/report", methods=["GET"])
def download_report(session_id: str) -> Response:
    """Safely download JSON/HTML forensic inspection/clean report."""
    session = FileSession.get(session_id)
    if session is None:
        return make_response(render_template("error.html", error="Session missing or expired."), 440)

    fmt = request.args.get("format", "json").lower()

    if fmt == "html":
        scan_res = session_to_scan_result(session)
        html_content = generate_html_report(scan_res)
        response = make_response(html_content, 200)
        response.headers["Content-Type"] = "text/html; charset=utf-8"
        download_name = f"traceclean_report_{Path(session.original_filename).stem}.html"
        response.headers["Content-Disposition"] = f"attachment; filename={download_name}"
    else:
        report_data = {
            "session_id": session.session_id,
            "original_filename": session.original_filename,
            "size": session.size,
            "cleaned_size": session.cleaned_size,
            "size_delta": session.size_delta,
            "size_delta_pct": session.size_delta_pct,
            "detected_kind": session.detected_kind,
            "suspicious": session.suspicious,
            "verification_status": session.verification_status,
            "status_reason": session.status_reason,
            "missing_tools": session.missing_tools,
            "verified_clean": session.verified_clean,
            "normalized_findings": session.normalized_findings,
            "score": session.score,
            "cleaning_outcome_state": session.cleaning_outcome_state,
            "inspect_report": session.inspect_report,
            "clean_report": session.clean_report,
            "post_clean_inspect": session.post_clean_inspect,
        }
        json_content = json.dumps(report_data, indent=2, ensure_ascii=False).encode("utf-8")
        response = make_response(json_content, 200)
        response.headers["Content-Type"] = "application/json; charset=utf-8"
        download_name = f"traceclean_report_{Path(session.original_filename).stem}.json"
        response.headers["Content-Disposition"] = f"attachment; filename={download_name}"

    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.route("/session/<session_id>/download/zip", methods=["GET"])
def download_session_zip(session_id: str) -> Response:
    """Safely download ZIP archive containing cleaned file, JSON report, and HTML report."""
    session = FileSession.get(session_id)
    if session is None:
        return make_response(render_template("error.html", error="Session missing or expired."), 440)

    try:
        zip_bytes = build_single_session_zip(session)
    except Exception as e:
        return make_response(render_template("error.html", error=f"Failed to generate ZIP archive: {e}"), 500)

    buf = io.BytesIO(zip_bytes)
    download_name = f"traceclean_archive_{Path(session.original_filename).stem}.zip"
    response = send_file(
        buf,
        as_attachment=True,
        download_name=download_name,
        mimetype="application/zip",
    )
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


# =====================================================================
# Phase 2 — API v1 & Batch / History Routes
# =====================================================================

@app.route("/batch", methods=["GET"])
def batch_page() -> str:
    """Multi-file batch scanning interface."""
    return render_template("batch.html")


@app.route("/batch", methods=["POST"])
def process_batch() -> Response | str:
    """Process multiple uploaded files as a batch scan."""
    uploaded_files = request.files.getlist("files")
    if not uploaded_files:
        return render_template("error.html", error="No files uploaded for batch scanning."), 400

    file_tuples = []
    for f in uploaded_files:
        if f.filename:
            file_tuples.append((f.filename, f.read()))

    if not file_tuples:
        return render_template("error.html", error="No valid files selected."), 400

    batch_res = run_batch_scan(file_tuples)

    # Save batch scan results to SQLite so they can be viewed/exported later and appear in history
    for item in batch_res.items:
        try:
            findings = [Finding.from_dict(f) for f in item["findings"]]
            score_obj = ProvenanceScore(**item["score"])
            scan_res = ProvenanceScanResult(
                scan_id=item["scan_id"],
                original_filename=item["original_filename"],
                kind=item["kind"],
                size=item["size"],
                created_at=item["created_at"],
                verification_status=item["verification_status"],
                verified_clean=item["verified_clean"],
                missing_tools=item["missing_tools"],
                status_reason=item["status_reason"],
                findings=findings,
                score=score_obj,
                raw_report=item["raw_report"],
            )
            file_bytes = None
            for fname, fbytes in file_tuples:
                if fname == item["original_filename"]:
                    file_bytes = fbytes
                    break
            save_db_scan(scan_res, file_bytes=file_bytes)
        except Exception:
            pass

    # Save aggregate ZIP bytes to a temporary directory in SESSION_BASE_DIR
    from session import SESSION_BASE_DIR
    try:
        zip_bytes = build_batch_zip(batch_res)
        batch_dir = SESSION_BASE_DIR / batch_res.batch_id
        batch_dir.mkdir(parents=True, exist_ok=True)
        (batch_dir / "batch.zip").write_bytes(zip_bytes)
        
        # Write metadata so Janitor cleans it up
        meta = {
            "session_id": batch_res.batch_id,
            "created_at": time.time(),
            "expires_at": time.time() + 3600,
        }
        (batch_dir / "session.json").write_text(json.dumps(meta), encoding="utf-8")
    except Exception:
        pass

    return make_response(json.dumps(batch_res.to_dict(), indent=2, ensure_ascii=False), 200, {"Content-Type": "application/json"})


@app.route("/batch/download/zip/<batch_id>", methods=["GET"])
def download_batch_zip(batch_id: str) -> Response:
    """Safely download ZIP archive containing batch inspection reports."""
    from session import SESSION_BASE_DIR
    safe_id = "".join(c for c in batch_id if c.isalnum() or c in ("-", "_"))
    zip_path = SESSION_BASE_DIR / safe_id / "batch.zip"
    if not zip_path.exists():
        return make_response(render_template("error.html", error="Batch ZIP archive not found or expired."), 404)

    response = send_file(
        zip_path,
        as_attachment=True,
        download_name=f"traceclean_batch_{safe_id}.zip",
        mimetype="application/zip",
    )
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.route("/history", methods=["GET"])
def history_page() -> str:
    """Local SQLite scan history log."""
    try:
        scans = list_db_scans(limit=100)
    except Exception:
        scans = []
    return render_template("history.html", scans=scans)


@app.route("/history/view/<scan_id>", methods=["GET"])
def view_historical_scan(scan_id: str) -> Response | str:
    """Render a read-only inspection dashboard for historical scans from SQLite."""
    scan = get_db_scan(scan_id)
    if scan is None:
        return render_template("error.html", error="Scan history record not found."), 404
    return render_template("inspect_history.html", scan=scan)


@app.route("/history/delete/<scan_id>", methods=["POST"])
def delete_historical_scan(scan_id: str) -> Response | str:
    """Delete a historical scan record from SQLite database."""
    success = delete_db_scan(scan_id)
    if not success:
        return render_template("error.html", error="Could not delete scan record."), 400
    return redirect(url_for("history_page"))


@app.route("/api/v1/scan", methods=["POST"])
def api_v1_scan() -> Response:
    """API v1: Scan a file and return normalized findings and exposure score."""
    if "file" not in request.files:
        return make_response(json.dumps({"ok": False, "error": "No file field in request"}), 400, {"Content-Type": "application/json"})

    f = request.files["file"]
    filename = f.filename or "input"
    file_bytes = f.read()

    if not file_bytes or len(file_bytes) > MAX_INPUT_BYTES:
        return make_response(json.dumps({"ok": False, "error": "Invalid or oversized file"}), 400, {"Content-Type": "application/json"})

    try:
        inspect_res = inspect_bytes(file_bytes, filename)
    except ValueError as e:
        return make_response(json.dumps({"ok": False, "error": str(e)}), 400, {"Content-Type": "application/json"})
    except Exception as e:
        return make_response(json.dumps({"ok": False, "error": f"Internal scan error: {e}"}), 500, {"Content-Type": "application/json"})

    score_obj = ProvenanceScore(**inspect_res["score"])
    findings = [Finding.from_dict(fd) for fd in inspect_res["normalized_findings"]]
    scan_res = ProvenanceScanResult(
        scan_id=inspect_res.get("scan_id", "scan_api"),
        original_filename=filename,
        kind=inspect_res["kind"],
        size=len(file_bytes),
        created_at=time.time(),
        verification_status=inspect_res["verification_status"],
        verified_clean=inspect_res["verified_clean"],
        missing_tools=inspect_res.get("missing_tools", []),
        status_reason=inspect_res.get("status_reason", ""),
        findings=findings,
        score=score_obj,
        raw_report=inspect_res["report"],
    )

    try:
        save_db_scan(scan_res, file_bytes=file_bytes)
    except Exception:
        pass

    return make_response(json.dumps(scan_res.to_dict(), indent=2, ensure_ascii=False), 200, {"Content-Type": "application/json"})


@app.route("/api/v1/scan/<scan_id>", methods=["GET"])
def api_v1_get_scan(scan_id: str) -> Response:
    """API v1: Retrieve scan details from SQLite scan history."""
    scan = get_db_scan(scan_id)
    if scan is None:
        return make_response(json.dumps({"ok": False, "error": "Scan not found"}), 404, {"Content-Type": "application/json"})

    return make_response(json.dumps(scan.to_dict(), indent=2, ensure_ascii=False), 200, {"Content-Type": "application/json"})


@app.route("/api/v1/scan/<scan_id>/report", methods=["GET"])
def api_v1_get_report(scan_id: str) -> Response:
    """API v1: Export report in json or html format."""
    fmt = request.args.get("format", "json").lower()
    scan = get_db_scan(scan_id)
    if scan is None:
        return make_response(json.dumps({"ok": False, "error": "Scan not found"}), 404, {"Content-Type": "application/json"})

    if fmt == "html":
        html_content = generate_html_report(scan)
        resp = make_response(html_content, 200)
        resp.headers["Content-Type"] = "text/html; charset=utf-8"
        return resp
    else:
        json_content = generate_json_report(scan)
        resp = make_response(json_content, 200)
        resp.headers["Content-Type"] = "application/json; charset=utf-8"
        return resp


@app.errorhandler(413)
def file_too_large(e: Any) -> tuple[str, int]:
    return render_template(
        "error.html",
        error=f"Uploaded file is too large. Maximum supported size is {MAX_INPUT_BYTES // (1024 * 1024)} MB.",
    ), 413


@app.errorhandler(404)
def not_found(e: Any) -> tuple[str, int]:
    return render_template("error.html", error="Page or resource not found."), 404


@app.errorhandler(500)
def internal_error(e: Any) -> tuple[str, int]:
    return render_template("error.html", error="An internal server error occurred."), 500


if __name__ == "__main__":
    host = os.environ.get("TRACECLEAN_WEB_HOST", "127.0.0.1")
    port = int(os.environ.get("TRACECLEAN_WEB_PORT", "5000"))
    app.run(host=host, port=port, debug=True)
