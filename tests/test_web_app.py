"""Integration tests for TraceClean Web Application (Flask)."""

from __future__ import annotations

import io
import json
import time
from pathlib import Path

import pytest

# Insert web/ into path to import app and session
ROOT = Path(__file__).resolve().parent.parent
WEB_DIR = ROOT / "web"
SERVICE_SCRIPTS = ROOT / "service" / "scripts"

import sys
if str(WEB_DIR) not in sys.path:
    sys.path.insert(0, str(WEB_DIR))
if str(SERVICE_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SERVICE_SCRIPTS))

from app import app
from session import FileSession, cleanup_expired_sessions


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_index_page(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"TraceClean" in response.data
    assert b"AI Content Provenance" in response.data


def test_upload_no_file(client):
    response = client.post("/upload", data={}, content_type="multipart/form-data")
    assert response.status_code == 400
    assert b"No file submitted" in response.data


def test_upload_empty_file(client):
    data = {"file": (io.BytesIO(b""), "empty.txt")}
    response = client.post("/upload", data=data, content_type="multipart/form-data")
    assert response.status_code == 400
    assert b"Uploaded file is empty" in response.data


def test_upload_text_file_and_flow(client):
    fixture = ROOT / "tests" / "fixtures" / "sample_watermarked.txt"
    file_bytes = fixture.read_bytes()

    # 1. Upload
    data = {"file": (io.BytesIO(file_bytes), "sample_watermarked.txt")}
    res = client.post("/upload", data=data, content_type="multipart/form-data")
    assert res.status_code == 302
    redirect_url = res.headers["Location"]
    assert "/inspect" in redirect_url

    session_id = redirect_url.split("/session/")[1].split("/inspect")[0]

    # 2. View Inspect Page
    inspect_res = client.get(redirect_url)
    assert inspect_res.status_code == 200
    assert b"Provenance Marks Detected" in inspect_res.data
    assert b"ZERO WIDTH SPACE" in inspect_res.data

    # 3. Clean
    clean_res = client.post(f"/session/{session_id}/clean", data={"nfkc": "1"})
    assert clean_res.status_code == 302
    assert f"/session/{session_id}/result" in clean_res.headers["Location"]

    # 4. View Result Page
    result_res = client.get(f"/session/{session_id}/result")
    assert result_res.status_code == 200
    assert b"File Cleaned Successfully" in result_res.data
    assert b"Size Delta" in result_res.data

    # 5. Download Cleaned Artifact
    dl_res = client.get(f"/session/{session_id}/download/cleaned")
    assert dl_res.status_code == 200
    assert dl_res.headers["Content-Disposition"].startswith("attachment;")
    assert "cleaned_sample_watermarked.txt" in dl_res.headers["Content-Disposition"]
    assert len(dl_res.data) < len(file_bytes)  # Watermarks removed

    # 6. Download JSON Report
    report_res = client.get(f"/session/{session_id}/download/report")
    assert report_res.status_code == 200
    assert report_res.headers["Content-Disposition"].startswith("attachment;")
    report_json = json.loads(report_res.data)
    assert report_json["original_filename"] == "sample_watermarked.txt"
    assert report_json["suspicious"] is True
    assert report_json["verification_status"] == "detected"
    assert "cleaned_size" in report_json
    assert "size_delta" in report_json
    assert "post_clean_inspect" in report_json


def test_upload_image_svg_flow(client):
    fixture = ROOT / "tests" / "fixtures" / "sample_meta.svg"
    file_bytes = fixture.read_bytes()

    # Upload
    data = {"file": (io.BytesIO(file_bytes), "sample_meta.svg")}
    res = client.post("/upload", data=data, content_type="multipart/form-data")
    assert res.status_code == 302

    session_id = res.headers["Location"].split("/session/")[1].split("/inspect")[0]

    # Clean
    client.post(f"/session/{session_id}/clean", data={})

    # Download
    dl_res = client.get(f"/session/{session_id}/download/cleaned")
    assert dl_res.status_code == 200
    assert b"metadata" not in dl_res.data.lower()  # metadata tag stripped


def test_session_isolation_and_filename_propagation(client):
    """Ensure session A data never leaks to session B, and filenames propagate accurately."""
    data_a = {"file": (io.BytesIO(b"Hello from File A"), "file_alpha.txt")}
    res_a = client.post("/upload", data=data_a, content_type="multipart/form-data")
    session_id_a = res_a.headers["Location"].split("/session/")[1].split("/inspect")[0]

    data_b = {"file": (io.BytesIO(b"Hello from File B with watermark \xe2\x80\x8b"), "file_beta.txt")}
    res_b = client.post("/upload", data=data_b, content_type="multipart/form-data")
    session_id_b = res_b.headers["Location"].split("/session/")[1].split("/inspect")[0]

    # Verify session A
    session_a = FileSession.get(session_id_a)
    assert session_a.original_filename == "file_alpha.txt"
    assert session_a.verification_status == "not_detected"
    assert session_a.verified_clean is True

    # Verify session B
    session_b = FileSession.get(session_id_b)
    assert session_b.original_filename == "file_beta.txt"
    assert session_b.verification_status == "detected"
    assert session_b.verified_clean is False

    # Download report for session A
    rep_a = client.get(f"/session/{session_id_a}/download/report")
    json_a = json.loads(rep_a.data)
    assert json_a["original_filename"] == "file_alpha.txt"
    assert json_a["verification_status"] == "not_detected"

    # Download report for session B
    rep_b = client.get(f"/session/{session_id_b}/download/report")
    json_b = json.loads(rep_b.data)
    assert json_b["original_filename"] == "file_beta.txt"
    assert json_b["verification_status"] == "detected"


def test_missing_tools_inconclusive_state(client, monkeypatch):
    """When required tools are missing for a format, verification status must be inconclusive, not verified clean."""
    import engine

    # Mock capabilities so c2patool and exiftool appear missing
    monkeypatch.setattr(
        engine,
        "capabilities",
        lambda: {
            "version": "dev",
            "tools": {"c2patool": False, "exiftool": False, "qpdf": False},
        },
    )

    clean_png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
    data = {"file": (io.BytesIO(clean_png), "clean_sample.png")}
    res = client.post("/upload", data=data, content_type="multipart/form-data")
    session_id = res.headers["Location"].split("/session/")[1].split("/inspect")[0]

    session = FileSession.get(session_id)
    assert session.verification_status == "inconclusive"
    assert session.verified_clean is False
    assert "c2patool" in session.missing_tools
    assert "exiftool" in session.missing_tools

    inspect_res = client.get(f"/session/{session_id}/inspect")
    assert inspect_res.status_code == 200
    assert b"Verification Inconclusive / Limited" in inspect_res.data
    assert b"Degraded Capability Notice" in inspect_res.data


def test_invalid_session_id(client):
    res = client.get("/session/non_existent_id_12345/inspect")
    assert res.status_code == 440
    assert b"Session missing" in res.data


def test_session_ttl_expiration():
    file_bytes = b"Hello world"
    session = FileSession.create(file_bytes, "test.txt", ttl_seconds=1)
    session_id = session.session_id

    assert FileSession.get(session_id) is not None

    # Wait for TTL to expire
    time.sleep(1.2)

    # Should now return None and cleanup directory
    assert FileSession.get(session_id) is None


def _ai_pdf() -> bytes:
    """A small but structurally valid PDF carrying AI provenance in /Info."""
    out = bytearray(b"%PDF-1.4\n")
    out.extend(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
    out.extend(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")
    out.extend(b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n")
    out.extend(b"4 0 obj\n<< /Producer (AI Generator v4) /Creator (TraceClean Test Suite) >>\nendobj\n")
    out.extend(b"xref\n0 5\n0000000000 65535 f\n0000000009 00000 n\n0000000057 00000 n\n0000000112 00000 n\n0000000183 00000 n\n")
    out.extend(b"trailer\n<< /Size 5 /Root 1 0 R /Info 4 0 R >>\nstartxref\n268\n%%EOF\n")
    return bytes(out)


class _Completed:
    def __init__(self, rc):
        self.returncode = rc


def test_pdf_outcome_no_cleaning_performed(client, monkeypatch):
    """State C: Required tools missing, PDF copied as-is, no cleaning performed."""
    import engine
    import container_meta

    monkeypatch.setattr(
        engine,
        "capabilities",
        lambda: {
            "version": "dev",
            "tools": {"c2patool": False, "exiftool": False, "qpdf": False},
        },
    )
    monkeypatch.setattr(container_meta, "which", lambda cmd: None)

    pdf_bytes = _ai_pdf()
    data = {"file": (io.BytesIO(pdf_bytes), "sample.pdf")}
    res = client.post("/upload", data=data, content_type="multipart/form-data")
    assert res.status_code == 302
    session_id = res.headers["Location"].split("/session/")[1].split("/inspect")[0]

    session = FileSession.get(session_id)
    assert session.verification_status == "inconclusive"

    clean_res = client.post(f"/session/{session_id}/clean")
    assert clean_res.status_code == 302

    result_res = client.get(f"/session/{session_id}/result")
    assert result_res.status_code == 200
    assert b"No PDF cleaning performed" in result_res.data
    assert b"original file was preserved unchanged" in result_res.data
    assert b"Verification incomplete" in result_res.data

    report_res = client.get(f"/session/{session_id}/download/report")
    assert report_res.status_code == 200
    json_data = json.loads(report_res.data)
    assert json_data["cleaning_outcome_state"] == "no_cleaning_performed"
    assert json_data["size_delta"] == 0


def test_pdf_outcome_cleaned_verification_incomplete(client, monkeypatch):
    """State B: Cleaning performed (exiftool), but verification tools missing (qpdf/c2patool)."""
    import engine
    import container_meta
    import subprocess

    monkeypatch.setattr(
        engine,
        "capabilities",
        lambda: {
            "version": "dev",
            "tools": {"c2patool": False, "exiftool": True, "qpdf": False},
        },
    )

    def fake_which(cmd):
        if cmd == "exiftool":
            return "/fake/bin/exiftool"
        return None

    def fake_run(cmd, **kwargs):
        return _Completed(0)

    monkeypatch.setattr(container_meta, "which", fake_which)
    monkeypatch.setattr(container_meta.subprocess, "run", fake_run)

    pdf_bytes = _ai_pdf()
    data = {"file": (io.BytesIO(pdf_bytes), "sample.pdf")}
    res = client.post("/upload", data=data, content_type="multipart/form-data")
    assert res.status_code == 302
    session_id = res.headers["Location"].split("/session/")[1].split("/inspect")[0]

    clean_res = client.post(f"/session/{session_id}/clean")
    assert clean_res.status_code == 302

    result_res = client.get(f"/session/{session_id}/result")
    assert result_res.status_code == 200
    assert b"Cleaning completed with limited verification" in result_res.data

    report_res = client.get(f"/session/{session_id}/download/report")
    assert report_res.status_code == 200
    json_data = json.loads(report_res.data)
    assert json_data["cleaning_outcome_state"] == "cleaned_verification_incomplete"


def test_pdf_outcome_fully_verified_and_cleaned(client, monkeypatch):
    """State A: Cleaning performed, all tools available, verified clean."""
    import engine
    import container_meta
    import subprocess

    monkeypatch.setattr(
        engine,
        "capabilities",
        lambda: {
            "version": "dev",
            "tools": {"c2patool": True, "exiftool": True, "qpdf": True},
        },
    )

    def fake_which(cmd):
        return f"/fake/bin/{cmd}"

    def fake_run(cmd, **kwargs):
        if cmd[0].endswith("qpdf"):
            Path(cmd[-1]).write_bytes(b"%PDF-1.4\n% rebuilt\n%%EOF\n")
        return _Completed(0)

    monkeypatch.setattr(container_meta, "which", fake_which)
    monkeypatch.setattr(container_meta.subprocess, "run", fake_run)

    pdf_bytes = _ai_pdf()
    data = {"file": (io.BytesIO(pdf_bytes), "sample.pdf")}
    res = client.post("/upload", data=data, content_type="multipart/form-data")
    assert res.status_code == 302
    session_id = res.headers["Location"].split("/session/")[1].split("/inspect")[0]

    clean_res = client.post(f"/session/{session_id}/clean")
    assert clean_res.status_code == 302

    result_res = client.get(f"/session/{session_id}/result")
    assert result_res.status_code == 200
    assert b"File Cleaned Successfully" in result_res.data

    report_res = client.get(f"/session/{session_id}/download/report")
    assert report_res.status_code == 200
    json_data = json.loads(report_res.data)
    assert json_data["cleaning_outcome_state"] == "fully_cleaned"


def test_pdf_outcome_findings_remain(client, monkeypatch):
    """State D: Cleaning performed, but post-clean inspection still detects signals."""
    import engine
    import container_meta
    import subprocess

    monkeypatch.setattr(
        engine,
        "capabilities",
        lambda: {
            "version": "dev",
            "tools": {"c2patool": True, "exiftool": True, "qpdf": True},
        },
    )

    def fake_which(cmd):
        return f"/fake/bin/{cmd}"

    def fake_run(cmd, **kwargs):
        return _Completed(0)

    original_inspect_bytes = engine.inspect_bytes
    def mock_inspect_bytes(data_bytes, filename):
        res = original_inspect_bytes(data_bytes, filename)
        if b"% rebuilt" in data_bytes or len(data_bytes) > 0:
            res["verification_status"] = "detected"
            res["normalized_findings"] = [{
                "id": "residue",
                "scan_id": "1",
                "category": "invisible_text",
                "signal": "ZERO_WIDTH_SPACE",
                "confidence": "confirmed",
                "severity": "critical",
                "location": "body",
                "evidence": {},
                "removable": True,
                "removed": False
            }]
        return res

    import app as app_module
    monkeypatch.setattr(app_module, "inspect_bytes", mock_inspect_bytes)
    monkeypatch.setattr(engine, "inspect_bytes", mock_inspect_bytes)
    monkeypatch.setattr(container_meta, "which", fake_which)
    monkeypatch.setattr(container_meta.subprocess, "run", fake_run)

    pdf_bytes = _ai_pdf()
    data = {"file": (io.BytesIO(pdf_bytes), "sample.pdf")}
    res = client.post("/upload", data=data, content_type="multipart/form-data")
    assert res.status_code == 302
    session_id = res.headers["Location"].split("/session/")[1].split("/inspect")[0]

    clean_res = client.post(f"/session/{session_id}/clean")
    assert clean_res.status_code == 302

    result_res = client.get(f"/session/{session_id}/result")
    assert result_res.status_code == 200
    assert b"Residue Signals Detected" in result_res.data

    report_res = client.get(f"/session/{session_id}/download/report")
    assert report_res.status_code == 200
    json_data = json.loads(report_res.data)
    assert json_data["cleaning_outcome_state"] == "findings_remain"
