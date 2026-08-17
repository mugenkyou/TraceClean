"""Integration tests for REST API v1 endpoints."""

from __future__ import annotations

import io
import json
import pytest

# Insert web directory into path
import sys
from pathlib import Path
WEB_DIR = Path(__file__).resolve().parent.parent / "web"
if str(WEB_DIR) not in sys.path:
    sys.path.insert(0, str(WEB_DIR))

from app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_api_v1_scan_endpoint(client):
    file_content = b"Sample text file with normal content."
    data = {"file": (io.BytesIO(file_content), "test.txt")}

    resp = client.post("/api/v1/scan", data=data, content_type="multipart/form-data")
    assert resp.status_code == 200

    res_json = json.loads(resp.data)
    assert "scan_id" in res_json
    assert res_json["original_filename"] == "test.txt"
    assert res_json["kind"] == "text"
    assert "findings" in res_json
    assert "score" in res_json
    assert res_json["score"]["score"] == 0.0


def test_api_v1_get_scan_endpoint(client):
    # First create a scan
    file_content = b"Sample text content."
    data = {"file": (io.BytesIO(file_content), "api_get_test.txt")}
    scan_resp = client.post("/api/v1/scan", data=data, content_type="multipart/form-data")
    scan_data = json.loads(scan_resp.data)
    scan_id = scan_data["scan_id"]

    # Now retrieve it
    get_resp = client.get(f"/api/v1/scan/{scan_id}")
    assert get_resp.status_code == 200
    get_data = json.loads(get_resp.data)
    assert get_data["scan_id"] == scan_id
    assert get_data["original_filename"] == "api_get_test.txt"


def test_api_v1_get_report_endpoint(client):
    file_content = b"Sample report content."
    data = {"file": (io.BytesIO(file_content), "report_test.txt")}
    scan_resp = client.post("/api/v1/scan", data=data, content_type="multipart/form-data")
    scan_id = json.loads(scan_resp.data)["scan_id"]

    # JSON report
    json_resp = client.get(f"/api/v1/scan/{scan_id}/report?format=json")
    assert json_resp.status_code == 200
    assert "application/json" in json_resp.headers["Content-Type"]

    # HTML report
    html_resp = client.get(f"/api/v1/scan/{scan_id}/report?format=html")
    assert html_resp.status_code == 200
    assert "text/html" in html_resp.headers["Content-Type"]
    assert "TraceClean Forensic Audit Report" in html_resp.data.decode("utf-8")
