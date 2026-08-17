"""Unit and integration tests for Phase 3 AI Watermark Lab."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

import numpy as np
import pytest
from PIL import Image

# Setup paths to import from provenance and web
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "web"))

from provenance.db import (
    init_db,
    save_experiment,
    get_experiment,
    list_experiments,
    save_experiment_run,
    get_experiment_run,
    list_experiment_runs,
    save_run_metrics,
    get_run_metrics,
    save_benchmark,
    list_benchmarks,
)
from provenance.metrics import (
    compute_lexical_divergence,
    compute_psnr,
    compute_ssim,
    compute_lpips,
    compute_semantic_similarity,
)
from provenance.experiments import (
    validate_config,
    run_pipeline,
    get_harness_status,
)
from web.app import app


@pytest.fixture(scope="module", autouse=True)
def cleanup_pil_modules():
    yield
    # Clean up PIL from sys.modules so that subsequent mock tests can load their own custom mock PIL
    import sys
    for k in list(sys.modules.keys()):
        if k == "PIL" or k.startswith("PIL."):
            sys.modules.pop(k, None)


# =====================================================================
# Database CRUD Tests
# =====================================================================

@pytest.fixture
def temp_db():
    """Temporary database file path fixture."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db_path = Path(path)
    init_db(db_path)
    yield db_path
    if db_path.is_file():
        db_path.unlink()


def test_experiment_db_crud(temp_db):
    exp_id = "test-exp-123"
    name = "Test Opt Benchmark"
    config_json = json.dumps({"experiment": {"name": name}})
    created_at = time.time()

    # Save
    save_experiment(exp_id, name, config_json, created_at, db_path=temp_db)
    
    # Retrieve
    exp = get_experiment(exp_id, db_path=temp_db)
    assert exp is not None
    assert exp["id"] == exp_id
    assert exp["name"] == name
    assert exp["configuration_json"] == config_json

    # List
    exps = list_experiments(db_path=temp_db)
    assert len(exps) == 1
    assert exps[0]["id"] == exp_id


def test_experiment_run_db_crud(temp_db):
    exp_id = "test-exp-123"
    run_id = "test-run-456"
    
    save_experiment(exp_id, "Test", "{}", time.time(), db_path=temp_db)
    save_experiment_run(
        run_id=run_id,
        experiment_id=exp_id,
        started_at=1000.0,
        finished_at=1005.0,
        status="completed",
        device="cpu",
        input_hash="hash123",
        configuration_hash="conf456",
        error=None,
        reproducibility_json="{}",
        db_path=temp_db,
    )

    run = get_experiment_run(run_id, db_path=temp_db)
    assert run is not None
    assert run["id"] == run_id
    assert run["experiment_id"] == exp_id
    assert run["status"] == "completed"
    assert run["device"] == "cpu"
    assert run["started_at"] == 1000.0
    assert run["finished_at"] == 1005.0

    runs = list_experiment_runs(exp_id, db_path=temp_db)
    assert len(runs) == 1
    assert runs[0]["id"] == run_id


def test_metrics_db_crud(temp_db):
    exp_id = "test-exp-123"
    run_id = "test-run-456"
    metrics = [
        {"name": "psnr", "value": 35.5, "unit": "dB"},
        {"name": "ssim", "value": 0.98, "unit": "ratio"},
    ]

    save_experiment(exp_id, "Test", "{}", 1000.0, db_path=temp_db)
    save_experiment_run(
        run_id=run_id,
        experiment_id=exp_id,
        started_at=1000.0,
        finished_at=1005.0,
        status="completed",
        device="cpu",
        input_hash="hash123",
        configuration_hash="conf456",
        error=None,
        reproducibility_json="{}",
        db_path=temp_db,
    )
    save_run_metrics(run_id, metrics, db_path=temp_db)
    
    retrieved = get_run_metrics(run_id, db_path=temp_db)
    assert len(retrieved) == 2
    metrics_map = {m["name"]: m for m in retrieved}
    assert metrics_map["psnr"]["value"] == 35.5
    assert metrics_map["psnr"]["unit"] == "dB"
    assert metrics_map["ssim"]["value"] == 0.98
    assert metrics_map["ssim"]["unit"] == "ratio"


def test_benchmarks_db_crud(temp_db):
    bench_id = "bench-text-v1"
    name = "Standard Text Suite"
    version = "1.0"
    desc = "Standard parameters evaluation"
    conf = "{}"

    save_benchmark(bench_id, name, version, desc, conf, db_path=temp_db)
    
    benchmarks = list_benchmarks(db_path=temp_db)
    assert len(benchmarks) == 1
    assert benchmarks[0]["id"] == bench_id
    assert benchmarks[0]["name"] == name
    assert benchmarks[0]["version"] == version
    assert benchmarks[0]["description"] == desc


# =====================================================================
# Configuration Validation Tests
# =====================================================================

def test_validation_rejects_malformed_yaml():
    with pytest.raises(ValueError, match="Invalid YAML configuration syntax"):
        validate_config("{experiment: invalid: syntax:")


def test_validation_rejects_oversized_payload():
    huge_yaml = "experiment:\n  name: " + ("x" * 600000)
    with pytest.raises(ValueError, match="payload exceeds maximum allowed size"):
        validate_config(huge_yaml)


def test_validation_rejects_missing_keys():
    # Missing input / watermark / attack
    partial = "experiment:\n  name: Test"
    with pytest.raises(ValueError, match="Missing required top-level configuration sections"):
        validate_config(partial)


def test_validation_validates_correct_struct():
    valid = """
experiment:
  name: Test Sweep
input:
  type: prompt
  content: "Prompt string"
watermark:
  family: text
  method: kgw
  parameters:
    device: cpu
attack:
  method: rewrite
  parameters:
    strength: paraphrase
"""
    parsed = validate_config(valid)
    assert parsed["experiment"]["name"] == "Test Sweep"
    assert parsed["watermark"]["family"] == "text"


# =====================================================================
# Quality Metrics Tests
# =====================================================================

def test_lexical_divergence():
    # Identical texts
    assert compute_lexical_divergence("Hello world text.", "Hello world text.") == 0.0
    # Fully disjoint bigrams
    assert compute_lexical_divergence("A B C.", "X Y Z.") == 1.0
    # Partially similar
    div = compute_lexical_divergence("The cat sat on the mat.", "The cat lay on the mat.")
    assert 0.0 < div < 1.0


def test_image_psnr_and_ssim():
    # Create simple colored images
    img1 = Image.new("RGB", (100, 100), color="blue")
    img2 = Image.new("RGB", (100, 100), color="blue")
    
    buf1 = io.BytesIO()
    img1.save(buf1, format="PNG")
    b1 = buf1.getvalue()

    buf2 = io.BytesIO()
    img2.save(buf2, format="PNG")
    b2 = buf2.getvalue()

    # Identical images
    assert compute_psnr(b1, b2) == float("inf")
    assert compute_ssim(b1, b2) == 1.0

    # Modify one image slightly
    img3 = Image.new("RGB", (100, 100), color="red")
    buf3 = io.BytesIO()
    img3.save(buf3, format="PNG")
    b3 = buf3.getvalue()

    assert compute_psnr(b1, b3) < float("inf")
    assert compute_ssim(b1, b3) < 1.0


def test_optional_metrics_handling():
    # These should handle import failures cleanly and return None if libs not present
    img = Image.new("RGB", (10, 10))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b = buf.getvalue()

    # Just run to make sure it doesn't raise unhandled exceptions
    compute_lpips(b, b)
    compute_semantic_similarity("test text", "test text")


# =====================================================================
# Pipeline Orchestration Tests (Mocked Subprocess calls)
# =====================================================================

@patch("provenance.experiments._run_subprocess")
def test_text_pipeline_execution(mock_sub, temp_db):
    exp_id = "exp-mock-text"
    run_id = "run-mock-text"
    
    # Setup mocks
    # 1. watermark generation output
    # 2. detect before output
    # 3. rewrite attack output
    # 4. detect after output
    mock_sub.side_effect = [
        # Watermark gen json payload
        '{"available": true, "watermarked_output": "temp.txt", "unwatermarked_output": null}',
        # Detect before json payload
        '{"score": 4.5, "is_watermarked": true}',
        # Rewrite output
        'This is the rewritten version of the text.',
        # Detect after json payload
        '{"score": 1.2, "is_watermarked": false}'
    ]

    config = {
        "experiment": {"name": "Mock Test"},
        "input": {"type": "prompt", "content": "Original prompt content"},
        "watermark": {
            "family": "text",
            "method": "kgw",
            "parameters": {"model": "opt-1.3b", "device": "cpu"}
        },
        "attack": {
            "method": "rewrite",
            "parameters": {"backend": "print-prompt", "strength": "paraphrase"}
        }
    }

    # Create dummy temp.txt which the mock generation returns
    temp_txt_path = Path("temp.txt")
    temp_txt_path.write_text("This is watermarked sample text content.", encoding="utf-8")

    try:
        # Temporarily point DB to our temp_db and mock MARKLLM_DIR
        with patch.dict(os.environ, {"MARKLLM_DIR": str(ROOT)}), \
             patch("provenance.experiments.save_experiment_run") as mock_save_run, \
             patch("provenance.experiments.save_run_metrics") as mock_save_metrics:
            
            run_pipeline(run_id, exp_id, config)
            
            # Check status saves
            assert mock_save_run.call_count >= 2
            # Check completed run saves metrics
            assert mock_save_metrics.call_count == 1
            metrics_arg = mock_save_metrics.call_args[0][1]
            metrics_map = {m["name"]: m for m in metrics_arg}
            assert metrics_map["detection_score_before"]["value"] == 4.5
            assert metrics_map["detection_score_after"]["value"] == 1.2
            assert "lexical_divergence" in metrics_map
            assert "runtime" in metrics_map
    finally:
        if temp_txt_path.is_file():
            temp_txt_path.unlink()


# =====================================================================
# CLI Tests
# =====================================================================

def test_cli_subcommands():
    cli_script = ROOT / "service" / "scripts" / "contenttrace.py"
    assert cli_script.exists()

    # Call with --help
    cmd = [sys.executable, str(cli_script), "--help"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    assert r.returncode == 0
    assert "experiment" in r.stdout

    # Call experiment list
    cmd = [sys.executable, str(cli_script), "experiment", "list"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    assert r.returncode == 0


# =====================================================================
# Web App / UI Smoke Tests
# =====================================================================

def test_web_routes():
    app.config["TESTING"] = True
    client = app.test_client()

    # GET /lab
    res = client.get("/lab")
    assert res.status_code == 200
    assert b"AI Watermark Lab" in res.data

    # GET /lab/experiment/create
    res = client.get("/lab/experiment/create")
    assert res.status_code == 200
    assert b"New Experiment configuration" in res.data


# =====================================================================
# Progress, Status, Metrics, & Error Tests
# =====================================================================

def test_progress_state_transitions(temp_db):
    from provenance.db import get_experiment_run, update_run_progress, save_experiment_run, save_experiment
    run_id = "test-progress-run-1"
    save_experiment("exp-1", "Mock Exp 1", "{}", time.time(), db_path=temp_db)
    save_experiment_run(
        run_id=run_id,
        experiment_id="exp-1",
        started_at=time.time(),
        finished_at=None,
        status="running",
        device="cpu",
        input_hash=None,
        configuration_hash="cfg-123",
        error=None,
        reproducibility_json="{}",
        db_path=temp_db,
    )
    
    # 1. Update to first stage
    update_run_progress(run_id, "Loading Model", 15, "Loading opt model weights", db_path=temp_db)
    run = get_experiment_run(run_id, db_path=temp_db)
    assert run["current_stage"] == "Loading Model"
    assert run["stage_percentage"] == 15
    assert run["stage_status"] == "Loading opt model weights"

    # 2. Update to second stage
    update_run_progress(run_id, "Running Attack", 65, "Executing paraphrase rewrite", db_path=temp_db)
    run = get_experiment_run(run_id, db_path=temp_db)
    assert run["current_stage"] == "Running Attack"
    assert run["stage_percentage"] == 65
    assert run["stage_status"] == "Executing paraphrase rewrite"


def test_harness_status_detection():
    status = get_harness_status()
    assert "markllm" in status
    assert "synthid" in status
    assert "ctrlregen" in status
    for h in status.values():
        assert "name" in h
        assert "status" in h
        assert "env_var" in h
        assert "path" in h


def test_failed_execution_handling(temp_db):
    from provenance.db import save_experiment
    run_id = "test-fail-run-1"
    config = {
        "experiment": {"name": "Fail Test"},
        "input": {"type": "prompt", "content": "Original content"},
        "watermark": {
            "family": "text",
            "method": "kgw",
            "parameters": {"model": "opt-125m"}
        },
        "attack": {
            "method": "rewrite",
            "parameters": {"backend": "invalid-backend-name"}
        }
    }
    
    save_experiment("exp-fail", "Fail Test", json.dumps(config), time.time())
    
    # Run pipeline where we expect failure due to invalid backend
    run_pipeline(run_id, "exp-fail", config)
    
    from provenance.db import get_experiment_run
    run = get_experiment_run(run_id)
    assert run["status"] == "failed"
    assert run["error"] is not None
    assert run["current_stage"] == "Failed"
    assert run["stage_percentage"] == 100


def test_report_rendering_and_status_routes(temp_db):
    app.config["TESTING"] = True
    client = app.test_client()

    # Create dummy experiment and run to render report
    from provenance.db import save_experiment, save_experiment_run
    save_experiment("exp-rep", "Rep Test", "{}", time.time())
    save_experiment_run(
        run_id="run-rep",
        experiment_id="exp-rep",
        started_at=time.time(),
        finished_at=time.time() + 10,
        status="completed",
        device="cpu",
        input_hash="hash-1",
        configuration_hash="hash-2",
        error=None,
        reproducibility_json="{}",
    )

    # 1. Test HTML report rendering
    res = client.get("/lab/run/run-rep/report?format=html")
    assert res.status_code == 200
    assert b"Experiment Audit Report" in res.data

    # 2. Test JSON report rendering
    res = client.get("/lab/run/run-rep/report?format=json")
    assert res.status_code == 200
    assert b"run-rep" in res.data or b"completed" in res.data

    # 3. Test Harness Status UI
    res = client.get("/lab/status")
    assert res.status_code == 200
    assert b"ML Dependencies" in res.data

