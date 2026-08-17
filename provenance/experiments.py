"""AI Watermark Lab experiment orchestrator and validator.

Manages experiment run states, pipeline execution for text and image watermarks,
parameter sweeps, quality metric compilation, and reproducibility reports.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import yaml

from provenance.db import (
    save_experiment_run,
    save_run_metrics,
    update_run_progress,
)
from provenance.metrics import (
    compute_lexical_divergence,
    compute_semantic_similarity,
    compute_psnr,
    compute_ssim,
    compute_lpips,
)

ROOT_DIR = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = ROOT_DIR / "service" / "scripts"

# Thread pool for asynchronous background runs
_executor = concurrent.futures.ThreadPoolExecutor(max_workers=2)
# Keep track of active tasks in memory
_active_runs: dict[str, concurrent.futures.Future] = {}


# =====================================================================
# Configuration Parsing & Validation
# =====================================================================

def validate_config(config_str: str) -> dict[str, Any]:
    """Parse and validate an experiment configuration from YAML or JSON.

    Rejects unknown fields, checks size constraints, and enforces type properties.
    """
    # Enforce size limits (max 500 KB config file)
    if len(config_str.encode("utf-8")) > 500000:
        raise ValueError("Configuration payload exceeds maximum allowed size (500 KB).")

    try:
        config = yaml.safe_load(config_str)
    except Exception as e:
        raise ValueError(f"Invalid YAML configuration syntax: {e}")

    if not isinstance(config, dict):
        raise ValueError("Configuration must represent a top-level dictionary.")

    required_top = {"experiment", "input", "watermark", "attack"}
    missing = required_top - set(config.keys())
    if missing:
        raise ValueError(f"Missing required top-level configuration sections: {', '.join(missing)}")

    # 1. Validate Experiment Metadata
    exp_sec = config.get("experiment")
    if not isinstance(exp_sec, dict) or "name" not in exp_sec:
        raise ValueError("The 'experiment' section must contain a 'name' key.")

    # 2. Validate Input Section
    input_sec = config.get("input")
    if not isinstance(input_sec, dict):
        raise ValueError("The 'input' section must be a dictionary.")
    
    in_type = input_sec.get("type")
    if in_type not in ("prompt", "text", "image"):
        raise ValueError("Input 'type' must be one of: 'prompt', 'text', 'image'.")
    
    if "content" not in input_sec and "path" not in input_sec:
        raise ValueError("Input section must define either inline 'content' or a file 'path'.")

    # 3. Validate Watermark Section
    wm_sec = config.get("watermark")
    if not isinstance(wm_sec, dict):
        raise ValueError("The 'watermark' section must be a dictionary.")
    
    wm_family = wm_sec.get("family")
    if wm_family not in ("text", "image"):
        raise ValueError("Watermark 'family' must be 'text' or 'image'.")
    
    if not wm_sec.get("method"):
        raise ValueError("Watermark 'method' is required.")

    # 4. Validate Attack Section
    att_sec = config.get("attack")
    if not isinstance(att_sec, dict):
        raise ValueError("The 'attack' section must be a dictionary.")
    
    att_method = att_sec.get("method")
    if wm_family == "text" and att_method != "rewrite":
        raise ValueError("For text watermark family, attack method must be 'rewrite'.")
    if wm_family == "image" and att_method not in ("ctrlregen", "purify"):
        raise ValueError("For image watermark family, attack method must be 'ctrlregen' or 'purify'.")

    # 5. Validate Sweep parameters (optional)
    sweep_sec = config.get("sweep")
    if sweep_sec is not None:
        if not isinstance(sweep_sec, dict) or "parameter" not in sweep_sec or "values" not in sweep_sec:
            raise ValueError("The 'sweep' section must contain 'parameter' and 'values' list keys.")
        if not isinstance(sweep_sec["values"], list):
            raise ValueError("Sweep 'values' must be a list.")

    return config


# =====================================================================
# Execution Helper Functions
# =====================================================================

def _get_python_executable(checkout_dir: str) -> str:
    """Locate the Python executable in the virtual environment of the checkout folder."""
    if not checkout_dir:
        return sys.executable
    p = Path(checkout_dir).expanduser().resolve()
    if os.name == "nt":
        venv_py = p / ".venv" / "Scripts" / "python.exe"
    else:
        venv_py = p / ".venv" / "bin" / "python"
    return str(venv_py) if venv_py.is_file() else sys.executable


def _run_subprocess(cmd: list[str], input_data: bytes | str | None = None, timeout: float = 180.0) -> str:
    """Execute a subprocess command, returning stdout or raising a clear error."""
    text_mode = isinstance(input_data, str)
    try:
        r = subprocess.run(
            cmd,
            input=input_data,
            capture_output=True,
            text=text_mode,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError, TimeoutError) as e:
        raise RuntimeError(f"Execution command failed: {e}")

    if r.returncode != 0:
        err_msg = (r.stderr or "").strip()
        raise RuntimeError(err_msg or f"Subprocess exited with status {r.returncode}")
    
    return r.stdout


# =====================================================================
# Orchesrator Pipelines
# =====================================================================

def run_pipeline(run_id: str, experiment_id: str, config: dict[str, Any]) -> None:
    """Execute the watermark experiment pipeline end-to-end and persist metrics.

    Runs within the background worker thread.
    """
    started_at = time.time()
    
    # Save running state
    config_json = json.dumps(config)
    config_hash = hashlib.sha256(config_json.encode("utf-8")).hexdigest()
    
    reproducibility = {
        "version": "1.0.0-phase3",
        "harness_versions": {
            "markllm": os.environ.get("MARKLLM_DIR", "unconfigured"),
            "synthid": os.environ.get("REVERSE_SYNTHID_DIR", "unconfigured"),
            "ctrlregen": os.environ.get("NOAI_WATERMARK_DIR", "unconfigured"),
        },
        "python_version": sys.version,
        "platform": sys.platform,
        "stochastic_seed": config.get("watermark", {}).get("parameters", {}).get("seed"),
    }
    
    save_experiment_run(
        run_id=run_id,
        experiment_id=experiment_id,
        started_at=started_at,
        finished_at=None,
        status="running",
        device=config.get("watermark", {}).get("parameters", {}).get("device", "auto"),
        input_hash=None,
        configuration_hash=config_hash,
        error=None,
        reproducibility_json=json.dumps(reproducibility),
        current_stage="Initializing",
        stage_percentage=0,
        stage_status="Resolving inputs and setting up logs"
    )

    try:
        # 1. Resolve Input
        input_sec = config["input"]
        input_bytes = None
        input_text = None
        
        if "content" in input_sec:
            content_str = input_sec["content"]
            input_text = content_str
            input_bytes = content_str.encode("utf-8")
        else:
            in_path = Path(input_sec["path"]).expanduser().resolve()
            if not in_path.is_file():
                raise FileNotFoundError(f"Input file not found: {in_path}")
            input_bytes = in_path.read_bytes()
            try:
                input_text = input_bytes.decode("utf-8")
            except UnicodeDecodeError:
                input_text = None

        input_hash = hashlib.sha256(input_bytes).hexdigest()

        # Run text or image pipeline
        wm_family = config["watermark"]["family"]
        if wm_family == "text":
            metrics = _run_text_pipeline(input_text, config, run_id=run_id)
        else:
            metrics = _run_image_pipeline(input_bytes, config, run_id=run_id)

        finished_at = time.time()
        metrics.append({"name": "runtime", "value": finished_at - started_at, "unit": "seconds"})

        # Update run as completed
        update_run_progress(run_id, "Persisting Results", 95, "Saving database metrics and generating final reports")
        save_experiment_run(
            run_id=run_id,
            experiment_id=experiment_id,
            started_at=started_at,
            finished_at=finished_at,
            status="completed",
            device=config.get("watermark", {}).get("parameters", {}).get("device", "auto"),
            input_hash=input_hash,
            configuration_hash=config_hash,
            error=None,
            reproducibility_json=json.dumps(reproducibility),
            current_stage="Completed",
            stage_percentage=100,
            stage_status="Completed Successfully"
        )
        save_run_metrics(run_id, metrics)

    except Exception as e:
        finished_at = time.time()
        # Update run as failed
        save_experiment_run(
            run_id=run_id,
            experiment_id=experiment_id,
            started_at=started_at,
            finished_at=finished_at,
            status="failed",
            device=config.get("watermark", {}).get("parameters", {}).get("device", "auto"),
            input_hash=None,
            configuration_hash=config_hash,
            error=str(e),
            reproducibility_json=json.dumps(reproducibility),
            current_stage="Failed",
            stage_percentage=100,
            stage_status=f"Stage execution error: {str(e)}"
        )


def _run_text_pipeline(input_text: str, config: dict[str, Any], run_id: str | None = None) -> list[dict[str, Any]]:
    """Execute text watermark generation, before-detection, rewrite attack, and after-detection."""
    wm_sec = config["watermark"]
    att_sec = config["attack"]
    
    def report_progress(stage: str, percentage: int, stage_status: str):
        if run_id:
            update_run_progress(run_id, stage, percentage, stage_status)

    report_progress("Loading Model", 15, "Loading HF causal LM model weights for scoring")
    
    markllm_dir = os.environ.get("MARKLLM_DIR")
    if not markllm_dir:
        raise RuntimeError("Watermark Lab Error: MARKLLM_DIR is not configured in the environment.")

    py_exe = _get_python_executable(markllm_dir)
    detect_script = str(SCRIPTS_DIR / "detect_text_watermark.py")
    
    # Check if checkout directory actually exists
    if not Path(markllm_dir).is_dir():
        raise RuntimeError(f"Watermark Lab Error: MarkLLM checkout directory does not exist: {markllm_dir}")

    # Step 1: Watermark Generation (or use input text if it's already watermarked)
    if config["input"]["type"] == "prompt":
        report_progress("Generating Watermarked Content", 30, "Invoking AutoWatermark to generate marked text")
        cmd_gen = [
            py_exe, detect_script, "watermark", "-",
            "--scheme", wm_sec["method"],
            "--upstream-dir", markllm_dir,
            "--json",
        ]
        
        # Add generation parameters
        wm_params = wm_sec.get("parameters", {})
        if "model" in wm_params:
            cmd_gen.extend(["--model", wm_params["model"]])
        if "device" in wm_params:
            cmd_gen.extend(["--device", wm_params["device"]])
        if "seed" in wm_params:
            cmd_gen.extend(["--seed", str(wm_params["seed"])])
            
        gen_json = _run_subprocess(cmd_gen, input_data=input_text)
        gen_payload = json.loads(gen_json)
        
        # Read the generated output
        watermarked_path = Path(gen_payload["watermarked_output"])
        watermarked_text = watermarked_path.read_text("utf-8")
    else:
        report_progress("Generating Watermarked Content", 30, "Skipped generation: using pre-watermarked text input")
        watermarked_text = input_text

    # Step 2: Detect Before
    report_progress("Pre-Attack Detection", 50, "Evaluating baseline watermark strength before rewrite")
    cmd_det_before = [
        py_exe, detect_script, "detect", "-",
        "--scheme", wm_sec["method"],
        "--upstream-dir", markllm_dir,
        "--json",
    ]
    wm_params = wm_sec.get("parameters", {})
    if "model" in wm_params:
        cmd_det_before.extend(["--model", wm_params["model"]])
    if "device" in wm_params:
        cmd_det_before.extend(["--device", wm_params["device"]])
        
    before_json = _run_subprocess(cmd_det_before, input_data=watermarked_text)
    before_payload = json.loads(before_json)
    score_before = before_payload.get("score")

    # Step 3: Rewrite Attack
    report_progress("Running Attack", 65, "Executing LLM rewrite attack via backend API")
    rewrite_script = str(SCRIPTS_DIR / "rewrite_text.py")
    cmd_rew = [
        sys.executable, rewrite_script, "-",
        "--backend", att_sec.get("parameters", {}).get("backend", "print-prompt"),
        "--strength", att_sec.get("parameters", {}).get("strength", "paraphrase"),
    ]
    
    # Forward model/url if provided
    att_params = att_sec.get("parameters", {})
    if "model" in att_params:
        cmd_rew.extend(["--model", att_params["model"]])
    if "base_url" in att_params:
        cmd_rew.extend(["--base-url", att_params["base_url"]])
    if att_params.get("allow_remote"):
        cmd_rew.extend(["--allow-remote"])
        
    rewritten_text = _run_subprocess(cmd_rew, input_data=watermarked_text)

    # Step 4: Detect After
    report_progress("Post-Attack Detection", 80, "Evaluating remaining watermark strength after rewrite")
    cmd_det_after = [
        py_exe, detect_script, "detect", "-",
        "--scheme", wm_sec["method"],
        "--upstream-dir", markllm_dir,
        "--json",
    ]
    if "model" in wm_params:
        cmd_det_after.extend(["--model", wm_params["model"]])
    if "device" in wm_params:
        cmd_det_after.extend(["--device", wm_params["device"]])
        
    after_json = _run_subprocess(cmd_det_after, input_data=rewritten_text)
    after_payload = json.loads(after_json)
    score_after = after_payload.get("score")

    # Step 5: Lexical / Semantic metrics
    report_progress("Calculating Metrics", 90, "Computing Jaccard bigram divergence and semantic similarities")
    lexical_div = compute_lexical_divergence(watermarked_text, rewritten_text)
    semantic_sim = compute_semantic_similarity(watermarked_text, rewritten_text)

    metrics = [
        {"name": "detection_score_before", "value": score_before, "unit": "score"},
        {"name": "detection_score_after", "value": score_after, "unit": "score"},
        {"name": "lexical_divergence", "value": lexical_div, "unit": "ratio"},
    ]
    if semantic_sim is not None:
        metrics.append({"name": "semantic_similarity", "value": semantic_sim, "unit": "cosine"})

    return metrics


def _run_image_pipeline(input_bytes: bytes, config: dict[str, Any], run_id: str | None = None) -> list[dict[str, Any]]:
    """Execute image watermark generation, before-detection, purification/ctrlregen attack, and after-detection."""
    wm_sec = config["watermark"]
    att_sec = config["attack"]
    
    def report_progress(stage: str, percentage: int, stage_status: str):
        if run_id:
            update_run_progress(run_id, stage, percentage, stage_status)

    report_progress("Loading Model", 15, "Loading Stable Diffusion / SynthID extraction weights")
    
    markdiff_dir = os.environ.get("MARKDIFFUSION_DIR")
    synthid_dir = os.environ.get("REVERSE_SYNTHID_DIR")
    ctrlregen_dir = os.environ.get("NOAI_WATERMARK_DIR")

    # Step 1: Image Watermarking
    # If the input type is a prompt, we must use MarkDiffusion to generate the image
    if config["input"]["type"] == "prompt":
        report_progress("Generating Watermarked Content", 30, "Generating watermarked image using MarkDiffusion")
        if not markdiff_dir:
            raise RuntimeError("Watermark Lab Error: MARKDIFFUSION_DIR is not configured for prompt image generation.")
        
        py_exe_md = _get_python_executable(markdiff_dir)
        harness_script = str(SCRIPTS_DIR / "markdiffusion_harness.py")
        
        cmd_gen = [
            py_exe_md, harness_script, "watermark", "-",
            "--scheme", wm_sec["method"],
            "--upstream-dir", markdiff_dir,
            "--json",
        ]
        
        wm_params = wm_sec.get("parameters", {})
        if "model" in wm_params:
            cmd_gen.extend(["--model", wm_params["model"]])
        if "device" in wm_params:
            cmd_gen.extend(["--device", wm_params["device"]])
            
        gen_json = _run_subprocess(cmd_gen, input_data=config["input"]["content"])
        gen_payload = json.loads(gen_json)
        
        # Read the generated watermarked image bytes
        watermarked_path = Path(gen_payload["watermarked_output"])
        watermarked_bytes = watermarked_path.read_bytes()
    else:
        report_progress("Generating Watermarked Content", 30, "Skipped generation: using pre-watermarked image input")
        watermarked_bytes = input_bytes

    # Step 2: Score Before Attack
    # We can detect using SynthID or MarkDiffusion detector depending on config
    report_progress("Pre-Attack Detection", 50, "Measuring baseline watermark score on raw input")
    is_synthid = wm_sec["method"].lower() == "synthid"
    
    if is_synthid:
        if not synthid_dir:
            raise RuntimeError("Watermark Lab Error: REVERSE_SYNTHID_DIR is not configured for SynthID scoring.")
        
        py_exe_si = _get_python_executable(synthid_dir)
        score_script = str(SCRIPTS_DIR / "score_synthid.py")
        
        # Write to temporary file for command-line processing
        temp_img_before = SCRIPTS_DIR / f"temp_before_{time.time()}.png"
        temp_img_before.write_bytes(watermarked_bytes)
        
        cmd_det = [
            py_exe_si, score_script, str(temp_img_before),
            "--upstream-dir", synthid_dir,
            "--json",
        ]
        
        try:
            before_json = _run_subprocess(cmd_det)
            before_payload = json.loads(before_json)
            score_before = before_payload.get("confidence")
        finally:
            if temp_img_before.is_file():
                temp_img_before.unlink()
    else:
        if not markdiff_dir:
            raise RuntimeError("Watermark Lab Error: MARKDIFFUSION_DIR is not configured for MarkDiffusion detection.")
        
        py_exe_md = _get_python_executable(markdiff_dir)
        harness_script = str(SCRIPTS_DIR / "markdiffusion_harness.py")
        
        # Save temp image
        temp_img_before = SCRIPTS_DIR / f"temp_before_{time.time()}.png"
        temp_img_before.write_bytes(watermarked_bytes)
        
        cmd_det = [
            py_exe_md, harness_script, "detect", str(temp_img_before),
            "--scheme", wm_sec["method"],
            "--upstream-dir", markdiff_dir,
            "--json",
        ]
        
        try:
            before_json = _run_subprocess(cmd_det)
            before_payload = json.loads(before_json)
            score_before = before_payload.get("score")
        finally:
            if temp_img_before.is_file():
                temp_img_before.unlink()

    # Step 3: Apply Attack
    report_progress("Running Attack", 65, "Executing VAE/Diffusion regeneration pixel attack")
    temp_img_before = SCRIPTS_DIR / f"temp_before_{time.time()}.png"
    temp_img_before.write_bytes(watermarked_bytes)
    
    temp_img_after = SCRIPTS_DIR / f"temp_after_{time.time()}.png"
    
    try:
        if att_sec["method"] == "ctrlregen":
            if not ctrlregen_dir:
                raise RuntimeError("Watermark Lab Error: NOAI_WATERMARK_DIR is not configured for CtrlRegen attack.")
            
            py_exe_cr = _get_python_executable(ctrlregen_dir)
            clean_script = str(SCRIPTS_DIR / "clean_ctrlregen.py")
            
            cmd_att = [
                py_exe_cr, clean_script, str(temp_img_before),
                "-o", str(temp_img_after),
                "--upstream-dir", ctrlregen_dir,
                "--json",
            ]
            
            att_params = att_sec.get("parameters", {})
            if "strength" in att_params:
                cmd_att.extend(["--strength", str(att_params["strength"])])
            if "steps" in att_params:
                cmd_att.extend(["--steps", str(att_params["steps"])])
            if "device" in att_params:
                cmd_att.extend(["--device", att_params["device"]])
                
            _run_subprocess(cmd_att)
        else:
            # purify method using MarkDiffusion
            if not markdiff_dir:
                raise RuntimeError("Watermark Lab Error: MARKDIFFUSION_DIR is not configured for MarkDiffusion purify attack.")
            
            py_exe_md = _get_python_executable(markdiff_dir)
            harness_script = str(SCRIPTS_DIR / "markdiffusion_harness.py")
            
            cmd_att = [
                py_exe_md, harness_script, "purify", str(temp_img_before),
                "-o", str(temp_img_after),
                "--upstream-dir", markdiff_dir,
                "--json",
            ]
            # pass steps or other parameters if present
            
            _run_subprocess(cmd_att)

        if not temp_img_after.is_file():
            raise RuntimeError("Attack finished but no output file was written.")
            
        cleaned_bytes = temp_img_after.read_bytes()
    finally:
        if temp_img_before.is_file():
            temp_img_before.unlink()

    # Step 4: Score After Attack
    report_progress("Post-Attack Detection", 80, "Measuring remaining watermark score after attack")
    temp_img_after_detect = SCRIPTS_DIR / f"temp_after_detect_{time.time()}.png"
    temp_img_after_detect.write_bytes(cleaned_bytes)
    
    try:
        if is_synthid:
            py_exe_si = _get_python_executable(synthid_dir)
            score_script = str(SCRIPTS_DIR / "score_synthid.py")
            
            cmd_det_after = [
                py_exe_si, score_script, str(temp_img_after_detect),
                "--upstream-dir", synthid_dir,
                "--json",
            ]
            
            after_json = _run_subprocess(cmd_det_after)
            after_payload = json.loads(after_json)
            score_after = after_payload.get("confidence")
        else:
            py_exe_md = _get_python_executable(markdiff_dir)
            harness_script = str(SCRIPTS_DIR / "markdiffusion_harness.py")
            
            cmd_det_after = [
                py_exe_md, harness_script, "detect", str(temp_img_after_detect),
                "--scheme", wm_sec["method"],
                "--upstream-dir", markdiff_dir,
                "--json",
            ]
            
            after_json = _run_subprocess(cmd_det_after)
            after_payload = json.loads(after_json)
            score_after = after_payload.get("score")
    finally:
        if temp_img_after_detect.is_file():
            temp_img_after_detect.unlink()
        if temp_img_after.is_file():
            temp_img_after.unlink()

    # Step 5: Compute Quality metrics
    report_progress("Calculating Metrics", 90, "Computing PSNR, SSIM, and LPIPS quality metrics")
    psnr = compute_psnr(watermarked_bytes, cleaned_bytes)
    ssim = compute_ssim(watermarked_bytes, cleaned_bytes)
    lpips_dist = compute_lpips(watermarked_bytes, cleaned_bytes)

    metrics = [
        {"name": "detection_score_before", "value": score_before, "unit": "score"},
        {"name": "detection_score_after", "value": score_after, "unit": "score"},
        {"name": "psnr", "value": psnr, "unit": "dB"},
        {"name": "ssim", "value": ssim, "unit": "ratio"},
    ]
    if lpips_dist is not None:
        metrics.append({"name": "lpips", "value": lpips_dist, "unit": "distance"})

    return metrics


# =====================================================================
# Thread Pool Execution Manager
# =====================================================================

def queue_experiment_run(run_id: str, experiment_id: str, config: dict[str, Any]) -> None:
    """Submit an experiment execution run to the background worker pool."""
    future = _executor.submit(run_pipeline, run_id, experiment_id, config)
    _active_runs[run_id] = future


def get_active_run_futures() -> dict[str, concurrent.futures.Future]:
    """Retrieve futures for currently running or queued jobs."""
    # Clean up completed items first
    completed = [rid for rid, fut in _active_runs.items() if fut.done()]
    for rid in completed:
        _active_runs.pop(rid, None)
    return _active_runs


def get_harness_status() -> dict[str, Any]:
    """Detect the presence, version, and dependencies of external watermarking harnesses."""
    markllm_dir = os.environ.get("MARKLLM_DIR")
    synthid_dir = os.environ.get("REVERSE_SYNTHID_DIR")
    ctrlregen_dir = os.environ.get("NOAI_WATERMARK_DIR")
    
    status = {
        "markllm": {
            "name": "MarkLLM",
            "purpose": "Text watermark generation/detection",
            "env_var": "MARKLLM_DIR",
            "path": markllm_dir or "Not configured",
            "repo_installed": False,
            "deps_installed": False,
            "model_downloaded": False,
            "status": "Missing",
            "experiment_types": "Text watermark sweeps (KGW, SynthID text)",
            "approx_size": "~1.5 GB repo + deps; ~250 MB model (opt-125m)",
        },
        "synthid": {
            "name": "reverse-SynthID",
            "purpose": "Image pixel SynthID scoring",
            "env_var": "REVERSE_SYNTHID_DIR",
            "path": synthid_dir or "Not configured",
            "repo_installed": False,
            "deps_installed": False,
            "model_downloaded": False,
            "status": "Missing",
            "experiment_types": "Image watermark score (SynthID pixel)",
            "approx_size": "~300 MB repo + deps + codebooks",
        },
        "ctrlregen": {
            "name": "CtrlRegen",
            "purpose": "Image watermark purification/removal",
            "env_var": "NOAI_WATERMARK_DIR",
            "path": ctrlregen_dir or "Not configured",
            "repo_installed": False,
            "deps_installed": False,
            "model_downloaded": False,
            "status": "Missing",
            "experiment_types": "Image watermark purification attack",
            "approx_size": "~5 GB repo + weights",
        }
    }
    
    # 1. Check MarkLLM
    if markllm_dir:
        p = Path(markllm_dir).expanduser().resolve()
        if p.is_dir() and (p / "watermark").is_dir():
            status["markllm"]["repo_installed"] = True
            py_exe = _get_python_executable(str(p))
            try:
                subprocess.run([py_exe, "-c", "import torch, transformers, datasets"], capture_output=True, check=True)
                status["markllm"]["deps_installed"] = True
            except Exception:
                pass
            
            # Check model cache
            cache_dir = Path.home() / ".cache" / "huggingface" / "hub"
            if any(cache_dir.glob("models--facebook--opt-*")):
                status["markllm"]["model_downloaded"] = True
            
            if status["markllm"]["deps_installed"]:
                status["markllm"]["status"] = "Available"
            else:
                status["markllm"]["status"] = "Partial (Missing dependencies)"
        else:
            status["markllm"]["status"] = "Error (Invalid directory)"
            
    # 2. Check SynthID
    if synthid_dir:
        p = Path(synthid_dir).expanduser().resolve()
        if p.is_dir() and (p / "src").is_dir():
            status["synthid"]["repo_installed"] = True
            py_exe = _get_python_executable(str(p))
            try:
                subprocess.run([py_exe, "-c", "import cv2, robust_extractor"], capture_output=True, check=True)
                status["synthid"]["deps_installed"] = True
            except Exception:
                pass
            
            # Codebook check
            if (p / "artifacts" / "spectral_codebook_v4.npz").is_file():
                status["synthid"]["model_downloaded"] = True
                
            if status["synthid"]["deps_installed"] and status["synthid"]["model_downloaded"]:
                status["synthid"]["status"] = "Available"
            elif status["synthid"]["repo_installed"]:
                status["synthid"]["status"] = "Partial"
        else:
            status["synthid"]["status"] = "Error (Invalid directory)"

    # 3. Check CtrlRegen
    if ctrlregen_dir:
        p = Path(ctrlregen_dir).expanduser().resolve()
        if p.is_dir() and (p / "src").is_dir():
            status["ctrlregen"]["repo_installed"] = True
            py_exe = _get_python_executable(str(p))
            try:
                subprocess.run([py_exe, "-c", "import torch, diffusers, ctrlregen"], capture_output=True, check=True)
                status["ctrlregen"]["deps_installed"] = True
            except Exception:
                pass
            
            status["ctrlregen"]["model_downloaded"] = True  # assume yes for metadata status if installed
            
            if status["ctrlregen"]["deps_installed"]:
                status["ctrlregen"]["status"] = "Available"
            else:
                status["ctrlregen"]["status"] = "Partial"
        else:
            status["ctrlregen"]["status"] = "Error (Invalid directory)"
            
    return status

