"""Reusable in-process engine API for TraceClean.

Provides clean Python functions to inspect and clean file bytes in-memory
or via temporary work directories, sharing the exact same pipeline logic
used by server.py, the CLI scripts, and the web application.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any

from common import (
    MAX_INPUT_BYTES,
    eprint,
    looks_binary,
    which,
)
from container_meta import clean_container, inspect_container
from format_dispatch import classify_bytes
from image_meta import clean_image, inspect_image
from score_stylometry import score_text_stylometry
from text_unicode import clean_text, inspect_text

VERSION = os.environ.get("TRACECLEAN_SERVER_VERSION", "dev")

ALLOWED_CLEAN_OPTIONS = {
    "nfkc": bool,
    "aggressive_homoglyphs": bool,
    "keep_non_ai_metadata": bool,
    "also_layer_a_text": bool,
    "remove_pixel": str,
    "strip_all_metadata": bool,
}


def capabilities() -> dict[str, Any]:
    """Report available system tools, pixel backends, and scorers."""
    return {
        "version": VERSION,
        "tools": {
            "c2patool": which("c2patool") is not None,
            "exiftool": which("exiftool") is not None,
            "qpdf": which("qpdf") is not None,
        },
        "pixel_backends": {
            "ctrlregen": bool(os.environ.get("NOAI_WATERMARK_DIR")),
            "diffusion": bool(os.environ.get("MARKDIFFUSION_DIR")),
        },
        "scorers": {
            "synthid": bool(os.environ.get("REVERSE_SYNTHID_DIR")),
            "stylometry": True,
        },
        "harnesses": {
            "markllm": bool(os.environ.get("MARKLLM_DIR")),
        },
    }


def _safe_name(name: str) -> str:
    """Reduce a client-supplied filename to a bare basename safe for temp use."""
    base = Path(name.replace("\\", "/")).name
    if base in ("", ".", ".."):
        return "input"
    return base


def _tmp_path(tmpdir: Path, *parts: str) -> Path:
    """Join parts under tmpdir securely, refusing escape attempts."""
    resolved_dir = tmpdir.resolve()
    target = resolved_dir.joinpath(*parts).resolve()
    if not str(target).startswith(str(resolved_dir)):
        raise ValueError(f"refusing path traversal attempt: {parts}")
    return target


def required_tools_for_kind_and_suffix(kind: str, suffix: str) -> list[str]:
    """Return list of CLI tools required for full forensic inspection coverage."""
    s = suffix.lower()
    if kind == "text":
        return []
    if kind == "image":
        if s == ".svg":
            return []
        return ["c2patool", "exiftool"]
    if kind == "container":
        if s in (".html", ".htm", ".md", ".markdown"):
            return []
        if s == ".pdf":
            return ["qpdf", "exiftool"]
        if s in (".docx", ".odt"):
            return ["exiftool"]
        return ["exiftool"]
    return []


def inspect_bytes(data: bytes, name: str) -> dict[str, Any]:
    """Inspect raw file bytes for AI provenance and watermark signals.

    Returns dict with keys: 'ok', 'kind', 'report', 'suspicious', 'verification_status',
    'status_reason', 'missing_tools', 'verified_clean'.
    Raises ValueError on invalid/corrupt input or size cap breaches.
    """
    if len(data) > MAX_INPUT_BYTES:
        raise ValueError(f"input exceeds maximum limit of {MAX_INPUT_BYTES} bytes")

    safe_filename = _safe_name(name)
    kind = classify_bytes(data, Path(safe_filename).suffix)
    suffix = Path(safe_filename).suffix

    with tempfile.TemporaryDirectory(prefix="tc-inspect-") as tmp:
        tmpdir = Path(tmp)
        path = _tmp_path(tmpdir, safe_filename or "input")
        path.write_bytes(data)

        if kind == "text":
            if looks_binary(data):
                raise ValueError("refusing to inspect bytes that look like a binary container as text")
            raw_text = data.decode("utf-8", errors="surrogateescape")
            report = inspect_text(raw_text).to_dict()
            s_rep = score_text_stylometry(raw_text, path=safe_filename or "<text>")
            report["stylometry"] = s_rep.to_dict()
        elif kind == "image":
            report = inspect_image(path).to_dict()
        else:
            report = inspect_container(path).to_dict()

    has_marks = bool(report.get("suspicious_total")) or bool(
        report.get("has_c2pa") or report.get("has_ai_metadata")
    ) or bool(report.get("stylometry", {}).get("score", 0.0) >= 0.65)

    # Tool requirement & coverage checks
    req_tools = required_tools_for_kind_and_suffix(kind, suffix)
    tool_caps = capabilities().get("tools", {})
    missing_tools = [t for t in req_tools if not tool_caps.get(t)]

    if has_marks:
        verification_status = "detected"
        status_reason = "AI provenance marks or suspicious signals detected."
    elif missing_tools:
        verification_status = "inconclusive"
        status_reason = f"No marks detected by built-in parsers, but required tool(s) ({', '.join(missing_tools)}) were unavailable for full verification."
    else:
        verification_status = "not_detected"
        status_reason = "Full inspection completed with all required tools available. No provenance marks detected."

    verified_clean = (verification_status == "not_detected")

    return {
        "ok": True,
        "kind": kind,
        "report": report,
        "suspicious": has_marks,
        "verification_status": verification_status,
        "status_reason": status_reason,
        "missing_tools": missing_tools,
        "verified_clean": verified_clean,
    }


def clean_bytes(
    data: bytes, name: str, options: dict[str, Any] | None = None
) -> tuple[bytes, dict[str, Any]]:
    """Clean raw file bytes using deterministic processing pipeline.

    Returns tuple of (cleaned_bytes, result_dict) containing 'ok', 'kind', 'report'.
    Raises ValueError on invalid input or unknown options.
    """
    if len(data) > MAX_INPUT_BYTES:
        raise ValueError(f"input exceeds maximum limit of {MAX_INPUT_BYTES} bytes")

    safe_filename = _safe_name(name)
    kind = classify_bytes(data, Path(safe_filename).suffix)

    opts = options or {}
    if not isinstance(opts, dict):
        raise ValueError("'options' must be an object")
    for key in opts:
        if key not in ALLOWED_CLEAN_OPTIONS:
            raise ValueError(f"unknown option: {key}")

    with tempfile.TemporaryDirectory(prefix="tc-clean-") as tmp:
        tmpdir = Path(tmp)
        src = _tmp_path(tmpdir, safe_filename or "input")
        src.write_bytes(data)

        if kind == "text":
            if looks_binary(data):
                raise ValueError("refusing to clean bytes that look like a binary container as text")
            text = data.decode("utf-8", errors="surrogateescape")
            cleaned, stats = clean_text(
                text,
                nfkc=bool(opts.get("nfkc")),
                aggressive_homoglyphs=bool(opts.get("aggressive_homoglyphs")),
            )
            cleaned_bytes = cleaned.encode("utf-8", errors="surrogateescape")
            report: dict[str, Any] = {"kind": "text", "stats": stats, "length": len(cleaned)}
        elif kind == "image":
            dest = tmpdir / "out.png"
            strip_all = not bool(opts.get("keep_non_ai_metadata"))
            if "strip_all_metadata" in opts:
                strip_all = bool(opts["strip_all_metadata"])
            remove_pixel = opts.get("remove_pixel")
            if remove_pixel not in (None, "ctrlregen", "diffusion"):
                raise ValueError("remove_pixel must be one of: ctrlregen, diffusion")
            result = clean_image(
                src,
                dest,
                strip_all_metadata=strip_all,
                remove_pixel=remove_pixel,
            )
            cleaned_bytes = dest.read_bytes()
            report = {"kind": "image", **result}
        else:
            dest = _tmp_path(tmpdir, f"out{Path(safe_filename).suffix}")
            result = clean_container(src, dest, also_layer_a_text=bool(opts.get("also_layer_a_text", True)))
            cleaned_bytes = dest.read_bytes()
            report = {"kind": "container", **result}

        report.pop("input", None)
        report.pop("output", None)

    return cleaned_bytes, {
        "ok": True,
        "kind": kind,
        "report": report,
    }
