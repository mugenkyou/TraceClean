"""Integration test for CLI inspect_file.py --score flag."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "service" / "scripts"
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def test_cli_inspect_file_score_flag():
    inspect_script = SCRIPTS_DIR / "inspect_file.py"
    sample_file = FIXTURES_DIR / "sample_watermarked.txt"
    assert inspect_script.exists()
    assert sample_file.exists()

    cmd = [
        sys.executable,
        str(inspect_script),
        str(sample_file),
        "--score",
    ]

    r = subprocess.run(cmd, capture_output=True, text=True)
    assert r.returncode in (0, 1)
    assert "Provenance Exposure Score:" in r.stdout
    assert "Status:" in r.stdout
    assert "Derivation:" in r.stdout
