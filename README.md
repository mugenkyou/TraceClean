# TraceClean — AI Content Provenance & Forensics

TraceClean is a local-first application and forensic tool designed to audit, evaluate, and clean AI content provenance markers and metadata from files and text.

---

## What It Does
TraceClean operates as a privacy-hygiene utility for content you own. It helps developers, researchers, and content creators:
- Inspect document and image files for embedded provenance signals, signature blocks, and hidden metadata.
- Clean files deterministically by stripping C2PA manifests, EXIF tags, XMP blocks, and other forensic signals.
- Evaluate the robustness of statistical watermarks in text and images under research conditions via an experimental Watermark Lab.

## Core Forensic Workflow
TraceClean removes metadata tags and structure markers without altering the primary payload bytes (like image pixels or document text):
1. **Layer A (Unicode / Text Formatting)**: Identifies and strips invisible Unicode space variations, Bidirectional (bidi) markers, zero-width spaces, and format controls frequently used by commercial generators.
2. **Metadata & Containers (Files)**: Parses and cleans standard formats (PNG, JPEG, WebP, SVG, PDF, DOCX, ODT, HTML, Markdown). It strips metadata blocks while leaving primary content intact.
3. **Layer B Rewrite (Token Re-sampling)**: Provides local re-writing scripts and prompts (supporting Ollama or OpenAI-compatible backends) to break statistical/lexical token signatures.

## Experimental Watermark Lab
The **AI Watermark Lab** is a separate, optional evaluation environment built into the project. It provides:
- A platform to configure and run reproducible watermark evaluation sweeps.
- Integration hooks for optional research harnesses (MarkLLM, reverse-SynthID, and CtrlRegen).
- Quality metric checks (lexical divergence, semantic similarity cosine scores, PSNR, SSIM, and runtime tracking) to measure degradation before and after attacks.
- Exportable audit reports in JSON and HTML format.

*Note: The Watermark Lab is an evaluation testbed. Detector results are specific to the configured research harness and do not represent universal watermark-removal certification.*

## Local-First & Privacy Model
TraceClean operates 100% locally. 
- All standard operations (metadata cleaning, Layer A text stripping, and stylometry checks) use standard library implementations.
- No network requests are made during normal file scanning.
- Your uploaded documents and processed outputs are never sent to external servers or telemetry endpoints.

---

## Installation

### 1. Requirements
- Python 3.10 or higher.
- System utilities (optional, pre-installed in Docker images):
  - `qpdf`: Required for structural PDF cleaning.
  - `exiftool`: Used for robust EXIF/XMP metadata stripping.
  - `c2patool`: Used to parse and strip C2PA manifest stores.

### 2. Standard Installation
Clone the repository and install the core dependencies:
```bash
git clone https://github.com/mugenkyou/TraceClean.git
cd TraceClean
pip install -r requirements.txt
```

To install development dependencies (including pytest and openapi validator):
```bash
pip install -r requirements-dev.txt
```

---

## Running the Application

### 1. Python CLI
Run deterministic file scan and clean operations directly:
```bash
# Inspect a file
python service/scripts/inspect_file.py draft.md

# Clean a file (metadata and Layer A Unicode)
python service/scripts/clean_file.py draft.md -o draft.cleaned.md
```

### 2. Standalone HTTP Service
Start the backend microservice (Stdlib only):
```bash
python service/scripts/server.py --host 127.0.0.1 --port 8765
```

### 3. Local Web UI Dashboard
Start the Flask-based browser interface:
```bash
python web/app.py
```
Open [http://127.0.0.1:5000](http://127.0.0.1:5000) to access the dashboard containing:
- **Forensic Scan**: Drag-and-drop file/text auditor.
- **Batch Scanner**: Clean folders or multiple files.
- **Scan History**: Review past scans logged in local SQLite (`contenttrace.db`).
- **Watermark Lab**: Interface for experimental evaluation runs.

### 4. Docker Compose
Run the entire setup (Core + optional harnesses) using Docker:
```bash
# Core service only
docker compose up --build -d

# Build optional harnesses
docker compose --profile harness --profile heavy up --build -d
```

---

## Optional Lab Initialization

The Watermark Lab supports third-party research harnesses that are not bundled by default. To configure them:
1. Define the environment variables pointing to their checkout paths:
   - `MARKLLM_DIR`
   - `REVERSE_SYNTHID_DIR`
   - `CTRLREGEN_DIR`
2. Initialize them via the UI Dashboard under the **Watermark Lab -> ML Status** page, or execute the setup scripts directly:
   ```bash
   ./service/scripts/setup_markllm.sh
   ./service/scripts/setup_synthid.sh
   ./service/scripts/setup_ctrlregen.sh
   ```

---

## Testing

Run the test suite using pytest:
```bash
python -m pytest
```

Integration tests requiring external checkouts can be excluded using:
```bash
python -m pytest -m "not integration"
```

---

## Research Limitations & Disclaimers
- **No Universal Guarantee**: TraceClean is a metadata cleaner and robust research interface, not a universal watermark bypass.
- **No Commercial Guarantee**: It does not guarantee compliance or evasion against all commercial or proprietary watermark checkers.
- **Payload Integrity**: While designed to strip metadata, aggressive rewriting or pixel manipulation can affect file structure or perceptual quality. Always verify clean copies.

## Security
For our security policy, vulnerabilities list, and reporting procedures, see [SECURITY.md](SECURITY.md).

## License
TraceClean is distributed under the [MIT License](LICENSE).
