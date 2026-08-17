# AI Watermark Lab & Reproducible Evaluation Subsystem

The AI Watermark Lab is an experimental verification and robustness-testing playground built on top of TraceClean. It provides a structured sandbox for orchestrating, executing, and persisting watermarking experiments, param-sweeps, and quality-vs-removal trade-off curves.

> [!IMPORTANT]
> **Methodology & Results Disclosure:**
> Watermark detection scores before and after attacks represent benchmark measurements under local, open-source conditions. A detection confidence of zero does not certify that commercial or vendor-specific production watermarks (e.g., OpenAI, Google SynthID, or metadata certificates) will fail to verify. content quality metrics (PSNR, SSIM, LPIPS, Jaccard distance) are mathematical proxies and may not map perfectly to human aesthetic judgment.

---

## 1. Architecture & Design

The subsystem operates independently of the core TraceClean deterministic forensic engine to ensure Phase 1 and Phase 2 architectures remain stable.

```
       +---------------------------------------------+
       |             TraceClean Web UI / CLI         |
       +----------------------+----------------------+
                              |
                              v
             +----------------------------------+
             |    Experiment Orchestrator       |
             |  (provenance/experiments.py)     |
             +---+--------------------------+---+
                 |                          |
                 v                          v
     +-----------------------+  +-----------------------+
     | Text Pipeline         |  | Image Pipeline        |
     | - MarkLLM Integration |  | - reverse-SynthID     |
     | - Rewrite Attacks     |  | - CtrlRegen Attacks   |
     +-----------------------+  +-----------------------+
                 |                          |
                 +------------+-------------+
                              |
                              v
             +----------------------------------+
             |       SQLite Database Ledger     |
             |       (provenance/db.py)         |
             +----------------------------------+
```

### Experiment Lifecycle
1. **Definition**: The configuration is parsed and validated (JSON schema check, max 500 KB limit).
2. **Setup**: The environment retrieves the target virtual environments and checks the local checkout directories.
3. **Execution**:
   - **Generation**: Creates watermarked text/image from inputs or prompt.
   - **Pre-Attack Score**: Queries detectors to establish baseline strength.
   - **Attack Phase**: Executes rewrite/purify attacks.
   - **Post-Attack Score**: Queries detectors to assess residual strength.
   - **Quality Metric Calculation**: Runs Jaccard Bigram distance, semantic similarity, PSNR, SSIM, and LPIPS.
4. **Persistence**: Saves run parameters, metrics ledger, and reproducibility logs to SQLite.

---

## 2. Supported Integrations

### A. MarkLLM (Text Watermarking)
- **Repository**: [THU-BPM/MarkLLM](https://github.com/THU-BPM/MarkLLM) (pinned commit `c45ddc40f7b761beabe55a1b8dc4690e531d1c6d`).
- **Required Env Var**: `MARKLLM_DIR`
- **Supported Schemes**: KGW (Kirchenbauer et al.), SynthID Text.
- **Model Files**: `facebook/opt-125m` (default testing) or `facebook/opt-1.3b` (default production), automatically cached locally by Hugging Face.

### B. reverse-SynthID (Image Scoring)
- **Repository**: [aloshdenny/reverse-SynthID](https://github.com/aloshdenny/reverse-SynthID) (pinned commit `b11083676fd3ee3ff97ce9d03c0e409e46905902`).
- **Required Env Var**: `REVERSE_SYNTHID_DIR`
- **Model Files**: Pinned spectral codebook vectors `spectral_codebook_v4.npz`.

### C. CtrlRegen (Image Attack/Purification)
- **Repository**: [aloshdenny/CtrlRegen](https://github.com/aloshdenny/CtrlRegen) (integrated via `NOAI_WATERMARK_DIR`).
- **Required Env Var**: `NOAI_WATERMARK_DIR`

---

## 3. Configuration Format & Sweeps

Experiments are specified in YAML files. Below is an example config executing a sweep over rewrite strengths:

```yaml
experiment:
  name: KGW Robustness Sweep

input:
  type: prompt
  content: "Artificial intelligence has rapidly evolved over the past decade..."

watermark:
  family: text
  method: kgw
  parameters:
    model: facebook/opt-125m
    device: cpu
    seed: 42

attack:
  method: rewrite
  parameters:
    backend: print-prompt
    strength: paraphrase

sweep:
  parameter: attack.parameters.strength
  values: ["paraphrase", "summarize", "expand"]
```

---

## 4. Metrics Evaluated

| Metric | Category | Range / Unit | Explanation |
|---|---|---|---|
| **detection_score_before** | Watermark | Float | Baseline score returned by the harness detector. |
| **detection_score_after** | Watermark | Float | Remaining watermark score after the attack. |
| **detection_score_delta** | Math Derived | Float | Change in detector score (Score After - Score Before). |
| **detection_score_reduction** | Math Derived | Percentage | Percentage of baseline score removed (`N/A` if baseline is 0). |
| **lexical_divergence** | Text Quality | 0.0 to 1.0 (Ratio) | Bigram Jaccard lexical distance (0 = identical, 1 = no overlap). |
| **semantic_similarity** | Text Quality | -1.0 to 1.0 (Cosine) | Sentence similarity using Sentence-Transformers. |
| **psnr** | Image Quality | Decibels (dB) | Peak Signal-to-Noise Ratio (higher = cleaner). |
| **ssim** | Image Quality | -1.0 to 1.0 (Ratio) | Structural Similarity Index. |
| **lpips** | Image Quality | Distance | Learned Perceptual Image Patch Similarity. |

---

## 5. Web UI & CLI Usage

### Web Interface
Navigate to `/lab` from the TraceClean navbar.
- **Harness Status**: Check `/lab/status` to diagnose path configuration, import dependencies, and monitor weights.
- **Create**: Upload or paste YAML configs at `/lab/experiment/create`.
- **Progress Panel**: View live polling progress displaying stage names (e.g. `Pre-Attack Detection`, `Running Attack`) and percentages.
- **Compare View**: Select multiple completed runs to render side-by-side metric tables and scatter trade-off graphs.

### CLI Suite
Use the workspace wrappers to inspect experiments:
- **Run Experiment**: `.\contenttrace.bat experiment run config.yaml`
- **List History**: `.\contenttrace.bat experiment list`
- **Show Detail**: `.\contenttrace.bat experiment show <run-id>`
- **Compare Runs**: `.\contenttrace.bat experiment compare <run-1> <run-2>`

---

## 6. Troubleshooting & Sandbox Settings

1. **ModuleNotFoundError: No module named 'visualize'**:
   - Ensure the sparse-checkout directories inside `setup_markllm.ps1` contain `/visualize/`. Run `git -C $env:MARKLLM_DIR sparse-checkout add "/visualize/"` if using an existing directory.
2. **Degraded Symlinks Warning on Windows**:
   - De-activate the warning by setting `$env:HF_HUB_DISABLE_SYMLINKS_WARNING="1"`.
3. **Out of Memory (OOM) on CPU**:
   - Always verify that the parameter `model: facebook/opt-125m` is passed to limit model sizes during offline benchmarking.
