# TraceClean Web Application (Phase 1 Web MVP)

The TraceClean Web Application provides a user-friendly browser interface for inspecting and deterministically cleaning AI provenance marks, C2PA claims, and metadata from documents and images without requiring command-line usage.

## Architecture

The web application lives in `web/` and is built using **Flask**, **Jinja2**, **Vanilla CSS**, and **Vanilla JS**.

```
TraceClean Engine Architecture
┌─────────────────────────────────────────────────────────────┐
│                       Browser UI                            │
│  Drag & Drop Upload ──► Categorized Inspect ──► Clean ──► Download │
└──────────────────────────────┬──────────────────────────────┘
                               │ HTTP / HTML
┌──────────────────────────────▼──────────────────────────────┐
│                    Flask Web App (web/)                     │
│               FileSession Storage & Routes                  │
└──────────────────────────────┬──────────────────────────────┘
                               │ In-Process Python Call
┌──────────────────────────────▼──────────────────────────────┐
│                TraceClean Engine (service/scripts/engine.py)│
│  classify_bytes ──► inspect_bytes ──► clean_bytes           │
└─────────────────────────────────────────────────────────────┘
```

The Flask web application calls `engine.py` directly in-process. It does not invoke network HTTP endpoints or external APIs, delivering zero-latency processing and maximum privacy.

## Supported Formats

| Format Category | Supported File Types |
| --- | --- |
| **Text Documents** | Plain Text (`.txt`), Markdown (`.md`), HTML (`.html`) |
| **Images** | PNG (`.png`), JPEG (`.jpg`/`.jpeg`), WebP (`.webp`), SVG (`.svg`) |
| **Document Containers** | PDF (`.pdf`), DOCX (`.docx`), ODT (`.odt`) |

## Running Locally

To start the Web UI locally on `http://127.0.0.1:5000`:

```bash
make serve-web
```

Or run directly with Python:

```bash
python web/app.py
```

Environment variables to customize host/port:
- `TRACECLEAN_WEB_HOST` (default: `127.0.0.1`)
- `TRACECLEAN_WEB_PORT` (default: `5000`)

## Session Lifecycle & Security

1. **Upload & Isolation**: Each uploaded file is stored in a dedicated temporary directory identified by a cryptographically random UUID4 (e.g. `/tmp/traceclean_web_sessions/<uuid>/`).
2. **File Validation**: Files are validated via magic-bytes (`classify_bytes`) and capped by `MAX_INPUT_BYTES` (256 MB).
3. **Safe Downloads**: Cleaned files and JSON reports are served with `Content-Disposition: attachment` headers, `X-Content-Type-Options: nosniff`, and `Cache-Control: no-store` to prevent execution or browser caching.
4. **TTL Expiration**: Sessions automatically expire after 1 hour (3600 seconds). A background janitor thread sweeps expired session folders periodically.

## Phase 1 Limitations

- **Deterministic Processing Only**: Layer A Unicode, file metadata, and container stripping are supported. Phase 1 web UI does not run heavy GPU LLM rewrite models or SynthID neural scorers.
