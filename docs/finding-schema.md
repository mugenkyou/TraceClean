# TraceClean Unified Finding Schema (v1.0)

The TraceClean Finding Schema normalizes raw detection output from diverse detectors (invisible Unicode parsers, stylometry scorers, EXIF/XMP metadata scanners, C2PA manifest parsers, document container inspectors) into a single, structured representation.

## Finding Schema Specification

```json
{
  "$schema": "https://traceclean.org/schemas/v1/finding.json",
  "version": "1.0",
  "type": "object",
  "required": [
    "id",
    "scan_id",
    "category",
    "signal",
    "confidence",
    "severity",
    "location",
    "evidence",
    "removable"
  ],
  "properties": {
    "id": {
      "type": "string",
      "description": "Stable unique identifier for the finding within a scan (e.g. find_a1b2c3d4)."
    },
    "scan_id": {
      "type": "string",
      "description": "Reference UUID of the scan session that produced the finding."
    },
    "category": {
      "type": "string",
      "enum": [
        "invisible_text",
        "statistical_text",
        "c2pa",
        "image_metadata",
        "document_metadata"
      ],
      "description": "Controlled category classifying the provenance signal."
    },
    "signal": {
      "type": "string",
      "description": "Specific signal identifier (e.g. ZERO_WIDTH_SPACE, C2PA_JUMBF_MANIFEST, EXIF_AI_GENERATOR_TAG)."
    },
    "confidence": {
      "type": "string",
      "enum": [
        "confirmed",
        "probable",
        "informational",
        "likely_false_positive"
      ],
      "description": "Detector confidence classification based on physical marker presence."
    },
    "severity": {
      "type": "string",
      "enum": [
        "critical",
        "high",
        "medium",
        "low",
        "info"
      ],
      "description": "Diagnostic severity rating measuring provenance exposure."
    },
    "location": {
      "type": "string",
      "description": "Human-readable structural location within the file (e.g. U+200B at offsets [12, 48], JPEG APP11 box, PDF /Metadata stream)."
    },
    "evidence": {
      "type": "object",
      "description": "Structured raw evidence extracted from the detector. Treated as untrusted input."
    },
    "removable": {
      "type": "boolean",
      "description": "True if TraceClean's deterministic cleaning pipeline can strip this signal."
    },
    "removed": {
      "type": ["boolean", "null"],
      "description": "True if post-clean audit verifies removal; False if remaining; null if unverified."
    }
  }
}
```

## Controlled Vocabularies

### Categories (`category`)
- `invisible_text`: Layer A zero-width spaces, soft hyphens, bidi overrides, tag characters, homoglyphs.
- `statistical_text`: Stylometric text patterns (uniform sentence length, repetitive connectors, LLM entropy markers).
- `c2pa`: C2PA claim manifests, JUMBF boxes, Content Credentials signatures.
- `image_metadata`: EXIF/XMP AI tags, PNG text chunks, JPEG APP markers, WebP/ISOBMFF metadata boxes.
- `document_metadata`: PDF structured object streams/XMP, DOCX/ODT core properties, HTML meta/script tags, SVG comments.

### Confidence Levels (`confidence`)
- `confirmed`: Deterministically verified physical marker (e.g. explicit C2PA JUMBF box, zero-width space byte sequence).
- `probable`: Strong heuristic indicator (e.g. high stylometric score >= 0.65, AI prompt string in XMP).
- `informational`: Contextual signal (e.g. space homoglyphs in non-Latin prose).
- `likely_false_positive`: Low-risk or orthographically valid character in script context.

### Severities (`severity`)
- `critical`: Cryptographic or explicit provenance manifests (C2PA JUMBF, EXIF AI Generator fields).
- `high`: High-density steganographic carriers (zero-width spaces, tag characters, bidi overrides).
- `medium`: Low-density hidden characters or high stylometry probability scores.
- `low`: Non-AI metadata tags or mild stylometric features.
- `info`: Informational structural properties.

## Adapter Mapping Rules

| Raw Detector Output | Normalized Category | Signal | Removable |
| --- | --- | --- | --- |
| `inspect_text()` ZWJS / Bidi / Tag hits | `invisible_text` | `ZERO_WIDTH_SPACE` / `BIDI_OVERRIDE` / `TAG_CHAR` | `true` |
| `score_stylometry()` score >= 0.65 | `statistical_text` | `STYLOMETRY_AI_PATTERN` | `false` (Layer B rewrite hook optional) |
| `image_meta()` `has_c2pa` / JUMBF box | `c2pa` | `C2PA_MANIFEST` | `true` |
| `image_meta()` EXIF / XMP AI tags | `image_metadata` | `EXIF_AI_TAG` / `XMP_PROMPT` | `true` |
| `container_meta()` PDF / DOCX / HTML | `document_metadata` | `PDF_METADATA` / `DOCX_CORE_PROP` | `true` |
