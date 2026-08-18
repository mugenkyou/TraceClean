# Security Policy

## Maintenance Model
TraceClean does not maintain a formal version support matrix. Security fixes target the latest state of the `main` branch. 

## Reporting a Vulnerability
Do not report security issues publicly via GitHub Issues. 
Please report vulnerabilities privately using **GitHub Security Advisories** (via the "Report a vulnerability" button on the Security tab of the repository).

## Scope and In-Scope Risks
This policy focuses on vulnerabilities in TraceClean itself. We prioritize reports detailing:
- **Path Traversal / Unsafe File Writes**: Ability to write files outside of the configured destination directories.
- **Command Injection / Unsafe Subprocess Invocation**: Vulnerabilities in how command arguments are constructed when calling system utilities like `exiftool`, `qpdf`, or `c2patool`.
- **Parser and Resource Exhaustion**: Denial of service or crash conditions caused by malicious inputs that exceed bounds.
- **Environment and Secret Leakage**: Exposure of environment details, API keys, or input file contents through log files, HTTP responses, or debug tracebacks.

## Out of Scope
- Vulnerabilities within optional third-party research libraries or repositories (such as MarkLLM, reverse-SynthID, or CtrlRegen).
- Vulnerabilities in standard system tools (e.g., `exiftool`, `qpdf`, `c2patool`) themselves.
- General AI watermark bypasses, removal limits, or verification failures under research conditions.
