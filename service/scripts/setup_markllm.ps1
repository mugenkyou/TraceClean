<#
.SYNOPSIS
  Port of setup_markllm.sh to Windows PowerShell.

.DESCRIPTION
  Bootstrap an external THU-BPM/MarkLLM checkout for the optional text-watermark harness.
  Clones MarkLLM locally (pinned commit), creates a virtual environment, and installs dependencies.

.PARAMETER Dir
  Checkout directory (default: $env:MARKLLM_DIR or ~\MarkLLM)

.PARAMETER Ref
  Commit to check out (default: pinned commit SHA; do not point to a moving branch)

.PARAMETER Python
  Python interpreter used to create the virtual environment (default: python)
#>
[CmdletBinding()]
param(
    [string]$Dir,
    [string]$Ref = 'c45ddc40f7b761beabe55a1b8dc4690e531d1c6d',
    [string]$Python = 'python'
)

$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

function Invoke-Checked {
    param([string]$What, [scriptblock]$Block)
    & $Block
    if ($LASTEXITCODE -ne 0) { throw "$What failed (code $LASTEXITCODE)" }
}

if (-not $Dir) {
    if ($env:MARKLLM_DIR) { $Dir = $env:MARKLLM_DIR }
    else { $Dir = Join-Path $HOME 'MarkLLM' }
}
$parent = Split-Path -Parent $Dir
if ($parent -and -not (Test-Path $parent)) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
if (-not (Test-Path $Dir)) { New-Item -ItemType Directory -Force -Path $Dir | Out-Null }
$Dir = (Resolve-Path $Dir).Path

if (-not (Test-Path (Join-Path $Dir '.git'))) {
    Write-Host "Cloning THU-BPM/MarkLLM into $Dir (pinned ref: $Ref)"
    Invoke-Checked 'git clone' { git clone --depth 1 --filter=blob:none --sparse https://github.com/THU-BPM/MarkLLM.git $Dir }
    Invoke-Checked 'git fetch' { git -C $Dir fetch --depth 1 origin $Ref }
    Invoke-Checked 'git checkout' { git -C $Dir checkout --detach $Ref }
    Invoke-Checked 'sparse-checkout' {
        git -C $Dir sparse-checkout set --no-cone `/watermark/ `/config/ `/utils/ `/exceptions/ `/visualize/ `/evaluation/dataset.py `/LICENSE `/README.md
    }
    $head = (git -C $Dir rev-parse HEAD).Trim()
    if ($head -ne $Ref) { throw "error: expected pinned ref $Ref, got $head" }
} else {
    Write-Host "Using existing checkout: $Dir"
}

$venvPython = Join-Path $Dir '.venv\Scripts\python.exe'
if (-not (Test-Path $venvPython)) {
    Write-Host "Creating venv at $Dir\.venv"
    Invoke-Checked 'create venv' { & $Python -m venv (Join-Path $Dir '.venv') }
}

Write-Host 'Installing Python dependencies'
# Pin pip (supply-chain hardening)
Invoke-Checked 'pip install pip' { & $venvPython -m pip install --upgrade 'pip==26.2.1' }

# Install dependencies from requirements-markllm.txt
Invoke-Checked 'pip install requirements' { & $venvPython -m pip install -r (Join-Path $ScriptDir 'requirements-markllm.txt') }

Write-Host ''
Write-Host 'MarkLLM Environment set up successfully.'
Write-Host 'To run experiments, configure:'
Write-Host "  `$env:MARKLLM_DIR = '$Dir'"
Write-Host ''
