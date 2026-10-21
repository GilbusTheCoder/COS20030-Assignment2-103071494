# COS20030 -- run ONCE in PowerShell; evaluates all attribute thresholds
# and optimises candidate combinations without rescanning the files.
$ErrorActionPreference = 'Stop'
$pythonScript = Join-Path $PSScriptRoot 'AdvancedYaraOneShot.py'
if (-not (Test-Path -LiteralPath $pythonScript -PathType Leaf)) {
    throw "Missing Python study: $pythonScript"
}
python $pythonScript
if ($LASTEXITCODE -ne 0) {
    throw "One-shot YARA analysis failed (Python exit code $LASTEXITCODE)."
}
