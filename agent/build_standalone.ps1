param(
    [string]$PythonExe = "python.exe",
    [string]$OutputDirectory = (Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..")) "dist")
)

$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$python = (Get-Command $PythonExe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source

& $python -c "import PyInstaller" 2>$null
if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller no esta instalado. Ejecuta: $python -m pip install -r requirements-agent-build.txt"
}

$output = [System.IO.Path]::GetFullPath($OutputDirectory)
$work = Join-Path $projectRoot "tmp\pyinstaller"
New-Item -ItemType Directory -Force -Path $output, $work | Out-Null

Push-Location $projectRoot
try {
    & $python -m PyInstaller `
        --noconfirm `
        --clean `
        --onefile `
        --windowed `
        --name CyberCheckAgent `
        --paths $projectRoot `
        --distpath $output `
        --workpath $work `
        --specpath $work `
        (Join-Path $PSScriptRoot "windows_agent.py")
    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller termino con codigo $LASTEXITCODE"
    }
} finally {
    Pop-Location
}

$artifact = Join-Path $output "CyberCheckAgent.exe"
if (-not (Test-Path -LiteralPath $artifact -PathType Leaf)) {
    throw "No se genero $artifact"
}
Write-Host "Agente autocontenido generado: $artifact"
