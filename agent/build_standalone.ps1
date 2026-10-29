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
    $artifacts = @(
        @{ Name = "CyberCheckAgent"; Script = "windows_agent.py" },
        @{ Name = "CyberCheckService"; Script = "windows_service.py" },
        @{ Name = "CyberCheckTray"; Script = "windows_tray.py" }
    )
    foreach ($artifact in $artifacts) {
        & $python -m PyInstaller `
            --noconfirm `
            --clean `
            --onefile `
            --windowed `
            --name $artifact.Name `
            --paths $projectRoot `
            --distpath $output `
            --workpath $work `
            --specpath $work `
            (Join-Path $PSScriptRoot $artifact.Script)
        if ($LASTEXITCODE -ne 0) {
            throw "PyInstaller fallo al generar $($artifact.Name) con codigo $LASTEXITCODE"
        }
    }
} finally {
    Pop-Location
}

foreach ($name in @("CyberCheckAgent.exe", "CyberCheckService.exe", "CyberCheckTray.exe")) {
    $artifactPath = Join-Path $output $name
    if (-not (Test-Path -LiteralPath $artifactPath -PathType Leaf)) {
        throw "No se genero $artifactPath"
    }
    Write-Host "Componente generado: $artifactPath"
}
