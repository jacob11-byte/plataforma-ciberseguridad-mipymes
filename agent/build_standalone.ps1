param(
    [string]$PythonExe = "python.exe",
    [string]$OutputDirectory = (Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..")) "dist"),
    # Enrollment for the double-click installer: api_url + registration_code,
    # never a device_id/token. Copy agent/enrollment.example.json to start.
    [string]$EnrollmentConfig = (Join-Path $PSScriptRoot "enrollment.json")
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

    foreach ($name in @("CyberCheckAgent.exe", "CyberCheckService.exe", "CyberCheckTray.exe")) {
        $artifactPath = Join-Path $output $name
        if (-not (Test-Path -LiteralPath $artifactPath -PathType Leaf)) {
            throw "No se genero $artifactPath"
        }
        Write-Host "Componente generado: $artifactPath"
    }

    if (-not (Test-Path -LiteralPath $EnrollmentConfig -PathType Leaf)) {
        Write-Warning "No existe $EnrollmentConfig; se omite CyberCheckSetup.exe. Copia agent\enrollment.example.json a agent\enrollment.json."
        return
    }
    $enrollment = Get-Content -LiteralPath $EnrollmentConfig -Raw | ConvertFrom-Json
    if ($enrollment.token -or $enrollment.device_id) {
        throw "$EnrollmentConfig no debe contener device_id ni token: todos los equipos compartirian identidad."
    }
    if (-not $enrollment.api_url) {
        throw "$EnrollmentConfig requiere api_url."
    }
    if ($enrollment.registration_code) {
        Write-Warning "El instalador incluira registration_code: no lo publiques. Sin ese campo, cada descarga desde el panel lleva su propio token."
    }
    # PyInstaller --add-data takes a destination folder, so stage the file
    # under the fixed name the installer looks for.
    $stagedEnrollment = Join-Path $work "enrollment.json"
    Copy-Item -LiteralPath $EnrollmentConfig -Destination $stagedEnrollment -Force
    $payloadArgs = @("CyberCheckAgent.exe", "CyberCheckService.exe", "CyberCheckTray.exe") | ForEach-Object {
        "--add-data"; "$(Join-Path $output $_);payload"
    }
    & $python -m PyInstaller `
        --noconfirm `
        --clean `
        --onefile `
        --windowed `
        --uac-admin `
        --name CyberCheckSetup `
        --paths $projectRoot `
        --distpath $output `
        --workpath $work `
        --specpath $work `
        @payloadArgs `
        --add-data "$stagedEnrollment;payload" `
        (Join-Path $PSScriptRoot "setup_installer.py")
    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller fallo al generar CyberCheckSetup con codigo $LASTEXITCODE"
    }
    Write-Host "Instalador generado: $(Join-Path $output 'CyberCheckSetup.exe')"
} finally {
    Pop-Location
}
