param(
    [string]$AgentExecutable = (Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..")) "dist\CyberCheckAgent.exe"),
    [string]$ConfigPath = (Join-Path $PSScriptRoot "agent_config.render.json"),
    [string]$InstallRoot = (Join-Path $env:ProgramFiles "CyberCheck\Agent"),
    [string]$DataRoot = (Join-Path $env:ProgramData "CyberCheck"),
    [string]$TaskName = "CyberCheck MIPYME Agent",
    [ValidateRange(1, 1440)][int]$IntervalMinutes = 5,
    [switch]$ReplaceConfig
)

$ErrorActionPreference = "Stop"
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Abre PowerShell como administrador para instalar el agente empresarial."
}

$sourceExecutable = (Resolve-Path -LiteralPath $AgentExecutable).Path
$sourceConfig = (Resolve-Path -LiteralPath $ConfigPath).Path
$installedExecutable = Join-Path $InstallRoot "CyberCheckAgent.exe"
$installedConfig = Join-Path $DataRoot "agent_config.json"

New-Item -ItemType Directory -Force -Path $InstallRoot, $DataRoot | Out-Null
Copy-Item -LiteralPath $sourceExecutable -Destination $installedExecutable -Force
if ($ReplaceConfig -or -not (Test-Path -LiteralPath $installedConfig)) {
    Copy-Item -LiteralPath $sourceConfig -Destination $installedConfig -Force
}

# El binario puede ser leido/ejecutado por usuarios, pero solo Administradores
# y SYSTEM pueden modificarlo. La configuracion y el token no son legibles por
# usuarios estandar.
& icacls.exe $InstallRoot /inheritance:r /grant:r `
    '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
if ($LASTEXITCODE -ne 0) { throw "No se pudo proteger $InstallRoot" }
& icacls.exe $DataRoot /inheritance:r /grant:r `
    '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw "No se pudo proteger $DataRoot" }

& (Join-Path $PSScriptRoot "install_scheduled_task.ps1") `
    -AgentExecutable $installedExecutable `
    -ConfigPath $installedConfig `
    -TaskName $TaskName `
    -IntervalMinutes $IntervalMinutes `
    -RunAsSystem

Write-Host "Agente empresarial instalado en $InstallRoot"
Write-Host "Datos protegidos en $DataRoot"
