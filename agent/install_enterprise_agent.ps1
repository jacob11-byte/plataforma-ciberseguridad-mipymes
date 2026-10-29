param(
    [string]$AgentExecutable = (Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..")) "dist\CyberCheckAgent.exe"),
    [string]$ServiceExecutable = (Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..")) "dist\CyberCheckService.exe"),
    [string]$TrayExecutable = (Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..")) "dist\CyberCheckTray.exe"),
    [string]$ConfigPath = (Join-Path $PSScriptRoot "agent_config.render.json"),
    [string]$InstallRoot = (Join-Path $env:ProgramFiles "CyberCheck\Agent"),
    [string]$DataRoot = (Join-Path $env:ProgramData "CyberCheck"),
    [string]$ServiceName = "CyberCheckAgent",
    [ValidateRange(30, 86400)][int]$IntervalSeconds = 300,
    [switch]$ReplaceConfig
)

$ErrorActionPreference = "Stop"
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Abre PowerShell como administrador para instalar el agente empresarial."
}

$sourceAgent = (Resolve-Path -LiteralPath $AgentExecutable).Path
$sourceService = (Resolve-Path -LiteralPath $ServiceExecutable).Path
$sourceTray = (Resolve-Path -LiteralPath $TrayExecutable).Path
$sourceConfig = (Resolve-Path -LiteralPath $ConfigPath).Path
$installedAgent = Join-Path $InstallRoot "CyberCheckAgent.exe"
$installedService = Join-Path $InstallRoot "CyberCheckService.exe"
$installedTray = Join-Path $InstallRoot "CyberCheckTray.exe"
$installedConfig = Join-Path $DataRoot "agent_config.json"
$publicRoot = Join-Path $DataRoot "public"

$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingService -and $existingService.Status -ne "Stopped") {
    Stop-Service -Name $ServiceName -Force
    $existingService.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
}
Get-Process -Name "CyberCheckTray" -ErrorAction SilentlyContinue | Stop-Process -Force
foreach ($taskName in @("CyberCheck MIPYME Agent", "CyberCheck MIPYME Agent User")) {
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        Write-Host "Tarea heredada eliminada: $taskName"
    }
}

New-Item -ItemType Directory -Force -Path $InstallRoot, $DataRoot, $publicRoot | Out-Null
Copy-Item -LiteralPath $sourceAgent -Destination $installedAgent -Force
Copy-Item -LiteralPath $sourceService -Destination $installedService -Force
Copy-Item -LiteralPath $sourceTray -Destination $installedTray -Force
if ($ReplaceConfig -or -not (Test-Path -LiteralPath $installedConfig)) {
    Copy-Item -LiteralPath $sourceConfig -Destination $installedConfig -Force
}

# Usuarios pueden ejecutar binarios y leer solo el estado publico. La
# configuracion, token, cola offline y logs quedan limitados a SYSTEM/Admin.
& icacls.exe $InstallRoot /inheritance:r /grant:r `
    '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
if ($LASTEXITCODE -ne 0) { throw "No se pudo proteger $InstallRoot" }
& icacls.exe $DataRoot /inheritance:r /grant:r `
    '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /T /C | Out-Null
if ($LASTEXITCODE -ne 0) { throw "No se pudo proteger $DataRoot" }
& icacls.exe $DataRoot /grant:r '*S-1-5-32-545:(RX)' | Out-Null
if ($LASTEXITCODE -ne 0) { throw "No se pudo permitir acceso al estado publico" }
& icacls.exe $publicRoot /inheritance:r /grant:r `
    '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' /T /C | Out-Null
if ($LASTEXITCODE -ne 0) { throw "No se pudo publicar el estado del agente" }

$serviceCommand = '"{0}" --config "{1}" --interval {2} --max-tasks 10 --service-name "{3}"' -f `
    $installedService, $installedConfig, $IntervalSeconds, $ServiceName
if ($existingService) {
    # Windows PowerShell 5.1 no escapa comillas internas al invocar sc.exe, asi
    # que la ruta del binario se actualiza directamente en el registro del SCM.
    Set-ItemProperty `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" `
        -Name ImagePath `
        -Value $serviceCommand
    & sc.exe config $ServiceName start= delayed-auto | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "No se pudo actualizar el servicio $ServiceName" }
} else {
    New-Service `
        -Name $ServiceName `
        -BinaryPathName $serviceCommand `
        -DisplayName "CyberCheck MIPYME Agent" `
        -Description "Recolecta evidencia de seguridad y procesa tareas autorizadas." `
        -StartupType Automatic | Out-Null
    & sc.exe config $ServiceName start= delayed-auto | Out-Null
}
& sc.exe description $ServiceName "Agente de postura de seguridad CyberCheck MIPYME" | Out-Null
& sc.exe failure $ServiceName reset= 86400 actions= restart/60000/restart/60000/restart/300000 | Out-Null
& sc.exe failureflag $ServiceName 1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw "No se pudo configurar la recuperacion del servicio" }

$runKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
New-ItemProperty `
    -Path $runKey `
    -Name "CyberCheckTray" `
    -Value ('"{0}" --data-root "{1}"' -f $installedTray, $DataRoot) `
    -PropertyType String `
    -Force | Out-Null

Start-Service -Name $ServiceName
Write-Host "Servicio instalado e iniciado: $ServiceName"
Write-Host "Componentes instalados en $InstallRoot"
Write-Host "Datos protegidos en $DataRoot"
Write-Host "El icono de bandeja iniciara en el proximo inicio de sesion."
