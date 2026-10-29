param(
    [string]$ServiceName = "CyberCheckAgent",
    [string]$InstallRoot = (Join-Path $env:ProgramFiles "CyberCheck\Agent"),
    [string]$DataRoot = (Join-Path $env:ProgramData "CyberCheck"),
    [switch]$RemoveData
)

$ErrorActionPreference = "Stop"
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Abre PowerShell como administrador para desinstalar el agente."
}

$runKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Remove-ItemProperty -Path $runKey -Name "CyberCheckTray" -ErrorAction SilentlyContinue
Get-Process -Name "CyberCheckTray" -ErrorAction SilentlyContinue | Stop-Process -Force

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service) {
    if ($service.Status -ne "Stopped") {
        Stop-Service -Name $ServiceName -Force
        $service.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
    }
    & sc.exe delete $ServiceName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "No se pudo eliminar el servicio $ServiceName" }
    Write-Host "Servicio eliminado: $ServiceName"
}

foreach ($taskName in @("CyberCheck MIPYME Agent", "CyberCheck MIPYME Agent User")) {
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        Write-Host "Tarea heredada eliminada: $taskName"
    }
}

$resolvedInstallRoot = [System.IO.Path]::GetFullPath($InstallRoot)
$programFilesRoot = [System.IO.Path]::GetFullPath($env:ProgramFiles).TrimEnd('\') + '\'
if (-not $resolvedInstallRoot.StartsWith($programFilesRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "InstallRoot debe permanecer dentro de Program Files."
}
if (Test-Path -LiteralPath $resolvedInstallRoot) {
    Remove-Item -LiteralPath $resolvedInstallRoot -Recurse -Force
    Write-Host "Componentes eliminados: $resolvedInstallRoot"
}

if ($RemoveData) {
    $resolvedDataRoot = [System.IO.Path]::GetFullPath($DataRoot)
    $programDataRoot = [System.IO.Path]::GetFullPath($env:ProgramData).TrimEnd('\') + '\'
    if (-not $resolvedDataRoot.StartsWith($programDataRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "DataRoot debe permanecer dentro de ProgramData."
    }
    if (Test-Path -LiteralPath $resolvedDataRoot) {
        Remove-Item -LiteralPath $resolvedDataRoot -Recurse -Force
        Write-Host "Configuracion, cola y logs eliminados: $resolvedDataRoot"
    }
} else {
    Write-Host "Datos conservados en $DataRoot. Usa -RemoveData para eliminarlos."
}
