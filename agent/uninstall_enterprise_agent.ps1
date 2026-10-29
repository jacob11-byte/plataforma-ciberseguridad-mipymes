param(
    [string]$TaskName = "CyberCheck MIPYME Agent",
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

foreach ($name in @($TaskName, "CyberCheck MIPYME Agent User") | Select-Object -Unique) {
    if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $name -Confirm:$false
        Write-Host "Tarea eliminada: $name"
    }
}

$resolvedInstallRoot = [System.IO.Path]::GetFullPath($InstallRoot)
$programFilesRoot = [System.IO.Path]::GetFullPath($env:ProgramFiles).TrimEnd('\') + '\'
if (-not $resolvedInstallRoot.StartsWith($programFilesRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "InstallRoot debe permanecer dentro de Program Files."
}
if (Test-Path -LiteralPath $resolvedInstallRoot) {
    Remove-Item -LiteralPath $resolvedInstallRoot -Recurse -Force
    Write-Host "Binario eliminado: $resolvedInstallRoot"
}

if ($RemoveData) {
    $resolvedDataRoot = [System.IO.Path]::GetFullPath($DataRoot)
    $programDataRoot = [System.IO.Path]::GetFullPath($env:ProgramData).TrimEnd('\') + '\'
    if (-not $resolvedDataRoot.StartsWith($programDataRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "DataRoot debe permanecer dentro de ProgramData."
    }
    if (Test-Path -LiteralPath $resolvedDataRoot) {
        Remove-Item -LiteralPath $resolvedDataRoot -Recurse -Force
        Write-Host "Configuracion, token y logs eliminados: $resolvedDataRoot"
    }
} else {
    Write-Host "Los datos se conservaron en $DataRoot. Usa -RemoveData para eliminarlos."
}
