param(
    [string]$ConfigPath = "C:\pg2\agent\agent_config.render.json",
    [string]$PythonExe = "",
    [string]$TaskName = "CyberCheck MIPYME Agent",
    [int]$IntervalMinutes = 5,
    [switch]$RunElevated
)

$agentPath = Resolve-Path "$PSScriptRoot\windows_agent.py"
$configFullPath = Resolve-Path $ConfigPath
$projectRoot = Resolve-Path "$PSScriptRoot\.."

if ([string]::IsNullOrWhiteSpace($PythonExe)) {
    $pyCommand = Get-Command py -ErrorAction SilentlyContinue
    if (-not $pyCommand) {
        throw "No se encontro py.exe. Instala Python 3.12 o pasa -PythonExe con la ruta completa."
    }
    $PythonExe = $pyCommand.Source
}

$action = New-ScheduledTaskAction `
    -Execute $PythonExe `
    -Argument "-3.12 `"$agentPath`" --config `"$configFullPath`" --poll-once --max-tasks 10" `
    -WorkingDirectory $projectRoot

$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
    -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)

$runLevel = if ($RunElevated) { "Highest" } else { "Limited" }
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel $runLevel
$settings = New-ScheduledTaskSettingsSet `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 10) `
    -StartWhenAvailable

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Settings $settings `
    -Description "Consulta tareas de CyberCheck y ejecuta verificaciones permitidas." `
    -Force

Write-Host "Tarea programada instalada: $TaskName"
