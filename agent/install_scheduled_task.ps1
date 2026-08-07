param(
    [string]$ConfigPath = "C:\pg2\agent\agent_config.render.example.json",
    [string]$PythonExe = "",
    [string]$TaskName = "CyberCheck MIPYME Agent",
    [int]$IntervalMinutes = 15,
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
    -Argument "-3.12 `"$agentPath`" --config `"$configFullPath`" --poll-once --max-tasks 2" `
    -WorkingDirectory $projectRoot

$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
    -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)

$runLevel = if ($RunElevated) { "Highest" } else { "Limited" }
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel $runLevel

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Description "Consulta tareas de CyberCheck y ejecuta verificaciones permitidas." `
    -Force

Write-Host "Tarea programada instalada: $TaskName"
