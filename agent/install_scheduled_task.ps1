param(
    [string]$ConfigPath = "C:\pg2\agent\agent_config.render.example.json",
    [string]$PythonExe = "py",
    [string]$TaskName = "CyberCheck MIPYME Agent",
    [int]$IntervalMinutes = 15
)

$agentPath = Resolve-Path "$PSScriptRoot\windows_agent.py"
$configFullPath = Resolve-Path $ConfigPath

$action = New-ScheduledTaskAction `
    -Execute $PythonExe `
    -Argument "-3.12 `"$agentPath`" --config `"$configFullPath`" --poll-once --max-tasks 2"

$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
    -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)

$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Description "Consulta tareas de CyberCheck y ejecuta verificaciones permitidas." `
    -Force

Write-Host "Tarea programada instalada: $TaskName"
