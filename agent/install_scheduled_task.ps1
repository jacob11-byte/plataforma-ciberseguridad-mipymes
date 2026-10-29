param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot "agent_config.render.json"),
    [string]$PythonExe = "",
    [string]$AgentExecutable = "",
    [string]$TaskName = "CyberCheck MIPYME Agent",
    [ValidateRange(1, 1440)][int]$IntervalMinutes = 5,
    [switch]$RunElevated,
    [switch]$RunAsSystem,
    [bool]$MigrateLegacyTasks = $true,
    [switch]$ValidateOnly
)

$ErrorActionPreference = "Stop"

function Resolve-ApplicationPath([string]$Candidate) {
    if (Test-Path -LiteralPath $Candidate -PathType Leaf) {
        return (Resolve-Path -LiteralPath $Candidate).Path
    }
    $command = Get-Command -Name $Candidate -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($command) {
        return $command.Source
    }
    throw "No se encontro el ejecutable de Python: $Candidate"
}

function Resolve-PythonWindowless([string]$RequestedExecutable) {
    $candidates = if ($RequestedExecutable) {
        @($RequestedExecutable)
    } else {
        @("python.exe", "py.exe")
    }

    foreach ($candidate in $candidates) {
        try {
            $executable = Resolve-ApplicationPath $candidate
            $fileName = [System.IO.Path]::GetFileName($executable)
            if ($fileName -ieq "pythonw.exe") {
                $probe = Join-Path (Split-Path -Parent $executable) "python.exe"
                $probeArgs = @()
            } elseif ($fileName -ieq "python.exe") {
                $probe = $executable
                $probeArgs = @()
            } elseif ($fileName -ieq "py.exe") {
                $probe = $executable
                $probeArgs = @("-3")
            } else {
                throw "Usa python.exe, pythonw.exe o py.exe en -PythonExe."
            }

            if (-not (Test-Path -LiteralPath $probe -PathType Leaf)) {
                throw "No se encontro python.exe junto al ejecutable indicado."
            }
            $resolved = & $probe @probeArgs -c "import sys; print(sys.executable)" 2>$null
            if ($LASTEXITCODE -ne 0 -or -not $resolved) {
                throw "El ejecutable indicado no encontro Python 3."
            }
            $python = [string]($resolved | Select-Object -Last 1)
            $pythonw = Join-Path (Split-Path -Parent $python) "pythonw.exe"
            if (-not (Test-Path -LiteralPath $python -PathType Leaf) -or
                -not (Test-Path -LiteralPath $pythonw -PathType Leaf)) {
                throw "La instalacion de Python no incluye python.exe y pythonw.exe."
            }
            $supported = & $python -c "import sys; print(int(sys.version_info >= (3, 10)))" 2>$null
            if ($LASTEXITCODE -ne 0 -or [string]($supported | Select-Object -Last 1) -ne "1") {
                throw "El agente requiere Python 3.10 o superior."
            }
            return (Resolve-Path -LiteralPath $pythonw).Path
        } catch {
            if ($RequestedExecutable) {
                throw
            }
        }
    }
    throw "No se encontro Python 3.10+ con pythonw.exe. Instala Python o pasa -PythonExe con su ruta completa."
}

$configFullPath = (Resolve-Path -LiteralPath $ConfigPath).Path
$account = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

if ($RunAsSystem) {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principalCheck = New-Object System.Security.Principal.WindowsPrincipal($identity)
    if (-not $principalCheck.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "-RunAsSystem requiere abrir PowerShell como administrador."
    }
}

if ($AgentExecutable) {
    $agentCommand = Resolve-ApplicationPath $AgentExecutable
    $workingDirectory = Split-Path -Parent $agentCommand
    $arguments = '--config "{0}" --poll-once --max-tasks 10' -f $configFullPath
    $runtimeLabel = $agentCommand
} else {
    $agentPath = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "windows_agent.py")).Path
    $workingDirectory = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
    $agentCommand = Resolve-PythonWindowless $PythonExe
    # Las rutas Windows no pueden contener comillas. Las comillas externas conservan espacios.
    $arguments = '"{0}" --config "{1}" --poll-once --max-tasks 10' -f $agentPath, $configFullPath
    $runtimeLabel = $agentCommand
}
$action = New-ScheduledTaskAction -Execute $agentCommand -Argument $arguments -WorkingDirectory $workingDirectory
$firstRun = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
    -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)
$triggers = @($firstRun)
if ($RunAsSystem) {
    $triggers += New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $runIdentity = "NT AUTHORITY\SYSTEM"
} else {
    $triggers += New-ScheduledTaskTrigger -AtLogOn -User $account
    $runLevel = if ($RunElevated) { "Highest" } else { "Limited" }
    $principal = New-ScheduledTaskPrincipal -UserId $account -LogonType Interactive -RunLevel $runLevel
    $runIdentity = $account
}
$settings = New-ScheduledTaskSettingsSet `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 30) `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -Hidden

if (-not $ValidateOnly) {
    Register-ScheduledTask `
        -TaskName $TaskName `
        -Action $action `
        -Trigger $triggers `
        -Principal $principal `
        -Settings $settings `
        -Description "Consulta tareas de CyberCheck y ejecuta verificaciones permitidas sin abrir consola." `
        -Force | Out-Null

    if ($MigrateLegacyTasks) {
        @("CyberCheck MIPYME Agent User") |
            Where-Object { $_ -ne $TaskName } |
            ForEach-Object {
                if (Get-ScheduledTask -TaskName $_ -ErrorAction SilentlyContinue) {
                    Stop-ScheduledTask -TaskName $_ -ErrorAction SilentlyContinue
                    Unregister-ScheduledTask -TaskName $_ -Confirm:$false
                    Write-Host "Tarea heredada eliminada: $_"
                }
            }
    }
}

if ($ValidateOnly) {
    Write-Host "Configuracion valida para la tarea: $TaskName"
} else {
    Write-Host "Tarea programada instalada: $TaskName"
}
Write-Host "Ejecutable sin ventana: $runtimeLabel"
Write-Host "Cuenta: $runIdentity"
if ($RunAsSystem) {
    Write-Host "Frecuencia: cada $IntervalMinutes minutos y al iniciar Windows"
} else {
    Write-Host "Frecuencia: cada $IntervalMinutes minutos y al iniciar sesion"
}
