from __future__ import annotations

import os
import platform
import socket
from typing import Any

from agent.core.powershell import run_powershell


def collect_system_inventory() -> dict[str, Any]:
    ip_address = None
    try:
        ip_address = socket.gethostbyname(socket.gethostname())
    except OSError:
        ip_address = None
    inventory = {
        "hostname": socket.gethostname(),
        "ip_address": ip_address,
        "os_version": platform.platform(),
        "architecture": platform.machine(),
        "windows_edition": None,
        "manufacturer": None,
        "model": None,
        "serial_number": None,
        "bios_version": None,
        "total_memory_mb": None,
        "domain": None,
        "logged_on_user": None,
    }
    if os.name != "nt":
        return inventory
    os_data = run_powershell(
        "Get-CimInstance Win32_OperatingSystem | "
        "Select-Object Caption,Version,BuildNumber,TotalVisibleMemorySize | ConvertTo-Json -Compress"
    )
    computer = run_powershell(
        "Get-CimInstance Win32_ComputerSystem | "
        "Select-Object Manufacturer,Model,Domain,UserName | ConvertTo-Json -Compress"
    )
    bios = run_powershell(
        "Get-CimInstance Win32_BIOS | "
        "Select-Object SerialNumber,SMBIOSBIOSVersion | ConvertTo-Json -Compress"
    )
    if isinstance(os_data, dict) and not os_data.get("error"):
        inventory["windows_edition"] = os_data.get("Caption")
        inventory["windows_version"] = os_data.get("Version")
        inventory["windows_build"] = os_data.get("BuildNumber")
        memory_kb = os_data.get("TotalVisibleMemorySize")
        inventory["total_memory_mb"] = int(int(memory_kb) / 1024) if str(memory_kb).isdigit() else None
    if isinstance(computer, dict) and not computer.get("error"):
        inventory["manufacturer"] = computer.get("Manufacturer")
        inventory["model"] = computer.get("Model")
        inventory["domain"] = computer.get("Domain")
        inventory["logged_on_user"] = computer.get("UserName")
    if isinstance(bios, dict) and not bios.get("error"):
        inventory["serial_number"] = bios.get("SerialNumber")
        inventory["bios_version"] = bios.get("SMBIOSBIOSVersion")
    return inventory
