from __future__ import annotations

import os
from typing import Any

from agent.core.powershell import run_powershell


def collect_security_controls() -> dict[str, Any]:
    if os.name != "nt":
        return {"status": "not_supported"}
    secure_boot = run_powershell(
        "try { Confirm-SecureBootUEFI | ConvertTo-Json -Compress } catch { @{ error=$_.Exception.Message } | ConvertTo-Json -Compress }"
    )
    tpm = run_powershell(
        "Get-Tpm -ErrorAction SilentlyContinue | "
        "Select-Object TpmPresent,TpmReady,TpmEnabled,TpmActivated,ManufacturerVersion | ConvertTo-Json -Compress"
    )
    bitlocker = run_powershell(
        "Get-BitLockerVolume -ErrorAction SilentlyContinue | "
        "Select-Object MountPoint,VolumeStatus,ProtectionStatus,EncryptionPercentage,EncryptionMethod | ConvertTo-Json -Compress"
    )
    uac = run_powershell(
        "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' | "
        "Select-Object EnableLUA,ConsentPromptBehaviorAdmin,PromptOnSecureDesktop | ConvertTo-Json -Compress"
    )
    smb1 = run_powershell(
        "Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue | "
        "Select-Object FeatureName,State | ConvertTo-Json -Compress"
    )
    rdp = run_powershell(
        "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' | "
        "Select-Object fDenyTSConnections | ConvertTo-Json -Compress"
    )
    nla = run_powershell(
        "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' | "
        "Select-Object UserAuthentication | ConvertTo-Json -Compress"
    )
    bitlocker_rows = bitlocker if isinstance(bitlocker, list) else ([bitlocker] if isinstance(bitlocker, dict) and not bitlocker.get("error") else [])
    return {
        "secure_boot": secure_boot,
        "tpm": tpm if isinstance(tpm, dict) else {"error": tpm},
        "bitlocker": bitlocker_rows,
        "uac": uac if isinstance(uac, dict) else {"error": uac},
        "smb1": smb1 if isinstance(smb1, dict) else {"error": smb1},
        "rdp": {
            "enabled": (isinstance(rdp, dict) and int(rdp.get("fDenyTSConnections", 1)) == 0),
            "nla_required": (isinstance(nla, dict) and int(nla.get("UserAuthentication", 0)) == 1),
            "raw": {"rdp": rdp, "nla": nla},
        },
    }
