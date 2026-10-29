"""Hardening and persistence checks that explain *what* is weak on a device.

Every probe is read-only. Values are returned raw so the server-side rules
can name the exact account, path, share or registry value that is at fault.
"""
from __future__ import annotations

import os
from typing import Any

from agent.core.powershell import run_powershell


def _rows(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [row for row in value if isinstance(row, dict)]
    if isinstance(value, dict) and not value.get("error"):
        return [value]
    return []


def _probe(value: Any) -> Any:
    """Keep collection failures explicit instead of looking like 'all good'."""
    if isinstance(value, dict) and value.get("error"):
        return {"error": str(value["error"])[:300]}
    return value


ACCOUNTS = (
    "Get-LocalUser | ForEach-Object { [pscustomobject]@{ "
    "Name=$_.Name; Enabled=$_.Enabled; PasswordRequired=$_.PasswordRequired; "
    "PasswordNeverExpires=($null -eq $_.PasswordExpires); "
    "PasswordLastSet=[string]$(if ($_.PasswordLastSet) { $_.PasswordLastSet.ToString('o') }); "
    "LastLogon=[string]$(if ($_.LastLogon) { $_.LastLogon.ToString('o') }); "
    "Sid=$_.SID.Value } } | ConvertTo-Json -Compress"
)

# secedit is locale independent, unlike 'net accounts'. Requires SYSTEM/admin.
PASSWORD_POLICY = (
    "$f = Join-Path $env:TEMP ('cc_sec_' + [guid]::NewGuid() + '.inf'); "
    "secedit /export /cfg $f /areas SECURITYPOLICY /quiet | Out-Null; $o = @{}; "
    "if (Test-Path $f) { Get-Content $f | ForEach-Object { "
    "if ($_ -match '^\\s*(MinimumPasswordLength|PasswordComplexity|MaximumPasswordAge|LockoutBadCount|LockoutDuration)\\s*=\\s*(-?\\d+)') "
    "{ $o[$matches[1]] = [int]$matches[2] } }; Remove-Item $f -Force -ErrorAction SilentlyContinue }; "
    "$o | ConvertTo-Json -Compress"
)

REGISTRY = (
    "function V($p, $n) { (Get-ItemProperty -Path $p -Name $n -ErrorAction SilentlyContinue).$n }; "
    "[pscustomobject]@{ "
    "WDigestUseLogonCredential = V 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' 'UseLogonCredential'; "
    "LmCompatibilityLevel = V 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' 'LmCompatibilityLevel'; "
    "LlmnrEnableMulticast = V 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' 'EnableMulticast'; "
    "AutoRunDisabledDrives = V 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' 'NoDriveTypeAutoRun' "
    "} | ConvertTo-Json -Compress"
)

DEFENDER_EXCLUSIONS = (
    "Get-MpPreference -ErrorAction Stop | "
    "Select-Object ExclusionPath,ExclusionProcess,ExclusionExtension | ConvertTo-Json -Compress"
)

AUTORUNS = (
    "$out = @(); "
    "$keys = @('HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', "
    "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce', "
    "'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run'); "
    "Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue | "
    "Where-Object { $_.PSChildName -match '^S-1-5-21-[\\d-]+$' } | ForEach-Object { "
    "$keys += \"Registry::HKEY_USERS\\$($_.PSChildName)\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" }; "
    "foreach ($k in $keys) { $p = Get-ItemProperty $k -ErrorAction SilentlyContinue; if ($p) { "
    "$p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { "
    "$out += [pscustomobject]@{ Location = $k; Name = $_.Name; Command = [string]$_.Value } } } }; "
    "$folders = @(\"$env:ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\"); "
    "Get-ChildItem 'C:\\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object { "
    "$folders += Join-Path $_.FullName 'AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup' }; "
    "foreach ($f in $folders) { Get-ChildItem -LiteralPath $f -File -ErrorAction SilentlyContinue | "
    "Where-Object { $_.Name -ne 'desktop.ini' } | ForEach-Object { "
    "$out += [pscustomobject]@{ Location = $f; Name = $_.Name; Command = $_.FullName } } }; "
    "$out | Select-Object -First 100 | ForEach-Object { $path = $null; "
    "if ($_.Command -match '^\\s*\"([^\"]+)\"') { $path = $matches[1] } "
    "elseif ($_.Command -match '^\\s*([^\\s]+\\.(exe|dll|bat|cmd|ps1|vbs|js|lnk|scr))') { $path = $matches[1] }; "
    "if ($path) { $path = [Environment]::ExpandEnvironmentVariables($path) }; $sig = $null; $signer = $null; "
    "if ($path -and (Test-Path -LiteralPath $path)) { $s = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction SilentlyContinue; "
    "$sig = [string]$s.Status; $signer = $s.SignerCertificate.Subject } elseif ($path) { $sig = 'FileMissing' }; "
    "[pscustomobject]@{ Location = $_.Location; Name = $_.Name; Command = $_.Command; Path = $path; "
    "Signature = $sig; Signer = $signer } } | ConvertTo-Json -Compress"
)

SHARES = (
    "Get-SmbShare -ErrorAction Stop | Where-Object { $_.Name -notmatch '\\$$' } | ForEach-Object { "
    "$name = $_.Name; $access = @(Get-SmbShareAccess -Name $name -ErrorAction SilentlyContinue | "
    "Where-Object { [string]$_.AccessControlType -eq 'Allow' } | "
    "ForEach-Object { \"$($_.AccountName)|$($_.AccessRight)\" }); "
    "[pscustomobject]@{ Name = $name; Path = $_.Path; Access = $access } } | ConvertTo-Json -Compress -Depth 4"
)


def collect_hardening() -> dict[str, Any]:
    if os.name != "nt":
        return {"status": "not_supported"}
    accounts = run_powershell(ACCOUNTS)
    policy = run_powershell(PASSWORD_POLICY, timeout=60)
    registry = run_powershell(REGISTRY)
    exclusions = run_powershell(DEFENDER_EXCLUSIONS)
    autoruns = run_powershell(AUTORUNS, timeout=120)
    shares = run_powershell(SHARES)
    return {
        "accounts": _rows(accounts) if not (isinstance(accounts, dict) and accounts.get("error")) else _probe(accounts),
        "password_policy": (
            policy if isinstance(policy, dict) and policy and not policy.get("error")
            else {"error": "No se pudo exportar la politica de seguridad local (requiere ejecutar como SYSTEM)"}
        ),
        "registry": registry if isinstance(registry, dict) else {"error": "No se pudo leer el registro"},
        "defender_exclusions": _probe(exclusions) if exclusions is not None else {},
        "autoruns": _rows(autoruns) if not (isinstance(autoruns, dict) and autoruns.get("error")) else _probe(autoruns),
        "shares": _rows(shares) if not (isinstance(shares, dict) and shares.get("error")) else _probe(shares),
    }
