import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from app.fixes import FIXES, fix_for, ps_quote
from app.plain import PLAIN, explain
from app.rules import KNOWLEDGE, evaluate_rules

# Realistic evidence for every rule, including names that need quoting.
SAMPLES = {
    "RISKY_SERVICE_ENABLED": {"services": [{"name": "RemoteRegistry"}, {"name": "WinRM"}]},
    "UNAUTHORIZED_LOCAL_ADMIN": {"unauthorized_accounts": ["DESKTOP-1\\O'Brien", "contabilidad"]},
    "BACKUP_OLD_OR_MISSING": {"path": "D:\\Copias de 'oficina'"},
    "ACCOUNT_NO_PASSWORD_REQUIRED": {"accounts": ["caja", "O'Neil"]},
    "DEFENDER_EXCLUSIONS": {"exclusions": [{"type": "carpeta", "value": "C:\\Users\\ana\\Downloads"},
                                           {"type": "proceso", "value": "C:\\Temp\\x.exe"},
                                           {"type": "extension", "value": "exe"}]},
    "AUTORUN_UNSIGNED_USER_PATH": {"entries": [
        {"name": "Updater", "path": "C:\\Users\\ana\\AppData\\Roaming\\upd.exe",
         "location": "Registry::HKEY_USERS\\S-1-5-21-1-2-3-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
        {"name": "x.exe", "path": "C:\\Users\\ana\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\x.exe",
         "location": "C:\\Users\\ana\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"}]},
    "SHARE_OPEN_TO_EVERYONE": {"shares": [{"name": "Contabilidad", "path": "D:\\Conta", "right": "Full"}]},
    "RISKY_PORT_LISTENING": {"exposed": [{"port": 5900, "service": "VNC", "process": "tvnserver"}]},
    "PROCESS_UNSIGNED_USER_PATH": {"processes": [{"name": "svc.exe", "pid": 44, "path": "C:\\Users\\ana\\AppData\\Local\\Temp\\svc.exe"}]},
    "BRUTE_FORCE_LOGON": {"top_sources": [{"user": "jacob", "source_ip": "185.220.101.4", "count": 12},
                                          {"user": "jacob", "source_ip": "-", "count": 3}]},
    "NEW_LOCAL_ACCOUNT": {"accounts": [{"target_user": "soporte2"}]},
    "ADMIN_GROUP_MEMBER_ADDED": {"changes": [{"member_sid": "S-1-5-21-1-2-3-1009"}]},
    "SUSPICIOUS_SERVICE_INSTALLED": {"services": [{"service_name": "Updater Service"}]},
    "VULNERABLE_SOFTWARE": {"programs": [{"product": "WinRAR", "installed": "7.11", "fixed_in": "7.13", "eol": False},
                                         {"product": "Adobe Flash Player", "installed": "32", "eol": True}]},
}

PARSE_AND_RESOLVE = r"""
$items = Get-Content -Raw -LiteralPath $args[0] | ConvertFrom-Json
$report = foreach ($item in $items) {
  $tokens = $null; $errors = $null
  $ast = [System.Management.Automation.Language.Parser]::ParseInput($item.command, [ref]$tokens, [ref]$errors)
  $problems = @($errors | ForEach-Object { "sintaxis: " + $_.Message })
  foreach ($call in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)) {
    $name = $call.GetCommandName()
    if (-not $name) { continue }
    $command = Get-Command -Name $name -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $command) { $problems += "no existe: $name"; continue }
    if ($command.CommandType -in 'Cmdlet', 'Function') {
      foreach ($element in $call.CommandElements) {
        if ($element -is [System.Management.Automation.Language.CommandParameterAst]) {
          $param = $element.ParameterName
          $known = $command.Parameters.Keys + ($command.Parameters.Values | ForEach-Object { $_.Aliases })
          if (-not ($known | Where-Object { $_ -like "$param*" })) { $problems += "parametro inexistente: $name -$param" }
        }
      }
    }
  }
  [pscustomobject]@{ rule = $item.rule; problems = @($problems) }
}
$report | ConvertTo-Json -Depth 4 -Compress
"""


class FixesTest(unittest.TestCase):
    def all_fixes(self):
        return {rule: fix_for(rule, SAMPLES.get(rule, {})) for rule in FIXES}

    def test_every_rule_builds_a_command(self):
        for rule, fix in self.all_fixes().items():
            self.assertIsNotNone(fix, rule)
            self.assertTrue(fix["command"].strip(), rule)
        self.assertEqual(set(FIXES) - set(KNOWLEDGE), set())

    def test_quoting_keeps_values_literal(self):
        self.assertEqual(ps_quote("O'Brien"), "'O''Brien'")
        self.assertEqual(ps_quote("$(Remove-Item C:\\)"), "'$(Remove-Item C:\\)'")
        admins = fix_for("UNAUTHORIZED_LOCAL_ADMIN", SAMPLES["UNAUTHORIZED_LOCAL_ADMIN"])["command"]
        self.assertIn("-Member 'DESKTOP-1\\O''Brien'", admins)

    def test_commands_use_the_real_values(self):
        fixes = self.all_fixes()
        self.assertIn("-LocalPort 5900", fixes["RISKY_PORT_LISTENING"]["command"])
        self.assertIn("-RemoteAddress '185.220.101.4'", fixes["BRUTE_FORCE_LOGON"]["command"])
        self.assertNotIn("-RemoteAddress '-'", fixes["BRUTE_FORCE_LOGON"]["command"])
        self.assertIn("winget upgrade --id RARLab.WinRAR", fixes["VULNERABLE_SOFTWARE"]["command"])
        self.assertIn("Remove-MpPreference -ExclusionExtension 'exe'", fixes["DEFENDER_EXCLUSIONS"]["command"])

    def test_dynamic_rules_without_data_offer_no_half_command(self):
        self.assertIsNone(fix_for("UNAUTHORIZED_LOCAL_ADMIN", {}))
        self.assertIsNone(fix_for("RISKY_PORT_LISTENING", {"exposed": [{"port": "abc"}]}))
        self.assertIsNone(fix_for("NO_SUCH_RULE", {}))

    def test_plain_explanation_never_sends_people_to_a_technician(self):
        for rule in PLAIN:
            text = explain(rule, "Alto", SAMPLES.get(rule, {}))
            joined = " ".join([text["what"], text["why"], *text["steps"], text["who_label"]])
            self.assertNotIn("Pide ayuda a tu técnico", joined, rule)
            self.assertNotIn("pide a tu técnico", joined.lower(), rule)
        firewall = [r for r in evaluate_rules({"firewall": {"domain": True, "private": True, "public": False}}) if r.triggered][0]
        diagnosis = firewall.diagnosis()
        self.assertEqual(diagnosis["quick_fix"]["command"], "Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True")
        self.assertEqual(diagnosis["plain"]["who_label"], "Lo puedes hacer tú: tiene solución rápida")

    @unittest.skipUnless(os.name == "nt", "PowerShell parser")
    def test_every_command_is_valid_powershell_with_existing_commands_and_parameters(self):
        items = [{"rule": rule, "command": fix["command"]} for rule, fix in self.all_fixes().items()]
        with tempfile.TemporaryDirectory() as directory:
            commands, script = Path(directory) / "commands.json", Path(directory) / "check.ps1"
            commands.write_text(json.dumps(items), encoding="utf-8")
            script.write_text(PARSE_AND_RESOLVE, encoding="utf-8-sig")
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(script), str(commands)],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180,
            )
        report = json.loads(result.stdout)
        problems = {row["rule"]: row["problems"] for row in report if row["problems"]}
        self.assertEqual(problems, {}, result.stderr[:500])


if __name__ == "__main__":
    unittest.main()
