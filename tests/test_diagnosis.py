import json
import tempfile
import unittest
from datetime import date
from pathlib import Path
from unittest import mock

from agent import windows_agent
from app.main import collection_issues, security_score
from app.rules import KNOWLEDGE, evaluate_rules


def triggered(evidence, today=None):
    return {result.rule_id: result for result in evaluate_rules(evidence, today=today) if result.triggered}


class DiagnosisTest(unittest.TestCase):
    def test_every_rule_has_risk_steps_and_references(self):
        for rule_id, knowledge in KNOWLEDGE.items():
            self.assertTrue(knowledge["risk"], rule_id)
            self.assertTrue(knowledge["steps"], rule_id)

    def test_brute_force_names_account_source_and_reason(self):
        failures = [
            {"event_id": 4625, "target_user": "contabilidad", "source_ip": "185.220.101.4",
             "logon_type": "10", "sub_status": "0xc000006a"}
            for _ in range(14)
        ]
        result = triggered({"security_detections": failures})["BRUTE_FORCE_LOGON"]
        self.assertEqual(result.severity, "Alto")
        self.assertIn("14 contra 'contabilidad' desde 185.220.101.4", result.detail)
        self.assertIn("escritorio remoto (RDP)", result.detail)
        self.assertIn("contrasena incorrecta", result.detail)
        self.assertIn("MITRE ATT&CK T1110", " ".join(result.references))
        self.assertNotIn("BRUTE_FORCE_LOGON", triggered({"security_detections": failures[:5]}))

    def test_log_cleared_and_suspicious_service(self):
        events = [
            {"event_id": 1102, "subject_user": "soporte", "time_created": "2026-10-28T03:12:00"},
            {"event_id": 7045, "service_name": "updsvc", "image_path": "C:\\Users\\ana\\AppData\\Local\\Temp\\x.exe",
             "account": "LocalSystem"},
            {"event_id": 7045, "service_name": "CyberCheck", "image_path": "C:\\Program Files\\CyberCheck\\svc.exe"},
        ]
        found = triggered({"security_detections": events})
        self.assertIn("soporte", found["SECURITY_LOG_CLEARED"].detail)
        self.assertEqual(found["SECURITY_LOG_CLEARED"].severity, "Critico")
        self.assertIn("updsvc", found["SUSPICIOUS_SERVICE_INSTALLED"].detail)
        self.assertNotIn("CyberCheck", found["SUSPICIOUS_SERVICE_INSTALLED"].detail)

    def test_service_arguments_do_not_make_a_trusted_binary_suspicious(self):
        events = [{"event_id": 7045, "service_name": "Agent",
                   "image_path": '"C:\\Program Files\\Agent\\svc.exe" --config "C:\\ProgramData\\Agent\\cfg.json"'}]
        self.assertNotIn("SUSPICIOUS_SERVICE_INSTALLED", triggered({"security_detections": events}))

    def test_empty_card_reader_is_not_usb_storage(self):
        evidence = {"connected_devices": {
            "usb_storage": [{"Model": "Generic- Multi-Card USB Device", "Size": None}],
            "unsigned_drivers": [], "device_errors": [],
        }}
        self.assertNotIn("USB_STORAGE_CONNECTED", triggered(evidence))
        evidence["connected_devices"]["usb_storage"][0]["Size"] = 32_000_000_000
        self.assertIn("32 GB", triggered(evidence)["USB_STORAGE_CONNECTED"].detail)

    def test_pending_updates_name_the_missing_kb(self):
        evidence = {"updates": {"pending_count": 2, "reboot_pending": False, "pending_updates": [
            {"title": "Actualizacion acumulativa 2026-10", "kb": "KB5066835", "severity": "Critical", "security": True},
            {"title": "Defender antimalware", "kb": "KB2267602", "severity": None, "security": False},
        ]}}
        result = triggered(evidence)["UPDATES_PENDING"]
        self.assertEqual(result.severity, "Critico")
        self.assertIn("KB5066835", result.detail)
        self.assertIn("1 de seguridad", result.detail)

    def test_hardening_rules_name_exact_objects(self):
        evidence = {"hardening": {"success": True, "data": {
            "accounts": [
                {"Name": "Invitado", "Enabled": True, "PasswordRequired": False, "Sid": "S-1-5-21-1-2-3-501"},
                {"Name": "caja", "Enabled": True, "PasswordRequired": False, "Sid": "S-1-5-21-1-2-3-1001"},
            ],
            "password_policy": {"MinimumPasswordLength": 0, "LockoutBadCount": 0},
            "registry": {"WDigestUseLogonCredential": 1, "LmCompatibilityLevel": 1, "LlmnrEnableMulticast": 0},
            "defender_exclusions": {"ExclusionPath": ["C:\\Users\\ana\\Downloads"], "ExclusionProcess": [], "ExclusionExtension": ["exe"]},
            "autoruns": [
                {"Name": "Updater", "Path": "C:\\Users\\ana\\AppData\\Roaming\\upd.exe", "Signature": "NotSigned", "Location": "HKCU Run"},
                {"Name": "OneDrive", "Path": "C:\\Users\\ana\\AppData\\Local\\OneDrive.exe", "Signature": "Valid", "Location": "HKCU Run"},
            ],
            "shares": [{"Name": "Contabilidad", "Path": "D:\\Conta", "Access": ["Todos|Full"]}],
        }}}
        found = triggered(evidence)
        self.assertIn("Invitado", found["GUEST_ACCOUNT_ENABLED"].detail)
        self.assertIn("caja", found["ACCOUNT_NO_PASSWORD_REQUIRED"].detail)
        self.assertNotIn("Invitado", found["ACCOUNT_NO_PASSWORD_REQUIRED"].detail)
        self.assertIn("0 caracteres", found["PASSWORD_POLICY_WEAK"].detail)
        self.assertEqual(found["WDIGEST_PLAINTEXT"].severity, "Critico")
        self.assertIn("LmCompatibilityLevel = 1", found["NTLMV1_ALLOWED"].detail)
        self.assertNotIn("LLMNR_ENABLED", found)
        self.assertEqual(found["DEFENDER_EXCLUSIONS"].severity, "Alto")
        self.assertIn("Downloads", found["DEFENDER_EXCLUSIONS"].detail)
        self.assertIn("upd.exe", found["AUTORUN_UNSIGNED_USER_PATH"].detail)
        self.assertNotIn("OneDrive", found["AUTORUN_UNSIGNED_USER_PATH"].detail)
        self.assertIn("Contabilidad", found["SHARE_OPEN_TO_EVERYONE"].detail)
        self.assertEqual(found["SHARE_OPEN_TO_EVERYONE"].severity, "Alto")

    def test_exclusions_hidden_without_admin_are_not_judged(self):
        evidence = {"hardening": {"success": True, "data": {"defender_exclusions": {
            "ExclusionPath": ["N/A: Must be an administrator to view exclusions"],
        }}}}
        self.assertEqual([r.rule_id for r in evaluate_rules(evidence) if r.rule_id == "DEFENDER_EXCLUSIONS"], [])

    def test_risky_ports_and_unsigned_processes(self):
        evidence = {
            "listening_ports": [
                {"address": "0.0.0.0", "port": 5900, "process_name": "tvnserver", "process_id": 812},
                {"address": "127.0.0.1", "port": 3306, "process_name": "mysqld", "process_id": 900},
            ],
            "process_inventory": {"success": True, "data": [
                {"name": "svchost32.exe", "process_id": 4410, "signature_status": "NotSigned",
                 "executable_path": "C:\\Users\\ana\\AppData\\Local\\Temp\\svchost32.exe"},
                {"name": "chrome.exe", "process_id": 10, "signature_status": "Valid",
                 "executable_path": "C:\\Users\\ana\\AppData\\Local\\Google\\chrome.exe"},
            ]},
        }
        found = triggered(evidence)
        self.assertIn("puerto 5900 (VNC) abierto por tvnserver (PID 812)", found["RISKY_PORT_LISTENING"].detail)
        self.assertNotIn("3306", found["RISKY_PORT_LISTENING"].detail)
        self.assertIn("svchost32.exe (PID 4410)", found["PROCESS_UNSIGNED_USER_PATH"].detail)
        self.assertNotIn("chrome", found["PROCESS_UNSIGNED_USER_PATH"].detail)

    def test_windows_end_of_support_uses_build_and_edition(self):
        win10 = {"system_inventory_v2": {"success": True, "data": {
            "windows_build": "19045", "windows_edition": "Microsoft Windows 10 Pro"}}}
        result = triggered(win10, today=date(2026, 10, 29))["OS_END_OF_SUPPORT"]
        self.assertIn("14/10/2025", result.detail)
        win11 = {"system_inventory_v2": {"success": True, "data": {
            "windows_build": "26200", "windows_edition": "Microsoft Windows 11 Pro"}}}
        self.assertNotIn("OS_END_OF_SUPPORT", triggered(win11, today=date(2026, 10, 29)))
        ltsc = {"system_inventory_v2": {"success": True, "data": {
            "windows_build": "19044", "windows_edition": "Windows 10 Enterprise LTSC 2021"}}}
        self.assertEqual([r for r in evaluate_rules(ltsc) if r.rule_id == "OS_END_OF_SUPPORT"], [])

    def test_antivirus_detail_lists_each_disabled_component(self):
        evidence = {"antivirus": {
            "name": "Microsoft Defender", "enabled": True, "real_time": False, "tamper_protected": False,
            "on_access_protection": True, "behavior_monitor": False, "ioav_protection": True,
            "preferences": {"DisableRealtimeMonitoring": True},
        }}
        detail = triggered(evidence)["ANTIVIRUS_DISABLED"].detail
        self.assertIn("tiempo real esta apagada", detail)
        self.assertIn("monitor de comportamiento esta apagado", detail)
        self.assertIn("DisableRealtimeMonitoring=True", detail)
        self.assertIn("Proteccion contra alteraciones", detail)

    def test_security_score_and_collection_issues(self):
        self.assertEqual(security_score([])["grade"], "A")
        score = security_score([
            {"status": "open", "severity": "Critico"},
            {"status": "open", "severity": "Alto"},
            {"status": "resolved", "severity": "Critico"},
        ])
        self.assertEqual(score["score"], 65)
        self.assertEqual(score["grade"], "C")
        issues = collection_issues({"scan_metadata": {"data": {"modules": [
            {"module": "updates", "status": "error", "error": "Acceso denegado"},
            {"module": "firewall", "status": "ok"},
        ]}}})
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["label"], "Windows Update")
        self.assertIn("SYSTEM", issues[0]["hint"])


class ScheduledScanTest(unittest.TestCase):
    def config(self, directory):
        path = Path(directory) / "agent_config.json"
        path.write_text("{}", encoding="utf-8")
        return {"api_url": "https://server.example", "device_id": "d", "token": "t", "_config_path": str(path)}

    def test_first_cycle_scans_then_waits_for_interval(self):
        with tempfile.TemporaryDirectory() as directory:
            config = self.config(directory)
            self.assertTrue(windows_agent.scheduled_scan_due(config, now=1_000_000))
            windows_agent.record_full_scan(config, ok=True, now=1_000_000)
            self.assertFalse(windows_agent.scheduled_scan_due(config, now=1_000_000 + 3600))
            self.assertTrue(windows_agent.scheduled_scan_due(config, now=1_000_000 + 12 * 3600))
            state = json.loads((Path(directory) / "agent_state.json").read_text(encoding="utf-8"))
            self.assertTrue(state["last_full_scan_ok"])

    def test_failed_scan_retries_after_an_hour(self):
        with tempfile.TemporaryDirectory() as directory:
            config = self.config(directory)
            windows_agent.record_full_scan(config, ok=False, now=1_000_000)
            self.assertFalse(windows_agent.scheduled_scan_due(config, now=1_000_000 + 1800))
            self.assertTrue(windows_agent.scheduled_scan_due(config, now=1_000_000 + 3600))

    def test_disabled_or_without_state_path(self):
        self.assertFalse(windows_agent.scheduled_scan_due({"api_url": "x"}))
        with tempfile.TemporaryDirectory() as directory:
            config = {**self.config(directory), "auto_scan_hours": 0}
            self.assertFalse(windows_agent.scheduled_scan_due(config))

    def test_poll_runs_scheduled_scan_and_records_it(self):
        with tempfile.TemporaryDirectory() as directory:
            config = self.config(directory)
            with mock.patch.object(windows_agent, "flush_outbox", return_value={"sent": 0, "pending": 0, "dead": 0}), \
                 mock.patch.object(windows_agent, "send_heartbeat", return_value={}), \
                 mock.patch.object(windows_agent, "request_json", return_value={"tasks": []}), \
                 mock.patch.object(windows_agent, "send_scan", return_value={"scan_id": 1}) as scan:
                windows_agent.poll_once(config)
                windows_agent.poll_once(config)
            scan.assert_called_once_with(config, "FULL_SCAN")


if __name__ == "__main__":
    unittest.main()
