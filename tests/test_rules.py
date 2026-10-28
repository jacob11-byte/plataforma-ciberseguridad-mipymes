import unittest

from app.rules import evaluate_rules


class RulesTest(unittest.TestCase):
    def test_detects_insecure_state(self):
        evidence = {
            "firewall": {"domain": True, "private": True, "public": False},
            "listening_ports": [{"port": 3389}],
            "services": [{"name": "RemoteRegistry", "running": True}],
            "local_administrators": ["Administrador", "UsuarioContabilidad"],
            "authorized_local_admins": ["Administrador"],
            "updates": {"pending_count": 4, "reboot_pending": True},
            "antivirus": {"enabled": False, "real_time": False, "active_threat_count": 1},
            "connected_devices": {
                "usb_storage": [{"Model": "USB Demo"}],
                "unsigned_drivers": [{"DeviceName": "Driver Demo"}],
                "device_errors": [{"FriendlyName": "Camara", "Status": "Error"}],
            },
            "backup": {"exists": True, "days_since_last_backup": 12, "latest_size": 200},
        }
        triggered = {result.rule_id for result in evaluate_rules(evidence) if result.triggered}
        self.assertIn("FIREWALL_PUBLIC_DISABLED", triggered)
        self.assertIn("RDP_EXPOSED", triggered)
        self.assertIn("RISKY_SERVICE_ENABLED", triggered)
        self.assertIn("UNAUTHORIZED_LOCAL_ADMIN", triggered)
        self.assertIn("UPDATES_PENDING", triggered)
        self.assertIn("ANTIVIRUS_DISABLED", triggered)
        self.assertIn("ANTIVIRUS_ACTIVE_THREATS", triggered)
        self.assertIn("USB_STORAGE_CONNECTED", triggered)
        self.assertIn("UNSIGNED_DEVICE_DRIVER", triggered)
        self.assertIn("DEVICE_WITH_ERROR", triggered)
        self.assertIn("BACKUP_OLD_OR_MISSING", triggered)

    def test_secure_state_has_no_findings(self):
        evidence = {
            "firewall": {"domain": True, "private": True, "public": True},
            "listening_ports": [{"port": 443}],
            "services": [{"name": "RemoteRegistry", "running": False}],
            "local_administrators": ["Administrador", "Soporte"],
            "updates": {"pending_count": 0, "reboot_pending": False},
            "antivirus": {"enabled": True, "real_time": True, "signature_age_days": 0, "quick_scan_age_days": 0, "active_threat_count": 0},
            "connected_devices": {"usb_storage": [], "unsigned_drivers": [], "device_errors": []},
            "backup": {"exists": True, "days_since_last_backup": 1, "latest_size": 200},
        }
        self.assertFalse(any(result.triggered for result in evaluate_rules(evidence)))

    def test_partial_evidence_only_evaluates_present_controls(self):
        results = evaluate_rules({"firewall": {"public": True}})
        self.assertEqual([result.rule_id for result in results], ["FIREWALL_PUBLIC_DISABLED"])
        self.assertFalse(results[0].triggered)

    def test_failed_or_incomplete_collection_cannot_prove_remediation(self):
        evidence = {
            "firewall": {"status": "error", "error": "access denied"},
            "listening_ports": {"status": "error", "error": "timed out"},
            "services": {"status": "error", "error": "timed out"},
            "local_administrators": {"status": "error", "error": "access denied"},
            "authorized_local_admins": ["Administrador"],
            "updates": {"status": "error", "error": "service unavailable"},
            "antivirus": {"status": "unavailable"},
            "connected_devices": {"status": "error", "error": "access denied"},
            "backup": {"status": "error", "error": "access denied"},
        }
        self.assertEqual(evaluate_rules(evidence), [])

    def test_admins_require_explicit_policy(self):
        self.assertEqual(evaluate_rules({"local_administrators": ["Soporte"]}), [])
        results = evaluate_rules({
            "local_administrators": ["Soporte"],
            "authorized_local_admins": ["Administrador"],
        })
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].triggered)

    def test_partial_antivirus_and_backup_do_not_claim_pass(self):
        evidence = {
            "antivirus": {"enabled": True},
            "backup": {"exists": True},
        }
        self.assertEqual(evaluate_rules(evidence), [])

    def test_windows_security_controls_use_measured_values(self):
        evidence = {
            "security_controls": {
                "success": True,
                "data": {
                    "uac": {"EnableLUA": 0},
                    "smb1": {"State": "Enabled"},
                    "rdp": {"raw": {
                        "rdp": {"fDenyTSConnections": 0},
                        "nla": {"UserAuthentication": 0},
                    }},
                },
            },
        }
        triggered = {result.rule_id for result in evaluate_rules(evidence) if result.triggered}
        self.assertEqual(triggered, {"UAC_DISABLED", "SMB1_ENABLED", "RDP_NLA_DISABLED"})

        evidence["security_controls"]["data"]["uac"]["EnableLUA"] = 1
        evidence["security_controls"]["data"]["smb1"]["State"] = "Disabled"
        evidence["security_controls"]["data"]["rdp"]["raw"]["nla"]["UserAuthentication"] = 1
        self.assertFalse(any(result.triggered for result in evaluate_rules(evidence)))

        evidence["security_controls"]["data"]["uac"] = {"error": "access denied"}
        evidence["security_controls"]["data"]["smb1"] = {"error": "not available"}
        evidence["security_controls"]["data"]["rdp"]["raw"]["nla"] = {"error": "access denied"}
        self.assertEqual(evaluate_rules(evidence), [])


if __name__ == "__main__":
    unittest.main()
