import unittest

from app.rules import evaluate_rules


class RulesTest(unittest.TestCase):
    def test_detects_insecure_state(self):
        evidence = {
            "firewall": {"domain": True, "private": True, "public": False},
            "listening_ports": [{"port": 3389}],
            "services": [{"name": "RemoteRegistry", "running": True}],
            "local_administrators": ["Administrador", "UsuarioContabilidad"],
            "updates": {"pending_count": 4, "reboot_pending": True},
            "antivirus": {"enabled": False, "real_time": False, "active_threat_count": 1},
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
        self.assertIn("BACKUP_OLD_OR_MISSING", triggered)

    def test_secure_state_has_no_findings(self):
        evidence = {
            "firewall": {"domain": True, "private": True, "public": True},
            "listening_ports": [{"port": 443}],
            "services": [{"name": "RemoteRegistry", "running": False}],
            "local_administrators": ["Administrador", "Soporte"],
            "updates": {"pending_count": 0, "reboot_pending": False},
            "antivirus": {"enabled": True, "real_time": True, "signature_age_days": 0, "quick_scan_age_days": 0, "active_threat_count": 0},
            "backup": {"exists": True, "days_since_last_backup": 1, "latest_size": 200},
        }
        self.assertFalse(any(result.triggered for result in evaluate_rules(evidence)))

    def test_partial_evidence_only_evaluates_present_controls(self):
        results = evaluate_rules({"firewall": {"public": True}})
        self.assertEqual([result.rule_id for result in results], ["FIREWALL_PUBLIC_DISABLED"])
        self.assertFalse(results[0].triggered)


if __name__ == "__main__":
    unittest.main()
