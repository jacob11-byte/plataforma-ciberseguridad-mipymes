import re
import unittest

from app.main import finding_view
from app.plain import PLAIN, explain
from app.rules import KNOWLEDGE, evaluate_rules

JARGON = re.compile(r"\b(RDP|SMB|NTLM\w*|LLMNR|WDigest|UAC|MITRE|CIS|CVE|KB\d*|ACL|SID|RID|TPM|UEFI|PID|IP)\b")


class PlainLanguageTest(unittest.TestCase):
    def test_every_rule_has_a_plain_explanation(self):
        self.assertEqual(set(KNOWLEDGE) - set(PLAIN), set(), "rules without plain-language text")

    def test_titles_avoid_technical_acronyms_and_texts_are_complete(self):
        for rule_id in PLAIN:
            for severity in ("Critico", "Alto", "Medio", "Bajo"):
                text = explain(rule_id, severity, {})
                self.assertIsNone(JARGON.search(text["title"]), f"{rule_id}: jargon in title {text['title']!r}")
                for key in ("title", "what", "why", "urgency", "who_label"):
                    self.assertTrue(text[key], f"{rule_id}: empty {key}")
                self.assertTrue(text["steps"], rule_id)
                self.assertIn(text["who"], {"pasos", "comando"})

    def test_explanations_use_the_real_details(self):
        found = {r.rule_id: r.diagnosis()["plain"] for r in evaluate_rules({
            "firewall": {"domain": True, "private": True, "public": False},
            "updates": {"pending_count": 4, "reboot_pending": True},
            "software_inventory": {"success": True, "data": [{"name": "WinRAR 7.11 (64-bit)", "version": "7.11.0"}]},
            "backup": {"exists": True, "days_since_last_backup": 12, "latest_size": 50, "path": "D:\\Copias"},
            "security_detections": [
                {"event_id": 4625, "target_user": "contabilidad", "source_ip": "185.220.101.4", "logon_type": "10"}] * 12,
        }) if r.triggered}
        self.assertIn("redes públicas", found["FIREWALL_PUBLIC_DISABLED"]["what"])
        self.assertIn("Hay 4 actualización(es)", found["UPDATES_PENDING"]["what"])
        self.assertIn("reiniciarse", found["UPDATES_PENDING"]["what"])
        self.assertIn("WinRAR 7.11.0 → actualiza a la versión 7.13", found["VULNERABLE_SOFTWARE"]["what"])
        self.assertIn("12 días", found["BACKUP_OLD_OR_MISSING"]["what"])
        self.assertIn("«contabilidad»", found["BRUTE_FORCE_LOGON"]["what"])
        self.assertIn("185.220.101.4", found["BRUTE_FORCE_LOGON"]["what"])
        self.assertEqual(found["FIREWALL_PUBLIC_DISABLED"]["who_label"], "Lo puedes hacer tú: tiene solución rápida")
        self.assertEqual(found["FIREWALL_PUBLIC_DISABLED"]["urgency"], "Importante: atiéndelo esta semana")

    def test_findings_stored_before_this_change_get_a_general_explanation(self):
        old = finding_view({"rule_id": "SMB1_ENABLED", "severity": "Alto", "details_json": '{"detail": "x"}'})
        self.assertEqual(old["diagnosis"]["plain"]["title"], PLAIN["SMB1_ENABLED"]["title"])
        self.assertEqual(old["diagnosis"]["detail"], "x")
        unknown = finding_view({"rule_id": "WAZUH:CVE-1", "severity": "Alto", "details_json": None})
        self.assertIsNone(unknown["diagnosis"]["plain"])


if __name__ == "__main__":
    unittest.main()
