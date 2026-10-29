import os
import re
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import alerts, main, storage

ORIGIN = {"Origin": "http://testserver"}
BAD_FIREWALL = {"firewall": {"domain": True, "private": True, "public": False}}
GOOD_FIREWALL = {"firewall": {"domain": True, "private": True, "public": True}}


class AlertsTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        patcher = patch.object(storage, "DB_PATH", Path(self.directory.name) / "alerts.db")
        patcher.start()
        self.addCleanup(patcher.stop)
        installer = Path(self.directory.name) / "CyberCheckSetup.exe"
        installer.write_bytes(b"MZ")
        env = patch.dict(os.environ, {
            "CYBERCHECK_ENV": "development", "RENDER_SERVICE_ID": "", "DATABASE_URL": "",
            "COOKIE_SECURE": "false", "AGENT_INSTALLER_PATH": str(installer),
            "SMTP_HOST": "smtp.example.test", "SMTP_FROM": "alertas@example.test",
        })
        env.start()
        self.addCleanup(env.stop)
        storage.init_db()
        self.sent = []
        deliver = patch.object(alerts, "deliver", side_effect=lambda message: self.sent.append(message) or True)
        deliver.start()
        self.addCleanup(deliver.stop)

        self.owner = TestClient(main.app)
        self.owner.post("/api/signup", json={
            "company_name": "Empresa Alertas", "email": "dueno@alertas.com", "password": "contrasena-segura-1",
        })
        response = self.owner.get("/api/agent/installer")
        token = re.search(r"CyberCheckSetup_([0-9a-f]{32})", response.headers["content-disposition"]).group(1)
        registered = TestClient(main.app).post("/api/register", json={"registration_code": token, "hostname": "PC-CAJA"}).json()
        self.device = registered["device_id"]
        self.headers = {"Authorization": f"Bearer {registered['token']}"}

    def scan(self, evidence, request_id):
        response = TestClient(main.app).post("/api/agent/results", headers=self.headers, json={
            "device_id": self.device, "scan_type": "FULL_SCAN", "evidence": evidence, "request_id": request_id,
        })
        self.assertEqual(response.status_code, 200, response.text)
        for thread in threading.enumerate():
            if thread.name == "cybercheck-alert":
                thread.join(5)

    def test_only_new_serious_findings_trigger_one_email(self):
        self.scan(BAD_FIREWALL, "alert-scan-0001")
        self.assertEqual(len(self.sent), 1)
        message = self.sent[0]
        self.assertEqual(message["To"], "dueno@alertas.com")
        self.assertIn("PC-CAJA", message["Subject"])
        self.assertIn("Cortafuegos publico desactivado", message.get_content())
        self.assertIn("/devices/" + self.device, message.get_content())

        self.scan(BAD_FIREWALL, "alert-scan-0002")
        self.assertEqual(len(self.sent), 1, "an already-open finding must not alert again")

        self.scan(GOOD_FIREWALL, "alert-scan-0003")
        self.assertEqual(len(self.sent), 1)
        self.scan(BAD_FIREWALL, "alert-scan-0004")
        self.assertEqual(len(self.sent), 2, "a reopened finding alerts again")

    def test_viewers_and_low_severity_are_not_emailed(self):
        self.owner.post("/api/users", headers=ORIGIN, json={
            "username": "lector@alertas.com", "password": "contrasena-segura-2", "role": "viewer",
        })
        self.owner.post("/api/users", headers=ORIGIN, json={
            "username": "tecnico@alertas.com", "password": "contrasena-segura-3", "role": "technician",
        })
        self.scan(BAD_FIREWALL, "alert-scan-0005")
        recipients = {address.strip() for address in self.sent[0]["To"].split(",")}
        self.assertEqual(recipients, {"dueno@alertas.com", "tecnico@alertas.com"})

        self.sent.clear()
        # Only a Bajo finding (LLMNR) -> nothing to send.
        self.scan({"hardening": {"success": True, "data": {"registry": {"LlmnrEnableMulticast": None}}}}, "alert-scan-0006")
        self.assertEqual(self.sent, [])

    def test_no_smtp_means_no_alerts(self):
        with patch.dict(os.environ, {"SMTP_HOST": ""}):
            self.scan(BAD_FIREWALL, "alert-scan-0007")
        self.assertEqual(self.sent, [])

    def test_report_page_requires_session(self):
        anonymous = TestClient(main.app).get(f"/devices/{self.device}/report", follow_redirects=False)
        self.assertEqual(anonymous.status_code, 302)
        page = self.owner.get(f"/devices/{self.device}/report")
        self.assertEqual(page.status_code, 200)
        self.assertIn("Informe de seguridad", page.text)


if __name__ == "__main__":
    unittest.main()
