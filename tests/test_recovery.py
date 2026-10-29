import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import alerts, main, storage

ORIGIN = {"Origin": "http://testserver"}


class RecoveryAndOfflineTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        patcher = patch.object(storage, "DB_PATH", Path(self.directory.name) / "recovery.db")
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
        deliver = patch.object(alerts, "deliver", side_effect=lambda m: self.sent.append(m) or True)
        deliver.start()
        self.addCleanup(deliver.stop)

    def wait_mail(self):
        import threading
        for thread in threading.enumerate():
            if thread.name == "cybercheck-alert":
                thread.join(5)

    def signup(self, email="ana@empresa.com", password="contrasena-segura-1"):
        client = TestClient(main.app)
        response = client.post("/api/signup", json={"company_name": "Empresa Rec", "email": email, "password": password})
        self.assertEqual(response.status_code, 200, response.text)
        return client

    def request_link(self, email):
        response = TestClient(main.app).post("/api/password/forgot", json={"email": email})
        self.wait_mail()
        return response

    def test_reset_flow_changes_password_and_closes_sessions(self):
        session = self.signup()
        self.assertEqual(session.get("/api/me").status_code, 200)
        response = self.request_link("ANA@empresa.com")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(self.sent), 1)
        token = re.search(r"/reset\?token=([\w-]+)", self.sent[0].get_content()).group(1)

        weak = TestClient(main.app).post("/api/password/reset", json={"token": token, "password": "corta"})
        self.assertEqual(weak.status_code, 400)
        done = TestClient(main.app).post("/api/password/reset", json={"token": token, "password": "otra-contrasena-nueva"})
        self.assertEqual(done.status_code, 200, done.text)

        self.assertEqual(session.get("/api/me").status_code, 401, "old sessions must be closed")
        old = TestClient(main.app).post("/api/login", json={"username": "ana@empresa.com", "password": "contrasena-segura-1"})
        self.assertEqual(old.status_code, 401)
        new = TestClient(main.app).post("/api/login", json={"username": "ana@empresa.com", "password": "otra-contrasena-nueva"})
        self.assertEqual(new.status_code, 200)
        reuse = TestClient(main.app).post("/api/password/reset", json={"token": token, "password": "una-tercera-contrasena"})
        self.assertEqual(reuse.status_code, 400, "a reset link is single use")

    def test_unknown_email_gets_same_answer_and_no_mail(self):
        self.signup()
        known = self.request_link("ana@empresa.com").json()
        unknown = self.request_link("nadie@empresa.com").json()
        self.assertEqual(known, unknown)
        self.assertEqual(len(self.sent), 1)

    def test_expired_link_and_missing_smtp(self):
        self.signup()
        self.request_link("ana@empresa.com")
        token = re.search(r"token=([\w-]+)", self.sent[0].get_content()).group(1)
        with storage.connect() as db:
            db.execute("UPDATE password_resets SET expires_at='2000-01-01 00:00:00'")
        expired = TestClient(main.app).post("/api/password/reset", json={"token": token, "password": "otra-contrasena-nueva"})
        self.assertEqual(expired.status_code, 400)
        with patch.dict(os.environ, {"SMTP_HOST": ""}):
            self.assertEqual(self.request_link("ana@empresa.com").status_code, 503)
            self.assertFalse(TestClient(main.app).get("/api/auth/providers").json()["reset"])

    def test_forgot_is_rate_limited(self):
        self.signup()
        for _ in range(main.PASSWORD_RESET_LIMIT):
            self.assertEqual(self.request_link("ana@empresa.com").status_code, 200)
        self.assertEqual(self.request_link("ana@empresa.com").status_code, 429)

    def test_offline_device_alerts_once_per_outage(self):
        owner = self.signup()
        token = re.search(
            r"CyberCheckSetup_([0-9a-f]{32})", owner.get("/api/agent/installer").headers["content-disposition"]
        ).group(1)
        device = TestClient(main.app).post("/api/register", json={"registration_code": token, "hostname": "PC-APAGADA"}).json()
        headers = {"Authorization": f"Bearer {device['token']}"}
        self.assertEqual(main.check_offline_devices(), 0, "a fresh device is not offline")

        with storage.connect() as db:
            db.execute("UPDATE devices SET last_seen='2000-01-01 00:00:00' WHERE device_id=?", (device["device_id"],))
        self.assertEqual(main.check_offline_devices(), 1)
        self.wait_mail()
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(self.sent[0]["To"], "ana@empresa.com")
        self.assertIn("PC-APAGADA", self.sent[0].get_content())
        self.assertEqual(main.check_offline_devices(), 0, "no repeat while the outage lasts")

        TestClient(main.app).post("/api/agent/heartbeat", headers=headers, json={
            "device_id": device["device_id"], "agent_version": "t"})
        with storage.connect() as db:
            db.execute("UPDATE devices SET last_seen='2000-01-01 00:00:00' WHERE device_id=?", (device["device_id"],))
        self.assertEqual(main.check_offline_devices(), 1, "a new outage alerts again after the device came back")

    def test_disconnected_devices_are_not_reported_offline(self):
        owner = self.signup()
        token = re.search(
            r"CyberCheckSetup_([0-9a-f]{32})", owner.get("/api/agent/installer").headers["content-disposition"]
        ).group(1)
        device = TestClient(main.app).post("/api/register", json={"registration_code": token, "hostname": "PC-BAJA"}).json()
        owner.post(f"/api/devices/{device['device_id']}/disconnect", headers=ORIGIN)
        with storage.connect() as db:
            db.execute("UPDATE devices SET last_seen='2000-01-01 00:00:00'")
        self.assertEqual(main.check_offline_devices(), 0)


if __name__ == "__main__":
    unittest.main()
