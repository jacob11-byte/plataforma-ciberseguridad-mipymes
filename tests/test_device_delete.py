import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import main, storage

ORIGIN = {"Origin": "http://testserver"}


class DeviceDeleteTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        patcher = patch.object(storage, "DB_PATH", Path(self.directory.name) / "delete.db")
        patcher.start()
        self.addCleanup(patcher.stop)
        installer = Path(self.directory.name) / "CyberCheckSetup.exe"
        installer.write_bytes(b"MZ")
        env = patch.dict(os.environ, {
            "CYBERCHECK_ENV": "development", "RENDER_SERVICE_ID": "", "DATABASE_URL": "",
            "COOKIE_SECURE": "false", "AGENT_INSTALLER_PATH": str(installer), "SMTP_HOST": "",
        })
        env.start()
        self.addCleanup(env.stop)
        storage.init_db()
        self.owner = TestClient(main.app)
        self.owner.post("/api/signup", json={"company_name": "Empresa Borrar", "email": "ana@borrar.com",
                                             "password": "contrasena-segura-1"})
        self.device_id, self.headers = self.enroll(self.owner, "PC-VIEJA")

    def enroll(self, client, host):
        token = re.search(r"CyberCheckSetup_([0-9a-f]{32})",
                          client.get("/api/agent/installer").headers["content-disposition"]).group(1)
        device = TestClient(main.app).post("/api/register", json={"registration_code": token, "hostname": host}).json()
        return device["device_id"], {"Authorization": f"Bearer {device['token']}"}

    def populate(self):
        agent = TestClient(main.app)
        response = agent.post("/api/agent/results", headers=self.headers, json={
            "device_id": self.device_id, "scan_type": "FULL_SCAN", "request_id": "delete-scan-0001",
            "evidence": {"firewall": {"domain": True, "private": True, "public": False},
                         "system_info": {"hostname": "PC-VIEJA"}}})
        self.assertEqual(response.status_code, 200, response.text)
        agent.post("/api/agent/events", headers=self.headers, json={"device_id": self.device_id, "events": [{
            "event_key": "evt-0001", "event_type": "usb_connected", "severity": "Medio", "title": "USB",
            "occurred_at": "2026-10-29T10:00:00+00:00"}]})
        self.owner.post("/api/tasks", headers=ORIGIN, json={"device_id": self.device_id, "task_type": "FULL_SCAN"})

    def counts(self):
        with storage.connect() as db:
            tables = ("devices", "findings", "scans", "evidences", "device_events", "tasks", "agent_credentials")
            result = {t: db.execute(f"SELECT COUNT(*) AS n FROM {t} WHERE device_id=?", (self.device_id,)).fetchone()["n"]
                      for t in tables}
            result["history"] = db.execute("SELECT COUNT(*) AS n FROM history").fetchone()["n"]
        return result

    def test_admin_deletes_device_and_all_its_history(self):
        self.populate()
        before = self.counts()
        self.assertTrue(all(before[t] > 0 for t in ("devices", "findings", "scans", "evidences", "device_events", "tasks")))
        response = self.owner.delete(f"/api/devices/{self.device_id}", headers=ORIGIN)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(all(value == 0 for value in self.counts().values()), self.counts())
        self.assertEqual(self.owner.get("/api/dashboard").json()["devices"], [])
        heartbeat = TestClient(main.app).post("/api/agent/heartbeat", headers=self.headers,
                                              json={"device_id": self.device_id, "agent_version": "x"})
        self.assertEqual(heartbeat.status_code, 403, "a deleted device can no longer report")
        events = [e["action"] for e in self.owner.get("/api/audit").json()["events"]]
        self.assertIn("device.delete", events)
        self.assertEqual(self.owner.delete(f"/api/devices/{self.device_id}", headers=ORIGIN).status_code, 404)

    def test_only_admins_of_the_same_company_can_delete(self):
        self.owner.post("/api/users", headers=ORIGIN, json={
            "username": "tec@borrar.com", "password": "contrasena-segura-2", "role": "technician"})
        technician = TestClient(main.app)
        technician.post("/api/login", json={"username": "tec@borrar.com", "password": "contrasena-segura-2"})
        self.assertEqual(technician.delete(f"/api/devices/{self.device_id}", headers=ORIGIN).status_code, 403)

        stranger = TestClient(main.app)
        stranger.post("/api/signup", json={"company_name": "Otra Empresa", "email": "x@otra.com",
                                           "password": "contrasena-segura-3"})
        self.assertEqual(stranger.delete(f"/api/devices/{self.device_id}", headers=ORIGIN).status_code, 404)
        self.assertEqual(self.counts()["devices"], 1)

    def test_reconnect_explains_instead_of_asking_for_commands(self):
        with storage.connect() as db:
            db.execute("UPDATE devices SET last_seen='2000-01-01 00:00:00' WHERE device_id=?", (self.device_id,))
        offline = self.owner.post(f"/api/devices/{self.device_id}/reconnect", headers=ORIGIN).json()
        self.assertEqual(offline["commands"], [])
        self.assertTrue(offline["steps"])
        self.assertIn("se reconecta solo", offline["message"])
        TestClient(main.app).post("/api/agent/heartbeat", headers=self.headers,
                                  json={"device_id": self.device_id, "agent_version": "x"})
        online = self.owner.post(f"/api/devices/{self.device_id}/reconnect", headers=ORIGIN).json()
        self.assertEqual(online["agent_status"], "online")


if __name__ == "__main__":
    unittest.main()
