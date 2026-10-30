import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import main, storage

ORIGIN = {"Origin": "http://testserver"}


class TaskProgressTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        patcher = patch.object(storage, "DB_PATH", Path(self.directory.name) / "progress.db")
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
        self.owner = self.company("dueno@progreso.com", "Empresa Progreso")
        token = re.search(r"CyberCheckSetup_([0-9a-f]{32})",
                          self.owner.get("/api/agent/installer").headers["content-disposition"]).group(1)
        registered = TestClient(main.app).post("/api/register", json={"registration_code": token, "hostname": "PC-CAJA"}).json()
        self.device = registered["device_id"]
        self.agent = {"Authorization": f"Bearer {registered['token']}"}

    def company(self, email, name):
        client = TestClient(main.app)
        response = client.post("/api/signup", json={"company_name": name, "email": email, "password": "contrasena-segura-1"})
        self.assertEqual(response.status_code, 200, response.text)
        return client

    def request_scan(self):
        response = self.owner.post("/api/tasks", headers=ORIGIN,
                                   json={"device_id": self.device, "task_type": "FULL_SCAN", "parameters": {}})
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()["task_id"]

    def progress(self, task_id):
        response = self.owner.get(f"/api/tasks/{task_id}")
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def test_progress_follows_the_review_until_it_finishes(self):
        task_id = self.request_scan()
        waiting = self.progress(task_id)
        self.assertEqual(waiting["status"], "pending")
        self.assertEqual(waiting["device_name"], "PC-CAJA")
        self.assertEqual(waiting["expected_seconds"], 150, "default for a computer that was never reviewed")
        self.assertIsNotNone(waiting["waiting_seconds"])
        self.assertIsNone(waiting["running_seconds"])

        TestClient(main.app).get(f"/api/agent/tasks?device_id={self.device}", headers=self.agent)
        running = self.progress(task_id)
        self.assertEqual(running["status"], "delivered")
        self.assertIsNotNone(running["running_seconds"])

        result = TestClient(main.app).post("/api/agent/results", headers=self.agent, json={
            "device_id": self.device, "scan_type": "FULL_SCAN", "task_id": task_id, "request_id": "progress-0001",
            "evidence": {"firewall": {"domain": True, "private": True, "public": True},
                         "scan_metadata": {"duration_ms": 97_400}},
        })
        self.assertEqual(result.status_code, 200, result.text)
        done = self.progress(task_id)
        self.assertEqual(done["status"], "completed")
        self.assertIsNotNone(done["finished_seconds"])

        # The next request estimates with how long this computer really took.
        TestClient(main.app).post(f"/api/agent/tasks/{task_id}/complete", headers=self.agent, json={})
        self.assertEqual(self.progress(self.request_scan())["expected_seconds"], 97)

    def test_failure_reports_the_agent_error(self):
        task_id = self.request_scan()
        TestClient(main.app).get(f"/api/agent/tasks?device_id={self.device}", headers=self.agent)
        TestClient(main.app).post(f"/api/agent/tasks/{task_id}/fail", headers=self.agent,
                                  json={"error": "PowerShell no respondio"})
        failed = self.progress(task_id)
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(failed["error"], "PowerShell no respondio")

    def test_other_companies_and_anonymous_users_cannot_see_it(self):
        task_id = self.request_scan()
        other = self.company("otro@ajena.com", "Empresa Ajena")
        self.assertEqual(other.get(f"/api/tasks/{task_id}").status_code, 404)
        self.assertEqual(TestClient(main.app).get(f"/api/tasks/{task_id}").status_code, 401)
        self.assertEqual(self.owner.get("/api/tasks/999999").status_code, 404)


if __name__ == "__main__":
    unittest.main()
