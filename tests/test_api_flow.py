import os
from pathlib import Path
import tempfile
import unittest

os.environ["CYBERCHECK_DB_PATH"] = str(Path(tempfile.gettempdir()) / "cybercheck_test.db")
os.environ["COOKIE_SECURE"] = "false"
os.environ["AGENT_REGISTRATION_CODE"] = "test-register-code"

from fastapi.testclient import TestClient

from app.main import app
from app.storage import DB_PATH, init_db


class ApiFlowTest(unittest.TestCase):
    def setUp(self):
        if DB_PATH.exists():
            DB_PATH.unlink()
        init_db()
        self.client = TestClient(app)

    def register_agent(self):
        response = self.client.post(
            "/api/register",
            json={
                "registration_code": "test-register-code",
                "company_name": "Empresa Real",
                "hostname": "DESKTOP-REAL",
                "os_version": "Windows-10",
                "windows_edition": "Windows 10 Pro",
                "architecture": "AMD64",
                "ip_address": "192.168.1.10",
                "agent_version": "0.2.0",
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def auth_header(self, token):
        return {"Authorization": f"Bearer {token}"}

    def login(self):
        response = self.client.post("/api/login", json={"username": "admin", "password": "admin123"})
        self.assertEqual(response.status_code, 200, response.text)

    def test_agent_registration_heartbeat_and_dashboard(self):
        registered = self.register_agent()
        self.assertEqual(len(registered["device_id"].split("-")), 5)
        self.assertTrue(registered["token"])

        heartbeat = self.client.post(
            "/api/agent/heartbeat",
            headers=self.auth_header(registered["token"]),
            json={"device_id": registered["device_id"], "agent_version": "0.2.0"},
        )
        self.assertEqual(heartbeat.status_code, 200, heartbeat.text)

        self.login()
        dashboard = self.client.get("/api/dashboard")
        self.assertEqual(dashboard.status_code, 200, dashboard.text)
        data = dashboard.json()
        self.assertEqual(data["summary"]["devices"], 1)
        self.assertNotIn("token", data["devices"][0])

    def test_invalid_agent_auth_is_rejected(self):
        registered = self.register_agent()
        response = self.client.post(
            "/api/agent/heartbeat",
            headers=self.auth_header("bad-token"),
            json={"device_id": registered["device_id"], "agent_version": "0.2.0"},
        )
        self.assertEqual(response.status_code, 403)

    def test_full_scan_duplicate_close_and_reopen(self):
        registered = self.register_agent()
        insecure = {
            "system_info": {"hostname": "DESKTOP-REAL", "windows_edition": "Windows 10 Pro", "architecture": "AMD64"},
            "firewall": {"domain": True, "private": True, "public": False},
        }
        for _ in range(2):
            response = self.client.post(
                "/api/agent/results",
                headers=self.auth_header(registered["token"]),
                json={"device_id": registered["device_id"], "scan_type": "FULL_SCAN", "evidence": insecure},
            )
            self.assertEqual(response.status_code, 200, response.text)

        self.login()
        data = self.client.get("/api/dashboard").json()
        firewall_findings = [item for item in data["findings"] if item["rule_id"] == "FIREWALL_PUBLIC_DISABLED"]
        self.assertEqual(len(firewall_findings), 1)
        self.assertEqual(firewall_findings[0]["status"], "open")

        secure = {"firewall": {"domain": True, "private": True, "public": True}}
        response = self.client.post(
            "/api/agent/results",
            headers=self.auth_header(registered["token"]),
            json={"device_id": registered["device_id"], "scan_type": "VERIFY_FIREWALL", "evidence": secure},
        )
        self.assertEqual(response.status_code, 200, response.text)
        data = self.client.get("/api/dashboard").json()
        firewall_findings = [item for item in data["findings"] if item["rule_id"] == "FIREWALL_PUBLIC_DISABLED"]
        self.assertEqual(firewall_findings[0]["status"], "resolved")

        response = self.client.post(
            "/api/agent/results",
            headers=self.auth_header(registered["token"]),
            json={"device_id": registered["device_id"], "scan_type": "VERIFY_FIREWALL", "evidence": insecure},
        )
        self.assertEqual(response.status_code, 200, response.text)
        data = self.client.get("/api/dashboard").json()
        firewall_findings = [item for item in data["findings"] if item["rule_id"] == "FIREWALL_PUBLIC_DISABLED"]
        self.assertEqual(firewall_findings[0]["status"], "reopened")

    def test_unknown_task_is_rejected(self):
        registered = self.register_agent()
        self.login()
        response = self.client.post(
            "/api/tasks",
            json={"device_id": registered["device_id"], "task_type": "RUN_POWERSHELL", "parameters": {}},
        )
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
