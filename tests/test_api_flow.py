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

    def test_device_detail_keeps_status_evidence_and_scan_metadata(self):
        registered = self.register_agent()
        evidence = {
            "timestamp": "2026-08-07T00:00:00+00:00",
            "agent_version": "0.2.0",
            "system_info": {"hostname": "DESKTOP-REAL", "windows_edition": "Windows 10 Pro", "architecture": "AMD64"},
            "firewall": {"domain": True, "private": True, "public": True},
            "antivirus": {"enabled": True, "real_time": True, "signature_age_days": 0, "quick_scan_age_days": 1, "active_threat_count": 0},
            "scan_metadata": {"duration_ms": 1200, "modules_success": 2, "modules_error": 0, "modules": []},
        }
        response = self.client.post(
            "/api/agent/results",
            headers=self.auth_header(registered["token"]),
            json={"device_id": registered["device_id"], "scan_type": "FULL_SCAN", "evidence": evidence},
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.login()
        detail = self.client.get(f"/api/devices/{registered['device_id']}/detail")
        self.assertEqual(detail.status_code, 200, detail.text)
        data = detail.json()
        self.assertEqual(data["summary"]["last_scan_duration_ms"], 1200)
        self.assertEqual(data["summary"]["modules_success"], 2)
        self.assertIn("firewall", data["controls"])
        statuses = {item["control"]: item["status"] for item in data["control_matrix"]}
        self.assertEqual(statuses["firewall"], "PASS")
        self.assertEqual(statuses["antivirus"], "PASS")

    def test_agent_gets_up_to_ten_pending_tasks(self):
        registered = self.register_agent()
        self.login()
        for task_type in ["VERIFY_FIREWALL", "VERIFY_PORTS", "VERIFY_ANTIVIRUS", "VERIFY_UPDATES", "VERIFY_BACKUP"]:
            response = self.client.post(
                "/api/tasks",
                json={"device_id": registered["device_id"], "task_type": task_type, "parameters": {}},
            )
            self.assertEqual(response.status_code, 200, response.text)
        response = self.client.get(
            f"/api/agent/tasks?device_id={registered['device_id']}&max_tasks=10",
            headers=self.auth_header(registered["token"]),
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(len(response.json()["tasks"]), 5)

    def test_disconnect_device_disables_agent_token_and_cancels_pending_tasks(self):
        registered = self.register_agent()
        self.login()
        task = self.client.post(
            "/api/tasks",
            json={"device_id": registered["device_id"], "task_type": "VERIFY_FIREWALL", "parameters": {}},
        )
        self.assertEqual(task.status_code, 200, task.text)
        disconnected = self.client.post(f"/api/devices/{registered['device_id']}/disconnect")
        self.assertEqual(disconnected.status_code, 200, disconnected.text)

        heartbeat = self.client.post(
            "/api/agent/heartbeat",
            headers=self.auth_header(registered["token"]),
            json={"device_id": registered["device_id"], "agent_version": "0.2.0"},
        )
        self.assertEqual(heartbeat.status_code, 403)

        detail = self.client.get(f"/api/devices/{registered['device_id']}/detail")
        self.assertEqual(detail.status_code, 200, detail.text)
        data = detail.json()
        self.assertEqual(data["device"]["agent_status"], "disconnected")
        self.assertEqual(data["tasks"][0]["status"], "canceled")

        reactivated = self.client.post(f"/api/devices/{registered['device_id']}/reactivate")
        self.assertEqual(reactivated.status_code, 200, reactivated.text)
        heartbeat = self.client.post(
            "/api/agent/heartbeat",
            headers=self.auth_header(registered["token"]),
            json={"device_id": registered["device_id"], "agent_version": "0.2.0"},
        )
        self.assertEqual(heartbeat.status_code, 200, heartbeat.text)

    def test_v2_snapshot_and_diff_are_persisted(self):
        registered = self.register_agent()
        base = {
            "system_info": {"hostname": "DESKTOP-REAL", "windows_edition": "Windows 10 Pro", "architecture": "AMD64"},
            "system_inventory_v2": {"success": True, "data": {"hostname": "DESKTOP-REAL", "model": "Model A"}, "error": None, "duration_ms": 10, "collected_at": "2026-08-07T00:00:00+00:00"},
            "security_controls": {"success": True, "data": {"secure_boot": True}, "error": None, "duration_ms": 10, "collected_at": "2026-08-07T00:00:00+00:00"},
            "scan_metadata": {"duration_ms": 20, "modules_success": 2, "modules_error": 0, "modules": []},
        }
        changed = {
            **base,
            "system_inventory_v2": {"success": True, "data": {"hostname": "DESKTOP-REAL", "model": "Model B"}, "error": None, "duration_ms": 10, "collected_at": "2026-08-07T00:01:00+00:00"},
        }
        for evidence in [base, changed]:
            response = self.client.post(
                "/api/agent/results",
                headers=self.auth_header(registered["token"]),
                json={"device_id": registered["device_id"], "scan_type": "V2_SNAPSHOT", "evidence": evidence},
            )
            self.assertEqual(response.status_code, 200, response.text)
        self.login()
        detail = self.client.get(f"/api/devices/{registered['device_id']}/detail")
        self.assertEqual(detail.status_code, 200, detail.text)
        data = detail.json()
        self.assertEqual(len(data["snapshots"]), 2)
        self.assertEqual(len(data["diffs"]), 1)
        self.assertIn("system_inventory_v2", data["controls"])

    def test_v2_tasks_are_whitelisted(self):
        registered = self.register_agent()
        self.login()
        response = self.client.post(
            "/api/tasks",
            json={"device_id": registered["device_id"], "task_type": "V2_SNAPSHOT", "parameters": {}},
        )
        self.assertEqual(response.status_code, 200, response.text)


if __name__ == "__main__":
    unittest.main()
