import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import main, storage


class SecurityTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.db_patch = patch.object(storage, "DB_PATH", Path(self.directory.name) / "security.db")
        self.db_patch.start()
        self.addCleanup(self.db_patch.stop)
        self.env_patch = patch.dict(os.environ, {
            "CYBERCHECK_ENV": "development",
            "RENDER_SERVICE_ID": "",
            "DATABASE_URL": "",
            "COOKIE_SECURE": "false",
            "ADMIN_USERNAME": "admin",
            "ADMIN_PASSWORD": "admin123",
            "SESSION_SECRET": "",
            "AGENT_REGISTRATION_CODE": "test-registration-code",
        })
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)
        storage.init_db()
        self.client = TestClient(main.app)

    def register(self, code="test-registration-code"):
        return self.client.post("/api/register", json={
            "registration_code": code,
            "company_name": "Empresa Seguridad",
            "hostname": "VM-TEST",
        })

    def test_new_agent_token_is_hashed_at_rest_and_still_authenticates(self):
        response = self.register()
        self.assertEqual(response.status_code, 200, response.text)
        data = response.json()
        with storage.connect() as db:
            device = db.execute("SELECT token FROM devices WHERE device_id=?", (data["device_id"],)).fetchone()
            credential = db.execute("SELECT token FROM agent_credentials WHERE device_id=?", (data["device_id"],)).fetchone()
        self.assertEqual(device["token"], storage.hash_agent_token(data["token"]))
        self.assertEqual(credential["token"], device["token"])
        self.assertNotIn(data["token"], str(device))
        heartbeat = self.client.post("/api/agent/heartbeat", headers={"Authorization": f"Bearer {data['token']}"}, json={
            "device_id": data["device_id"], "agent_version": "test",
        })
        self.assertEqual(heartbeat.status_code, 200, heartbeat.text)

    def test_legacy_plaintext_token_is_migrated_without_reenrollment(self):
        with storage.connect() as db:
            company_id = storage.insert_returning_id(db, "INSERT INTO companies(name) VALUES (?)", ("Legado",))
            db.execute("INSERT INTO devices(device_id, company_id, name, token) VALUES (?, ?, ?, ?)",
                       ("legacy-device", company_id, "Legacy", "legacy-secret-token"))
            db.execute("INSERT INTO agent_credentials(device_id, token) VALUES (?, ?)",
                       ("legacy-device", "legacy-secret-token"))
        storage.init_db()
        with storage.connect() as db:
            token = db.execute("SELECT token FROM agent_credentials WHERE device_id=?", ("legacy-device",)).fetchone()["token"]
        self.assertEqual(token, storage.hash_agent_token("legacy-secret-token"))
        heartbeat = self.client.post("/api/agent/heartbeat", headers={"Authorization": "Bearer legacy-secret-token"}, json={
            "device_id": "legacy-device", "agent_version": "legacy",
        })
        self.assertEqual(heartbeat.status_code, 200, heartbeat.text)

    def test_registration_is_rate_limited_even_when_code_is_correct(self):
        for _ in range(main.REGISTRATION_ATTEMPT_LIMIT):
            self.assertEqual(self.register("wrong-code").status_code, 403)
        blocked = self.register()
        self.assertEqual(blocked.status_code, 429)
        self.assertIn("Retry-After", blocked.headers)

    def test_login_is_rate_limited(self):
        for _ in range(main.LOGIN_ATTEMPT_LIMIT):
            failed = self.client.post("/api/login", json={"username": "admin", "password": "incorrect"})
            self.assertEqual(failed.status_code, 401)
        blocked = self.client.post("/api/login", json={"username": "admin", "password": "admin123"})
        self.assertEqual(blocked.status_code, 429)
        self.assertIn("Retry-After", blocked.headers)

    def test_cross_site_mutation_is_rejected_without_blocking_panel(self):
        self.assertEqual(self.client.post("/api/login", json={"username": "admin", "password": "admin123"}).status_code, 200)
        cross_site = self.client.post("/api/ai/company-chat", headers={"Origin": "https://evil.example"}, json={"question": "Estado actual"})
        self.assertEqual(cross_site.status_code, 403)
        same_site = self.client.post("/api/ai/company-chat", headers={"Origin": "http://testserver"}, json={"question": "Estado actual"})
        self.assertEqual(same_site.status_code, 200, same_site.text)

    def test_failed_collection_is_not_displayed_as_pass_and_admin_policy_is_saved(self):
        registered = self.register().json()
        result = self.client.post("/api/agent/results", headers={"Authorization": f"Bearer {registered['token']}"}, json={
            "device_id": registered["device_id"],
            "scan_type": "VERIFY_FIREWALL",
            "evidence": {
                "firewall": {"status": "error", "error": "Access denied"},
                "local_administrators": ["Administrador"],
                "authorized_local_admins": ["Administrador"],
            },
        })
        self.assertEqual(result.status_code, 200, result.text)
        self.assertEqual(self.client.post("/api/login", json={"username": "admin", "password": "admin123"}).status_code, 200)
        detail = self.client.get(f"/api/devices/{registered['device_id']}/detail").json()
        statuses = {item["control"]: item["status"] for item in detail["control_matrix"]}
        self.assertEqual(statuses["firewall"], "NOT_AVAILABLE")
        self.assertEqual(detail["controls"]["admin_policy"]["data"]["authorized_local_admins"], ["Administrador"])

    def test_production_refuses_example_credentials(self):
        with patch.dict(os.environ, {
            "CYBERCHECK_ENV": "production",
            "ADMIN_PASSWORD": "admin123",
            "SESSION_SECRET": "s" * 40,
            "AGENT_REGISTRATION_CODE": "r" * 32,
            "DATABASE_URL": "postgresql://example.invalid/test",
            "COOKIE_SECURE": "true",
        }):
            with self.assertRaisesRegex(RuntimeError, "ADMIN_PASSWORD"):
                main.validate_security_config()

    def test_development_session_secret_is_separate_from_admin_password(self):
        self.assertNotEqual(main._session_secret(), main._admin_password())
        self.assertEqual(main._session_secret(), main._session_secret())

    def test_existing_database_gets_task_and_idempotency_columns(self):
        legacy_path = Path(self.directory.name) / "legacy-schema.db"
        legacy_db = sqlite3.connect(legacy_path)
        try:
            db = legacy_db
            db.executescript("""
                CREATE TABLE scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    status TEXT NOT NULL
                );
                CREATE TABLE tasks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT NOT NULL,
                    task_type TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    parameters_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    delivered_at TEXT,
                    completed_at TEXT
                );
            """)
            db.commit()
        finally:
            legacy_db.close()
        with patch.object(storage, "DB_PATH", legacy_path):
            storage.init_db()
            with storage.connect() as db:
                scan_columns = set(storage.table_columns(db, "scans"))
                task_columns = set(storage.table_columns(db, "tasks"))
        self.assertTrue({"request_id", "task_id"}.issubset(scan_columns))
        self.assertTrue({"delivery_attempts", "last_error", "result_scan_id"}.issubset(task_columns))


if __name__ == "__main__":
    unittest.main()
