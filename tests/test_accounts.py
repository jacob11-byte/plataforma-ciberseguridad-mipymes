import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import main, storage
from app.accounts import hash_password, verify_password

ORIGIN = {"Origin": "http://testserver"}


class AccountsAndCredentialsTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        db_patch = patch.object(storage, "DB_PATH", Path(self.directory.name) / "accounts.db")
        db_patch.start()
        self.addCleanup(db_patch.stop)
        env_patch = patch.dict(os.environ, {
            "CYBERCHECK_ENV": "development",
            "RENDER_SERVICE_ID": "",
            "DATABASE_URL": "",
            "COOKIE_SECURE": "false",
            "ADMIN_USERNAME": "admin",
            "ADMIN_PASSWORD": "admin123",
            "AGENT_REGISTRATION_CODE": "test-registration-code",
        })
        env_patch.start()
        self.addCleanup(env_patch.stop)
        storage.init_db()
        self.admin = self.client_for("admin", "admin123")

    def client_for(self, username, password, expected=200):
        client = TestClient(main.app)
        response = client.post("/api/login", json={"username": username, "password": password})
        self.assertEqual(response.status_code, expected, response.text)
        return client

    def create_user(self, username, role, password="contrasena-segura-1"):
        response = self.admin.post("/api/users", headers=ORIGIN, json={
            "username": username, "password": password, "role": role,
        })
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def register(self):
        response = TestClient(main.app).post("/api/register", json={
            "registration_code": "test-registration-code",
            "company_name": "Empresa Roles",
            "hostname": "PC-ROLES",
        })
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def heartbeat(self, device_id, token):
        return TestClient(main.app).post(
            "/api/agent/heartbeat",
            headers={"Authorization": f"Bearer {token}"},
            json={"device_id": device_id, "agent_version": "test"},
        )

    def test_password_hash_roundtrip(self):
        stored = hash_password("una-clave-larga-123")
        self.assertTrue(stored.startswith("scrypt$"))
        self.assertTrue(verify_password("una-clave-larga-123", stored))
        self.assertFalse(verify_password("otra-clave-larga-123", stored))
        self.assertFalse(verify_password("x", "texto-plano"))

    def test_roles_limit_actions(self):
        device = self.register()
        self.create_user("lector", "viewer")
        self.create_user("tecnico", "technician")
        viewer = self.client_for("lector", "contrasena-segura-1")
        technician = self.client_for("tecnico", "contrasena-segura-1")

        self.assertEqual(viewer.get("/api/me").json()["role"], "viewer")
        self.assertEqual(viewer.get("/api/dashboard").status_code, 200)
        task = {"device_id": device["device_id"], "task_type": "FULL_SCAN", "parameters": {}}
        self.assertEqual(viewer.post("/api/tasks", headers=ORIGIN, json=task).status_code, 403)
        self.assertEqual(technician.post("/api/tasks", headers=ORIGIN, json=task).status_code, 200)
        self.assertEqual(
            technician.post(f"/api/devices/{device['device_id']}/disconnect", headers=ORIGIN).status_code, 403
        )
        self.assertEqual(technician.get("/api/users").status_code, 403)
        self.assertEqual(technician.get("/api/audit").status_code, 403)

        actions = [event["action"] for event in self.admin.get("/api/audit").json()["events"]]
        self.assertIn("task.create", actions)
        self.assertIn("user.create", actions)
        self.assertIn("login.success", actions)

    def test_user_validation_and_reserved_names(self):
        weak = self.admin.post("/api/users", headers=ORIGIN, json={"username": "debil", "password": "corta", "role": "viewer"})
        self.assertEqual(weak.status_code, 400)
        reserved = self.admin.post("/api/users", headers=ORIGIN, json={
            "username": "admin", "password": "contrasena-segura-1", "role": "viewer",
        })
        self.assertEqual(reserved.status_code, 409)
        bad_role = self.admin.post("/api/users", headers=ORIGIN, json={
            "username": "raro", "password": "contrasena-segura-1", "role": "root",
        })
        self.assertEqual(bad_role.status_code, 400)
        listed = self.admin.get("/api/users").json()
        self.assertEqual(listed["users"], [])

    def test_password_change_and_disable_revoke_sessions(self):
        user = self.create_user("operador", "technician")
        session = self.client_for("operador", "contrasena-segura-1")
        self.assertEqual(session.get("/api/me").status_code, 200)

        changed = self.admin.patch(f"/api/users/{user['id']}", headers=ORIGIN, json={"password": "nueva-contrasena-22"})
        self.assertEqual(changed.status_code, 200, changed.text)
        self.assertEqual(session.get("/api/me").status_code, 401)
        self.client_for("operador", "contrasena-segura-1", expected=401)
        fresh = self.client_for("operador", "nueva-contrasena-22")

        disabled = self.admin.patch(f"/api/users/{user['id']}", headers=ORIGIN, json={"active": False})
        self.assertEqual(disabled.status_code, 200, disabled.text)
        self.assertFalse(disabled.json()["active"])
        self.assertEqual(fresh.get("/api/me").status_code, 401)
        self.client_for("operador", "nueva-contrasena-22", expected=401)

    def test_admin_cannot_remove_own_admin_access(self):
        user = self.create_user("jefa", "admin")
        jefa = self.client_for("jefa", "contrasena-segura-1")
        response = jefa.patch(f"/api/users/{user['id']}", headers=ORIGIN, json={"role": "viewer"})
        self.assertEqual(response.status_code, 409)

    def test_credential_rotation_with_grace_period(self):
        device = self.register()
        device_id, old_token = device["device_id"], device["token"]
        self.assertFalse(self.heartbeat(device_id, old_token).json()["rotate_credential"])

        requested = self.admin.post(f"/api/devices/{device_id}/rotate-credential", headers=ORIGIN)
        self.assertEqual(requested.status_code, 200, requested.text)
        self.assertTrue(self.heartbeat(device_id, old_token).json()["rotate_credential"])

        rotated = TestClient(main.app).post(
            "/api/agent/rotate-credential",
            headers={"Authorization": f"Bearer {old_token}"},
            json={"device_id": device_id},
        )
        self.assertEqual(rotated.status_code, 200, rotated.text)
        new_token = rotated.json()["token"]
        self.assertNotEqual(new_token, old_token)

        # Until the new token is used the old one keeps working.
        self.assertEqual(self.heartbeat(device_id, old_token).status_code, 200)
        first_use = self.heartbeat(device_id, new_token)
        self.assertEqual(first_use.status_code, 200)
        self.assertEqual(self.heartbeat(device_id, old_token).status_code, 403)
        self.assertFalse(self.heartbeat(device_id, new_token).json()["rotate_credential"])

        # Reactivation after a disconnect must not revive the retired token.
        self.admin.post(f"/api/devices/{device_id}/disconnect", headers=ORIGIN)
        self.assertEqual(self.heartbeat(device_id, new_token).status_code, 403)
        self.admin.post(f"/api/devices/{device_id}/reactivate", headers=ORIGIN)
        self.assertEqual(self.heartbeat(device_id, new_token).status_code, 200)
        self.assertEqual(self.heartbeat(device_id, old_token).status_code, 403)

    def test_expired_credential_is_rejected(self):
        device = self.register()
        with storage.connect() as db:
            db.execute(
                "UPDATE agent_credentials SET expires_at='2000-01-01 00:00:00' WHERE device_id=?",
                (device["device_id"],),
            )
        self.assertEqual(self.heartbeat(device["device_id"], device["token"]).status_code, 403)

    def test_old_credentials_trigger_rotation(self):
        device = self.register()
        with storage.connect() as db:
            db.execute(
                "UPDATE agent_credentials SET created_at='2000-01-01 00:00:00' WHERE device_id=?",
                (device["device_id"],),
            )
        self.assertTrue(self.heartbeat(device["device_id"], device["token"]).json()["rotate_credential"])


if __name__ == "__main__":
    unittest.main()
