import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import main, storage
from agent.setup_installer import enrollment_token_from_name

ORIGIN = {"Origin": "http://testserver"}


class TenancyTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        db_patch = patch.object(storage, "DB_PATH", Path(self.directory.name) / "tenancy.db")
        db_patch.start()
        self.addCleanup(db_patch.stop)
        installer = Path(self.directory.name) / "CyberCheckSetup.exe"
        installer.write_bytes(b"MZ-fake-installer")
        env_patch = patch.dict(os.environ, {
            "CYBERCHECK_ENV": "development",
            "RENDER_SERVICE_ID": "",
            "DATABASE_URL": "",
            "COOKIE_SECURE": "false",
            "ADMIN_USERNAME": "admin",
            "ADMIN_PASSWORD": "admin123",
            "AGENT_REGISTRATION_CODE": "global-registration-code",
            "AGENT_INSTALLER_PATH": str(installer),
            "GOOGLE_CLIENT_ID": "",
            "GOOGLE_CLIENT_SECRET": "",
        })
        env_patch.start()
        self.addCleanup(env_patch.stop)
        storage.init_db()

    def signup(self, email, company="Empresa", password="contrasena-segura-1", expected=200):
        client = TestClient(main.app)
        response = client.post("/api/signup", json={
            "company_name": company, "email": email, "password": password,
        })
        self.assertEqual(response.status_code, expected, response.text)
        return client

    def enroll(self, client):
        response = client.get("/api/agent/installer")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.content, b"MZ-fake-installer")
        filename = re.search(r'filename="?([^";]+)', response.headers["content-disposition"]).group(1)
        token = enrollment_token_from_name(filename)
        self.assertIsNotNone(token, filename)
        return token

    def register(self, code, company_name="Ignorada"):
        response = TestClient(main.app).post("/api/register", json={
            "registration_code": code, "company_name": company_name, "hostname": "PC-" + code[:6],
        })
        return response

    def test_signup_creates_isolated_admin_account(self):
        client = self.signup("Ana@Empresa.com", company="Ferreteria Ana")
        me = client.get("/api/me").json()
        self.assertEqual(me["username"], "ana@empresa.com")
        self.assertEqual(me["role"], "admin")
        self.assertEqual(me["company_name"], "Ferreteria Ana")
        self.signup("ana@empresa.com", expected=409)
        self.signup("otro@empresa.com", password="corta", expected=400)
        self.signup("no-es-correo", expected=400)
        relogin = TestClient(main.app).post("/api/login", json={
            "username": "ANA@empresa.com", "password": "contrasena-segura-1",
        })
        self.assertEqual(relogin.status_code, 200, relogin.text)

    def test_installer_token_enrolls_into_downloading_company_only(self):
        alice = self.signup("alice@a.com", company="Empresa A")
        bob = self.signup("bob@b.com", company="Empresa B")
        token = self.enroll(alice)
        registered = self.register(token, company_name="Empresa B")
        self.assertEqual(registered.status_code, 200, registered.text)
        device_id = registered.json()["device_id"]

        self.assertEqual([d["device_id"] for d in alice.get("/api/dashboard").json()["devices"]], [device_id])
        self.assertEqual(bob.get("/api/dashboard").json()["devices"], [])
        self.assertEqual(bob.get(f"/api/devices/{device_id}/detail").status_code, 404)
        self.assertEqual(bob.get(f"/api/devices/{device_id}/ai-summary").status_code, 404)
        task = {"device_id": device_id, "task_type": "FULL_SCAN", "parameters": {}}
        self.assertEqual(bob.post("/api/tasks", headers=ORIGIN, json=task).status_code, 404)
        self.assertEqual(bob.post(f"/api/devices/{device_id}/disconnect", headers=ORIGIN).status_code, 404)
        self.assertEqual(alice.post("/api/tasks", headers=ORIGIN, json=task).status_code, 200)

        bob_actions = [event["action"] for event in bob.get("/api/audit").json()["events"]]
        self.assertNotIn("device.register", bob_actions)
        alice_actions = [event["action"] for event in alice.get("/api/audit").json()["events"]]
        self.assertIn("device.register", alice_actions)
        self.assertIn("installer.download", alice_actions)

    def test_users_are_scoped_to_company(self):
        alice = self.signup("alice@a.com", company="Empresa A")
        bob = self.signup("bob@b.com", company="Empresa B")
        created = alice.post("/api/users", headers=ORIGIN, json={
            "username": "tecnico@a.com", "password": "contrasena-segura-2", "role": "technician",
        })
        self.assertEqual(created.status_code, 200, created.text)
        self.assertEqual([u["username"] for u in bob.get("/api/users").json()["users"]], ["bob@b.com"])
        hijack = bob.patch(f"/api/users/{created.json()['id']}", headers=ORIGIN, json={"active": False})
        self.assertEqual(hijack.status_code, 404)

    def test_global_code_never_picks_company_by_name(self):
        alice = self.signup("alice@a.com", company="Empresa A")
        registered = self.register("global-registration-code", company_name="Empresa A")
        self.assertEqual(registered.status_code, 200, registered.text)
        self.assertEqual(alice.get("/api/dashboard").json()["devices"], [])
        admin = TestClient(main.app)
        admin.post("/api/login", json={"username": "admin", "password": "admin123"})
        self.assertEqual(len(admin.get("/api/dashboard").json()["devices"]), 1)

    def test_revoked_or_expired_tokens_are_rejected(self):
        alice = self.signup("alice@a.com", company="Empresa A")
        token = self.enroll(alice)
        self.assertEqual(alice.post("/api/agent/installer/revoke", headers=ORIGIN).json()["revoked"], 1)
        self.assertEqual(self.register(token).status_code, 403)
        expired = self.enroll(alice)
        with storage.connect() as db:
            db.execute("UPDATE enrollment_tokens SET expires_at='2000-01-01 00:00:00'")
        self.assertEqual(self.register(expired).status_code, 403)
        self.assertEqual(self.register("0" * 32).status_code, 403)

    def test_viewer_cannot_download_installer(self):
        alice = self.signup("alice@a.com", company="Empresa A")
        alice.post("/api/users", headers=ORIGIN, json={
            "username": "lector@a.com", "password": "contrasena-segura-2", "role": "viewer",
        })
        viewer = TestClient(main.app)
        viewer.post("/api/login", json={"username": "lector@a.com", "password": "contrasena-segura-2"})
        self.assertEqual(viewer.get("/api/agent/installer").status_code, 403)

    def test_google_sign_in_creates_then_reuses_account(self):
        profile = {"email": "maria@gmail.com", "email_verified": True, "name": "Maria"}
        with patch.dict(os.environ, {"GOOGLE_CLIENT_ID": "id", "GOOGLE_CLIENT_SECRET": "secret"}), \
             patch.object(main, "_google_profile", return_value=profile):
            self.assertTrue(TestClient(main.app).get("/api/auth/providers").json()["google"])
            for _ in range(2):
                client = TestClient(main.app)
                start = client.get("/auth/google/start", follow_redirects=False)
                self.assertEqual(start.status_code, 302)
                state = re.search(r"state=([^&]+)", start.headers["location"]).group(1)
                callback = client.get(f"/auth/google/callback?code=abc&state={state}")
                self.assertEqual(callback.status_code, 200, callback.text)
                me = client.get("/api/me").json()
                self.assertEqual(me["username"], "maria@gmail.com")
                self.assertEqual(me["company_name"], "Empresa de Maria")
        with storage.connect() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"], 1)

    def test_google_rejects_forged_state_and_unverified_email(self):
        with patch.dict(os.environ, {"GOOGLE_CLIENT_ID": "id", "GOOGLE_CLIENT_SECRET": "secret"}):
            client = TestClient(main.app)
            forged = client.get("/auth/google/callback?code=abc&state=forged", follow_redirects=False)
            self.assertEqual(forged.status_code, 302)
            self.assertIn("/login?error=", forged.headers["location"])
            with patch.object(main, "_google_profile", return_value={"email": "x@gmail.com", "email_verified": False}):
                start = client.get("/auth/google/start", follow_redirects=False)
                state = re.search(r"state=([^&]+)", start.headers["location"]).group(1)
                result = client.get(f"/auth/google/callback?code=abc&state={state}", follow_redirects=False)
            self.assertIn("/login?error=", result.headers["location"])

    def test_installer_filename_parsing(self):
        token = "0123456789abcdef0123456789abcdef"
        self.assertEqual(enrollment_token_from_name(f"CyberCheckSetup_{token}.exe"), token)
        self.assertEqual(enrollment_token_from_name(f"CyberCheckSetup_{token} (1).exe"), token)
        self.assertIsNone(enrollment_token_from_name("CyberCheckSetup.exe"))


if __name__ == "__main__":
    unittest.main()
