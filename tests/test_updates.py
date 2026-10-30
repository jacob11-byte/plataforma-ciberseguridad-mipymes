import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from unittest.mock import patch

from fastapi.testclient import TestClient

from agent import setup_installer, windows_agent
from agent.setup_installer import NotLinkedError, SetupError, decide_config, load_enrollment
from app import main, storage


class ServerUpdateOfferTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        patcher = patch.object(storage, "DB_PATH", Path(self.directory.name) / "updates.db")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.installer = Path(self.directory.name) / "CyberCheckSetup.exe"
        self.installer.write_bytes(b"MZ-installer-0.9.0")
        env = patch.dict(os.environ, {
            "CYBERCHECK_ENV": "development", "RENDER_SERVICE_ID": "", "DATABASE_URL": "", "COOKIE_SECURE": "false",
            "AGENT_REGISTRATION_CODE": "update-code-12345678", "AGENT_INSTALLER_PATH": str(self.installer),
            "LATEST_AGENT_VERSION": "0.9.0", "AGENT_AUTO_UPDATE": "true",
        })
        env.start()
        self.addCleanup(env.stop)
        storage.init_db()
        device = TestClient(main.app).post("/api/register", json={
            "registration_code": "update-code-12345678", "hostname": "PC-UPD"}).json()
        self.device_id, self.headers = device["device_id"], {"Authorization": f"Bearer {device['token']}"}

    def heartbeat(self, version):
        return TestClient(main.app).post("/api/agent/heartbeat", headers=self.headers, json={
            "device_id": self.device_id, "agent_version": version}).json()

    def test_outdated_agent_gets_an_offer_with_the_installer_hash(self):
        offer = self.heartbeat("0.8.1")["update"]
        self.assertEqual(offer["version"], "0.9.0")
        self.assertEqual(offer["sha256"], hashlib.sha256(b"MZ-installer-0.9.0").hexdigest())
        self.assertEqual(offer["url"], "/api/agent/update")
        self.assertIsNone(self.heartbeat("0.9.0")["update"])
        self.assertIsNone(self.heartbeat("0.10.0")["update"], "10 > 9: versions compare as numbers")

    def test_update_download_requires_a_device_token(self):
        client = TestClient(main.app)
        response = client.get(f"/api/agent/update?device_id={self.device_id}", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"MZ-installer-0.9.0")
        self.assertEqual(response.headers["x-installer-sha256"], hashlib.sha256(b"MZ-installer-0.9.0").hexdigest())
        denied = client.get(f"/api/agent/update?device_id={self.device_id}", headers={"Authorization": "Bearer nope"})
        self.assertEqual(denied.status_code, 403)

    def test_auto_update_can_be_turned_off(self):
        with patch.dict(os.environ, {"AGENT_AUTO_UPDATE": "false"}):
            self.assertIsNone(self.heartbeat("0.1.0")["update"])

    def test_latest_release_reads_github_and_caches(self):
        payload = {"tag_name": "agent-v0.8.2", "assets": [
            {"name": "otro.zip", "browser_download_url": "x"},
            {"name": "CyberCheckSetup.exe", "browser_download_url": "https://github.com/r/releases/download/agent-v0.8.2/CyberCheckSetup.exe"}]}

        class Response:
            def raise_for_status(self): pass
            def json(self): return payload

        main._release_cache.update({"checked": 0.0, "info": None})
        with patch.dict(os.environ, {"AGENT_INSTALLER_PATH": ""}), patch.object(main.httpx, "get", return_value=Response()) as get:
            first = main._latest_release()
            second = main._latest_release()
        self.assertEqual(first, {"version": "0.8.2", "url": payload["assets"][1]["browser_download_url"]})
        self.assertEqual(second, first)
        self.assertEqual(get.call_count, 1, "cached for an hour")
        main._release_cache.update({"checked": 0.0, "info": None})


class AgentSelfUpdateTest(unittest.TestCase):
    OFFER = {"version": "9.9.9", "sha256": "a" * 64, "url": "/api/agent/update"}

    def config(self, directory):
        path = Path(directory) / "agent_config.json"
        path.write_text("{}", encoding="utf-8")
        return {"api_url": "https://server.example", "device_id": "d", "token": "t", "_config_path": str(path)}

    def run_update(self, config, offer, download_ok=True):
        def fake_download(cfg, url, target, sha):
            target.write_bytes(b"MZ")
            return download_ok

        with patch.object(windows_agent.sys, "frozen", True, create=True), \
             patch.object(windows_agent, "download_update", side_effect=fake_download) as download, \
             patch.object(windows_agent.subprocess, "Popen") as popen:
            result = windows_agent.maybe_self_update(config, offer)
        return result, download, popen

    @unittest.skipUnless(os.name == "nt", "Windows only")
    def test_downloads_verifies_and_launches_silently_once(self):
        with tempfile.TemporaryDirectory() as directory:
            config = self.config(directory)
            result, download, popen = self.run_update(config, self.OFFER)
            self.assertTrue(result)
            args = popen.call_args.args[0]
            self.assertTrue(args[0].endswith("CyberCheckSetup-9.9.9.exe"))
            self.assertEqual(args[1:], ["/quiet", "/update"])
            again, _download, popen_again = self.run_update(config, self.OFFER)
            self.assertFalse(again, "no retry within 6 hours")
            popen_again.assert_not_called()

    @unittest.skipUnless(os.name == "nt", "Windows only")
    def test_rejects_bad_offers_and_failed_downloads(self):
        with tempfile.TemporaryDirectory() as directory:
            config = self.config(directory)
            for offer in ({**self.OFFER, "version": windows_agent.AGENT_VERSION}, {**self.OFFER, "sha256": "short"},
                          {**self.OFFER, "url": "https://evil.example/x.exe"}, None):
                result, download, popen = self.run_update(config, offer)
                self.assertFalse(result, offer)
                popen.assert_not_called()
            result, _download, popen = self.run_update(config, {**self.OFFER, "version": "9.9.10"}, download_ok=False)
            self.assertFalse(result)
            popen.assert_not_called()

    def test_not_frozen_never_updates(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(windows_agent.subprocess, "Popen") as popen:
            self.assertFalse(windows_agent.maybe_self_update(self.config(directory), self.OFFER))
            popen.assert_not_called()

    def test_download_keeps_file_only_when_hash_matches(self):
        body = b"MZ-real-installer"

        class Response:
            def __init__(self): self.chunks = [body, b""]
            def read(self, size): return self.chunks.pop(0)
            def __enter__(self): return self
            def __exit__(self, *args): return False

        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "setup.exe"
            config = {"api_url": "https://server.example", "device_id": "d", "token": "t"}
            with patch.object(windows_agent.urllib.request, "urlopen", return_value=Response()):
                self.assertFalse(windows_agent.download_update(config, "/api/agent/update", target, "0" * 64))
            self.assertFalse(target.exists())
            with patch.object(windows_agent.urllib.request, "urlopen", return_value=Response()):
                self.assertTrue(windows_agent.download_update(
                    config, "/api/agent/update", target, hashlib.sha256(body).hexdigest()))
            self.assertEqual(target.read_bytes(), body)


class InstallerUpgradeTest(unittest.TestCase):
    def test_generic_installer_upgrades_an_enrolled_computer(self):
        existing = {"api_url": "https://server.example", "device_id": "dev", "token": "tok"}
        self.assertEqual(decide_config(existing, None), (existing, "kept"))
        with self.assertRaises(NotLinkedError):
            decide_config({"api_url": "https://server.example"}, None)
        with self.assertRaises(NotLinkedError):
            decide_config(None, None)

    def test_missing_token_is_reported_as_not_linked(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "enrollment.json"
            path.write_text(json.dumps({"api_url": "https://server.example"}), encoding="utf-8")
            with self.assertRaises(NotLinkedError):
                load_enrollment(path)
            self.assertTrue(issubclass(NotLinkedError, SetupError))


if __name__ == "__main__":
    unittest.main()
