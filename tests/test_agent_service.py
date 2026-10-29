import json
import os
import tempfile
import threading
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from agent import windows_agent
from agent.outbox import Outbox
from agent.public_status import read_public_status, sanitize_status
from agent.windows_service import run_agent_cycle, run_service_worker
from agent.windows_tray import status_summary


class AgentOutboxTest(unittest.TestCase):
    def test_outbox_deduplicates_request_and_never_stores_token(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "outbox.db"
            outbox = Outbox(path)
            payload = {
                "device_id": "device-1",
                "scan_type": "FULL_SCAN",
                "evidence": {"system_info": {"hostname": "pc"}},
                "request_id": "request-123",
                "task_id": None,
            }
            self.assertTrue(outbox.enqueue("request-123", payload))
            self.assertFalse(outbox.enqueue("request-123", payload))
            self.assertEqual(outbox.stats(), {"pending": 1, "dead": 0})
            stored = list(outbox.ready())[0]
            self.assertEqual(stored.payload, payload)
            with self.assertRaisesRegex(ValueError, "credenciales"):
                outbox.enqueue("request-456", {**payload, "request_id": "request-456", "token": "secret"})

    def test_send_scan_queues_transient_failure_and_flushes_later(self):
        config = {
            "api_url": "https://server.example",
            "device_id": "device-1",
            "token": "secret",
        }
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.dict(os.environ, {"CYBERCHECK_DATA_DIR": directory}), \
             mock.patch.object(windows_agent, "collect_evidence", return_value={"system_info": {}}), \
             mock.patch.object(
                 windows_agent,
                 "request_json",
                 side_effect=urllib.error.URLError("offline"),
             ):
            result = windows_agent.send_scan(config, "FULL_SCAN", request_id="request-offline")
            self.assertTrue(result["queued"])
            self.assertEqual(Outbox().stats()["pending"], 1)

            with mock.patch.object(windows_agent, "request_json", return_value={"scan_id": 1}):
                flushed = windows_agent.flush_outbox(config)
            self.assertEqual(flushed, {"sent": 1, "pending": 0, "dead": 0})

    def test_flush_resends_without_task_when_task_no_longer_accepts_results(self):
        config = {"api_url": "https://server.example", "device_id": "device-1", "token": "secret"}
        payload = {
            "device_id": "device-1",
            "scan_type": "FULL_SCAN",
            "evidence": {},
            "request_id": "task-id:9",
            "task_id": 9,
        }
        conflict = urllib.error.HTTPError("https://server.example", 409, "Conflict", {}, None)
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.dict(os.environ, {"CYBERCHECK_DATA_DIR": directory}):
            Outbox().enqueue("task-id:9", payload)
            with mock.patch.object(
                windows_agent, "request_json", side_effect=[conflict, {"scan_id": 3}]
            ) as request:
                flushed = windows_agent.flush_outbox(config)
        self.assertEqual(flushed, {"sent": 1, "pending": 0, "dead": 0})
        self.assertIsNone(request.call_args.args[3]["task_id"])
        self.assertEqual(request.call_args.args[3]["request_id"], "task-id:9")

    def test_queued_task_is_not_marked_complete_before_delivery(self):
        config = {"api_url": "https://server.example", "device_id": "device-1", "token": "secret"}
        task = {"id": 7, "task_type": "FULL_SCAN"}
        with mock.patch.object(windows_agent, "flush_outbox", return_value={"sent": 0, "pending": 0, "dead": 0}), \
             mock.patch.object(windows_agent, "send_heartbeat"), \
             mock.patch.object(windows_agent, "request_json", return_value={"tasks": [task]}) as request, \
             mock.patch.object(windows_agent, "send_scan", return_value={"queued": True}):
            windows_agent.poll_once(config)
        self.assertEqual(request.call_count, 1)
        self.assertEqual(request.call_args.args[0], "GET")


class AgentCredentialRotationTest(unittest.TestCase):
    def test_rotation_persists_new_token_without_runtime_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "agent.json"
            config = {
                "api_url": "https://server.example",
                "device_id": "device-1",
                "token": "old-token",
                "_config_path": str(config_path),
            }
            config_path.write_text(json.dumps(config), encoding="utf-8")
            with mock.patch.object(windows_agent, "request_json", return_value={"token": "n" * 43}):
                self.assertTrue(windows_agent.rotate_credential(config))
            stored = json.loads(config_path.read_text(encoding="utf-8"))
        self.assertEqual(config["token"], "n" * 43)
        self.assertEqual(stored["token"], "n" * 43)
        self.assertNotIn("_config_path", stored)

    def test_failed_write_keeps_old_token(self):
        config = {
            "api_url": "https://server.example",
            "device_id": "device-1",
            "token": "old-token",
            "_config_path": "unused.json",
        }
        with mock.patch.object(windows_agent, "request_json", return_value={"token": "n" * 43}), \
             mock.patch.object(windows_agent, "write_agent_config", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                windows_agent.rotate_credential(config)
        self.assertEqual(config["token"], "old-token")

    def test_poll_rotates_when_heartbeat_requests_it(self):
        config = {"api_url": "https://server.example", "device_id": "device-1", "token": "secret"}
        with mock.patch.object(windows_agent, "flush_outbox", return_value={"sent": 0, "pending": 0, "dead": 0}), \
             mock.patch.object(windows_agent, "send_heartbeat", return_value={"rotate_credential": True}), \
             mock.patch.object(windows_agent, "rotate_credential") as rotate, \
             mock.patch.object(windows_agent, "request_json", return_value={"tasks": []}):
            windows_agent.poll_once(config)
        rotate.assert_called_once_with(config)


class AgentServiceTest(unittest.TestCase):
    def test_revoked_device_is_reported_distinctly(self):
        config = {
            "api_url": "https://server.example",
            "device_id": "device-1",
            "token": "top-secret",
            "_config_path": "agent.json",
        }
        forbidden = urllib.error.HTTPError("https://server.example", 403, "Forbidden", {}, None)
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.dict(os.environ, {"CYBERCHECK_DATA_DIR": directory}), \
             mock.patch("agent.windows_service.ensure_registered"), \
             mock.patch("agent.windows_service.poll_once", side_effect=forbidden):
            status = run_agent_cycle(config)
        self.assertEqual(status["connectivity"], "revoked")
        self.assertIn("desconectado", status_summary(status))

    def test_service_cycle_writes_sanitized_public_status(self):
        config = {
            "api_url": "https://server.example",
            "device_id": "device-1",
            "token": "top-secret",
            "_config_path": "agent.json",
        }
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.dict(os.environ, {"CYBERCHECK_DATA_DIR": directory}), \
             mock.patch("agent.windows_service.ensure_registered"), \
             mock.patch("agent.windows_service.poll_once"):
            status = run_agent_cycle(config)
            stored = read_public_status()
        self.assertEqual(status["connectivity"], "online")
        self.assertEqual(stored["connectivity"], "online")
        self.assertNotIn("token", stored)
        self.assertNotIn("_config_path", stored)

    def test_console_worker_stops_after_one_cycle(self):
        config = {
            "api_url": "http://127.0.0.1:8000",
            "device_id": "device-1",
            "token": "secret",
        }
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "agent.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            with mock.patch.dict(os.environ, {"CYBERCHECK_DATA_DIR": directory}), \
                 mock.patch("agent.windows_service.run_agent_cycle") as cycle:
                result = run_service_worker(config_path, threading.Event(), once=True)
        self.assertEqual(result, 0)
        cycle.assert_called_once()

    def test_public_status_allowlist_and_tray_summary(self):
        clean = sanitize_status({
            "service_state": "running",
            "connectivity": "offline",
            "outbox_pending": 2,
            "token": "must-not-leak",
        })
        self.assertNotIn("token", clean)
        self.assertIn("2 resultado(s) en cola", status_summary(clean))


if __name__ == "__main__":
    unittest.main()
