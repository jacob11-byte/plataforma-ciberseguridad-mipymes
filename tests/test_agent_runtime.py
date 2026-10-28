import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from agent import windows_agent
from agent.core import powershell


class AgentRuntimeTest(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "Windows process flag")
    def test_powershell_child_uses_no_window_flag(self):
        completed = SimpleNamespace(returncode=0, stdout="true", stderr="")
        with mock.patch.object(powershell.subprocess, "run", return_value=completed) as run:
            self.assertIs(powershell.run_powershell("$true | ConvertTo-Json"), True)
        self.assertEqual(run.call_args.kwargs["creationflags"], subprocess.CREATE_NO_WINDOW)
        self.assertIn("-NonInteractive", run.call_args.args[0])

    def test_failed_collectors_preserve_error(self):
        failure = {"error": "Access denied"}
        with mock.patch.object(windows_agent, "os", SimpleNamespace(name="nt")), \
             mock.patch.object(windows_agent, "run_powershell", return_value=failure):
            collectors = (
                windows_agent.collect_firewall,
                windows_agent.collect_ports,
                lambda: windows_agent.collect_services(["TermService"]),
                windows_agent.collect_admins,
                windows_agent.collect_updates,
                windows_agent.collect_antivirus,
                windows_agent.collect_connected_devices,
            )
            for collector in collectors:
                with self.subTest(collector=collector):
                    result = collector()
                    self.assertIsInstance(result, dict)
                    self.assertEqual(result["status"], "error")
                    self.assertIn("Access denied", result["error"])

    def test_firewall_requires_all_three_profiles(self):
        with mock.patch.object(windows_agent, "os", SimpleNamespace(name="nt")), \
             mock.patch.object(windows_agent, "run_powershell", return_value={"Name": "Public", "Enabled": True}):
            self.assertEqual(windows_agent.collect_firewall()["status"], "error")

    def test_windows_numeric_enums_are_interpreted_correctly(self):
        profiles = [
            {"Name": "Domain", "Enabled": 1},
            {"Name": "Private", "Enabled": 1},
            {"Name": "Public", "Enabled": 0},
        ]
        with mock.patch.object(windows_agent, "os", SimpleNamespace(name="nt")), \
             mock.patch.object(windows_agent, "run_powershell", return_value=profiles):
            self.assertEqual(windows_agent.collect_firewall()["public"], False)

        service = {"Name": "TermService", "Status": 4, "StartType": 2}
        with mock.patch.object(windows_agent, "os", SimpleNamespace(name="nt")), \
             mock.patch.object(windows_agent, "run_powershell", return_value=service):
            self.assertEqual(windows_agent.collect_services(["TermService"]), [{
                "name": "TermService", "status": "Running", "start_type": "Automatic", "running": True,
            }])

    def test_poll_once_does_not_send_duplicate_heartbeat(self):
        config = {"api_url": "http://127.0.0.1:8000", "device_id": "dev1", "token": "secret"}
        with mock.patch.object(sys, "argv", ["agent", "--poll-once"]), \
             mock.patch.object(Path, "read_text", return_value=json.dumps(config)), \
             mock.patch.object(windows_agent, "configure_logging"), \
             mock.patch.object(windows_agent, "ensure_registered"), \
             mock.patch.object(windows_agent, "send_heartbeat") as heartbeat, \
             mock.patch.object(windows_agent, "poll_once") as poll:
            self.assertEqual(windows_agent.main(), 0)
        heartbeat.assert_not_called()
        poll.assert_called_once()

    def test_admin_allowlist_is_evidence_only_when_configured(self):
        with mock.patch.object(windows_agent, "system_info", return_value={"hostname": "test"}), \
             mock.patch.object(windows_agent, "collect_admins", return_value=["LocalAdmin"]):
            without = windows_agent.collect_evidence({}, "VERIFY_ADMINISTRATORS")
            with_allowlist = windows_agent.collect_evidence(
                {"authorized_local_admins": ["LocalAdmin"]}, "VERIFY_ADMINISTRATORS"
            )
        self.assertNotIn("authorized_local_admins", without)
        self.assertEqual(with_allowlist["authorized_local_admins"], ["LocalAdmin"])

    def test_log_failure_redacts_credentials(self):
        with mock.patch.object(windows_agent.LOGGER, "error") as log:
            windows_agent.log_failure(
                "request", RuntimeError("token123 code456"),
                {"token": "token123", "registration_code": "code456"},
            )
        message = log.call_args.args[-1]
        self.assertEqual(message, "[REDACTED] [REDACTED]")


if __name__ == "__main__":
    unittest.main()
