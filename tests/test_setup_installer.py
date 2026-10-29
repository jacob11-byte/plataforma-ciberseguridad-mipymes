import json
import tempfile
import unittest
from pathlib import Path

from agent import setup_installer
from agent.setup_installer import SetupError, load_enrollment, parse_flags, resolve_config, service_command

ENROLLMENT = {
    "api_url": "https://server.example",
    "registration_code": "codigo-de-registro-largo-123456",
    "company_name": "Empresa",
}


class SetupInstallerTest(unittest.TestCase):
    def write(self, directory, value):
        path = Path(directory) / "enrollment.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_enrollment_with_device_token_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write(directory, {**ENROLLMENT, "device_id": "d", "token": "t"})
            with self.assertRaisesRegex(SetupError, "device_id"):
                load_enrollment(path)

    def test_enrollment_requires_registration_code_and_https(self):
        with tempfile.TemporaryDirectory() as directory:
            no_code = self.write(directory, {"api_url": "https://server.example"})
            with self.assertRaises(SetupError):
                load_enrollment(no_code)
            plain_http = self.write(directory, {**ENROLLMENT, "api_url": "http://server.example"})
            with self.assertRaises(SetupError):
                load_enrollment(plain_http)
            self.assertEqual(load_enrollment(self.write(directory, ENROLLMENT))["company_name"], "Empresa")

    def test_fresh_install_writes_enrollment(self):
        config, reason = resolve_config(None, ENROLLMENT, rejected=lambda _: self.fail("no check"))
        self.assertEqual(reason, "enroll")
        self.assertEqual(config["registration_code"], ENROLLMENT["registration_code"])

    def test_upgrade_keeps_valid_identity(self):
        existing = {"api_url": "https://server.example/", "device_id": "dev", "token": "tok"}
        config, reason = resolve_config(existing, ENROLLMENT, rejected=lambda _: False)
        self.assertEqual(reason, "kept")
        self.assertIs(config, existing)

    def test_rejected_identity_is_re_enrolled(self):
        existing = {"api_url": "https://server.example", "device_id": "dev", "token": "stale"}
        config, reason = resolve_config(existing, ENROLLMENT, rejected=lambda _: True)
        self.assertEqual(reason, "enroll")
        self.assertNotIn("token", config)

    def test_identity_for_another_server_is_replaced(self):
        existing = {"api_url": "https://old.example", "device_id": "dev", "token": "tok"}
        _config, reason = resolve_config(existing, ENROLLMENT, rejected=lambda _: self.fail("no check"))
        self.assertEqual(reason, "enroll")

    def test_flags_accept_windows_and_unix_styles(self):
        self.assertEqual(parse_flags(["/Uninstall", "--quiet", "-PURGE"]), {"uninstall", "quiet", "purge"})

    def test_service_command_quotes_paths_with_spaces(self):
        command = service_command(Path(r"C:\Program Files\CyberCheck\Agent"), Path(r"C:\ProgramData\CyberCheck\agent_config.json"))
        self.assertTrue(command.startswith('"C:\\Program Files\\CyberCheck\\Agent\\CyberCheckService.exe" --config "'))
        self.assertIn(f"--service-name \"{setup_installer.SERVICE_NAME}\"", command)


if __name__ == "__main__":
    unittest.main()
