import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import main, storage


class RetentionTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        patcher = patch.object(storage, "DB_PATH", Path(self.directory.name) / "retention.db")
        patcher.start()
        self.addCleanup(patcher.stop)
        env = patch.dict(os.environ, {
            "CYBERCHECK_ENV": "development", "RENDER_SERVICE_ID": "", "DATABASE_URL": "",
            "COOKIE_SECURE": "false", "AGENT_REGISTRATION_CODE": "retention-code-123",
        })
        env.start()
        self.addCleanup(env.stop)
        storage.init_db()

    def test_old_evidence_is_pruned_but_last_state_of_each_control_survives(self):
        client = TestClient(main.app)
        device = client.post("/api/register", json={
            "registration_code": "retention-code-123", "company_name": "Empresa Retencion", "hostname": "PC-RET",
        }).json()
        headers = {"Authorization": f"Bearer {device['token']}"}

        def send(index, evidence):
            response = client.post("/api/agent/results", headers=headers, json={
                "device_id": device["device_id"], "scan_type": "FULL_SCAN",
                "evidence": evidence, "request_id": f"scan-{index:04d}-retention",
            })
            self.assertEqual(response.status_code, 200, response.text)

        # Backup is only ever reported by the very first scan.
        send(0, {"firewall": {"domain": True, "private": True, "public": True},
                 "backup": {"exists": True, "path": "C:\\B", "days_since_last_backup": 1, "latest_size": 5}})
        for index in range(1, main.SCANS_WITH_EVIDENCE + 10):
            send(index, {"firewall": {"domain": True, "private": True, "public": True}})

        with storage.connect() as db:
            scans = db.execute("SELECT COUNT(*) AS n FROM scans").fetchone()["n"]
            firewall_scans = db.execute(
                "SELECT COUNT(DISTINCT scan_id) AS n FROM evidences WHERE control='status_firewall'"
            ).fetchone()["n"]
            backup = db.execute("SELECT COUNT(*) AS n FROM evidences WHERE control='status_backup'").fetchone()["n"]
        self.assertEqual(scans, main.SCANS_WITH_EVIDENCE + 10)
        self.assertEqual(firewall_scans, main.SCANS_WITH_EVIDENCE)
        self.assertEqual(backup, 1, "the last known backup state must not be pruned")


if __name__ == "__main__":
    unittest.main()
