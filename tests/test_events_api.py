import os
import re
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import alerts, main, storage

ORIGIN = {"Origin": "http://testserver"}


def event(key, severity="Medio", title="Evento de prueba"):
    return {"event_key": key, "event_type": "usb_connected", "severity": severity, "title": title,
            "detail": "detalle", "occurred_at": "2026-10-29T10:00:00+00:00", "data": {"k": 1}}


class EventsApiTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        patcher = patch.object(storage, "DB_PATH", Path(self.directory.name) / "events.db")
        patcher.start()
        self.addCleanup(patcher.stop)
        installer = Path(self.directory.name) / "CyberCheckSetup.exe"
        installer.write_bytes(b"MZ")
        env = patch.dict(os.environ, {
            "CYBERCHECK_ENV": "development", "RENDER_SERVICE_ID": "", "DATABASE_URL": "",
            "COOKIE_SECURE": "false", "AGENT_INSTALLER_PATH": str(installer), "SMTP_HOST": "",
        })
        env.start()
        self.addCleanup(env.stop)
        storage.init_db()
        main._event_email_last.clear()
        self.alice = self.company("alice@a.com", "Empresa A", "PC-A")
        self.bob = self.company("bob@b.com", "Empresa B", "PC-B")

    def company(self, email, name, host):
        client = TestClient(main.app)
        client.post("/api/signup", json={"company_name": name, "email": email, "password": "contrasena-segura-1"})
        header = client.get("/api/agent/installer").headers["content-disposition"]
        token = re.search(r"CyberCheckSetup_([0-9a-f]{32})", header).group(1)
        device = TestClient(main.app).post("/api/register", json={"registration_code": token, "hostname": host}).json()
        return {"client": client, "device_id": device["device_id"], "headers": {"Authorization": f"Bearer {device['token']}"}}

    def push(self, company, events, headers=None):
        return TestClient(main.app).post("/api/agent/events", headers=company["headers"] if headers is None else headers, json={
            "device_id": company["device_id"], "events": events})

    def test_ingest_dedupes_and_validates(self):
        first = self.push(self.alice, [event("k-0001"), event("k-0002")])
        self.assertEqual(first.json(), {"accepted": 2, "duplicates": 0})
        self.assertEqual(self.push(self.alice, [event("k-0001"), event("k-0003")]).json(), {"accepted": 1, "duplicates": 1})
        bad = self.push(self.alice, [{**event("k-0004"), "severity": "Apocaliptico"}])
        self.assertEqual(bad.status_code, 422)
        self.assertEqual(self.push(self.alice, []).status_code, 422)
        self.assertEqual(self.push(self.alice, [event("k-0005")], headers={"Authorization": "Bearer nope"}).status_code, 403)
        self.assertEqual(self.push(self.alice, [event("k-0006")], headers={}).status_code, 401)

    def test_other_device_token_cannot_write_here(self):
        response = self.push(self.alice, [event("k-9999")], headers=self.bob["headers"])
        self.assertEqual(response.status_code, 403)

    def test_feed_is_company_scoped_and_incremental(self):
        self.push(self.alice, [event("a-0001", "Alto", "uno"), event("a-0002", "Critico", "dos")])
        feed = self.alice["client"].get("/api/events").json()
        self.assertEqual([e["title"] for e in feed["events"]], ["dos", "uno"], "newest first")
        self.assertEqual(feed["events"][0]["device_name"], "PC-A")
        self.assertEqual(feed["events"][0]["data"], {"k": 1})
        self.assertNotIn("event_key", feed["events"][0])
        self.assertEqual(self.bob["client"].get("/api/events").json()["events"], [])

        latest = feed["latest_id"]
        self.assertEqual(self.alice["client"].get(f"/api/events?after_id={latest}").json()["events"], [])
        self.push(self.alice, [event("a-0003", "Medio", "tres")])
        newer = self.alice["client"].get(f"/api/events?after_id={latest}").json()
        self.assertEqual([e["title"] for e in newer["events"]], ["tres"])

    def test_device_filter_respects_tenancy(self):
        self.push(self.alice, [event("a-0100")])
        mine = self.alice["client"].get(f"/api/events?device_id={self.alice['device_id']}")
        self.assertEqual(len(mine.json()["events"]), 1)
        theirs = self.bob["client"].get(f"/api/events?device_id={self.alice['device_id']}")
        self.assertEqual(theirs.status_code, 404)
        self.assertEqual(TestClient(main.app).get("/api/events").status_code, 401)

    def test_storage_is_bounded_per_device(self):
        with patch.object(main, "EVENTS_KEPT_PER_DEVICE", 5):
            for start in range(0, 8, 4):
                self.push(self.alice, [event(f"b-{start + n:04d}") for n in range(4)])
        with storage.connect() as db:
            kept = [row["event_key"] for row in db.execute("SELECT event_key FROM device_events ORDER BY id").fetchall()]
        self.assertEqual(len(kept), 5)
        self.assertEqual(kept[-1], "b-0007")

    def test_serious_events_email_admins_with_throttle(self):
        sent = []
        with patch.dict(os.environ, {"SMTP_HOST": "smtp.example.test"}), \
             patch.object(alerts, "deliver", side_effect=lambda m: sent.append(m) or True):
            self.push(self.alice, [event("m-0001", "Medio")])
            self.assertEqual(sent, [], "medium events never email")
            self.push(self.alice, [event("m-0002", "Critico", "Registro borrado")])
            for thread in threading.enumerate():
                if thread.name == "cybercheck-alert":
                    thread.join(5)
            self.assertEqual(len(sent), 1)
            self.assertEqual(sent[0]["To"], "alice@a.com")
            self.assertIn("Registro borrado", sent[0].get_content())
            self.push(self.alice, [event("m-0003", "Critico", "Otro")])
            self.assertEqual(len(sent), 1, "throttled inside the interval")

    def test_events_keep_the_device_online(self):
        with storage.connect() as db:
            db.execute("UPDATE devices SET last_seen='2000-01-01 00:00:00', offline_alerted=?", (True,))
        self.push(self.alice, [event("o-0001")])
        with storage.connect() as db:
            row = db.execute("SELECT last_seen, offline_alerted FROM devices WHERE device_id=?", (self.alice["device_id"],)).fetchone()
        self.assertGreater(str(row["last_seen"]), "2020")
        self.assertFalse(row["offline_alerted"])


if __name__ == "__main__":
    unittest.main()
