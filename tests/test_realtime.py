import unittest

from agent import realtime
from agent.realtime import Classifier, EventMonitor, parse_time

T0 = 1_800_000_000.0


def iso_at(offset):
    return realtime.iso(T0 + offset)


def failure(record, user="contabilidad", ip="185.220.101.4", at=0):
    return {"log": "Security", "record_id": str(record), "event_id": 4625, "time_created": iso_at(at),
            "target_user": user, "source_ip": ip, "logon_type": "10"}


def proc(pid, path, created="2026-10-29T10:00:00Z", name="x.exe"):
    return {"pid": pid, "ppid": 4, "name": name, "path": path, "created": created}


def classifier(statuses=None):
    return Classifier(signer=lambda paths: {p: (statuses or {}).get(p, "NotSigned") for p in paths})


class BruteForceTest(unittest.TestCase):
    def test_burst_alerts_once_per_cooldown(self):
        c = classifier()
        events = c.process({"events": [failure(i, at=i) for i in range(6)]}, now=T0 + 10)
        self.assertEqual([e["event_type"] for e in events], ["logon_failure_burst"])
        self.assertEqual(events[0]["severity"], "Alto")
        self.assertIn("6 inicios de sesion fallidos", events[0]["detail"])
        self.assertIn("185.220.101.4", events[0]["detail"])
        self.assertIn("escritorio remoto", events[0]["detail"])
        again = c.process({"events": [failure(100 + i, at=20 + i) for i in range(2)]}, now=T0 + 30)
        self.assertEqual(again, [], "same level inside the cooldown must not repeat")

    def test_heavier_attack_escalates_to_critical(self):
        c = classifier()
        c.process({"events": [failure(i, at=i) for i in range(6)]}, now=T0 + 10)
        events = c.process({"events": [failure(200 + i, at=20 + i) for i in range(16)]}, now=T0 + 40)
        self.assertEqual(events[0]["severity"], "Critico")

    def test_few_failures_and_old_ones_are_ignored(self):
        c = classifier()
        self.assertEqual(c.process({"events": [failure(i, at=i) for i in range(4)]}, now=T0 + 10), [])
        old = c.process({"events": [failure(50 + i, user="otro", at=-1000) for i in range(8)]}, now=T0 + 10)
        self.assertEqual(old, [])

    def test_same_record_is_counted_once(self):
        c = classifier()
        batch = {"events": [failure(1, at=1)] * 8}
        self.assertEqual(c.process(batch, now=T0 + 10), [])


class WindowsEventsTest(unittest.TestCase):
    def classify(self, *rows):
        c = classifier()
        return c.process({"events": [{**row, "record_id": str(i), "time_created": iso_at(i)} for i, row in enumerate(rows)]}, now=T0 + 10)

    def test_account_group_and_log_events(self):
        events = self.classify(
            {"log": "Security", "event_id": 4720, "target_user": "soporte2", "subject_user": "admin"},
            {"log": "Security", "event_id": 4732, "member_sid": "S-1-5-21-1", "group": "Administradores",
             "group_sid": "S-1-5-32-544", "subject_user": "admin"},
            {"log": "Security", "event_id": 4732, "member_sid": "S-1-5-21-2", "group": "Usuarios", "group_sid": "S-1-5-32-545"},
            {"log": "Security", "event_id": 1102, "subject_user": "soporte2"},
        )
        by_type = {e["event_type"]: e for e in events}
        self.assertEqual(set(by_type), {"account_created", "admin_group_change", "log_cleared"})
        self.assertEqual(by_type["log_cleared"]["severity"], "Critico")
        self.assertEqual(by_type["admin_group_change"]["severity"], "Alto")
        self.assertIn("soporte2", by_type["account_created"]["title"])

    def test_service_install_severity(self):
        events = self.classify(
            {"log": "System", "event_id": 7045, "service_name": "bad", "image_path": "C:\\Users\\ana\\AppData\\Local\\Temp\\b.exe", "account": "LocalSystem"},
            {"log": "System", "event_id": 7045, "service_name": "ok", "image_path": '"C:\\Program Files\\App\\a.exe" --config "C:\\ProgramData\\a.json"'},
        )
        self.assertEqual([e["severity"] for e in events], ["Alto", "Medio"])

    def test_defender_events(self):
        events = self.classify(
            {"log": "Defender", "event_id": 1116, "message": "Name: Trojan:Win32/Test"},
            {"log": "Defender", "event_id": 5001, "message": "Real-time protection is disabled."},
        )
        self.assertEqual([(e["severity"], e["title"]) for e in events], [
            ("Critico", "Defender detecto una amenaza"),
            ("Critico", "Proteccion en tiempo real de Defender desactivada")])
        self.assertIn("Trojan:Win32/Test", events[0]["detail"])


class SnapshotDiffTest(unittest.TestCase):
    BASE = {"events": [], "processes": [proc(1, "C:\\Windows\\System32\\svchost.exe")],
            "ports": [{"address": "0.0.0.0", "port": 135, "pid": 1}], "usb": []}

    def test_first_snapshot_only_sets_the_baseline(self):
        c = classifier()
        self.assertEqual(c.process(self.BASE, now=T0), [])

    def test_new_unsigned_process_in_user_folder(self):
        c = classifier()
        c.process(self.BASE, now=T0)
        evil = "C:\\Users\\ana\\AppData\\Local\\Temp\\svchost32.exe"
        snap = {**self.BASE, "processes": self.BASE["processes"] + [proc(99, evil, name="svchost32.exe")]}
        events = c.process(snap, now=T0 + 30)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "process_unsigned_user_path")
        self.assertIn(evil, events[0]["detail"])
        self.assertEqual(c.process(snap, now=T0 + 60), [], "an already-seen process is not reported again")

    def test_signed_or_system_processes_are_quiet(self):
        c = Classifier(signer=lambda paths: {p: "Valid" for p in paths})
        c.process(self.BASE, now=T0)
        snap = {**self.BASE, "processes": self.BASE["processes"] + [
            proc(5, "C:\\Users\\ana\\AppData\\Local\\Google\\chrome.exe"),
            proc(6, "C:\\Program Files\\App\\app.exe")]}
        self.assertEqual(c.process(snap, now=T0 + 30), [])

    def test_new_listening_ports(self):
        c = classifier()
        c.process(self.BASE, now=T0)
        snap = {**self.BASE, "processes": self.BASE["processes"] + [proc(7, "C:\\x\\vnc.exe", name="tvnserver.exe")],
                "ports": self.BASE["ports"] + [
                    {"address": "0.0.0.0", "port": 5900, "pid": 7},
                    {"address": "127.0.0.1", "port": 8080, "pid": 7},
                    {"address": "::", "port": 8443, "pid": 7}]}
        events = c.process(snap, now=T0 + 30)
        self.assertEqual({(e["severity"], e["data"]["port"]) for e in events}, {("Alto", 5900), ("Medio", 8443)})
        self.assertIn("tvnserver.exe", next(e for e in events if e["data"]["port"] == 5900)["detail"])

    def test_new_usb_drive(self):
        c = classifier()
        c.process(self.BASE, now=T0)
        snap = {**self.BASE, "usb": [{"model": "Kingston DataTraveler", "serial": "ABC123", "size": "32000000000"}]}
        events = c.process(snap, now=T0 + 30)
        self.assertEqual(events[0]["event_type"], "usb_connected")
        self.assertIn("32 GB", events[0]["detail"])
        self.assertEqual(c.process(snap, now=T0 + 60), [])

    def test_drive_present_at_start_and_unplugged_later(self):
        c = classifier()
        drive = {"model": "Kingston DataTraveler", "serial": "K1", "size": "32000000000"}
        start = c.process({**self.BASE, "usb": [drive]}, now=T0)
        self.assertEqual([e["event_type"] for e in start], ["usb_connected"])
        self.assertTrue(start[0]["data"]["already_connected"])
        self.assertEqual(c.process({**self.BASE, "usb": [drive]}, now=T0 + 30), [])
        gone = c.process({**self.BASE, "usb": []}, now=T0 + 60)
        self.assertEqual([(e["event_type"], e["severity"]) for e in gone], [("usb_disconnected", "Info")])
        self.assertIn("Kingston", gone[0]["detail"])
        back = c.process({**self.BASE, "usb": [drive]}, now=T0 + 90)
        self.assertEqual([e["event_type"] for e in back], ["usb_connected"])
        self.assertFalse(back[0]["data"]["already_connected"])

    def test_empty_card_reader_is_not_a_usb_drive(self):
        c = classifier()
        c.process(self.BASE, now=T0)
        reader = {"model": "Generic Multi-Card", "serial": "R1", "size": None}
        self.assertEqual(c.process({**self.BASE, "usb": [reader]}, now=T0 + 30), [])
        with_card = {**reader, "size": "16000000000"}
        events = c.process({**self.BASE, "usb": [with_card]}, now=T0 + 60)
        self.assertEqual(events[0]["event_type"], "usb_connected")

    def test_flood_is_capped(self):
        c = classifier()
        c.process(self.BASE, now=T0)
        rows = [{"log": "Security", "record_id": str(i), "event_id": 4720, "target_user": f"u{i}",
                 "time_created": iso_at(i)} for i in range(80)]
        events = c.process({**self.BASE, "events": rows}, now=T0 + 30)
        self.assertEqual(len(events), realtime.MAX_EVENTS_PER_CYCLE)
        self.assertEqual(events[-1]["event_type"], "events_omitted")


class MonitorTest(unittest.TestCase):
    def make(self, send, snapshots):
        feed = iter(snapshots)
        return EventMonitor({"token": "t", "device_id": "d"}, send, collect=lambda since: next(feed),
                            classifier=classifier())

    def test_failed_delivery_is_retried_without_losing_events(self):
        sent, fail = [], [True]

        def send(config, batch):
            if fail[0]:
                raise OSError("offline")
            sent.append(list(batch))

        row = {"log": "Security", "record_id": "1", "event_id": 1102, "subject_user": "x", "time_created": iso_at(0)}
        monitor = self.make(send, [{"events": [row]}, {"events": []}])
        self.assertEqual(monitor.cycle(), 0)
        self.assertEqual(len(monitor.pending), 1)
        fail[0] = False
        self.assertEqual(monitor.cycle(), 1)
        self.assertEqual(len(monitor.pending), 0)
        self.assertEqual(sent[0][0]["event_type"], "log_cleared")

    def test_unavailable_snapshot_does_not_move_the_window(self):
        monitor = self.make(lambda c, b: None, [None])
        before = monitor.since
        self.assertEqual(monitor.cycle(), 0)
        self.assertEqual(monitor.since, before)

    def test_pending_queue_is_bounded(self):
        monitor = self.make(lambda c, b: (_ for _ in ()).throw(OSError()), [])
        monitor.pending.extend({"n": i} for i in range(realtime.PENDING_LIMIT + 50))
        self.assertEqual(len(monitor.pending), realtime.PENDING_LIMIT)


class TimeParsingTest(unittest.TestCase):
    def test_powershell_roundtrip_format(self):
        self.assertEqual(parse_time("2026-10-29T12:00:00.1234567Z"), parse_time("2026-10-29T12:00:00.123456+00:00"))
        self.assertGreater(parse_time("garbage"), 0)


if __name__ == "__main__":
    unittest.main()
