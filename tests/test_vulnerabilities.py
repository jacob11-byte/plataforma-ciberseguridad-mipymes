import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import kev, main, storage, vulndb
from app.rules import evaluate_rules


def program(name, version):
    return {"name": name, "version": version}


def triggered(evidence, catalog=None):
    return {r.rule_id: r for r in evaluate_rules(evidence, kev=catalog) if r.triggered}


class VulnDbTest(unittest.TestCase):
    def match(self, name, version):
        return vulndb.match_software([program(name, version)])

    def test_version_comparison(self):
        self.assertEqual(vulndb.parse_version("PuTTY release 0.81 (64-bit)"), (0, 81))
        self.assertTrue(vulndb.version_lt((7, 11, 0), (7, 13)))
        self.assertFalse(vulndb.version_lt((7, 13, 0), (7, 13)))
        self.assertFalse(vulndb.version_lt((25, 1), (25, 1, 0)))

    def test_winrar(self):
        found = self.match("WinRAR 7.11 (64-bit)", "7.11.0")
        self.assertEqual(found[0]["fixed_in"], "7.13")
        self.assertEqual(found[0]["cves"], ["CVE-2025-6218", "CVE-2025-8088"])
        self.assertEqual(self.match("WinRAR 7.13 (64-bit)", "7.13.0"), [])

    def test_seven_zip_reports_only_cves_that_apply_to_the_installed_version(self):
        self.assertEqual(self.match("7-Zip 24.08 (x64)", "24.08")[0]["cves"],
                         ["CVE-2025-0411", "CVE-2025-11001", "CVE-2025-11002", "CVE-2025-55188"])
        self.assertEqual(self.match("7-Zip 24.09 (x64)", "24.09")[0]["cves"],
                         ["CVE-2025-11001", "CVE-2025-11002", "CVE-2025-55188"])
        only = self.match("7-Zip 25.00 (x64)", "25.00")[0]
        self.assertEqual((only["cves"], only["fixed_in"]), (["CVE-2025-55188"], "25.01"))
        self.assertEqual(self.match("7-Zip 25.01 (x64)", "25.01"), [])

    def test_putty_and_notepad(self):
        self.assertEqual(self.match("PuTTY release 0.80 (64-bit)", "0.80.0.0")[0]["cves"], ["CVE-2024-31497"])
        self.assertEqual(self.match("PuTTY release 0.81 (64-bit)", "0.81.0.0"), [])
        self.assertEqual(self.match("Notepad++ (64-bit x64)", "8.8.1")[0]["fixed_in"], "8.8.2")
        self.assertEqual(self.match("Notepad++ (64-bit x64)", "8.8.2"), [])

    def test_end_of_life_and_unrelated_software(self):
        flash = self.match("Adobe Flash Player 32 NPAPI", "32.0.0.465")[0]
        self.assertTrue(flash["eol"])
        self.assertTrue(self.match("Python 2.7.18", "2.7.18150")[0]["eol"])
        self.assertEqual(self.match("Python 3.12.0 (64-bit)", "3.12.150"), [])
        self.assertEqual(self.match("Google Chrome", "130.0.1"), [])
        self.assertEqual(vulndb.match_software([None, {"name": None}]), [])

    def test_extra_entries_from_json_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "extra.json"
            path.write_text('[{"pattern": "^acme tool", "product": "Acme", "fixed_in": "2.0", "cves": ["cve-2030-1"]}]')
            with patch.dict(os.environ, {"VULN_DB_PATH": str(path)}):
                found = self.match("Acme Tool", "1.9")
            self.assertEqual(found[0]["cves"], ["CVE-2030-1"])
            path.write_text("not json")
            with patch.dict(os.environ, {"VULN_DB_PATH": str(path)}):
                self.assertEqual(len(vulndb.entries()), len(vulndb.CURATED))


class VulnerabilityRulesTest(unittest.TestCase):
    SOFTWARE = {"software_inventory": {"success": True, "data": [program("WinRAR 7.11 (64-bit)", "7.11.0")]}}
    UPDATES = {"updates": {"pending_count": 2, "reboot_pending": False, "pending_updates": [
        {"title": "Actualizacion acumulativa", "kb": "KB5066835", "severity": "Critical", "cves": ["CVE-2025-59230", "CVE-2025-1"]},
        {"title": "Defender", "kb": "KB2267602", "severity": None, "cves": []},
    ]}}

    def test_vulnerable_software_is_critical_when_exploited(self):
        quiet = triggered(self.SOFTWARE, {})["VULNERABLE_SOFTWARE"]
        self.assertEqual(quiet.severity, "Alto")
        self.assertIn("WinRAR 7.11.0 (corregido en 7.13)", quiet.detail)
        self.assertEqual(quiet.fix_command, "winget upgrade --id RARLab.WinRAR")
        loud = triggered(self.SOFTWARE, {"CVE-2025-8088": {"ransomware": False}})["VULNERABLE_SOFTWARE"]
        self.assertEqual(loud.severity, "Critico")
        self.assertIn("CVE-2025-8088 [EXPLOTADA ACTIVAMENTE - CISA KEV]", loud.detail)
        self.assertEqual(loud.evidence["exploited_in_wild"], ["CVE-2025-8088"])

    def test_clean_inventory_closes_the_finding(self):
        rules = evaluate_rules({"software_inventory": {"success": True, "data": [program("WinRAR 7.13 (64-bit)", "7.13.0")]}})
        rule = next(r for r in rules if r.rule_id == "VULNERABLE_SOFTWARE")
        self.assertFalse(rule.triggered)
        failed = evaluate_rules({"software_inventory": {"success": False, "data": None, "error": "x"}})
        self.assertNotIn("VULNERABLE_SOFTWARE", [r.rule_id for r in failed])

    def test_pending_patch_for_exploited_cve(self):
        catalog = {"CVE-2025-59230": {"ransomware": True, "added": "2025-10-14"}}
        rule = triggered(self.UPDATES, catalog)["EXPLOITED_VULN_UNPATCHED"]
        self.assertEqual(rule.severity, "Critico")
        self.assertIn("KB5066835 -> CVE-2025-59230", rule.detail)
        self.assertIn("ransomware", rule.detail)
        self.assertEqual(rule.evidence["exploited_cves"], ["CVE-2025-59230"])

    def test_unknown_catalog_never_claims_safety(self):
        self.assertNotIn("EXPLOITED_VULN_UNPATCHED", [r.rule_id for r in evaluate_rules(self.UPDATES, kev=None)])
        clean = evaluate_rules(self.UPDATES, kev={"CVE-2099-1": {}})
        self.assertFalse(next(r for r in clean if r.rule_id == "EXPLOITED_VULN_UNPATCHED").triggered)


class KevCatalogTest(unittest.TestCase):
    DOCUMENT = {"vulnerabilities": [
        {"cveID": "CVE-2025-8088", "vulnerabilityName": "WinRAR Path Traversal", "product": "WinRAR",
         "dateAdded": "2025-08-12", "knownRansomwareCampaignUse": "Unknown"},
        {"cveID": "cve-2025-59230", "knownRansomwareCampaignUse": "Known"},
        {"cveID": "bogus"},
    ]}

    def tearDown(self):
        kev.load({"vulnerabilities": []})

    def test_parse_and_lookup(self):
        parsed = kev.parse(self.DOCUMENT)
        self.assertEqual(sorted(parsed), ["CVE-2025-59230", "CVE-2025-8088"])
        self.assertTrue(parsed["CVE-2025-59230"]["ransomware"])
        self.assertFalse(parsed["CVE-2025-8088"]["ransomware"])

    def test_refresh_keeps_last_good_copy_on_failure(self):
        class Response:
            def raise_for_status(self): pass
            def json(self): return KevCatalogTest.DOCUMENT

        with patch.object(kev.httpx, "get", return_value=Response()), \
             patch.object(kev, "_cache_file", return_value=Path(tempfile.gettempdir()) / "kev-test.json"):
            self.assertTrue(kev.refresh())
        self.assertIn("CVE-2025-8088", kev.catalog())
        with patch.object(kev.httpx, "get", side_effect=kev.httpx.ConnectError("offline")):
            self.assertFalse(kev.refresh())
        self.assertIn("CVE-2025-8088", kev.catalog(), "a failed refresh must not wipe the catalog")


class MsrcTest(unittest.TestCase):
    def month(self, cve, kb, exploited=False):
        threat = "Publicly Disclosed:No;Exploited:%s;Latest Software Release:Exploitation Detected" % ("Yes" if exploited else "No")
        return {"Vulnerability": [{
            "CVE": cve, "Threats": [{"Type": 1, "Description": {"Value": threat}}],
            "Remediations": [{"Description": {"Value": kb}, "SubType": "Security Update"},
                             {"Description": {"Value": "Release Notes"}}],
        }]}

    def tearDown(self):
        from app import msrc
        msrc.load({"KB0": {"CVE-0-0"}}, set())  # reset to a known state
        msrc._catalog = {}

    def test_parse_document_maps_kb_to_cve_and_exploited(self):
        from app import msrc
        kbs, exploited = {}, set()
        msrc.parse_document(self.month("cve-2026-1111", "5066835", exploited=True), kbs, exploited)
        msrc.parse_document(self.month("CVE-2026-2222", "5066835"), kbs, exploited)
        self.assertEqual(kbs, {"KB5066835": {"CVE-2026-1111", "CVE-2026-2222"}})
        self.assertEqual(exploited, {"CVE-2026-1111"})

    def test_pending_kb_without_agent_cves_is_resolved_through_msrc(self):
        msrc = {"kbs": {"KB5066835": ["CVE-2026-1111", "CVE-2026-2222"]}, "exploited": ["CVE-2026-1111"]}
        updates = {"pending_count": 1, "reboot_pending": False, "pending_updates": [
            {"title": "Acumulativa", "kb": "KB5066835", "severity": None, "cves": []}]}
        rows = vulndb.device_vulnerabilities(updates, None, None, msrc)
        self.assertEqual([(r["cve"], r["kev"], r["exploited_by"]) for r in rows],
                         [("CVE-2026-1111", True, ["Microsoft"]), ("CVE-2026-2222", False, [])])
        rule = {r.rule_id: r for r in evaluate_rules({"updates": updates}, msrc=msrc) if r.triggered}["EXPLOITED_VULN_UNPATCHED"]
        self.assertEqual(rule.severity, "Critico")
        self.assertIn("KB5066835 -> CVE-2026-1111", rule.detail)

    def test_refresh_uses_most_recent_months_and_survives_failures(self):
        from app import msrc
        index = {"value": [
            {"ID": "2026-Aug", "InitialReleaseDate": "2026-08-11T07:00:00Z", "CvrfUrl": "u/aug"},
            {"ID": "2026-Oct", "InitialReleaseDate": "2026-10-13T07:00:00Z", "CvrfUrl": "u/oct"},
            {"ID": "2026-Sep", "InitialReleaseDate": "2026-09-08T07:00:00Z", "CvrfUrl": "u/sep"},
        ]}
        docs = {"u/oct": self.month("CVE-2026-0010", "5000010", True), "u/sep": self.month("CVE-2026-0009", "5000009"),
                "u/aug": self.month("CVE-2026-0008", "5000008")}
        fetched = []

        class Response:
            def __init__(self, payload): self.payload = payload
            def json(self): return self.payload

        def fake_get(url, **kwargs):
            fetched.append(url)
            return Response(index if url == msrc.INDEX_URL else docs[url])

        with patch.dict(os.environ, {"MSRC_MONTHS": "2"}), patch.object(msrc.httpx, "get", side_effect=fake_get), \
             patch.object(msrc, "_cache_file", return_value=Path(tempfile.gettempdir()) / "msrc-test.json"):
            self.assertTrue(msrc.refresh())
        self.assertEqual(fetched[1:], ["u/oct", "u/sep"], "newest months first, aug is skipped")
        self.assertEqual(sorted(msrc.catalog()["kbs"]), ["KB5000009", "KB5000010"])
        self.assertEqual(msrc.catalog()["exploited"], ["CVE-2026-0010"])
        with patch.object(msrc.httpx, "get", side_effect=msrc.httpx.ConnectError("offline")):
            self.assertFalse(msrc.refresh())
        self.assertIn("KB5000010", msrc.catalog()["kbs"], "a failed refresh keeps the last good map")


class DeviceVulnerabilitiesApiTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        patcher = patch.object(storage, "DB_PATH", Path(self.directory.name) / "vulns.db")
        patcher.start()
        self.addCleanup(patcher.stop)
        env = patch.dict(os.environ, {
            "CYBERCHECK_ENV": "development", "RENDER_SERVICE_ID": "", "DATABASE_URL": "",
            "COOKIE_SECURE": "false", "AGENT_REGISTRATION_CODE": "vuln-code-1234567",
        })
        env.start()
        self.addCleanup(env.stop)
        storage.init_db()

    def test_detail_lists_cves_with_kev_first_and_findings_are_created(self):
        client = TestClient(main.app)
        device = client.post("/api/register", json={
            "registration_code": "vuln-code-1234567", "company_name": "Empresa Vuln", "hostname": "PC-VULN"}).json()
        catalog = {"CVE-2025-8088": {"ransomware": False, "added": "2025-08-12"}}
        evidence = {
            "software_inventory": {"success": True, "data": [program("WinRAR 7.11 (64-bit)", "7.11.0"),
                                                             program("Adobe Flash Player 32", "32.0")]},
            "updates": {"pending_count": 1, "reboot_pending": False, "pending_updates": [
                {"title": "Acumulativa", "kb": "KB1", "severity": "Critical", "cves": ["CVE-2025-1111"]}]},
        }
        with patch.object(kev, "catalog", return_value=catalog):
            result = client.post("/api/agent/results", headers={"Authorization": f"Bearer {device['token']}"}, json={
                "device_id": device["device_id"], "scan_type": "FULL_SCAN", "evidence": evidence,
                "request_id": "vuln-scan-0001"})
            self.assertEqual(result.status_code, 200, result.text)
            admin = TestClient(main.app)
            admin.post("/api/login", json={"username": "admin", "password": "admin123"})
            detail = admin.get(f"/api/devices/{device['device_id']}/detail").json()
        self.assertTrue(detail["kev_loaded"])
        cves = [row["cve"] for row in detail["vulnerabilities"]]
        self.assertEqual(cves[0], "CVE-2025-8088")
        self.assertTrue(detail["vulnerabilities"][0]["kev"])
        self.assertIn("CVE-2025-1111", cves)
        self.assertTrue(any(row["source"] == "Fin de soporte" for row in detail["vulnerabilities"]))
        rules = {f["rule_id"]: f for f in detail["findings"] if f["status"] != "resolved"}
        self.assertEqual(rules["VULNERABLE_SOFTWARE"]["severity"], "Critico")
        self.assertIn("Adobe Flash Player", rules["VULNERABLE_SOFTWARE"]["diagnosis"]["detail"])


if __name__ == "__main__":
    unittest.main()
