import json
import unittest
from urllib.parse import parse_qs

import httpx

from app.wazuh_integration import (
    WazuhAPIError,
    WazuhClient,
    WazuhConfig,
    WazuhResponseError,
)


def server_collection(items, total=None, failed=0):
    return {
        "error": 0,
        "data": {
            "affected_items": items,
            "total_affected_items": len(items) if total is None else total,
            "total_failed_items": failed,
            "failed_items": [],
        },
    }


def index_hit(document_id, cve, *, agent_id="001", status=None):
    vulnerability = {
        "id": cve,
        "detected_at": "2026-10-27T12:00:00Z",
        "severity": "High",
        "score": {"base": 8.1},
    }
    if status is not None:
        vulnerability["status"] = status
    return {
        "_index": "wazuh-states-vulnerabilities-lab",
        "_id": document_id,
        "_source": {
            "agent": {"id": agent_id, "name": "vm-windows"},
            "package": {"name": "Example App", "version": "1.2.3"},
            "vulnerability": vulnerability,
        },
    }


def search_page(items, total, scroll_id="scroll-1", failed=0):
    return {
        "_scroll_id": scroll_id,
        "timed_out": False,
        "_shards": {"failed": failed},
        "hits": {"total": {"value": total, "relation": "eq"}, "hits": items},
    }


class WazuhClientTest(unittest.TestCase):
    def setUp(self):
        self.config = WazuhConfig(
            server_url="https://server.example:55000",
            server_username="server-reader",
            server_password="server-secret",
            indexer_url="https://indexer.example:9200",
            indexer_username="index-reader",
            indexer_password="index-secret",
            page_size=2,
            max_pages=4,
        )

    def make_client(self, server_handler, indexer_handler=None):
        if indexer_handler is None:
            indexer_handler = lambda _request: httpx.Response(500)
        server = httpx.Client(transport=httpx.MockTransport(server_handler))
        indexer = httpx.Client(transport=httpx.MockTransport(indexer_handler))
        self.addCleanup(server.close)
        self.addCleanup(indexer.close)
        return WazuhClient(self.config, server_http=server, indexer_http=indexer)

    def test_server_inventory_paginates_and_uses_jwt(self):
        requests = []

        def server_handler(request):
            requests.append(request)
            if request.url.path == "/security/user/authenticate":
                self.assertEqual(request.method, "POST")
                self.assertTrue(request.headers["authorization"].startswith("Basic "))
                return httpx.Response(200, json={"error": 0, "data": {"token": "jwt-1"}})
            self.assertEqual(request.headers["authorization"], "Bearer jwt-1")
            self.assertEqual(request.url.path, "/syscollector/001/packages")
            offset = int(parse_qs(request.url.query.decode())["offset"][0])
            if offset == 0:
                return httpx.Response(200, json=server_collection(
                    [{"name": "A", "version": "1"}, {"name": "B", "version": "2"}], total=3
                ))
            return httpx.Response(200, json=server_collection([{"name": "C", "version": "3"}], total=3))

        client = self.make_client(server_handler)
        self.assertEqual([p["name"] for p in client.get_packages("001")], ["A", "B", "C"])
        self.assertEqual(len(requests), 3)
        self.assertEqual(requests[1].extensions["timeout"]["read"], 10.0)

    def test_expired_jwt_is_refreshed_once(self):
        authentications = 0

        def server_handler(request):
            nonlocal authentications
            if request.url.path == "/security/user/authenticate":
                authentications += 1
                return httpx.Response(200, json={"error": 0, "data": {"token": f"jwt-{authentications}"}})
            if request.headers["authorization"] == "Bearer jwt-1":
                return httpx.Response(401)
            return httpx.Response(200, json=server_collection([{"id": "001"}]))

        client = self.make_client(server_handler)
        self.assertEqual(client.get_agent("001")["id"], "001")
        self.assertEqual(authentications, 2)

    def test_indexer_scroll_normalizes_real_document_fields(self):
        requests = []

        def indexer_handler(request):
            requests.append(request)
            self.assertTrue(request.headers["authorization"].startswith("Basic "))
            if request.url.path == "/wazuh-states-vulnerabilities*/_search":
                body = json.loads(request.content)
                self.assertEqual(body["query"], {"term": {"agent.id": "001"}})
                self.assertEqual(body["sort"], ["_doc"])
                return httpx.Response(200, json=search_page([
                    index_hit("doc-1", "CVE-2026-1234"),
                    index_hit("doc-2", "CVE-2026-4567", status="Active"),
                ], total=3))
            if request.method == "POST" and request.url.path == "/_search/scroll":
                return httpx.Response(200, json=search_page([
                    index_hit("doc-3", "CVE-2026-9999")
                ], total=3))
            self.assertEqual(request.method, "DELETE")
            return httpx.Response(200, json={"succeeded": True})

        client = self.make_client(lambda _request: httpx.Response(500), indexer_handler)
        evidence = client.get_vulnerabilities("001")
        self.assertEqual([item["cve"] for item in evidence], [
            "CVE-2026-1234", "CVE-2026-4567", "CVE-2026-9999"
        ])
        self.assertEqual(evidence[0]["source"], "wazuh_indexer")
        self.assertEqual(evidence[0]["source_document_id"], "doc-1")
        self.assertEqual(evidence[0]["package_name"], "Example App")
        self.assertEqual(evidence[0]["package_version"], "1.2.3")
        self.assertEqual(evidence[0]["observed_at"], "2026-10-27T12:00:00Z")
        self.assertIsNone(evidence[0]["status"])
        self.assertEqual(evidence[1]["status"], "Active")
        self.assertEqual(len(requests), 3)
        self.assertEqual(requests[-1].method, "DELETE")

    def test_indexer_failure_does_not_return_partial_evidence(self):
        def indexer_handler(request):
            if request.url.path == "/wazuh-states-vulnerabilities*/_search":
                return httpx.Response(200, json=search_page([
                    index_hit("doc-1", "CVE-2026-1234"),
                    index_hit("doc-2", "CVE-2026-4567"),
                ], total=3))
            if request.method == "DELETE":
                return httpx.Response(200, json={"succeeded": True})
            return httpx.Response(200, json=search_page([], total=3, failed=1))

        client = self.make_client(lambda _request: httpx.Response(500), indexer_handler)
        with self.assertRaises(WazuhResponseError):
            client.get_vulnerabilities("001")

    def test_missing_index_is_an_error_not_an_empty_result(self):
        client = self.make_client(
            lambda _request: httpx.Response(500),
            lambda _request: httpx.Response(404, json={"error": "index_not_found_exception"}),
        )
        with self.assertRaises(WazuhAPIError) as error:
            client.get_vulnerabilities("001")
        self.assertEqual(error.exception.status_code, 404)

    def test_server_partial_collection_is_an_error(self):
        def handler(request):
            if request.url.path == "/security/user/authenticate":
                return httpx.Response(200, json={"error": 0, "data": {"token": "jwt"}})
            return httpx.Response(200, json=server_collection([{"name": "A"}], failed=1))

        client = self.make_client(handler)
        with self.assertRaises(WazuhResponseError):
            client.get_packages("001")

    def test_snapshot_normalizes_inventory_and_checks_agent_name(self):
        def server_handler(request):
            if request.url.path == "/security/user/authenticate":
                return httpx.Response(200, json={"error": 0, "data": {"token": "jwt"}})
            if request.url.path == "/agents":
                return httpx.Response(200, json=server_collection([{"id": "001", "name": "vm-windows"}]))
            if request.url.path.endswith("/packages"):
                return httpx.Response(200, json=server_collection([{
                    "name": "Example App", "version": "1.2.3", "scan": {"time": "2026-10-27T12:00:00Z"}
                }]))
            return httpx.Response(200, json=server_collection([{
                "hotfix": "KB5000000", "scan": {"time": "2026-10-27T12:00:00Z"}
            }]))

        def indexer_handler(request):
            if request.method == "DELETE":
                return httpx.Response(200, json={"succeeded": True})
            return httpx.Response(200, json=search_page([
                index_hit("doc-1", "CVE-2026-1234", agent_id="001")
            ], total=1))

        snapshot = self.make_client(server_handler, indexer_handler).fetch_agent_snapshot("001")
        self.assertEqual(snapshot["packages"][0]["source"], "wazuh_server_api")
        self.assertEqual(snapshot["packages"][0]["version"], "1.2.3")
        self.assertEqual(snapshot["hotfixes"][0]["hotfix"], "KB5000000")
        self.assertEqual(snapshot["vulnerabilities"][0]["cve"], "CVE-2026-1234")

        def stale_indexer_handler(request):
            if request.method == "DELETE":
                return httpx.Response(200, json={"succeeded": True})
            stale = index_hit("doc-old", "CVE-2025-1234")
            stale["_source"]["agent"]["name"] = "old-vm"
            return httpx.Response(200, json=search_page([stale], total=1))

        with self.assertRaises(WazuhResponseError):
            self.make_client(server_handler, stale_indexer_handler).fetch_agent_snapshot("001")

    def test_configuration_requires_tls_and_hides_secrets(self):
        self.assertNotIn("server-secret", repr(self.config))
        self.assertNotIn("index-secret", repr(self.config))
        with self.assertRaises(ValueError):
            WazuhConfig(
                server_url="http://server.example:55000",
                server_username="u", server_password="p",
                indexer_url="https://indexer.example:9200",
                indexer_username="u", indexer_password="p",
            )
        client = self.make_client(lambda _request: httpx.Response(500))
        with self.assertRaises(ValueError):
            client.get_packages("../001")


if __name__ == "__main__":
    unittest.main()
