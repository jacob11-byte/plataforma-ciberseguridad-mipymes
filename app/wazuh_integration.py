"""Read-only Wazuh integration for agent inventory and vulnerability evidence.

Wazuh 4.8 removed ``GET /vulnerability/{agent_id}``. Current vulnerability
state is stored in the indexer, while agent inventory remains available from
the Wazuh server API. This module deliberately uses both APIs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import os
import re
from typing import Any
from urllib.parse import urlsplit

import httpx


_AGENT_ID = re.compile(r"^[0-9]{3,}$")


class WazuhIntegrationError(RuntimeError):
    """A Wazuh request or response could not be used as trustworthy evidence."""


class WazuhAPIError(WazuhIntegrationError):
    def __init__(self, service: str, status_code: int | None = None):
        self.service = service
        self.status_code = status_code
        suffix = f" (HTTP {status_code})" if status_code is not None else ""
        super().__init__(f"Wazuh {service} request failed{suffix}")


class WazuhResponseError(WazuhIntegrationError):
    """Wazuh returned incomplete, malformed, or partial data."""


@dataclass(frozen=True)
class WazuhConfig:
    server_url: str
    server_username: str
    server_password: str = field(repr=False)
    indexer_url: str = ""
    indexer_username: str = ""
    indexer_password: str = field(default="", repr=False)
    server_ca_bundle: str | None = None
    indexer_ca_bundle: str | None = None
    timeout_seconds: float = 10.0
    page_size: int = 500
    max_pages: int = 200

    def __post_init__(self) -> None:
        for name, value in (("server_url", self.server_url), ("indexer_url", self.indexer_url)):
            parts = urlsplit(value)
            if (
                parts.scheme != "https"
                or not parts.hostname
                or parts.username is not None
                or parts.password is not None
                or parts.path not in ("", "/")
                or parts.query
                or parts.fragment
            ):
                raise ValueError(f"{name} must be an HTTPS origin without credentials or path")
        if not all((self.server_username, self.server_password, self.indexer_username, self.indexer_password)):
            raise ValueError("Both Wazuh API credentials are required")
        if self.timeout_seconds <= 0 or not 1 <= self.page_size <= 500 or not 1 <= self.max_pages <= 1000:
            raise ValueError("Invalid Wazuh timeout or pagination limits")

    @classmethod
    def from_env(cls) -> WazuhConfig:
        """Load configuration without exposing credentials in logs or repr."""
        return cls(
            server_url=os.getenv("WAZUH_SERVER_URL", ""),
            server_username=os.getenv("WAZUH_SERVER_USER", ""),
            server_password=os.getenv("WAZUH_SERVER_PASSWORD", ""),
            indexer_url=os.getenv("WAZUH_INDEXER_URL", ""),
            indexer_username=os.getenv("WAZUH_INDEXER_USER", ""),
            indexer_password=os.getenv("WAZUH_INDEXER_PASSWORD", ""),
            server_ca_bundle=os.getenv("WAZUH_SERVER_CA_BUNDLE") or None,
            indexer_ca_bundle=os.getenv("WAZUH_INDEXER_CA_BUNDLE") or None,
        )


class WazuhClient:
    """Read Wazuh 4.8+ data; injected HTTP clients allow transport-level tests."""

    def __init__(
        self,
        config: WazuhConfig,
        *,
        server_http: httpx.Client | None = None,
        indexer_http: httpx.Client | None = None,
    ) -> None:
        self.config = config
        self._owns_server = server_http is None
        self._owns_indexer = indexer_http is None
        self._server_http = server_http or httpx.Client(
            verify=config.server_ca_bundle or True,
            timeout=config.timeout_seconds,
            trust_env=False,
        )
        self._indexer_http = indexer_http or httpx.Client(
            verify=config.indexer_ca_bundle or True,
            timeout=config.timeout_seconds,
            trust_env=False,
        )
        self._server_token: str | None = None

    def close(self) -> None:
        if self._owns_server:
            self._server_http.close()
        if self._owns_indexer:
            self._indexer_http.close()

    def __enter__(self) -> WazuhClient:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def _authenticate_server(self) -> str:
        response = self._send(
            self._server_http,
            "server API",
            "POST",
            f"{self.config.server_url.rstrip('/')}/security/user/authenticate",
            auth=httpx.BasicAuth(self.config.server_username, self.config.server_password),
            timeout=self.config.timeout_seconds,
        )
        data = self._server_json(response)
        token = data.get("data", {}).get("token") if isinstance(data.get("data"), dict) else None
        if not isinstance(token, str) or not token:
            raise WazuhResponseError("Wazuh server API authentication returned no token")
        self._server_token = token
        return token

    @staticmethod
    def _send(client: httpx.Client, service: str, method: str, url: str, **kwargs: Any) -> httpx.Response:
        try:
            response = client.request(method, url, **kwargs)
        except httpx.HTTPError as exc:
            raise WazuhAPIError(service) from exc
        if response.status_code >= 400:
            raise WazuhAPIError(service, response.status_code)
        return response

    @staticmethod
    def _server_json(response: httpx.Response) -> dict[str, Any]:
        try:
            payload = response.json()
        except ValueError as exc:
            raise WazuhResponseError("Wazuh server API returned invalid JSON") from exc
        if not isinstance(payload, dict) or payload.get("error") != 0 or not isinstance(payload.get("data"), dict):
            raise WazuhResponseError("Wazuh server API returned an error or invalid data")
        return payload

    def _server_get(self, path: str, *, params: dict[str, Any] | None = None) -> dict[str, Any]:
        url = f"{self.config.server_url.rstrip('/')}{path}"
        for attempt in range(2):
            token = self._server_token or self._authenticate_server()
            try:
                response = self._send(
                    self._server_http,
                    "server API",
                    "GET",
                    url,
                    params=params,
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=self.config.timeout_seconds,
                )
            except WazuhAPIError as exc:
                if exc.status_code == 401 and attempt == 0:
                    self._server_token = None
                    continue
                raise
            return self._server_json(response)
        raise WazuhAPIError("server API", 401)

    def _server_items(self, path: str, *, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        offset = 0
        for _page in range(self.config.max_pages):
            query = {**(params or {}), "offset": offset, "limit": self.config.page_size}
            data = self._server_get(path, params=query)["data"]
            items = data.get("affected_items")
            total = data.get("total_affected_items")
            failed = data.get("total_failed_items", 0)
            if (
                not isinstance(items, list)
                or not isinstance(total, int)
                or total < 0
                or not isinstance(failed, int)
                or failed != 0
                or any(not isinstance(item, dict) for item in items)
                or offset + len(items) > total
            ):
                raise WazuhResponseError("Wazuh server API returned partial or invalid collection")
            results.extend(items)
            offset += len(items)
            if offset >= total:
                return results
            if not items:
                raise WazuhResponseError("Wazuh server API pagination stopped before completion")
        raise WazuhResponseError("Wazuh server API result exceeded configured pagination limit")

    @staticmethod
    def _validated_agent_id(agent_id: str) -> str:
        if not isinstance(agent_id, str) or not _AGENT_ID.fullmatch(agent_id):
            raise ValueError("Wazuh agent ID must be a numeric string of at least three digits")
        return agent_id

    def list_agents(self) -> list[dict[str, Any]]:
        return self._server_items("/agents")

    def get_agent(self, agent_id: str) -> dict[str, Any]:
        agent_id = self._validated_agent_id(agent_id)
        items = self._server_items("/agents", params={"agents_list": agent_id})
        matches = [item for item in items if item.get("id") == agent_id]
        if len(matches) != 1:
            raise WazuhResponseError("Wazuh agent was not returned uniquely by the server API")
        return matches[0]

    def get_packages(self, agent_id: str) -> list[dict[str, Any]]:
        agent_id = self._validated_agent_id(agent_id)
        return self._server_items(f"/syscollector/{agent_id}/packages")

    def get_hotfixes(self, agent_id: str) -> list[dict[str, Any]]:
        agent_id = self._validated_agent_id(agent_id)
        return self._server_items(f"/syscollector/{agent_id}/hotfixes")

    def _indexer_request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        response = self._send(
            self._indexer_http,
            "indexer API",
            method,
            f"{self.config.indexer_url.rstrip('/')}{path}",
            auth=httpx.BasicAuth(self.config.indexer_username, self.config.indexer_password),
            timeout=self.config.timeout_seconds,
            **kwargs,
        )
        try:
            payload = response.json()
        except ValueError as exc:
            raise WazuhResponseError("Wazuh indexer API returned invalid JSON") from exc
        if not isinstance(payload, dict):
            raise WazuhResponseError("Wazuh indexer API returned an invalid response")
        return payload

    @staticmethod
    def _search_hits(payload: dict[str, Any]) -> list[dict[str, Any]]:
        shards = payload.get("_shards")
        hits = payload.get("hits")
        items = hits.get("hits") if isinstance(hits, dict) else None
        if (
            payload.get("timed_out") is True
            or not isinstance(shards, dict)
            or shards.get("failed", 0) != 0
            or not isinstance(items, list)
            or any(not isinstance(item, dict) for item in items)
        ):
            raise WazuhResponseError("Wazuh indexer search was incomplete or invalid")
        return items

    def get_vulnerabilities(
        self, agent_id: str, *, expected_agent_name: str | None = None
    ) -> list[dict[str, Any]]:
        """Return normalized current CVE evidence for one Wazuh agent.

        Scroll pagination is used because an agent can exceed OpenSearch's
        ordinary 10,000-result window. A failed page rejects the entire result.
        """
        agent_id = self._validated_agent_id(agent_id)
        evidence: list[dict[str, Any]] = []
        retrieved_at = datetime.now(timezone.utc).isoformat()
        scroll_id: str | None = None
        try:
            payload = self._indexer_request(
                "POST",
                "/wazuh-states-vulnerabilities*/_search",
                params={"scroll": "1m"},
                json={
                    "size": self.config.page_size,
                    "sort": ["_doc"],
                    "query": {"term": {"agent.id": agent_id}},
                },
            )
            for page in range(self.config.max_pages):
                items = self._search_hits(payload)
                scroll_id = payload.get("_scroll_id") or scroll_id
                for hit in items:
                    evidence.append(normalize_vulnerability(
                        hit, agent_id, retrieved_at, expected_agent_name=expected_agent_name
                    ))
                total = payload.get("hits", {}).get("total", {})
                total_complete = (
                    isinstance(total, dict)
                    and total.get("relation") == "eq"
                    and isinstance(total.get("value"), int)
                    and total["value"] >= 0
                    and len(evidence) >= total["value"]
                )
                if (
                    len(items) < self.config.page_size
                    and isinstance(total, dict)
                    and total.get("relation") == "eq"
                    and isinstance(total.get("value"), int)
                    and len(evidence) != total["value"]
                ):
                    raise WazuhResponseError("Wazuh indexer returned fewer documents than reported")
                if (
                    len(items) < self.config.page_size
                    or total_complete
                ):
                    return evidence
                if page + 1 >= self.config.max_pages:
                    break
                if not scroll_id:
                    raise WazuhResponseError("Wazuh indexer omitted scroll ID before the last page")
                payload = self._indexer_request(
                    "POST", "/_search/scroll", json={"scroll": "1m", "scroll_id": scroll_id}
                )
            raise WazuhResponseError("Wazuh indexer result exceeded configured pagination limit")
        finally:
            if scroll_id:
                try:
                    self._indexer_request("DELETE", "/_search/scroll", json={"scroll_id": [scroll_id]})
                except WazuhIntegrationError:
                    # Scroll contexts expire after one minute; cleanup failure
                    # must not replace the result of the read operation.
                    pass

    def fetch_agent_snapshot(self, agent_id: str) -> dict[str, Any]:
        """Fetch a complete snapshot; any source error aborts the snapshot."""
        agent_id = self._validated_agent_id(agent_id)
        agent = self.get_agent(agent_id)
        agent_name = agent.get("name")
        if not isinstance(agent_name, str) or not agent_name:
            raise WazuhResponseError("Wazuh agent has no name for identity verification")
        retrieved_at = datetime.now(timezone.utc).isoformat()
        return {
            "source": "wazuh",
            "wazuh_agent_id": agent_id,
            "retrieved_at": retrieved_at,
            "agent": agent,
            "packages": [normalize_package(item, agent_id, retrieved_at) for item in self.get_packages(agent_id)],
            "hotfixes": [normalize_hotfix(item, agent_id, retrieved_at) for item in self.get_hotfixes(agent_id)],
            "vulnerabilities": self.get_vulnerabilities(agent_id, expected_agent_name=agent_name),
        }


def normalize_package(item: dict[str, Any], agent_id: str, retrieved_at: str) -> dict[str, Any]:
    if item.get("agent_id", agent_id) != agent_id:
        raise WazuhResponseError("Wazuh package belongs to another agent")
    name = item.get("name")
    if not isinstance(name, str) or not name:
        raise WazuhResponseError("Wazuh package has no name")
    scan = item.get("scan")
    scan = scan if isinstance(scan, dict) else {}
    return {
        "kind": "package",
        "source": "wazuh_server_api",
        "wazuh_agent_id": agent_id,
        "name": name,
        "version": item.get("version"),
        "observed_at": scan.get("time"),
        "retrieved_at": retrieved_at,
        "raw": item,
    }


def normalize_hotfix(item: dict[str, Any], agent_id: str, retrieved_at: str) -> dict[str, Any]:
    if item.get("agent_id", agent_id) != agent_id:
        raise WazuhResponseError("Wazuh hotfix belongs to another agent")
    hotfix = item.get("hotfix")
    if not isinstance(hotfix, str) or not hotfix:
        raise WazuhResponseError("Wazuh hotfix has no identifier")
    scan = item.get("scan")
    scan = scan if isinstance(scan, dict) else {}
    return {
        "kind": "hotfix",
        "source": "wazuh_server_api",
        "wazuh_agent_id": agent_id,
        "hotfix": hotfix,
        "observed_at": scan.get("time"),
        "retrieved_at": retrieved_at,
        "raw": item,
    }


def normalize_vulnerability(
    hit: dict[str, Any], agent_id: str, retrieved_at: str, *, expected_agent_name: str | None = None
) -> dict[str, Any]:
    """Preserve Wazuh's observed facts without inventing a status or CVE."""
    source = hit.get("_source")
    if not isinstance(source, dict):
        raise WazuhResponseError("Wazuh vulnerability document has no source")
    agent = source.get("agent")
    vulnerability = source.get("vulnerability")
    package = source.get("package")
    if not isinstance(agent, dict) or agent.get("id") != agent_id or not isinstance(vulnerability, dict):
        raise WazuhResponseError("Wazuh vulnerability document has invalid agent or vulnerability")
    if not isinstance(hit.get("_index"), str) or not isinstance(hit.get("_id"), str):
        raise WazuhResponseError("Wazuh vulnerability document has no index identity")
    if expected_agent_name is not None and agent.get("name") != expected_agent_name:
        raise WazuhResponseError("Wazuh vulnerability belongs to another agent name")
    vulnerability_id = vulnerability.get("id")
    if not isinstance(vulnerability_id, str) or not vulnerability_id:
        raise WazuhResponseError("Wazuh vulnerability document has no identifier")
    if package is not None and not isinstance(package, dict):
        raise WazuhResponseError("Wazuh vulnerability document has invalid package")
    package = package or {}
    score = vulnerability.get("score")
    score = score if isinstance(score, dict) else {}
    return {
        "kind": "vulnerability",
        "source": "wazuh_indexer",
        "source_index": hit.get("_index"),
        "source_document_id": hit.get("_id"),
        "wazuh_agent_id": agent_id,
        "wazuh_agent_name": agent.get("name"),
        "vulnerability_id": vulnerability_id,
        "cve": vulnerability_id if re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", vulnerability_id) else None,
        "package_name": package.get("name"),
        "package_version": package.get("version"),
        "status": vulnerability.get("status"),
        "severity": vulnerability.get("severity"),
        "cvss_score": score.get("base"),
        "observed_at": vulnerability.get("detected_at"),
        "retrieved_at": retrieved_at,
        "raw": source,
    }
