"""CISA Known Exploited Vulnerabilities (KEV) catalog, cached in memory.

The catalog lists CVEs that are being exploited in the wild right now. It is
downloaded in a background thread (never inside a request) and refreshed every
24 hours; if the download fails the last good copy stays in use.
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

import httpx

LOGGER = logging.getLogger("cybercheck.kev")
DEFAULT_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
REFRESH_SECONDS = 24 * 60 * 60

_catalog: dict[str, dict[str, Any]] = {}
_loaded_at = 0.0
_started = False
_lock = threading.Lock()


def _cache_file() -> Path:
    return Path(tempfile.gettempdir()) / "cybercheck-kev.json"


def parse(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    catalog: dict[str, dict[str, Any]] = {}
    for item in document.get("vulnerabilities", []):
        cve = str(item.get("cveID", "")).strip().upper()
        if cve.startswith("CVE-"):
            catalog[cve] = {
                "name": item.get("vulnerabilityName"),
                "product": item.get("product"),
                "added": item.get("dateAdded"),
                "ransomware": str(item.get("knownRansomwareCampaignUse", "")).lower() == "known",
            }
    return catalog


def load(document: dict[str, Any]) -> int:
    global _catalog, _loaded_at
    catalog = parse(document)
    if catalog:
        with _lock:
            _catalog, _loaded_at = catalog, time.time()
    return len(catalog)


def catalog() -> dict[str, dict[str, Any]] | None:
    """The loaded catalog, or None while it is not available (so callers never
    treat 'unknown' as 'not exploited')."""
    with _lock:
        return _catalog or None


def refresh() -> bool:
    url = os.getenv("KEV_URL", DEFAULT_URL)
    if not url:
        return False
    try:
        response = httpx.get(url, timeout=30, follow_redirects=True)
        response.raise_for_status()
        document = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        LOGGER.warning("No se pudo actualizar el catalogo KEV: %s", type(exc).__name__)
        return False
    if load(document) == 0:
        return False
    try:
        _cache_file().write_text(json.dumps(document), encoding="utf-8")
    except OSError:
        pass
    return True


def _run() -> None:
    cache = _cache_file()
    try:
        if cache.is_file() and time.time() - cache.stat().st_mtime < REFRESH_SECONDS:
            load(json.loads(cache.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        pass
    while True:
        if catalog() is None or time.time() - _loaded_at >= REFRESH_SECONDS:
            refresh()
        time.sleep(5 * 60 if catalog() is None else 60 * 60)


def start_refresher() -> None:
    global _started
    if _started or not os.getenv("KEV_URL", DEFAULT_URL):
        return
    _started = True
    threading.Thread(target=_run, name="cybercheck-kev", daemon=True).start()
