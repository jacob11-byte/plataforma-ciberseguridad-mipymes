"""Microsoft Security Update Guide (MSRC CVRF): which KB fixes which CVE.

Windows Update rarely fills in CVE ids for modern cumulative updates, so the
KB -> CVE map is built from Microsoft's own monthly security bulletins, which
also flag vulnerabilities as ``Exploited:Yes``. Each month is ~20 MB of JSON:
it is processed one at a time in a background thread and only a compact map is
kept (and cached on disk for 24 hours).
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

LOGGER = logging.getLogger("cybercheck.msrc")
INDEX_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/updates"
REFRESH_SECONDS = 24 * 60 * 60
HEADERS = {"Accept": "application/json"}

_catalog: dict[str, Any] = {}
_loaded_at = 0.0
_started = False
_lock = threading.Lock()


def months_to_load() -> int:
    try:
        return max(1, min(12, int(os.getenv("MSRC_MONTHS", "3"))))
    except ValueError:
        return 3


def _cache_file() -> Path:
    return Path(tempfile.gettempdir()) / "cybercheck-msrc.json"


def parse_document(document: dict[str, Any], kbs: dict[str, set[str]], exploited: set[str]) -> None:
    """Fold one monthly CVRF document into the KB map and exploited set."""
    for vulnerability in document.get("Vulnerability", []):
        cve = str(vulnerability.get("CVE", "")).strip().upper()
        if not cve.startswith("CVE-"):
            continue
        if any("Exploited:Yes" in str((threat.get("Description") or {}).get("Value", ""))
               for threat in vulnerability.get("Threats", [])):
            exploited.add(cve)
        for remediation in vulnerability.get("Remediations", []):
            value = str((remediation.get("Description") or {}).get("Value", "")).strip()
            if value.isdigit():
                kbs.setdefault(f"KB{value}", set()).add(cve)


def load(kbs: dict[str, set[str]], exploited: set[str]) -> None:
    global _catalog, _loaded_at
    if not kbs:
        return
    with _lock:
        _catalog = {"kbs": {kb: sorted(cves) for kb, cves in kbs.items()}, "exploited": sorted(exploited)}
        _loaded_at = time.time()


def catalog() -> dict[str, Any] | None:
    """``{"kbs": {KB: [CVE]}, "exploited": [CVE]}`` or None while not loaded."""
    with _lock:
        return _catalog or None


def exploited_set(data: dict[str, Any] | None) -> set[str]:
    return set((data or {}).get("exploited", ()))


def refresh() -> bool:
    kbs: dict[str, set[str]] = {}
    exploited: set[str] = set()
    try:
        index = httpx.get(INDEX_URL, headers=HEADERS, timeout=60).json()["value"]
        index.sort(key=lambda item: str(item.get("InitialReleaseDate", "")), reverse=True)
        for month in index[: months_to_load()]:
            document = httpx.get(month["CvrfUrl"], headers=HEADERS, timeout=180, follow_redirects=True).json()
            parse_document(document, kbs, exploited)
            del document  # free ~100 MB before the next month
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        LOGGER.warning("No se pudo actualizar el boletin de Microsoft: %s", type(exc).__name__)
        return False
    if not kbs:
        return False
    load(kbs, exploited)
    try:
        _cache_file().write_text(json.dumps(catalog()), encoding="utf-8")
    except OSError:
        pass
    return True


def _run() -> None:
    cache = _cache_file()
    try:
        if cache.is_file() and time.time() - cache.stat().st_mtime < REFRESH_SECONDS:
            saved = json.loads(cache.read_text(encoding="utf-8"))
            load({kb: set(cves) for kb, cves in saved["kbs"].items()}, set(saved["exploited"]))
    except (OSError, ValueError, KeyError):
        pass
    while True:
        if catalog() is None or time.time() - _loaded_at >= REFRESH_SECONDS:
            refresh()
        # Retry soon while there is no data at all; otherwise check hourly.
        time.sleep(5 * 60 if catalog() is None else 60 * 60)


def start_refresher() -> None:
    global _started
    if _started or os.getenv("MSRC_DISABLED", "").lower() in {"1", "true", "yes"}:
        return
    _started = True
    threading.Thread(target=_run, name="cybercheck-msrc", daemon=True).start()
