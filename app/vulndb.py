"""Vulnerability intelligence for installed software and pending Windows patches.

Three sources, each honest about what it can prove:

* Windows Update itself reports which CVEs every missing patch fixes.
* A small CURATED table (product, fixed-in version, CVEs, end-of-life) for
  widely used tools. It is deliberately short: every entry has a verifiable
  fixed version. Extend it with a JSON file (see ``VULN_DB_PATH``).
* CISA KEV marks which of those CVEs are being exploited in the wild.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Entry:
    pattern: str
    product: str
    fixed_in: str | None  # None means the product is end-of-life
    cves: tuple[str, ...]
    summary: str
    winget_id: str | None = None


CURATED: tuple[Entry, ...] = (
    Entry(r"^winrar\b", "WinRAR", "7.13", ("CVE-2025-6218", "CVE-2025-8088"),
          "Ruta de archivos manipulada al abrir un RAR: permite ejecutar codigo (explotada por grupos de ataque).",
          "RARLab.WinRAR"),
    Entry(r"^7-zip\b", "7-Zip", "24.09", ("CVE-2025-0411",),
          "Evade la marca de descarga de Windows (Mark-of-the-Web) al abrir archivos comprimidos.", "7zip.7zip"),
    Entry(r"^7-zip\b", "7-Zip", "25.00", ("CVE-2025-11001", "CVE-2025-11002"),
          "Enlaces simbolicos en un ZIP permiten escribir archivos fuera de la carpeta y ejecutar codigo.", "7zip.7zip"),
    Entry(r"^7-zip\b", "7-Zip", "25.01", ("CVE-2025-55188",),
          "Escritura arbitraria de archivos al extraer un archivo manipulado.", "7zip.7zip"),
    Entry(r"^putty\b", "PuTTY", "0.81", ("CVE-2024-31497",),
          "Claves ECDSA NIST P-521 recuperables: un atacante puede suplantar al usuario en servidores SSH.",
          "PuTTY.PuTTY"),
    Entry(r"^notepad\+\+", "Notepad++", "8.8.2", ("CVE-2025-49144",),
          "El instalador permite escalar privilegios a SYSTEM.", "Notepad++.Notepad++"),
    # End-of-life software: no security fix will ever be published.
    Entry(r"^adobe flash player", "Adobe Flash Player", None, (),
          "Flash termino su soporte el 31/12/2020 y Adobe bloqueo su ejecucion; tiene fallas sin corregir."),
    Entry(r"^microsoft silverlight", "Microsoft Silverlight", None, (),
          "Silverlight dejo de recibir actualizaciones de seguridad el 12/10/2021."),
    Entry(r"^apple quicktime|^quicktime", "QuickTime para Windows", None, (),
          "Apple lo descontinuo en 2016; sus vulnerabilidades conocidas nunca se corrigieron."),
    Entry(r"^python 2\.", "Python 2", None, (),
          "Python 2 termino su soporte el 01/01/2020 y ya no recibe parches de seguridad."),
)

VERSION = re.compile(r"\d+(?:\.\d+)*")


def parse_version(value: Any) -> tuple[int, ...] | None:
    match = VERSION.search(str(value or ""))
    return tuple(int(part) for part in match.group(0).split(".")) if match else None


def version_lt(left: tuple[int, ...], right: tuple[int, ...]) -> bool:
    size = max(len(left), len(right))
    return left + (0,) * (size - len(left)) < right + (0,) * (size - len(right))


def entries() -> tuple[Entry, ...]:
    """Built-in entries plus any in the JSON file named by VULN_DB_PATH."""
    path = os.getenv("VULN_DB_PATH")
    if not path or not Path(path).is_file():
        return CURATED
    try:
        extra = json.loads(Path(path).read_text(encoding="utf-8"))
        return CURATED + tuple(
            Entry(
                str(item["pattern"]).lower(), str(item["product"]), item.get("fixed_in"),
                tuple(str(cve).upper() for cve in item.get("cves", [])), str(item.get("summary", "")),
                item.get("winget_id"),
            )
            for item in extra if isinstance(item, dict) and item.get("pattern") and item.get("product")
        )
    except (OSError, ValueError, KeyError, TypeError):
        return CURATED


def match_software(software: list[Any]) -> list[dict[str, Any]]:
    """Installed programs affected by a curated entry, grouped per program."""
    found: dict[tuple[str, str], dict[str, Any]] = {}
    for program in software:
        if not isinstance(program, dict):
            continue
        name = str(program.get("name") or "")
        installed = parse_version(program.get("version")) or parse_version(name)
        for entry in entries():
            if not re.search(entry.pattern, name.strip().lower()):
                continue
            if entry.fixed_in is not None:
                fixed = parse_version(entry.fixed_in)
                if installed is None or fixed is None or not version_lt(installed, fixed):
                    continue
            key = (entry.product, str(program.get("version") or ""))
            item = found.setdefault(key, {
                "product": entry.product, "installed": program.get("version") or "desconocida",
                "name": name, "fixed_in": None, "eol": False, "cves": [], "summaries": [], "winget_id": entry.winget_id,
                "by_cve": {},
            })
            for cve in entry.cves:
                item["by_cve"][cve] = {"summary": entry.summary, "fixed_in": entry.fixed_in}
            if entry.fixed_in is None:
                item["eol"] = True
            elif item["fixed_in"] is None or version_lt(parse_version(item["fixed_in"]), parse_version(entry.fixed_in)):
                item["fixed_in"] = entry.fixed_in
            item["cves"] = sorted(set(item["cves"]) | set(entry.cves))
            item["summaries"].append(entry.summary)
    return list(found.values())


def pending_update_cves(updates: Any, msrc: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """CVEs fixed by the missing Windows patches.

    Combines what Windows Update reports with Microsoft's bulletin map
    (KB -> CVE), which is the reliable source for cumulative updates.
    """
    items = updates.get("pending_updates") if isinstance(updates, dict) else None
    known = (msrc or {}).get("kbs", {})
    result = []
    for update in items or []:
        if not isinstance(update, dict):
            continue
        kbs = [part.strip().upper() for part in str(update.get("kb") or "").split(",") if part.strip()]
        cves = {str(cve).upper() for cve in update.get("cves") or []}
        for kb in kbs:
            cves |= set(known.get(kb, ()))
        for cve in sorted(cves):
            result.append({"cve": cve, "kb": ", ".join(kbs) or None, "title": update.get("title"),
                           "severity": update.get("severity")})
    return result


def exploited_by(cve: str, kev: dict[str, dict[str, Any]] | None, msrc: dict[str, Any] | None) -> list[str]:
    sources = []
    if cve in (kev or {}):
        sources.append("CISA KEV")
    if cve in set((msrc or {}).get("exploited", ())):
        sources.append("Microsoft")
    return sources


MAX_ROWS = 500


def device_vulnerabilities(
    updates: Any, software: Any, kev: dict[str, dict[str, Any]] | None, msrc: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    """Flat list shown in the panel: one row per CVE (or end-of-life product).

    ``kev`` in each row means "exploited in the wild" according to CISA or
    Microsoft; ``exploited_by`` names which.
    """
    kev = kev or {}
    rows: list[dict[str, Any]] = []

    def exploited(cve: str) -> dict[str, Any]:
        info = kev.get(cve) or {}
        sources = exploited_by(cve, kev, msrc)
        return {"kev": bool(sources), "exploited_by": sources, "ransomware": bool(info.get("ransomware")),
                "kev_added": info.get("added")}

    for item in pending_update_cves(updates, msrc):
        rows.append({
            "cve": item["cve"], "source": "Windows Update", "product": "Windows / Microsoft",
            "installed": None, "fixed_in": item["kb"], "severity": item["severity"], "summary": item["title"],
            **exploited(item["cve"]),
        })
    for match in match_software(software if isinstance(software, list) else []):
        if match["eol"] and not match["cves"]:
            rows.append({
                "cve": None, "source": "Fin de soporte", "product": match["product"], "installed": match["installed"],
                "fixed_in": None, "severity": "Alto", "summary": match["summaries"][0],
                "kev": False, "exploited_by": [], "ransomware": False, "kev_added": None,
            })
        for cve in match["cves"]:
            detail = match["by_cve"].get(cve, {})
            rows.append({
                "cve": cve, "source": "Base curada", "product": match["product"], "installed": match["installed"],
                "fixed_in": detail.get("fixed_in") or match["fixed_in"], "severity": "Alto",
                "summary": detail.get("summary") or match["summaries"][0],
                **exploited(cve),
            })
    rows.sort(key=lambda row: (not row["kev"], row["cve"] or "~"))
    return rows[:MAX_ROWS]
