"""
Scanner de dependances vulnerables.

Croise les dependances d'un projet avec la base mondiale des vulnerabilites
open-source **OSV.dev** (qui agrege GitHub Advisory, PyPA, CVE, etc.). C'est le
mecanisme qui permet de detecter TOUTES les failles DEJA DECOUVERTES dans les
dependances - pas la logique metier, mais les composants tiers.

Sans dependance externe (stdlib seule). Necessite un acces reseau a api.osv.dev.
"""
import json
import os
import re
import urllib.request
from dataclasses import dataclass, asdict
from typing import List, Optional

_OSV_QUERY = "https://api.osv.dev/v1/query"
_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9._-]+)\s*==\s*([A-Za-z0-9._!+-]+)")


@dataclass
class DepVuln:
    package: str
    version: str
    id: str
    summary: str
    severity: str
    fixed: str

    def to_dict(self):
        return asdict(self)


def parse_requirements(path: str):
    """Renvoie [(nom, version)] pour les lignes epinglees `name==version`."""
    out = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                m = _REQ_LINE.match(line)
                if m:
                    out.append((m.group(1), m.group(2)))
    except OSError:
        pass
    return out


def find_requirements(root: str) -> List[str]:
    if os.path.isfile(root):
        return [root]
    hits = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in {".git", "node_modules", ".venv", "venv"}]
        for fn in filenames:
            if fn == "requirements.txt" or (fn.startswith("requirements") and fn.endswith(".txt")):
                hits.append(os.path.join(dirpath, fn))
    return hits


def installed_packages():
    """Dependances reellement installees dans l'environnement courant."""
    try:
        from importlib import metadata
    except ImportError:
        return []
    out = []
    for dist in metadata.distributions():
        name = dist.metadata["Name"]
        ver = dist.version
        if name and ver:
            out.append((name, ver))
    return out


def _cvss_label(vector: str) -> str:
    """Etiquette grossiere a partir d'un vecteur CVSS (impact eleve -> HIGH)."""
    high = any(m in vector for m in ("/C:H", "/I:H", "/A:H", "VC:H", "VI:H", "VA:H"))
    low = any(m in vector for m in ("/C:L", "/I:L", "/A:L", "VC:L", "VI:L", "VA:L"))
    if high:
        return "HIGH"
    if low:
        return "MEDIUM"
    return "LOW"


def _extract(vuln: dict) -> dict:
    summary = vuln.get("summary") or (vuln.get("details", "").split("\n", 1)[0])
    sev = vuln.get("database_specific", {}).get("severity", "")
    if not sev:
        for s in vuln.get("severity", []) or []:
            score = s.get("score", "")
            sev = _cvss_label(score) if score.startswith("CVSS") else score
            break
    fixed = set()
    for aff in vuln.get("affected", []) or []:
        for rng in aff.get("ranges", []) or []:
            for ev in rng.get("events", []) or []:
                if "fixed" in ev:
                    fixed.add(ev["fixed"])
    return {"summary": summary[:160], "severity": sev or "?",
            "fixed": ", ".join(sorted(fixed)) or "?"}


def query_osv(name: str, version: str, ecosystem: str = "PyPI", timeout: int = 25) -> List[dict]:
    body = json.dumps({"package": {"name": name, "ecosystem": ecosystem},
                       "version": version}).encode()
    req = urllib.request.Request(_OSV_QUERY, data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r).get("vulns", []) or []
    except Exception:
        return []


def scan_dependencies(packages, ecosystem: str = "PyPI") -> List[DepVuln]:
    """packages = [(nom, version)]. Renvoie la liste des vulnerabilites connues."""
    found = []
    seen = set()
    for name, version in packages:
        key = (name.lower(), version)
        if key in seen:
            continue
        seen.add(key)
        for vuln in query_osv(name, version, ecosystem):
            info = _extract(vuln)
            found.append(DepVuln(package=name, version=version, id=vuln.get("id", "?"),
                                 summary=info["summary"], severity=info["severity"],
                                 fixed=info["fixed"]))
    return found


def scan_project_deps(root: str, use_installed: bool = False) -> List[DepVuln]:
    if use_installed:
        packages = installed_packages()
    else:
        packages = []
        for req in find_requirements(root):
            packages.extend(parse_requirements(req))
    return scan_dependencies(packages)
