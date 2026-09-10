"""Parcours de fichiers et agregation des findings."""
import os
from typing import List, Dict

from .detectors import Finding, scan_source

# Extensions analysees en AST (Python) vs. en regex-secrets seulement.
_PY_EXT = {".py", ".pyw"}
_TEXT_EXT = {".py", ".pyw", ".js", ".ts", ".java", ".go", ".rb", ".php", ".c",
             ".cpp", ".cs", ".sh", ".yaml", ".yml", ".json", ".env", ".txt",
             ".cfg", ".ini", ".toml", ".tf", ".jsonl"}
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist",
              "build", ".mypy_cache", ".pytest_cache"}
_MAX_BYTES = 1_000_000  # 1 Mo par fichier


def iter_files(root: str) -> List[str]:
    """Liste les fichiers analysables sous `root` (fichier ou dossier)."""
    if os.path.isfile(root):
        return [root]
    out: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            if os.path.splitext(fn)[1].lower() in _TEXT_EXT:
                out.append(os.path.join(dirpath, fn))
    return out


def scan_one(path: str) -> List[Finding]:
    """Analyse un seul fichier et renvoie ses findings (liste vide si aucun)."""
    try:
        if os.path.getsize(path) > _MAX_BYTES:
            return []
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
    except OSError:
        return []
    language = "python" if os.path.splitext(path)[1].lower() in _PY_EXT else "generic"
    return scan_source(text, language=language)


def scan_path(root: str) -> Dict[str, List[Finding]]:
    """Analyse un fichier ou un dossier. Renvoie {chemin: [findings]}."""
    results: Dict[str, List[Finding]] = {}
    for path in iter_files(root):
        findings = scan_one(path)
        if findings:
            results[path] = findings
    return results


def summarize(results: Dict[str, List[Finding]]) -> Dict:
    """Statistiques agregees pour le rapport."""
    by_severity: Dict[str, int] = {}
    by_cwe: Dict[str, int] = {}
    total = 0
    for findings in results.values():
        for f in findings:
            total += 1
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
            by_cwe[f.cwe] = by_cwe.get(f.cwe, 0) + 1
    return {
        "files_with_findings": len(results),
        "total_findings": total,
        "by_severity": by_severity,
        "by_cwe": by_cwe,
    }
