"""
Rapport Markdown des findings (commentaire de PR, resume de job GitHub).

Deterministe, sans dependance : sert a la GitHub Action azarus-audit.
"""
from typing import Dict, List

from .detectors import Finding
from .scanner import summarize

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_SEV_LABEL = {
    "critical": "CRITIQUE",
    "high": "ELEVE",
    "medium": "MOYEN",
    "low": "FAIBLE",
}
_SEV_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}

# Marqueur : permet a la CI de retrouver et mettre a jour SON commentaire.
MARKER = "<!-- azarus-audit-report -->"


def to_markdown(results: Dict[str, List[Finding]]) -> str:
    """Rend un rapport Markdown lisible dans un commentaire de PR."""
    lines = [MARKER, "## 🛡️ azarus-audit : rapport de sécurité", ""]

    if not results:
        lines.append("✅ **Aucune vulnérabilité détectée.**")
        lines.append("")
        lines.append("_Analyse déterministe (AST + flux + secrets), hors-ligne._")
        return "\n".join(lines)

    s = summarize(results)
    by_sev = s["by_severity"]
    counts = ", ".join(
        f"{_SEV_EMOJI.get(k, '')} {_SEV_LABEL.get(k, k)} : {by_sev[k]}"
        for k in sorted(by_sev, key=lambda k: _SEV_ORDER.get(k, 9))
    )
    lines.append(
        f"**{s['total_findings']} vulnérabilité(s)** dans "
        f"{s['files_with_findings']} fichier(s). {counts}"
    )
    lines.append("")

    for path in sorted(results):
        findings = sorted(
            results[path],
            key=lambda f: (_SEV_ORDER.get(f.severity, 9), f.line),
        )
        lines.append(f"### `{path}`")
        lines.append("")
        lines.append("| Sévérité | CWE | Ligne | Vulnérabilité |")
        lines.append("|---|---|---|---|")
        for f in findings:
            emoji = _SEV_EMOJI.get(f.severity, "")
            label = _SEV_LABEL.get(f.severity, f.severity)
            src = " _(IA)_" if getattr(f, "source", "") == "ai" else ""
            cwe_link = (
                f"[{f.cwe}](https://cwe.mitre.org/data/definitions/"
                f"{f.cwe.split('-')[-1]}.html)"
            )
            msg = f.message.replace("|", "\\|")
            lines.append(
                f"| {emoji} {label} | {cwe_link} | {f.line} | "
                f"{f.name}{src}<br>{msg} |"
            )
        lines.append("")

    lines.append("---")
    lines.append(
        "_Analyse déterministe (AST + flux + secrets), hors-ligne. "
        "[azarus-audit](https://github.com/kymrapro-del/azarus-ai)._"
    )
    return "\n".join(lines)
