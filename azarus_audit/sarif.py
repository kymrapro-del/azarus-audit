"""
Export SARIF 2.1.0 des findings.

SARIF est le format standard des outils d'analyse statique ; il s'integre
directement a GitHub code scanning (onglet Security) et aux IDE.
"""
from typing import Dict, List

from .detectors import Finding
from . import __version__

# Severite SARIF (level) + score numerique GitHub (security-severity).
_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
_SCORE = {"critical": "9.5", "high": "8.0", "medium": "5.0", "low": "3.0"}
_INFO_URI = "https://github.com/kymrapro-del/azarus-ai"


def to_sarif(results: Dict[str, List[Finding]]) -> dict:
    rules_by_id: dict = {}
    sarif_results = []

    for path, findings in results.items():
        for f in findings:
            if f.cwe not in rules_by_id:
                rules_by_id[f.cwe] = {
                    "id": f.cwe,
                    "name": f.name,
                    "shortDescription": {"text": f.name},
                    "helpUri": f"https://cwe.mitre.org/data/definitions/{f.cwe.split('-')[-1]}.html",
                    "properties": {"security-severity": _SCORE.get(f.severity, "5.0")},
                }
            sarif_results.append({
                "ruleId": f.cwe,
                "level": _LEVEL.get(f.severity, "warning"),
                "message": {"text": f"{f.name}: {f.message}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": path},
                        "region": {"startLine": max(f.line, 1)},
                    }
                }],
                "properties": {"confidence": f.confidence, "severity": f.severity},
            })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "azarus-audit",
                "version": __version__,
                "informationUri": _INFO_URI,
                "rules": list(rules_by_id.values()),
            }},
            "results": sarif_results,
        }],
    }
