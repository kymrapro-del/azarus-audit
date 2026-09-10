#!/usr/bin/env python3
"""
Evaluation du scanner sur un VRAI jeu de donnees externe (code Python public).

Mesure, sur des paires reelles code vulnerable / code corrige :
  - taux de detection : part du code VULNERABLE ou le scanner leve au moins un finding ;
  - taux de faux positifs : part du code SUR (corrige) ou il leve un finding.

Note d'honnetete : le code "sur" du dataset n'est corrige que pour UNE faille
precise ; il peut contenir d'autres motifs risquables. Le taux de faux positifs
est donc un MAJORANT, pas une mesure pure.

Usage :
    python -m azarus_audit.benchmark.external [--max-rows 3000] [--md rapport.md]
Telecharge automatiquement les donnees si le cache est absent.
"""
import argparse
import json
import os

from azarus_audit.detectors import scan_source
from azarus_audit.benchmark.fetch_external import fetch_python_samples, _DEFAULT_OUT


def _load(path, max_rows):
    if not os.path.exists(path):
        fetch_python_samples(max_rows, path)
    vuln, safe = [], []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            (vuln if rec["kind"] == "vuln" else safe).append(rec["code"])
    return vuln, safe


_HIGH = {"critical", "high"}


def _has_finding(code, high_only=False):
    try:
        fs = scan_source(code, "python")
    except Exception:
        return False
    if high_only:
        fs = [f for f in fs if f.severity in _HIGH]
    return len(fs) > 0


def evaluate(path=_DEFAULT_OUT, max_rows=3000):
    vuln, safe = _load(path, max_rows)
    n_v, n_s = len(vuln), len(safe)

    def rates(high_only):
        tp = sum(1 for c in vuln if _has_finding(c, high_only))
        fp = sum(1 for c in safe if _has_finding(c, high_only))
        return {
            "detected": tp, "false_positives": fp,
            "detection_rate_pct": round(tp / n_v * 100, 1) if n_v else 0.0,
            "false_positive_rate_pct": round(fp / n_s * 100, 1) if n_s else 0.0,
        }

    return {"dataset": "CyberNative/Code_Vulnerability_Security_DPO (Python)",
            "n_vuln": n_v, "n_safe": n_s,
            "all": rates(False), "high": rates(True)}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-rows", type=int, default=3000)
    ap.add_argument("--cache", default=_DEFAULT_OUT)
    ap.add_argument("--md", default=os.path.join(os.path.dirname(__file__), "external_report.md"))
    args = ap.parse_args(argv)

    m = evaluate(args.cache, args.max_rows)
    a, h = m["all"], m["high"]
    print("Evaluation externe (Python) sur donnees publiques reelles")
    print("=" * 62)
    print(f"  Dataset       : {m['dataset']}")
    print(f"  Echantillons  : {m['n_vuln']} vulnerables + {m['n_safe']} surs")
    print("  --- toutes severites ---")
    print(f"  DETECTION     : {a['detected']}/{m['n_vuln']} = {a['detection_rate_pct']}%")
    print(f"  FAUX POSITIFS : {a['false_positives']}/{m['n_safe']} = {a['false_positive_rate_pct']}% (majorant)")
    print("  --- tier actionnable (critique + eleve) ---")
    print(f"  DETECTION     : {h['detected']}/{m['n_vuln']} = {h['detection_rate_pct']}%")
    print(f"  FAUX POSITIFS : {h['false_positives']}/{m['n_safe']} = {h['false_positive_rate_pct']}% (majorant)")
    print("=" * 62)

    lines = [
        "# Evaluation externe du scanner (donnees publiques reelles)",
        "",
        f"- Source : `{m['dataset']}` (Hugging Face)",
        f"- Echantillons Python : {m['n_vuln']} vulnerables + {m['n_safe']} surs",
        "",
        "## Toutes severites",
        f"- Detection : **{a['detected']}/{m['n_vuln']} = {a['detection_rate_pct']}%**",
        f"- Faux positifs : **{a['false_positives']}/{m['n_safe']} = "
        f"{a['false_positive_rate_pct']}%** (majorant)",
        "",
        "## Tier actionnable (severite critique + eleve)",
        f"- Detection : **{h['detected']}/{m['n_vuln']} = {h['detection_rate_pct']}%**",
        f"- Faux positifs : **{h['false_positives']}/{m['n_safe']} = "
        f"{h['false_positive_rate_pct']}%** (majorant)",
        "",
        "> Le code \"sur\" n'est corrige que pour une faille precise ; il peut",
        "> contenir d'autres motifs risquables. Le taux de faux positifs est donc",
        "> un majorant. Reproductible : `python -m azarus_audit.benchmark.external`.",
    ]
    with open(args.md, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"Rapport : {args.md}")


if __name__ == "__main__":
    main()
