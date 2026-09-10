#!/usr/bin/env python3
"""
Harnais de mesure reproductible pour azarus_audit.

Execute le scanner deterministe sur chaque cas etiquete et calcule
precision / rappel / F1 au niveau des CWE, plus le detail par cas.

Usage :
    python -m azarus_audit.benchmark.run [--json rapport.json] [--md rapport.md]
"""
import argparse
import json
import os
import sys

# Permet l'execution directe (python azarus_audit/benchmark/run.py).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from azarus_audit.detectors import scan_source  # noqa: E402
from azarus_audit.benchmark.cases import CASES   # noqa: E402


def run():
    tp = fp = fn = 0
    rows = []
    for case in CASES:
        detected = sorted({f.cwe for f in scan_source(case["code"], case["language"])})
        expected = sorted(set(case["expected"]))
        d, e = set(detected), set(expected)
        c_tp, c_fp, c_fn = len(e & d), len(d - e), len(e - d)
        tp += c_tp
        fp += c_fp
        fn += c_fn
        ok = (d == e)
        rows.append({"id": case["id"], "expected": expected, "detected": detected,
                     "ok": ok, "tp": c_tp, "fp": c_fp, "fn": c_fn})

    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    exact = sum(1 for r in rows if r["ok"])

    summary = {
        "cases": len(CASES),
        "exact_case_match": exact,
        "cwe_true_positives": tp,
        "cwe_false_positives": fp,
        "cwe_false_negatives": fn,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
    }
    return summary, rows


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", metavar="FICHIER")
    ap.add_argument("--md", metavar="FICHIER")
    args = ap.parse_args(argv)

    summary, rows = run()

    print("Benchmark azarus_audit (detecteurs deterministes)")
    print("=" * 60)
    for r in rows:
        status = "OK " if r["ok"] else "XX "
        print(f"  {status} {r['id']:<22} attendu={r['expected']} detecte={r['detected']}")
    print("=" * 60)
    print(f"  Cas               : {summary['cases']}")
    print(f"  Correspondance ex.: {summary['exact_case_match']}/{summary['cases']}")
    print(f"  Precision         : {summary['precision']}")
    print(f"  Rappel            : {summary['recall']}")
    print(f"  F1                : {summary['f1']}")
    print(f"  (TP={summary['cwe_true_positives']} "
          f"FP={summary['cwe_false_positives']} FN={summary['cwe_false_negatives']})")
    print("=" * 60)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"summary": summary, "rows": rows}, f, ensure_ascii=False, indent=2)
        print(f"JSON : {args.json}")
    if args.md:
        lines = ["# Benchmark azarus_audit", "",
                 f"- Cas : {summary['cases']}",
                 f"- Correspondance exacte : {summary['exact_case_match']}/{summary['cases']}",
                 f"- Precision : {summary['precision']}",
                 f"- Rappel : {summary['recall']}",
                 f"- F1 : {summary['f1']}",
                 "", "| Cas | Attendu | Detecte | OK |", "|---|---|---|---|"]
        for r in rows:
            lines.append(f"| {r['id']} | {r['expected']} | {r['detected']} | "
                         f"{'oui' if r['ok'] else 'NON'} |")
        with open(args.md, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        print(f"MD : {args.md}")

    # Sortie non nulle si des faux negatifs (utile en CI).
    return 0 if summary["cwe_false_negatives"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
