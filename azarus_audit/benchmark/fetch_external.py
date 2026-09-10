#!/usr/bin/env python3
"""
Recupere un vrai jeu de donnees public de vulnerabilites pour valider le scanner
sur du code externe (pas notre propre corpus).

Source : dataset Hugging Face `CyberNative/Code_Vulnerability_Security_DPO`
(paires code vulnerable / code corrige, multi-langage). On ne garde que Python.
On telecharge a la demande via l'API datasets-server ; rien n'est redistribue
dans le depot (seuls les chiffres agreges le sont).

Usage :
    python -m azarus_audit.benchmark.fetch_external [--max-rows 3000] [--out FICHIER]
"""
import argparse
import json
import os
import re
import urllib.parse
import urllib.request

_DATASET = "CyberNative/Code_Vulnerability_Security_DPO"
_BASE = "https://datasets-server.huggingface.co/rows"
_DEFAULT_OUT = os.path.join(os.path.dirname(__file__), "_external_cache.jsonl")


def _fetch_rows(offset, length=100, timeout=40):
    url = (f"{_BASE}?dataset={urllib.parse.quote(_DATASET, safe='')}"
           f"&config=default&split=train&offset={offset}&length={length}")
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.load(r)["rows"]


def _extract_code(md):
    if not md:
        return ""
    m = re.search(r"```[A-Za-z0-9_+-]*\s*(.*?)```", md, re.S)
    return (m.group(1) if m else md).strip()


def fetch_python_samples(max_rows=3000, out_path=_DEFAULT_OUT):
    """Ecrit un jsonl {code, kind, label}. kind = 'vuln' | 'safe'."""
    n_vuln = n_safe = offset = 0
    with open(out_path, "w", encoding="utf-8") as f:
        while offset < max_rows:
            try:
                rows = _fetch_rows(offset)
            except Exception as e:
                print(f"Arret (reseau) a offset={offset} : {e}")
                break
            if not rows:
                break
            for r in rows:
                row = r["row"]
                if (row.get("lang") or "").lower() != "python":
                    continue
                label = row.get("vulnerability") or ""
                v = _extract_code(row.get("rejected"))
                s = _extract_code(row.get("chosen"))
                if v:
                    f.write(json.dumps({"code": v, "kind": "vuln", "label": label},
                                       ensure_ascii=False) + "\n")
                    n_vuln += 1
                if s:
                    f.write(json.dumps({"code": s, "kind": "safe", "label": label},
                                       ensure_ascii=False) + "\n")
                    n_safe += 1
            offset += len(rows)
            if len(rows) < 100:
                break
    print(f"Python : {n_vuln} vulnerables + {n_safe} surs -> {out_path}")
    return out_path


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-rows", type=int, default=3000)
    ap.add_argument("--out", default=_DEFAULT_OUT)
    args = ap.parse_args(argv)
    fetch_python_samples(args.max_rows, args.out)


if __name__ == "__main__":
    main()
