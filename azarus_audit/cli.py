#!/usr/bin/env python3
"""
azarus-audit - CLI d'audit de securite.

Usage :
    python -m azarus_audit.cli scan <chemin> [--json rapport.json] [--triage]
    python -m azarus_audit.cli scan .        # audite le dossier courant

Codes de sortie :
    0 = aucun finding
    1 = findings detectes
    2 = erreur d'usage
"""
import argparse
import json
import sys

from .scanner import scan_path, summarize
from . import __version__

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_SEV_LABEL = {"critical": "CRITIQUE", "high": "ELEVE", "medium": "MOYEN", "low": "FAIBLE"}


def _print_report(results):
    if not results:
        print("Aucune vulnerabilite detectee.")
        return
    for path in sorted(results):
        findings = sorted(results[path], key=lambda f: (_SEV_ORDER.get(f.severity, 9), f.line))
        print(f"\n{path}")
        for f in findings:
            tag = " (IA)" if getattr(f, "source", "") == "ai" else ""
            print(f"  [{_SEV_LABEL.get(f.severity, f.severity):>8}] {f.cwe:<8} "
                  f"L{f.line:<4} {f.name}{tag}")
            print(f"           {f.message}")
            if f.snippet:
                print(f"           > {f.snippet}")
    s = summarize(results)
    print("\n" + "=" * 60)
    print(f"  {s['total_findings']} finding(s) dans {s['files_with_findings']} fichier(s)")
    if s["by_severity"]:
        parts = [f"{_SEV_LABEL.get(k, k)}={v}" for k, v in
                 sorted(s["by_severity"].items(), key=lambda kv: _SEV_ORDER.get(kv[0], 9))]
        print("  Severite : " + ", ".join(parts))
    if s["by_cwe"]:
        print("  CWE : " + ", ".join(f"{k}={v}" for k, v in sorted(s["by_cwe"].items())))
    print("=" * 60)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="azarus-audit", description="Auditeur de securite open-source.")
    ap.add_argument("--version", action="version", version=f"azarus-audit {__version__}")
    sub = ap.add_subparsers(dest="cmd")

    p_scan = sub.add_parser("scan", help="Analyser un fichier ou un dossier.")
    p_scan.add_argument("path", help="Fichier ou dossier a auditer.")
    p_scan.add_argument("--json", metavar="FICHIER", help="Ecrire le rapport JSON.")
    p_scan.add_argument("--sarif", metavar="FICHIER",
                        help="Ecrire un rapport SARIF 2.1.0 (GitHub code scanning, IDE).")
    p_scan.add_argument("--markdown", metavar="FICHIER",
                        help="Ecrire un rapport Markdown (commentaire de PR, resume CI).")
    p_scan.add_argument("--triage", action="store_true",
                        help="Ajouter une explication du modele Azarus (necessite l'endpoint).")
    p_scan.add_argument("--ai", action="store_true",
                        help="Moteur IA : le modele cherche aussi des failles (findings marques IA).")
    p_scan.add_argument("--experts-config", metavar="FICHIER",
                        help="Config JSON des experts IA (routage multi-adaptateurs). "
                             "A defaut, variable AZARUS_EXPERTS puis modele unique.")
    p_scan.add_argument("--expert", metavar="NOM",
                        help="Forcer un expert (nom de modele servi) pour --ai et --triage, "
                             "en court-circuitant le routage automatique.")
    p_scan.add_argument("--fail-on", default="low",
                        choices=["critical", "high", "medium", "low", "never"],
                        help="Severite minimale qui fait echouer la commande (defaut: low).")

    p_dash = sub.add_parser("dashboard", help="Tableau de bord live (scan unique, necessite rich).")
    p_dash.add_argument("path", help="Fichier ou dossier a auditer.")

    p_con = sub.add_parser("console",
                           help="Console interactive 4 quadrants permanents (necessite prompt_toolkit).")
    p_con.add_argument("path", nargs="?", default=".",
                       help="Chemin a scanner au demarrage (optionnel).")

    p_deps = sub.add_parser("deps",
                            help="Detecter les dependances vulnerables via la base mondiale OSV.dev.")
    p_deps.add_argument("path", nargs="?", default=".",
                        help="Projet ou requirements.txt (defaut: dossier courant).")
    p_deps.add_argument("--installed", action="store_true",
                        help="Analyser les paquets installes plutot que requirements.txt.")
    p_deps.add_argument("--json", metavar="FICHIER", help="Ecrire le rapport JSON.")

    args = ap.parse_args(argv)

    if args.cmd == "deps":
        from .deps import scan_project_deps
        from .ascii_art import print_banner
        print_banner()
        vulns = scan_project_deps(args.path, use_installed=args.installed)
        if not vulns:
            print("\nAucune dependance vulnerable connue (source : OSV.dev).")
        else:
            print()
            for v in vulns:
                print(f"  [{v.severity:>8}] {v.package}=={v.version}  {v.id}")
                print(f"           {v.summary}")
                print(f"           corrige dans : {v.fixed}")
            print("\n" + "=" * 60)
            print(f"  {len(vulns)} vulnerabilite(s) connue(s) dans les dependances")
            print("=" * 60)
        if args.json:
            with open(args.json, "w", encoding="utf-8") as fh:
                json.dump([v.to_dict() for v in vulns], fh, ensure_ascii=False, indent=2)
            print(f"Rapport JSON : {args.json}")
        return 1 if vulns else 0

    if args.cmd == "dashboard":
        try:
            from .dashboard import run_dashboard
        except ImportError:
            print("Le tableau de bord necessite 'rich' : pip install rich", file=sys.stderr)
            return 2
        return run_dashboard(args.path)

    if args.cmd == "console":
        try:
            from .tui import run_console
        except ImportError:
            print("La console necessite 'prompt_toolkit' : pip install prompt_toolkit", file=sys.stderr)
            return 2
        return run_console(args.path)

    if args.cmd != "scan":
        ap.print_help()
        return 2

    from .ascii_art import print_banner
    print_banner()
    print()
    results = scan_path(args.path)

    expert_cfg = None
    if args.ai or args.triage:
        from .experts import load_config
        expert_cfg = load_config(args.experts_config)
        if expert_cfg.is_multi_expert() and not args.expert:
            print(f"Experts IA actifs : {', '.join(sorted(expert_cfg.models))}")

    if args.ai:
        from .ai_engine import ai_scan_source
        from .scanner import iter_files
        ai_files = [p for p in iter_files(args.path) if p.endswith(".py")][:20]
        for path in ai_files:
            try:
                code = open(path, encoding="utf-8", errors="ignore").read()
            except OSError:
                continue
            ai_findings = ai_scan_source(code, model=args.expert,
                                         config=expert_cfg, path=path)
            if ai_findings:
                results.setdefault(path, []).extend(ai_findings)

    triaged = {}
    if args.triage:
        from .triage import explain
        for path, findings in results.items():
            try:
                ctx = open(path, encoding="utf-8", errors="ignore").read()
            except OSError:
                ctx = ""
            for f in findings:
                note = explain(f, ctx, model=args.expert, config=expert_cfg)
                if note:
                    triaged[(path, f.line, f.cwe)] = note

    _print_report(results)
    if triaged:
        print("\nTriage Azarus :")
        for (path, line, cwe), note in triaged.items():
            print(f"  {path}:{line} {cwe} -> {note}")

    if args.json:
        payload = {
            "version": __version__,
            "summary": summarize(results),
            "results": {p: [f.to_dict() for f in fs] for p, fs in results.items()},
        }
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
        print(f"\nRapport JSON : {args.json}")

    if args.sarif:
        from .sarif import to_sarif
        with open(args.sarif, "w", encoding="utf-8") as fh:
            json.dump(to_sarif(results), fh, ensure_ascii=False, indent=2)
        print(f"Rapport SARIF : {args.sarif}")

    if args.markdown:
        from .report_md import to_markdown
        with open(args.markdown, "w", encoding="utf-8") as fh:
            fh.write(to_markdown(results))
        print(f"Rapport Markdown : {args.markdown}")

    if args.fail_on == "never" or not results:
        return 0
    threshold = _SEV_ORDER[args.fail_on]
    worst = min((_SEV_ORDER.get(f.severity, 9) for fs in results.values() for f in fs), default=9)
    return 1 if worst <= threshold else 0


if __name__ == "__main__":
    sys.exit(main())
