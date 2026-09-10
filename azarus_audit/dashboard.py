#!/usr/bin/env python3
"""
Tableau de bord terminal en 4 quadrants egaux pour azarus-audit.

Ecran divise en quatre panneaux de taille identique, chacun avec un role precis :

    +-------------------------+-------------------------+
    |  1. PROGRESSION         |  2. VULNERABILITES      |
    |  (fichiers, barre, %)   |  (flux des findings)    |
    +-------------------------+-------------------------+
    |  3. LOGS                |  4. RESUME              |
    |  (activite horodatee)   |  (compteurs sev / CWE)  |
    +-------------------------+-------------------------+

Usage :
    python -m azarus_audit.cli dashboard <chemin>
    python -m azarus_audit.dashboard <chemin>
"""
import os
import sys
import time
from collections import deque, Counter
from datetime import datetime

from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .scanner import iter_files, scan_one

_SEV_STYLE = {"critical": "bold white on red", "high": "bold red",
              "medium": "yellow", "low": "cyan"}
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_SEV_LABEL = {"critical": "CRITIQUE", "high": "ELEVE", "medium": "MOYEN", "low": "FAIBLE"}


def _build_layout() -> Layout:
    root = Layout()
    root.split_column(Layout(name="top", ratio=1), Layout(name="bottom", ratio=1))
    root["top"].split_row(Layout(name="progress", ratio=1), Layout(name="findings", ratio=1))
    root["bottom"].split_row(Layout(name="logs", ratio=1), Layout(name="summary", ratio=1))
    return root


def _bar(pct: float, width: int = 30) -> Text:
    filled = int(pct * width)
    t = Text()
    t.append("=" * filled, style="green")
    t.append("-" * (width - filled), style="grey37")
    return t


def _progress_panel(done, total, current) -> Panel:
    pct = (done / total) if total else 1.0
    body = Group(
        Text(f"Fichiers : {done}/{total}", style="bold"),
        _bar(pct),
        Text(f"{pct * 100:5.1f} %", style="bold green"),
        Text(""),
        Text("En cours :", style="grey58"),
        Text(current or "(termine)", style="cyan", overflow="ellipsis", no_wrap=True),
    )
    return Panel(body, title="1. Progression", border_style="green")


def _findings_panel(recent) -> Panel:
    table = Table.grid(padding=(0, 1))
    table.add_column(justify="left", no_wrap=True)
    table.add_column(justify="left", no_wrap=True)
    table.add_column(justify="left", overflow="ellipsis", no_wrap=True)
    if not recent:
        table.add_row(Text("Aucune vulnerabilite pour l'instant.", style="grey58"))
    for f, path in recent:
        loc = f"{os.path.basename(path)}:{f.line}"
        table.add_row(
            Text(f" {_SEV_LABEL.get(f.severity, f.severity)} ",
                 style=_SEV_STYLE.get(f.severity, "white")),
            Text(f.cwe, style="bold"),
            Text(f"{loc}  {f.name}", style="grey74"),
        )
    return Panel(table, title="2. Vulnerabilites", border_style="red")


def _logs_panel(lines) -> Panel:
    body = Text("\n".join(lines) or "En attente...", style="grey74",
                overflow="ellipsis", no_wrap=True)
    return Panel(body, title="3. Logs", border_style="blue")


def _summary_panel(sev_counts, cwe_counts, total) -> Panel:
    t = Table.grid(padding=(0, 2))
    t.add_column(justify="left")
    t.add_column(justify="right")
    t.add_row(Text("Total findings", style="bold"), Text(str(total), style="bold"))
    t.add_row(Text(""), Text(""))
    for sev in sorted(sev_counts, key=lambda s: _SEV_ORDER.get(s, 9)):
        t.add_row(Text(_SEV_LABEL.get(sev, sev), style=_SEV_STYLE.get(sev, "white")),
                  Text(str(sev_counts[sev])))
    if cwe_counts:
        t.add_row(Text(""), Text(""))
        for cwe, n in sorted(cwe_counts.items()):
            t.add_row(Text(cwe, style="grey74"), Text(str(n)))
    return Panel(t, title="4. Resume", border_style="magenta")


def run_dashboard(root_path: str, delay: float = 0.0) -> int:
    console = Console()
    files = iter_files(root_path)
    layout = _build_layout()

    recent = deque(maxlen=14)
    logs = deque(maxlen=14)
    sev_counts: Counter = Counter()
    cwe_counts: Counter = Counter()
    total = 0

    def stamp(msg):
        logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

    def render(done, current):
        layout["progress"].update(_progress_panel(done, len(files), current))
        layout["findings"].update(_findings_panel(list(recent)))
        layout["logs"].update(_logs_panel(list(logs)))
        layout["summary"].update(_summary_panel(sev_counts, cwe_counts, total))

    stamp(f"Cible : {root_path}")
    stamp(f"{len(files)} fichier(s) a analyser")
    render(0, "")

    with Live(layout, console=console, refresh_per_second=12, screen=True):
        for i, path in enumerate(files, 1):
            findings = scan_one(path)
            if findings:
                stamp(f"{len(findings)} finding(s) : {os.path.basename(path)}")
                for f in sorted(findings, key=lambda x: _SEV_ORDER.get(x.severity, 9)):
                    recent.append((f, path))
                    sev_counts[f.severity] += 1
                    cwe_counts[f.cwe] += 1
                    total += 1
            render(i, path)
            if delay:
                time.sleep(delay)
        stamp("Analyse terminee.")
        render(len(files), "")
        time.sleep(1.0)

    # Recapitulatif apres fermeture de l'ecran alternatif.
    console.print(f"\nTermine : {total} finding(s) dans {len(files)} fichier(s) analyse(s).")
    if sev_counts:
        parts = [f"{_SEV_LABEL.get(k, k)}={v}" for k, v in
                 sorted(sev_counts.items(), key=lambda kv: _SEV_ORDER.get(kv[0], 9))]
        console.print("Severite : " + ", ".join(parts))
    return 1 if total else 0


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print("Usage : python -m azarus_audit.dashboard <chemin>")
        return 2
    return run_dashboard(argv[0])


if __name__ == "__main__":
    sys.exit(main())
