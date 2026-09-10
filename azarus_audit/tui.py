#!/usr/bin/env python3
"""
Console interactive azarus-audit : 4 quadrants permanents.

    +-------------------------+-------------------------+
    |  1. COMMANDES           |  2. RESULTATS           |
    |  (invite ou tu tapes)   |  (findings du scan)     |
    +-------------------------+-------------------------+
    |  3. LOGS                |  4. RESUME              |
    |  (activite horodatee)   |  (compteurs sev / CWE)  |
    +-------------------------+-------------------------+

Les quatre fenetres restent affichees en permanence. La fenetre 1 (haut-gauche)
est une ligne de commande : on y tape des commandes, les trois autres reagissent.

Commandes : scan <chemin> | benchmark | help | clear | quit
Quitter : 'quit', ou Ctrl-Q, ou Ctrl-C.

Usage :
    python -m azarus_audit.cli console [chemin]
"""
from collections import deque, Counter
from datetime import datetime

from prompt_toolkit import Application
from prompt_toolkit.formatted_text import ANSI
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import HSplit, VSplit, Layout, Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.widgets import Frame, TextArea
from prompt_toolkit.styles import Style

from . import ascii_art
from .scanner import scan_path

# --- couleurs ANSI ---
C_CRIT = "\x1b[1;97;41m"           # blanc gras sur rouge
C_HIGH = "\x1b[38;5;208m"          # orange
C_MED = "\x1b[33m"                 # jaune
C_LOW = "\x1b[36m"                 # cyan
C_DIM = "\x1b[90m"                 # gris
C_ACC = "\x1b[38;2;16;185;129m"    # emeraude (accent rassurant)
C_B = "\x1b[1m"
C_R = "\x1b[0m"

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_SEV_LABEL = {"critical": "CRITIQUE", "high": "ELEVE", "medium": "MOYEN", "low": "FAIBLE"}
_SEV_COLOR = {"critical": C_CRIT, "high": C_HIGH, "medium": C_MED, "low": C_LOW}


def _welcome() -> str:
    art = "\n".join(f"{C_ACC}{C_B}{line}{C_R}" for line in ascii_art.render_word("AZARUS"))
    return (
        art
        + f"\n\n{C_ACC}{C_B}audit{C_R}{C_DIM}  ·  scanner de vulnerabilites CWE{C_R}\n\n"
        + f"{C_DIM}Tape une commande dans la fenetre 1 (haut-gauche) :{C_R}\n"
        + f"  {C_ACC}scan <chemin>{C_R}   analyser un fichier ou un dossier\n"
        + f"  {C_ACC}benchmark{C_R}       lancer le banc de test interne\n"
        + f"  {C_ACC}help{C_R}            afficher l'aide\n"
        + f"  {C_ACC}quit{C_R}            quitter (ou Ctrl-Q)"
    )


_HELP = (
    f"{C_ACC}{C_B}Commandes{C_R}\n"
    f"  {C_ACC}scan <chemin>{C_R}   analyser un fichier ou un dossier\n"
    f"  {C_ACC}benchmark{C_R}       lancer le banc de test interne\n"
    f"  {C_ACC}clear{C_R}           vider les panneaux\n"
    f"  {C_ACC}help{C_R}            afficher cette aide\n"
    f"  {C_ACC}quit{C_R} / {C_ACC}exit{C_R}     quitter (ou Ctrl-Q)"
)


class _State:
    def __init__(self):
        self.console = deque(maxlen=200)
        self.results = _welcome()
        self.logs = deque(maxlen=200)
        self.summary = f"{C_DIM}Aucun scan pour l'instant.{C_R}"
        self.console.append(f"{C_ACC}{C_B}azarus-audit{C_R} {C_DIM}console{C_R}")
        self.console.append(f"{C_DIM}Tape 'help' puis Entree.{C_R}")

    def log(self, msg):
        self.logs.append(f"{C_DIM}[{datetime.now().strftime('%H:%M:%S')}]{C_R} {msg}")


def _format_results(results) -> str:
    if not results:
        return f"{C_ACC}{C_B}Aucune vulnerabilite detectee.{C_R}\n{C_DIM}Le code analyse est propre.{C_R}"
    out = []
    for path in sorted(results):
        out.append(f"{C_B}{path}{C_R}")
        findings = sorted(results[path], key=lambda f: (_SEV_ORDER.get(f.severity, 9), f.line))
        for f in findings:
            col = _SEV_COLOR.get(f.severity, "")
            badge = f"{col} {_SEV_LABEL.get(f.severity, f.severity):^8} {C_R}"
            out.append(f"  {badge} {C_B}{f.cwe:<8}{C_R} {C_DIM}L{f.line}{C_R}  {f.name}")
    return "\n".join(out)


def _format_summary(results) -> str:
    sev: Counter = Counter()
    cwe: Counter = Counter()
    total = 0
    for findings in results.values():
        for f in findings:
            total += 1
            sev[f.severity] += 1
            cwe[f.cwe] += 1
    lines = [f"{C_B}Total findings :{C_R} {C_ACC}{C_B}{total}{C_R}",
             f"{C_DIM}Fichiers touches :{C_R} {len(results)}", ""]
    for s in sorted(sev, key=lambda x: _SEV_ORDER.get(x, 9)):
        col = _SEV_COLOR.get(s, "")
        lines.append(f"  {col}{_SEV_LABEL.get(s, s):<9}{C_R} {sev[s]}")
    if cwe:
        lines.append("")
        lines.append(f"{C_DIM}par CWE{C_R}")
        for c in sorted(cwe):
            lines.append(f"  {C_ACC}{c:<9}{C_R} {cwe[c]}")
    return "\n".join(lines)


def build_application(initial_path: str = ".", input=None, output=None):
    """Construit (sans la lancer) l'application 4 quadrants. Testable hors TTY.

    `input`/`output` permettent d'injecter un pipe pour les tests headless.
    """
    state = _State()

    def run_command(text: str):
        cmd = text.strip()
        if not cmd:
            return
        state.console.append(f"{C_ACC}>{C_R} {cmd}")
        parts = cmd.split(maxsplit=1)
        verb = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""

        if verb in ("quit", "exit"):
            from prompt_toolkit.application.current import get_app
            get_app().exit()
        elif verb == "help":
            state.results = _HELP
            state.log("aide affichee")
        elif verb == "clear":
            state.results = _welcome()
            state.summary = f"{C_DIM}Aucun scan.{C_R}"
            state.logs.clear()
            state.log("panneaux vides")
        elif verb == "benchmark":
            from .benchmark.run import run as run_bench
            summary, _ = run_bench()
            state.results = (
                f"{C_ACC}{C_B}Benchmark interne{C_R}\n"
                f"  cas            : {summary['cases']}\n"
                f"  correspondance : {C_ACC}{summary['exact_case_match']}/{summary['cases']}{C_R}\n"
                f"  precision      : {C_ACC}{summary['precision']}{C_R}\n"
                f"  rappel         : {C_ACC}{summary['recall']}{C_R}\n"
                f"  F1             : {C_ACC}{summary['f1']}{C_R}"
            )
            state.summary = state.results
            state.log("benchmark execute")
        elif verb == "scan":
            target = arg or "."
            state.log(f"scan : {C_ACC}{target}{C_R}")
            try:
                results = scan_path(target)
            except Exception as e:
                state.results = f"{C_HIGH}Erreur : {e}{C_R}"
                state.log(f"{C_HIGH}erreur scan{C_R}")
                return
            state.results = _format_results(results)
            state.summary = _format_summary(results)
            n = sum(len(v) for v in results.values())
            state.log(f"{C_B}{n}{C_R} finding(s) dans {len(results)} fichier(s)")
        else:
            state.log(f"{C_HIGH}commande inconnue :{C_R} {verb}")
            state.console.append(f"  {C_DIM}inconnue : {verb} (tape 'help'){C_R}")

    def accept(buff):
        run_command(buff.text)
        buff.reset()
        return None

    input_field = TextArea(
        height=1, prompt=[("class:prompt", "> ")], multiline=False,
        wrap_lines=False, accept_handler=accept, style="class:input",
    )

    def _ctrl(getter):
        return FormattedTextControl(lambda: ANSI(getter()))

    header = Window(_ctrl(lambda: f" {C_ACC}{C_B}AZARUS{C_R}{C_DIM} · audit{C_R}"), height=1)
    footer = Window(_ctrl(lambda: f" {C_DIM}scan <chemin> · benchmark · help · quit (Ctrl-Q){C_R}"),
                    height=1)
    console_view = Window(_ctrl(lambda: "\n".join(state.console)), wrap_lines=True)
    results_view = Window(_ctrl(lambda: state.results), wrap_lines=True)
    logs_view = Window(_ctrl(lambda: "\n".join(state.logs) or f"{C_DIM}En attente...{C_R}"),
                       wrap_lines=True)
    summary_view = Window(_ctrl(lambda: state.summary), wrap_lines=True)

    top_left = Frame(
        HSplit([header, Window(height=1, char="─"), console_view,
                Window(height=1, char="─"), input_field, footer]),
        title="1. Commandes")
    top_right = Frame(results_view, title="2. Resultats")
    bottom_left = Frame(logs_view, title="3. Logs")
    bottom_right = Frame(summary_view, title="4. Resume")

    root = HSplit([
        VSplit([top_left, top_right]),
        VSplit([bottom_left, bottom_right]),
    ])

    kb = KeyBindings()

    @kb.add("c-q")
    @kb.add("c-c")
    def _(event):
        event.app.exit()

    style = Style.from_dict({
        "frame.border": "#10b981",
        "frame.label": "#10b981 bold",
        "prompt": "#10b981 bold",
        "input": "#ffffff",
    })

    app = Application(
        layout=Layout(root, focused_element=input_field),
        key_bindings=kb, style=style, full_screen=True, mouse_support=True,
        input=input, output=output,
    )
    app.state = state

    if initial_path and initial_path not in (".",):
        run_command(f"scan {initial_path}")
    return app


def run_console(initial_path: str = ".") -> int:
    build_application(initial_path).run()
    return 0
