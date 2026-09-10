"""
Identite visuelle ASCII de azarus-audit (stdlib pure, aucune dependance).

Rendu soigne facon CLI premium : cadre arrondi, accent vert emeraude
rassurant (#10B981), wordmark en blocs 8-bit, sous-titre discret. Les couleurs
ANSI se desactivent automatiquement hors terminal ou si NO_COLOR est defini.
"""
import os
import sys

# --- couleurs ANSI (truecolor, degradables) ---
# Accent : vert emeraude, couleur rassurante ("securise, sous controle").
_ACCENT = "\x1b[38;2;16;185;129m"    # #10B981 (emerald)
_ACCENT_DIM = "\x1b[38;2;13;120;90m"
_GREY = "\x1b[38;2;150;150;150m"
_BOLD = "\x1b[1m"
_RESET = "\x1b[0m"

# --- police blocs pleins : chaque glyphe = 5 lignes de 5 colonnes ---
_GLYPHS = {
    "A": [" ███ ", "█   █", "█████", "█   █", "█   █"],
    "Z": ["█████", "   █ ", "  █  ", " █   ", "█████"],
    "R": ["████ ", "█   █", "████ ", "█  █ ", "█   █"],
    "U": ["█   █", "█   █", "█   █", "█   █", " ███ "],
    "S": [" ████", "█    ", " ███ ", "    █", "████ "],
    "D": ["███  ", "█  █ ", "█   █", "█  █ ", "███  "],
    "I": ["█████", "  █  ", "  █  ", "  █  ", "█████"],
    "T": ["█████", "  █  ", "  █  ", "  █  ", "  █  "],
    " ": ["     ", "     ", "     ", "     ", "     "],
}


def _use_color() -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    return sys.stdout.isatty()


def render_word(word: str) -> list:
    """Renvoie les 5 lignes du wordmark pour `word` (lettres connues)."""
    rows = ["", "", "", "", ""]
    for ch in word.upper():
        glyph = _GLYPHS.get(ch, _GLYPHS[" "])
        for i in range(5):
            rows[i] += glyph[i] + " "
    return [r.rstrip() for r in rows]


def banner(subtitle: str = "Auditeur de securite open-source  |  scanner CWE") -> str:
    """Banniere complete, encadree, prete a imprimer."""
    art = render_word("AZARUS")
    width = max(max(len(l) for l in art), len(subtitle) + 2, 40)
    color = _use_color()

    A = _ACCENT if color else ""
    AD = _ACCENT_DIM if color else ""
    G = _GREY if color else ""
    B = _BOLD if color else ""
    R = _RESET if color else ""

    top = f"{AD}╭{'─' * (width + 2)}╮{R}"
    bottom = f"{AD}╰{'─' * (width + 2)}╯{R}"
    out = [top]
    for line in art:
        out.append(f"{AD}│{R} {A}{B}{line.ljust(width)}{R} {AD}│{R}")
    out.append(f"{AD}│{R} {G}{subtitle.ljust(width)}{R} {AD}│{R}")
    out.append(bottom)
    return "\n".join(out)


def tagline() -> str:
    """Ligne compacte pour les en-tetes serres (dashboard)."""
    color = _use_color()
    A = _ACCENT if color else ""
    G = _GREY if color else ""
    B = _BOLD if color else ""
    R = _RESET if color else ""
    return f"{A}{B}AZARUS{R} {G}audit  ·  scanner de vulnerabilites CWE{R}"


def print_banner(force: bool = False) -> None:
    """Imprime la banniere si on est dans un terminal (ou si force)."""
    if force or sys.stdout.isatty():
        print(banner())


if __name__ == "__main__":
    print(banner())
    print()
    print(tagline())
