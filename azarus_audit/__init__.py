"""
azarus_audit - Auditeur de securite open-source, auto-hebergeable.

Coeur deterministe (analyse AST + motifs) qui detecte des vulnerabilites
mappees aux identifiants CWE, sans dependance a une IA. Une triage optionnelle
par un modele open-weights (Azarus) sert a expliquer et prioriser les findings.

Le but du projet : detecter des vulnerabilites serieuses dans du code source,
de facon reproductible et verifiable. L'IA est un composant, pas le coeur.
"""

__version__ = "0.1.0"

from .detectors import Finding, scan_source  # noqa: F401
