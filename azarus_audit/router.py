"""
Routeur d'experts IA.

Decide vers quel expert (nom de modele servi) envoyer une tache d'analyse :

  - `route_for_cwe`  : le triage connait deja le CWE d'un finding deterministe,
                       on route donc precisement (ex: CWE-327 -> expert crypto).
  - `route_for_file` : la decouverte ouverte (--ai) n'a pas encore de CWE ; on
                       route par nature du fichier (code applicatif LLM/agent ->
                       expert securite LLM, sinon expert code generique).

Purement deterministe, sans reseau : entierement testable hors ligne.
Sans dependance externe (stdlib pure, compatible Python 3.9+).
"""
import re
from typing import Optional

from .experts import (
    ExpertConfig,
    EXPERT_FOR_CWE,
    DEFAULT_FAMILY,
    FAMILY_LLM,
    load_config,
)

# Indices qu'un fichier manipule un modele/agent LLM (declenche l'expert LLM-sec).
_LLM_HINTS = re.compile(
    r"\b(?:import\s+openai|from\s+openai|import\s+anthropic|from\s+anthropic|"
    r"langchain|llama_index|llamaindex|litellm|"
    r"chat\.completions|chat_completion|"
    r"system[_\s]?prompt|/v1/chat/completions)\b",
    re.IGNORECASE,
)


def family_for_cwe(cwe: str) -> str:
    """Famille d'expert associee a un CWE (repli sur la famille par defaut)."""
    return EXPERT_FOR_CWE.get((cwe or "").upper().strip(), DEFAULT_FAMILY)


def route_for_cwe(cwe: str, config: Optional[ExpertConfig] = None) -> str:
    """Nom de modele servi a interroger pour trier un finding de ce CWE."""
    cfg = config or load_config()
    return cfg.model_for_family(family_for_cwe(cwe))


def looks_like_llm_app(code: str) -> bool:
    """Heuristique : le code parle-t-il a un modele/agent LLM ?"""
    if not code:
        return False
    return bool(_LLM_HINTS.search(code))


def route_for_file(path: str, code: str,
                   config: Optional[ExpertConfig] = None) -> str:
    """Nom de modele servi pour la decouverte ouverte sur un fichier.

    Un fichier applicatif LLM/agent va vers l'expert securite LLM (s'il est
    configure) ; tout le reste va vers l'expert code par defaut.
    """
    cfg = config or load_config()
    if looks_like_llm_app(code):
        return cfg.model_for_family(FAMILY_LLM)
    return cfg.model_for_family(DEFAULT_FAMILY)
