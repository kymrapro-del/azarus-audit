"""
Triage optionnelle par un modele open-weights (Azarus).

Le coeur du scanner est deterministe et fonctionne sans IA. Cette couche
facultative demande au modele d'expliquer un finding et d'estimer s'il s'agit
d'un vrai positif, en langage clair. Elle est activee par l'option --triage.
"""
import json
import os
import urllib.request
import urllib.error
from typing import Optional

from .detectors import Finding
from .experts import ExpertConfig, load_config
from .router import route_for_cwe

_DEFAULT_URL = os.environ.get(
    "AZARUS_BASE_URL", "https://kyky34167--azarus-final-serve-serve.modal.run/v1")
_MODEL = os.environ.get("AZARUS_MODEL", "azarus")
_KEY = os.environ.get("AZARUS_API_KEY", "none")


def explain(finding: Finding, code_context: str,
            base_url: Optional[str] = None, model: Optional[str] = None,
            timeout: int = 120, config: Optional[ExpertConfig] = None) -> Optional[str]:
    """Renvoie une explication courte du finding, ou None si indisponible.

    L'expert est choisi selon le CWE du finding (route_for_cwe), sauf si `model`
    est fourni explicitement. Comportement inchange en mono-modele.
    """
    cfg = config or load_config()
    chosen_url = base_url or cfg.base_url
    chosen_model = model or route_for_cwe(finding.cwe, cfg)
    prompt = (
        "Tu es un auditeur de securite. Voici un finding statique et le code.\n"
        f"CWE: {finding.cwe} ({finding.name})\n"
        f"Ligne {finding.line}: {finding.snippet}\n\n"
        f"Contexte:\n```\n{code_context[:1500]}\n```\n\n"
        "En 2 phrases maximum: est-ce un vrai risque ici, et comment le corriger ? "
        "Si c'est probablement un faux positif, dis-le."
    )
    body = {
        "model": chosen_model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2,
        "max_tokens": 200,
    }
    req = urllib.request.Request(
        chosen_url.rstrip("/") + "/chat/completions",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {cfg.api_key}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.load(r)
        msg = data["choices"][0]["message"]
        content = msg.get("content") or ""
        if "</think>" in content:  # repli si le parser de raisonnement est inactif
            content = content.split("</think>", 1)[1]
        return content.strip() or None
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, KeyError):
        return None
