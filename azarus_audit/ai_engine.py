"""
Moteur d'analyse IA (le modele comme MOTEUR, pas comme chat).

Le modele open-weights (Azarus) lit le code et renvoie des findings STRUCTURES
en JSON, en COMPLEMENT du coeur deterministe. Il attrape des failles de logique
ou de contexte que les regles ne voient pas ; en contrepartie il peut halluciner,
donc ses findings sont clairement marques (source="ai") et separables.

Sans dependance externe (stdlib). Necessite l'endpoint du modele.
"""
import json
import os
import re
import urllib.request
from typing import List

from .detectors import Finding

_BASE_URL = os.environ.get("AZARUS_BASE_URL", "https://kyky34167--azarus-final-serve-serve.modal.run/v1")
_MODEL = os.environ.get("AZARUS_MODEL", "azarus")
_KEY = os.environ.get("AZARUS_API_KEY", "none")

_PROMPT = (
    "Tu es un MOTEUR d'analyse de securite statique. Analyse le code ci-dessous "
    "et liste uniquement les VRAIES vulnerabilites de securite.\n"
    "Reponds STRICTEMENT par un tableau JSON, sans aucun texte autour. Chaque "
    "element : {\"cwe\": \"CWE-XX\", \"line\": <entier>, \"severity\": "
    "\"critical|high|medium|low\", \"title\": \"...\", \"fix\": \"...\"}. "
    "Si aucune vulnerabilite : [].\n\n"
    "Code:\n```python\n{code}\n```"
)

_VALID_SEV = {"critical", "high", "medium", "low"}


def _extract_json_array(text: str):
    if "</think>" in text:
        text = text.split("</think>", 1)[1]
    m = re.search(r"\[.*\]", text, re.S)
    if not m:
        return []
    try:
        data = json.loads(m.group(0))
        return data if isinstance(data, list) else []
    except (ValueError, TypeError):
        return []


def _call_model(prompt, base_url, model, max_tokens=900, timeout=180):
    body = {"model": model, "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1, "max_tokens": max_tokens}
    req = urllib.request.Request(base_url.rstrip("/") + "/chat/completions",
                                 data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json",
                                          "Authorization": f"Bearer {_KEY}"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = json.load(r)
    msg = data["choices"][0]["message"]
    return msg.get("content") or ""


def ai_scan_source(code: str, base_url: str = _BASE_URL, model: str = _MODEL,
                   max_lines: int = 400) -> List[Finding]:
    """Analyse un extrait via le modele. Renvoie des Finding (source='ai')."""
    code = "\n".join(code.splitlines()[:max_lines])
    try:
        raw = _call_model(_PROMPT.replace("{code}", code), base_url, model)
    except Exception:
        return []
    out = []
    for item in _extract_json_array(raw):
        if not isinstance(item, dict):
            continue
        cwe = str(item.get("cwe", "")).upper().strip()
        if not cwe.startswith("CWE-"):
            continue
        sev = str(item.get("severity", "medium")).lower().strip()
        if sev not in _VALID_SEV:
            sev = "medium"
        try:
            line = int(item.get("line", 0))
        except (ValueError, TypeError):
            line = 0
        title = str(item.get("title", "Vulnerabilite (analyse IA)"))[:120]
        fix = str(item.get("fix", ""))[:200]
        out.append(Finding(cwe=cwe, name=title, severity=sev, confidence="medium",
                           line=max(line, 0), message=fix or "Signale par le moteur IA.",
                           snippet="", source="ai"))
    return out
