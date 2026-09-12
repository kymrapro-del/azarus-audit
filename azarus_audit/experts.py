"""
Configuration des experts IA (routage multi-adaptateurs).

Le principe : un seul modele de base (Qwen3-32B) sert plusieurs adaptateurs LoRA
specialises, exposes par vLLM sous des noms distincts. azarus-audit route chaque
tache vers le bon expert selon le CWE (triage) ou la nature du fichier (decouverte).

Ce module ne fait AUCUN appel reseau : il ne fait que decider quel nom de modele
utiliser. La table CWE -> famille d'expert est fixe (elle suit les detecteurs) ;
seule l'association famille -> nom de modele servi est configurable.

Retro-compatibilite : par defaut, TOUTES les familles pointent vers le meme nom
de modele (AZARUS_MODEL, defaut "azarus"). Le comportement est donc identique a
l'ancien fonctionnement mono-modele tant qu'aucun expert n'est configure.

Sans dependance externe (stdlib pure, compatible Python 3.9+).
"""
import json
import os
from dataclasses import dataclass, field
from typing import Dict, Optional

# --------------------------------------------------------------------------
# Familles d'experts. Chaque CWE emis par les detecteurs est rattache a une
# famille. Les familles sans CWE (ex: "llm-sec") sont choisies par heuristique
# de fichier lors de la decouverte ouverte (--ai).
# --------------------------------------------------------------------------
FAMILY_CODE = "code"        # injections & flux : SQLi, cmd, eval, deser, XXE, SSRF, path
FAMILY_CRYPTO = "crypto"    # crypto, TLS, secrets, aleatoire faible
FAMILY_CONFIG = "config"    # durcissement : debug, fichiers temp, permissions
FAMILY_LLM = "llm-sec"      # securite des applications LLM/agents (OWASP LLM Top 10)

DEFAULT_FAMILY = FAMILY_CODE

# Table figee CWE -> famille (miroir des CWE produits par detectors.py).
EXPERT_FOR_CWE: Dict[str, str] = {
    "CWE-89": FAMILY_CODE,     # injection SQL
    "CWE-78": FAMILY_CODE,     # injection de commande OS
    "CWE-94": FAMILY_CODE,     # injection de code (eval/exec)
    "CWE-502": FAMILY_CODE,    # deserialisation non sure
    "CWE-611": FAMILY_CODE,    # entites XML externes (XXE)
    "CWE-918": FAMILY_CODE,    # SSRF
    "CWE-22": FAMILY_CODE,     # traversee de chemin
    "CWE-327": FAMILY_CRYPTO,  # hachage/chiffrement faible
    "CWE-295": FAMILY_CRYPTO,  # verification TLS desactivee
    "CWE-798": FAMILY_CRYPTO,  # secret en clair
    "CWE-330": FAMILY_CRYPTO,  # aleatoire non cryptographique
    "CWE-489": FAMILY_CONFIG,  # serveur de debogage expose
    "CWE-377": FAMILY_CONFIG,  # fichier temporaire non securise
    "CWE-732": FAMILY_CONFIG,  # permissions trop permissives
}

ALL_FAMILIES = (FAMILY_CODE, FAMILY_CRYPTO, FAMILY_CONFIG, FAMILY_LLM)

# Valeurs d'environnement (memes noms que ai_engine.py / triage.py existants).
_DEFAULT_BASE_URL = os.environ.get(
    "AZARUS_BASE_URL", "https://kyky34167--azarus-final-serve-serve.modal.run/v1")
_DEFAULT_MODEL = os.environ.get("AZARUS_MODEL", "azarus")
_DEFAULT_KEY = os.environ.get("AZARUS_API_KEY", "none")


@dataclass
class ExpertConfig:
    """Association famille d'expert -> nom de modele servi, + acces endpoint.

    `models` mappe une famille (FAMILY_*) vers le nom de modele expose par le
    serveur d'inference (ex: "expert-crypto"). Toute famille absente retombe sur
    `default_model`.
    """
    base_url: str = _DEFAULT_BASE_URL
    api_key: str = _DEFAULT_KEY
    default_model: str = _DEFAULT_MODEL
    models: Dict[str, str] = field(default_factory=dict)

    def model_for_family(self, family: str) -> str:
        """Nom de modele servi pour une famille, avec repli sur le defaut."""
        return self.models.get(family) or self.default_model

    def is_multi_expert(self) -> bool:
        """Vrai si au moins un expert distinct du modele par defaut est declare."""
        return any(m and m != self.default_model for m in self.models.values())


def _config_from_mapping(data: dict) -> ExpertConfig:
    """Construit une ExpertConfig depuis un dict (JSON de config ou d'env).

    Forme attendue :
        {
          "base_url": "https://.../v1",
          "api_key": "none",
          "default_model": "azarus",
          "experts": {"code": "expert-code", "crypto": "expert-crypto", ...}
        }
    Les cles inconnues dans "experts" sont ignorees (on ne route que ALL_FAMILIES).
    """
    experts = data.get("experts") or {}
    models = {fam: str(experts[fam]) for fam in ALL_FAMILIES
              if fam in experts and experts[fam]}
    return ExpertConfig(
        base_url=str(data.get("base_url") or _DEFAULT_BASE_URL),
        api_key=str(data.get("api_key") or _DEFAULT_KEY),
        default_model=str(data.get("default_model") or _DEFAULT_MODEL),
        models=models,
    )


def load_config(path: Optional[str] = None) -> ExpertConfig:
    """Charge la configuration des experts.

    Priorite :
      1. `path` explicite (fichier JSON), si fourni.
      2. Variable d'environnement AZARUS_EXPERTS (chemin de fichier OU JSON inline).
      3. Defauts : toutes les familles -> AZARUS_MODEL (comportement mono-modele).

    Toute erreur de lecture/parse retombe silencieusement sur le defaut : l'IA
    reste optionnelle, elle ne doit jamais casser un scan.
    """
    source = path or os.environ.get("AZARUS_EXPERTS")
    if not source:
        return ExpertConfig()

    raw = None
    # Chemin de fichier ?
    try:
        if os.path.isfile(source):
            with open(source, encoding="utf-8") as fh:
                raw = fh.read()
    except OSError:
        raw = None
    # Sinon, tenter JSON inline (utile pour AZARUS_EXPERTS='{"experts":{...}}').
    if raw is None:
        raw = source

    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            return _config_from_mapping(data)
    except (ValueError, TypeError):
        pass
    return ExpertConfig()
