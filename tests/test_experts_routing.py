"""
Tests du routage multi-experts (deterministe, hors ligne, aucun appel reseau).

Verifie : la table CWE -> famille, le choix du modele servi par famille, le
repli mono-modele (retro-compatibilite), l'heuristique LLM et le chargement de
configuration (JSON inline et dict).

Executable avec pytest, ou directement : `python tests/test_experts_routing.py`.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from azarus_audit.experts import (                        # noqa: E402
    ExpertConfig, load_config, _config_from_mapping,
    FAMILY_CODE, FAMILY_CRYPTO, FAMILY_CONFIG, FAMILY_LLM,
)
from azarus_audit.router import (                         # noqa: E402
    family_for_cwe, route_for_cwe, route_for_file, looks_like_llm_app,
)


# Config multi-experts de reference pour les tests.
_MULTI = ExpertConfig(
    default_model="azarus",
    models={
        FAMILY_CODE: "expert-code",
        FAMILY_CRYPTO: "expert-crypto",
        FAMILY_CONFIG: "expert-config",
        FAMILY_LLM: "expert-llm-sec",
    },
)


# --- table CWE -> famille ---
def test_family_code_cwes():
    for cwe in ("CWE-89", "CWE-78", "CWE-94", "CWE-502", "CWE-611", "CWE-918", "CWE-22"):
        assert family_for_cwe(cwe) == FAMILY_CODE, cwe


def test_family_crypto_cwes():
    for cwe in ("CWE-327", "CWE-295", "CWE-798", "CWE-330"):
        assert family_for_cwe(cwe) == FAMILY_CRYPTO, cwe


def test_family_config_cwes():
    for cwe in ("CWE-489", "CWE-377", "CWE-732"):
        assert family_for_cwe(cwe) == FAMILY_CONFIG, cwe


def test_unknown_cwe_falls_back_to_code():
    assert family_for_cwe("CWE-99999") == FAMILY_CODE
    assert family_for_cwe("") == FAMILY_CODE


def test_family_is_case_insensitive():
    assert family_for_cwe("cwe-327") == FAMILY_CRYPTO


# --- routage CWE -> modele servi ---
def test_route_for_cwe_multi_expert():
    assert route_for_cwe("CWE-89", _MULTI) == "expert-code"
    assert route_for_cwe("CWE-327", _MULTI) == "expert-crypto"
    assert route_for_cwe("CWE-489", _MULTI) == "expert-config"


def test_route_for_cwe_mono_model_backward_compat():
    # Config par defaut : aucune famille declaree -> tout retombe sur default_model.
    cfg = ExpertConfig(default_model="azarus")
    assert route_for_cwe("CWE-89", cfg) == "azarus"
    assert route_for_cwe("CWE-327", cfg) == "azarus"
    assert cfg.is_multi_expert() is False


def test_partial_config_falls_back_for_missing_family():
    cfg = ExpertConfig(default_model="azarus", models={FAMILY_CRYPTO: "expert-crypto"})
    assert route_for_cwe("CWE-327", cfg) == "expert-crypto"   # declare
    assert route_for_cwe("CWE-89", cfg) == "azarus"           # repli
    assert cfg.is_multi_expert() is True


# --- heuristique LLM et routage fichier ---
def test_looks_like_llm_app():
    assert looks_like_llm_app("from openai import OpenAI") is True
    assert looks_like_llm_app("import langchain") is True
    assert looks_like_llm_app("client.chat.completions.create(...)") is True
    assert looks_like_llm_app("def add(a, b):\n    return a + b") is False


def test_route_for_file_llm_vs_code():
    llm_code = "import anthropic\nclient = anthropic.Anthropic()"
    plain = "x = 1 + 1\nprint(x)"
    assert route_for_file("app.py", llm_code, _MULTI) == "expert-llm-sec"
    assert route_for_file("util.py", plain, _MULTI) == "expert-code"


def test_route_for_file_mono_model():
    cfg = ExpertConfig(default_model="azarus")
    assert route_for_file("app.py", "import openai", cfg) == "azarus"


# --- chargement de configuration ---
def test_config_from_inline_json():
    raw = ('{"base_url": "http://localhost:8000/v1", "default_model": "azarus",'
           ' "experts": {"crypto": "expert-crypto", "inconnu": "x"}}')
    cfg = _load_inline(raw)
    assert cfg.base_url == "http://localhost:8000/v1"
    assert cfg.models == {"crypto": "expert-crypto"}   # cle inconnue ignoree


def _load_inline(raw):
    # load_config accepte du JSON inline via AZARUS_EXPERTS ; on teste le parseur.
    prev = os.environ.get("AZARUS_EXPERTS")
    os.environ["AZARUS_EXPERTS"] = raw
    try:
        return load_config()
    finally:
        if prev is None:
            os.environ.pop("AZARUS_EXPERTS", None)
        else:
            os.environ["AZARUS_EXPERTS"] = prev


def test_config_from_mapping_ignores_unknown_families():
    cfg = _config_from_mapping({"experts": {"code": "c", "bogus": "b"}})
    assert cfg.models == {"code": "c"}


def test_load_config_bad_input_returns_default():
    cfg = _load_inline("pas du tout du json")
    assert cfg.is_multi_expert() is False


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS: {fn.__name__}")
    print(f"\nALL {len(fns)} ROUTING TESTS PASSED")
