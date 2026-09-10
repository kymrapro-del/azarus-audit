"""
Tests unitaires du scanner azarus_audit.

Verifie les vrais positifs (chaque detecteur), l'absence de faux positifs sur
les versions sures, la suppression inline et la forme du rapport SARIF.

Executable avec pytest, ou directement : `python tests/test_azarus_audit.py`.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from azarus_audit.detectors import scan_source          # noqa: E402
from azarus_audit.sarif import to_sarif                 # noqa: E402
from azarus_audit.report_md import to_markdown, MARKER  # noqa: E402


def _cwes(code, lang="python"):
    return {f.cwe for f in scan_source(code, lang)}


# --- vrais positifs ---
def test_sqli_concat():
    assert "CWE-89" in _cwes('cursor.execute("SELECT * FROM t WHERE n=\'" + n + "\'")')


def test_sqli_fstring():
    assert "CWE-89" in _cwes('cursor.execute(f"SELECT * FROM t WHERE id={i}")')


def test_command_injection():
    assert "CWE-78" in _cwes('import os\nos.system("ping " + host)')


def test_eval_exec():
    assert "CWE-94" in _cwes("eval(user_input)")


def test_pickle_and_yaml():
    assert "CWE-502" in _cwes("import pickle\npickle.loads(b)")
    assert "CWE-502" in _cwes("import yaml\nyaml.load(s)")


def test_weak_hash_is_low_severity():
    fs = scan_source("import hashlib\nhashlib.md5(b'x')")
    assert any(f.cwe == "CWE-327" and f.severity == "low" for f in fs)


def test_tls_verify_false():
    assert "CWE-295" in _cwes("import requests\nrequests.get(u, verify=False)")


def test_hardcoded_secret():
    assert "CWE-798" in _cwes('password = "s3cr3tR3al"')


def test_random_for_secret():
    assert "CWE-330" in _cwes("import random\ntoken = random.random()")


def test_flask_debug():
    assert "CWE-489" in _cwes("app.run(debug=True)")


# --- absence de faux positifs ---
def test_safe_parameterized_sql():
    assert _cwes('cursor.execute("SELECT * FROM t WHERE n=?", (n,))') == set()


def test_safe_subprocess_list():
    assert _cwes('import subprocess\nsubprocess.run(["ping", host])') == set()


def test_secret_from_env_not_flagged():
    assert _cwes('import os\npassword = os.environ["DB_PASSWORD"]') == set()


def test_placeholder_secret_not_flagged():
    assert _cwes('password = "changeme"') == set()
    assert _cwes('api_key = "your_api_key_here"') == set()


def test_md5_usedforsecurity_false_not_flagged():
    assert _cwes("import hashlib\nhashlib.md5(b'x', usedforsecurity=False)") == set()


def test_execute_non_sql_not_flagged():
    # 'execute' hors contexte SQL (ex. WSGI) ne doit pas lever CWE-89.
    assert "CWE-89" not in _cwes("server.execute(app)")


# --- suppression inline ---
def test_suppression_nosec():
    assert _cwes('password = "s3cr3tR3al"  # nosec') == set()
    assert _cwes('password = "s3cr3tR3al"  # azarus: ignore') == set()


def test_xxe():
    assert "CWE-611" in _cwes("p = etree.XMLParser(resolve_entities=True)")


def test_chmod_permissive():
    assert "CWE-732" in _cwes("import os\nos.chmod(p, 0o777)")


def test_chmod_safe_not_flagged():
    assert _cwes("import os\nos.chmod(p, 0o644)") == set()


# --- analyse de flux (taint) ---
def test_taint_sqli_via_variable():
    assert "CWE-89" in _cwes('def f():\n q = request.args["x"]\n cursor.execute(q)')


def test_taint_path_traversal():
    assert "CWE-22" in _cwes('def f():\n open(request.args["file"])')


def test_taint_ssrf():
    assert "CWE-918" in _cwes('import requests\ndef f():\n requests.get(request.args["u"])')


def test_taint_command_via_input():
    assert "CWE-78" in _cwes("import os\ndef f():\n os.system(input())")


def test_taint_open_method_not_flagged():
    # .open() (methode) n'est pas le open() builtin : pas de CWE-22.
    assert "CWE-22" not in _cwes("def f():\n client.open(request.path)")


def test_taint_constant_safe():
    assert _cwes('def f():\n cursor.execute("SELECT 1")') == set()


# --- dependances (parsing hors-ligne) ---
def test_requirements_parsing():
    import tempfile
    from azarus_audit.deps import parse_requirements
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as f:
        f.write("requests==2.19.0\n# comment\nflask>=1.0\nurllib3==1.24  # pin\n")
        path = f.name
    try:
        pkgs = dict(parse_requirements(path))
    finally:
        os.unlink(path)
    assert pkgs.get("requests") == "2.19.0"
    assert pkgs.get("urllib3") == "1.24"
    assert "flask" not in pkgs  # non epingle (>=) : ignore


# --- moteur IA (parsing hors-ligne, sans reseau) ---
def test_ai_extract_json_array():
    from azarus_audit.ai_engine import _extract_json_array
    assert _extract_json_array('bla [{"a": 1}] end') == [{"a": 1}]
    assert _extract_json_array("<think>x</think> []") == []
    assert _extract_json_array("aucun json ici") == []


def test_ai_engine_maps_findings():
    from azarus_audit import ai_engine
    orig = ai_engine._call_model
    ai_engine._call_model = lambda *a, **k: (
        '[{"cwe":"CWE-89","line":3,"severity":"high","title":"SQLi","fix":"params"}]')
    try:
        fs = ai_engine.ai_scan_source("code")
    finally:
        ai_engine._call_model = orig
    assert len(fs) == 1
    assert fs[0].cwe == "CWE-89" and fs[0].severity == "high" and fs[0].source == "ai"


def test_ai_engine_network_error_is_safe():
    from azarus_audit import ai_engine
    orig = ai_engine._call_model

    def boom(*a, **k):
        raise OSError("no network")
    ai_engine._call_model = boom
    try:
        assert ai_engine.ai_scan_source("code") == []
    finally:
        ai_engine._call_model = orig


# --- SARIF ---
def test_sarif_shape():
    results = {"a.py": scan_source('password = "s3cr3tR3al"')}
    doc = to_sarif(results)
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "azarus-audit"
    assert run["results"] and run["results"][0]["ruleId"] == "CWE-798"


# --- Markdown (GitHub Action / commentaire de PR) ---
def test_markdown_clean():
    md = to_markdown({})
    assert MARKER in md
    assert "Aucune vulnérabilité" in md


def test_markdown_findings():
    results = {"a.py": scan_source('password = "s3cr3tR3al"')}
    md = to_markdown(results)
    assert MARKER in md
    assert "CWE-798" in md
    assert "cwe.mitre.org" in md
    assert "| Sévérité |" in md


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL {fn.__name__}: {e}")
    print(f"\n{len(fns) - failed}/{len(fns)} tests OK")
    sys.exit(1 if failed else 0)
