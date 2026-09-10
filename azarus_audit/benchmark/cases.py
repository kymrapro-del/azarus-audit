"""
Jeu de test etiquete : chaque cas contient du code et les CWE ATTENDUS.
Les cas "sains" (expected vide) mesurent les faux positifs.

Ce corpus est volontairement petit et lisible ; il s'etend en ajoutant des
entrees. Il sert la reproductibilite, pas a gonfler un score.
"""

CASES = [
    # ---- CWE-89 : injection SQL ----
    {"id": "sqli_concat", "language": "python", "expected": ["CWE-89"],
     "code": 'cursor.execute("SELECT * FROM users WHERE name = \'" + name + "\'")'},
    {"id": "sqli_fstring", "language": "python", "expected": ["CWE-89"],
     "code": 'cursor.execute(f"SELECT * FROM t WHERE id = {uid}")'},
    {"id": "sqli_percent", "language": "python", "expected": ["CWE-89"],
     "code": 'cursor.execute("SELECT * FROM t WHERE id = %s" % uid)'},
    {"id": "sqli_safe_param", "language": "python", "expected": [],
     "code": 'cursor.execute("SELECT * FROM users WHERE name = ?", (name,))'},
    {"id": "sqli_safe_const", "language": "python", "expected": [],
     "code": 'cursor.execute("SELECT 1")'},

    # ---- CWE-78 : injection de commande ----
    {"id": "cmd_os_system", "language": "python", "expected": ["CWE-78"],
     "code": 'import os\nos.system("ping " + host)'},
    {"id": "cmd_shell_true", "language": "python", "expected": ["CWE-78"],
     "code": 'import subprocess\nsubprocess.run("ls " + path, shell=True)'},
    {"id": "cmd_safe_list", "language": "python", "expected": [],
     "code": 'import subprocess\nsubprocess.run(["ping", host])'},

    # ---- CWE-94 : injection de code ----
    {"id": "code_eval", "language": "python", "expected": ["CWE-94"],
     "code": 'eval(user_input)'},
    {"id": "code_exec", "language": "python", "expected": ["CWE-94"],
     "code": 'exec(payload)'},
    {"id": "code_safe_literal", "language": "python", "expected": [],
     "code": 'import ast\nast.literal_eval(user_input)'},

    # ---- CWE-502 : deserialisation non sure ----
    {"id": "deser_pickle", "language": "python", "expected": ["CWE-502"],
     "code": 'import pickle\ndata = pickle.loads(blob)'},
    {"id": "deser_yaml", "language": "python", "expected": ["CWE-502"],
     "code": 'import yaml\ncfg = yaml.load(stream)'},
    {"id": "deser_safe_json", "language": "python", "expected": [],
     "code": 'import json\ndata = json.loads(blob)'},
    {"id": "deser_safe_yaml", "language": "python", "expected": [],
     "code": 'import yaml\ncfg = yaml.safe_load(stream)'},

    # ---- CWE-327 : hachage faible ----
    {"id": "hash_md5", "language": "python", "expected": ["CWE-327"],
     "code": 'import hashlib\nh = hashlib.md5(pw.encode()).hexdigest()'},
    {"id": "hash_safe_sha256", "language": "python", "expected": [],
     "code": 'import hashlib\nh = hashlib.sha256(pw.encode()).hexdigest()'},

    # ---- CWE-295 : TLS non verifie ----
    {"id": "tls_verify_false", "language": "python", "expected": ["CWE-295"],
     "code": 'import requests\nrequests.get(url, verify=False)'},
    {"id": "tls_safe", "language": "python", "expected": [],
     "code": 'import requests\nrequests.get(url)'},

    # ---- CWE-798 : secrets en clair ----
    {"id": "secret_password", "language": "python", "expected": ["CWE-798"],
     "code": 'password = "hunter2super"'},
    {"id": "secret_apikey_literal", "language": "python", "expected": ["CWE-798"],
     "code": 'API_KEY = "sk-abcdef1234567890abcdef12"'},  # nosec (fixture de test)
    {"id": "secret_env_safe", "language": "python", "expected": [],
     "code": 'import os\npassword = os.environ["DB_PASSWORD"]'},
    {"id": "secret_hf_token_yaml", "language": "generic", "expected": ["CWE-798"],
     "code": 'token: hf_abcdefghijklmnopqrstuvwxyz012345'},  # nosec (fixture de test)
    {"id": "secret_env_ref_safe", "language": "generic", "expected": [],
     "code": 'token: ${HF_TOKEN}'},
]
