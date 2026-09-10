"""
Detecteurs deterministes de vulnerabilites.

- Analyse AST pour le code Python (precis, peu de faux positifs).
- Motifs regex pour les secrets en clair (multi-langage).
Chaque finding est mappe a un identifiant CWE.
"""
import ast
import re
from dataclasses import dataclass, asdict
from typing import List, Optional


@dataclass
class Finding:
    cwe: str
    name: str
    severity: str          # low | medium | high | critical
    confidence: str        # low | medium | high
    line: int
    message: str
    snippet: str = ""
    source: str = "ast"    # ast | regex

    def to_dict(self):
        return asdict(self)


# --------------------------------------------------------------------------
# Aide : caractériser une chaine construite dynamiquement (interpolation).
# --------------------------------------------------------------------------
def _dynamic_string_confidence(node: ast.AST) -> Optional[str]:
    """Renvoie 'high'/'medium' si le noeud represente une chaine construite a
    partir de donnees variables, None si c'est une constante sure."""
    if isinstance(node, ast.Constant):
        return None
    # f-string avec au moins un champ interpole
    if isinstance(node, ast.JoinedStr):
        if any(isinstance(v, ast.FormattedValue) for v in node.values):
            return "high"
        return None
    # concatenation "a" + var  ou  var + "b"
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _dynamic_string_confidence(node.left)
        right = _dynamic_string_confidence(node.right)
        if _looks_stringy(node.left) or _looks_stringy(node.right):
            if left == "high" or right == "high":
                return "high"
            if isinstance(node.left, (ast.Name, ast.Attribute, ast.Subscript, ast.Call)) or \
               isinstance(node.right, (ast.Name, ast.Attribute, ast.Subscript, ast.Call)):
                return "high"
        return None
    # formatage % :  "... %s ..." % (var)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
            return "high"
        return None
    # "...".format(var)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
            and node.func.attr == "format":
        if isinstance(node.func.value, ast.Constant):
            return "high"
    # variable seule : origine inconnue -> suspicion moderee
    if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)):
        return "medium"
    return None


def _looks_stringy(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return True
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp):
        return _looks_stringy(node.left) or _looks_stringy(node.right)
    return False


def _attr_chain(node: ast.AST) -> str:
    """os.path.join -> 'os.path.join' ; execute -> 'execute'."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _kw(call: ast.Call, name: str) -> Optional[ast.AST]:
    for k in call.keywords:
        if k.arg == name:
            return k.value
    return None


# --------------------------------------------------------------------------
# Visiteur AST (Python).
# --------------------------------------------------------------------------
class _PyVisitor(ast.NodeVisitor):
    EXECUTE_METHODS = {"execute", "executemany", "executescript"}
    HASH_WEAK = {"md5", "sha1"}

    def __init__(self, lines: List[str]):
        self.lines = lines
        self.findings: List[Finding] = []

    def _snippet(self, node) -> str:
        i = getattr(node, "lineno", 0) - 1
        if 0 <= i < len(self.lines):
            return self.lines[i].strip()[:200]
        return ""

    def _add(self, node, cwe, name, severity, confidence, message):
        self.findings.append(Finding(
            cwe=cwe, name=name, severity=severity, confidence=confidence,
            line=getattr(node, "lineno", 0), message=message,
            snippet=self._snippet(node), source="ast",
        ))

    # --- appels de fonctions ---
    def visit_Call(self, node: ast.Call):
        fname = _attr_chain(node.func)
        short = fname.split(".")[-1]

        # CWE-89 : injection SQL via cursor.execute(chaine dynamique).
        # On exige une chaine REELLEMENT construite (concat/f-string/%), pas une
        # simple variable : 'execute' est un nom de methode courant (WSGI, etc.),
        # ce qui evite des faux positifs hors contexte SQL.
        if short in self.EXECUTE_METHODS and node.args:
            if _dynamic_string_confidence(node.args[0]) == "high":
                self._add(node, "CWE-89", "Injection SQL", "critical", "high",
                          "Requete SQL construite par concatenation/interpolation. "
                          "Utilisez des requetes parametrees (placeholders).")

        # CWE-78 : injection de commande
        if fname in ("os.system", "os.popen") and node.args:
            if _dynamic_string_confidence(node.args[0]):
                self._add(node, "CWE-78", "Injection de commande OS", "critical", "high",
                          f"{fname}() avec une commande dynamique. Preferez subprocess "
                          "avec une liste d'arguments et sans shell.")
        if short in ("run", "call", "check_output", "check_call", "Popen"):
            shell = _kw(node, "shell")
            if isinstance(shell, ast.Constant) and shell.value is True:
                dyn = node.args and _dynamic_string_confidence(node.args[0])
                if dyn:
                    self._add(node, "CWE-78", "Injection de commande OS", "critical", "high",
                              "subprocess avec shell=True et une commande dynamique. "
                              "Passez une liste d'arguments et shell=False.")
                else:
                    self._add(node, "CWE-78", "Usage de shell=True", "medium", "medium",
                              "subprocess avec shell=True : a eviter si evitable.")

        # CWE-94 : eval/exec de donnees non constantes
        if fname in ("eval", "exec") and node.args:
            if not isinstance(node.args[0], ast.Constant):
                self._add(node, "CWE-94", "Injection de code (eval/exec)", "critical", "high",
                          f"{fname}() sur une expression non constante. Evitez eval/exec "
                          "sur des donnees non fiables.")

        # CWE-502 : deserialisation non sure
        if fname in ("pickle.loads", "pickle.load", "cPickle.loads", "marshal.loads"):
            self._add(node, "CWE-502", "Deserialisation non sure", "high", "medium",
                      f"{fname}() peut executer du code arbitraire sur des donnees non fiables.")
        if fname in ("yaml.load",):
            loader = _kw(node, "Loader")
            safe = loader is not None and _attr_chain(loader).split(".")[-1] in ("SafeLoader",)
            if not safe:
                self._add(node, "CWE-502", "yaml.load sans SafeLoader", "high", "high",
                          "yaml.load sans SafeLoader peut instancier des objets arbitraires. "
                          "Utilisez yaml.safe_load.")

        # CWE-327 : hachage faible. On respecte usedforsecurity=False (usage non
        # securite explicite, ex. cache/checksum) pour reduire les faux positifs.
        ufs = _kw(node, "usedforsecurity")
        ufs_false = isinstance(ufs, ast.Constant) and ufs.value is False
        if fname.startswith("hashlib.") and short in self.HASH_WEAK and not ufs_false:
            self._add(node, "CWE-327", "Algorithme de hachage faible", "low", "low",
                      f"{fname}() est inadapte a la securite (mots de passe, integrite). "
                      "Preferez SHA-256+ ou un KDF (bcrypt/argon2), ou usedforsecurity=False.")
        if fname == "hashlib.new" and node.args and isinstance(node.args[0], ast.Constant) \
                and str(node.args[0].value).lower() in self.HASH_WEAK and not ufs_false:
            self._add(node, "CWE-327", "Algorithme de hachage faible", "low", "low",
                      "hashlib.new avec un algorithme faible (md5/sha1).")

        # CWE-295 : verification TLS desactivee
        verify = _kw(node, "verify")
        if isinstance(verify, ast.Constant) and verify.value is False:
            self._add(node, "CWE-295", "Verification TLS desactivee", "high", "high",
                      "verify=False desactive la validation du certificat TLS.")
        if fname == "ssl._create_unverified_context":
            self._add(node, "CWE-295", "Contexte TLS non verifie", "high", "high",
                      "ssl._create_unverified_context desactive la validation TLS.")
        check_hostname = _kw(node, "check_hostname")
        if isinstance(check_hostname, ast.Constant) and check_hostname.value is False:
            self._add(node, "CWE-295", "Verification du nom d'hote TLS desactivee", "high", "high",
                      "check_hostname=False expose aux attaques d'interception (MITM).")

        # CWE-489 : serveur de debogage expose (Flask/Werkzeug)
        debug = _kw(node, "debug")
        if short == "run" and isinstance(debug, ast.Constant) and debug.value is True:
            self._add(node, "CWE-489", "Mode debug active", "medium", "high",
                      "run(debug=True) expose un debugger interactif ; a proscrire en production.")

        # CWE-377 : fichier temporaire non securise
        if fname == "tempfile.mktemp":
            self._add(node, "CWE-377", "Fichier temporaire non securise", "medium", "high",
                      "tempfile.mktemp() est sujet a une condition de course. "
                      "Utilisez tempfile.mkstemp() ou NamedTemporaryFile.")

        # CWE-611 : entites XML externes (XXE)
        resolve_ent = _kw(node, "resolve_entities")
        if isinstance(resolve_ent, ast.Constant) and resolve_ent.value is True:
            self._add(node, "CWE-611", "Entites XML externes (XXE)", "high", "high",
                      "resolve_entities=True autorise les entites externes (XXE). "
                      "Utilisez defusedxml ou desactivez les entites.")

        # CWE-732 : permissions de fichier trop permissives
        if fname == "os.chmod" and len(node.args) >= 2 \
                and isinstance(node.args[1], ast.Constant) \
                and isinstance(node.args[1].value, int):
            mode = node.args[1].value
            if mode == 0o777 or (mode & 0o002):
                self._add(node, "CWE-732", "Permissions trop permissives", "medium", "high",
                          "chmod accorde des droits en ecriture a tous. Restreignez le mode.")

        self.generic_visit(node)

    # --- affectations de secrets en clair ---
    _SECRET_NAME = re.compile(r"(?i)(pass|passwd|password|secret|api_?key|access_?key|token|private_?key)")
    # Valeurs manifestement factices : evite les faux positifs sur des exemples.
    _PLACEHOLDER = re.compile(
        r"(?i)(^<.*>$|\$\{|\{\{|%\(|example|changeme|change_me|your[_-]|xxx+|"
        r"placeholder|redacted|dummy|insert[_-]?|foobar|to[_-]?do)")

    @staticmethod
    def _target_names(node):
        for tgt in node.targets:
            if isinstance(tgt, ast.Name):
                yield tgt.id
            elif isinstance(tgt, ast.Attribute):
                yield tgt.attr

    def visit_Assign(self, node: ast.Assign):
        secret_target = any(self._SECRET_NAME.search(n) for n in self._target_names(node))

        # CWE-798 : secret en clair (valeur litterale, hors placeholders evidents)
        if secret_target and isinstance(node.value, ast.Constant) \
                and isinstance(node.value.value, str):
            val = node.value.value
            if len(val) >= 4 and not self._PLACEHOLDER.search(val):
                self._add(node, "CWE-798", "Identifiant/secret en clair", "high", "medium",
                          "Secret code en dur. Utilisez une variable d'environnement ou un coffre.")

        # CWE-330 : aleatoire non cryptographique pour un secret
        if secret_target and isinstance(node.value, ast.Call):
            chain = _attr_chain(node.value.func)
            if chain.startswith("random."):
                self._add(node, "CWE-330", "Aleatoire non cryptographique", "high", "high",
                          "Le module 'random' n'est pas sur pour des secrets. "
                          "Utilisez le module 'secrets' ou os.urandom.")
        self.generic_visit(node)


# --------------------------------------------------------------------------
# Analyse de flux (taint) intra-fonction : suit les donnees non fiables
# (request.*, input(), sys.argv) jusqu'a un point dangereux (sink).
# --------------------------------------------------------------------------
def _iter_scope(node):
    """Descend dans un scope sans entrer dans les def/class imbriquees."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        yield child
        yield from _iter_scope(child)


def _expr_is_tainted(node, tainted) -> bool:
    """Vrai si l'expression contient une source non fiable ou une variable teintee."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name):
            if sub.id in tainted or sub.id == "request":
                return True
        elif isinstance(sub, ast.Call) and _attr_chain(sub.func) == "input":
            return True
        elif isinstance(sub, ast.Attribute) and _attr_chain(sub).startswith("sys.argv"):
            return True
    return False


_SSRF_HOSTS = ("requests.", "httpx.", "aiohttp.")
_SSRF_SHORT = {"get", "post", "put", "delete", "patch", "head", "request", "urlopen"}


def _taint_findings(tree, lines) -> List[Finding]:
    out: List[Finding] = []
    scopes = [tree] + [n for n in ast.walk(tree)
                       if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    for scope in scopes:
        nodes = list(_iter_scope(scope))
        assigns = [n for n in nodes if isinstance(n, ast.Assign)]
        tainted = set()
        changed = True
        while changed:          # point fixe
            changed = False
            for a in assigns:
                if _expr_is_tainted(a.value, tainted):
                    for tgt in a.targets:
                        if isinstance(tgt, ast.Name) and tgt.id not in tainted:
                            tainted.add(tgt.id)
                            changed = True
        for call in [n for n in nodes if isinstance(n, ast.Call)]:
            if not call.args or not _expr_is_tainted(call.args[0], tainted):
                continue
            fname = _attr_chain(call.func)
            short = fname.split(".")[-1]
            cwe = name = None
            if fname in ("os.system", "os.popen"):
                cwe, name = "CWE-78", "Injection de commande (donnee utilisateur)"
            elif fname in ("eval", "exec"):
                cwe, name = "CWE-94", "Injection de code (donnee utilisateur)"
            elif short in ("execute", "executemany", "executescript"):
                cwe, name = "CWE-89", "Injection SQL (donnee utilisateur)"
            elif (isinstance(call.func, ast.Name) and call.func.id == "open") \
                    or fname in ("io.open", "os.open"):
                cwe, name = "CWE-22", "Traversee de chemin (Path Traversal)"
            elif fname == "urllib.request.urlopen" or \
                    (short in _SSRF_SHORT and fname.startswith(_SSRF_HOSTS)):
                cwe, name = "CWE-918", "Requete cote serveur controlee (SSRF)"
            if cwe:
                ln = getattr(call, "lineno", 0)
                snippet = lines[ln - 1].strip()[:200] if 0 <= ln - 1 < len(lines) else ""
                out.append(Finding(cwe=cwe, name=name, severity="high", confidence="high",
                                   line=ln, message="Une donnee non fiable atteint ce point "
                                   "sensible (analyse de flux). Validez/echappez l'entree.",
                                   snippet=snippet, source="taint"))
    return out


# --------------------------------------------------------------------------
# Détecteurs regex (multi-langage) pour secrets a haute confiance.
# --------------------------------------------------------------------------
_SECRET_PATTERNS = [
    ("CWE-798", "Token Hugging Face", re.compile(r"hf_[A-Za-z0-9]{20,}")),
    ("CWE-798", "Cle API OpenAI", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("CWE-798", "Cle d'acces AWS", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("CWE-798", "Token GitHub", re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}")),
    ("CWE-798", "Cle privee (PEM)", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("CWE-798", "Google API key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
]


def _scan_secrets_regex(text: str) -> List[Finding]:
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        for cwe, name, pat in _SECRET_PATTERNS:
            if pat.search(line):
                out.append(Finding(
                    cwe=cwe, name=name, severity="high", confidence="high",
                    line=i, message=f"{name} detecte en clair. Revoquez-le et "
                    "stockez-le hors du code (variable d'environnement/coffre).",
                    snippet=(line.strip()[:60] + "..." if len(line) > 60 else line.strip()),
                    source="regex",
                ))
    return out


# --------------------------------------------------------------------------
# API publique.
# --------------------------------------------------------------------------
_SUPPRESS = re.compile(r"#\s*(nosec|azarus\s*:\s*ignore)\b", re.I)


def _suppressed_lines(text: str) -> set:
    """Lignes portant un commentaire de suppression (# nosec / # azarus: ignore)."""
    return {i for i, line in enumerate(text.splitlines(), 1) if _SUPPRESS.search(line)}


def scan_source(text: str, language: str = "python") -> List[Finding]:
    """Analyse un extrait de code source et renvoie la liste des findings."""
    findings: List[Finding] = []
    findings.extend(_scan_secrets_regex(text))
    if language == "python":
        try:
            tree = ast.parse(text)
        except SyntaxError:
            return findings
        lines = text.splitlines()
        visitor = _PyVisitor(lines)
        visitor.visit(tree)
        findings.extend(visitor.findings)
        findings.extend(_taint_findings(tree, lines))
    # suppression inline
    suppressed = _suppressed_lines(text)
    findings = [f for f in findings if f.line not in suppressed]
    # dedup (meme cwe + meme ligne)
    seen = set()
    uniq = []
    for f in sorted(findings, key=lambda x: (x.line, x.cwe)):
        key = (f.cwe, f.line)
        if key not in seen:
            seen.add(key)
            uniq.append(f)
    return uniq
