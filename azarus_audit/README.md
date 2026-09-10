# azarus-audit

Auditeur de securite open-source, auto-hebergeable, qui detecte des
vulnerabilites serieuses dans du code source et les mappe aux identifiants
**CWE**.

Le coeur est **deterministe** (analyse AST + motifs) et fonctionne **sans IA**,
hors-ligne. Une couche facultative de **triage par un modele open-weights
(Azarus)** explique les findings et aide a ecarter les faux positifs. L'IA est
un composant, pas le coeur.

## Installation

```bash
pip install .            # fournit la commande `azarus-audit`
# ou sans installation :
python -m azarus_audit scan chemin/

# TUI (facultatif) :
pip install ".[tui]"     # rich + prompt_toolkit
```

Le scan, le benchmark, le rapport JSON et l'export SARIF ne dependent d'aucune
librairie externe (stdlib pure).

## Detecteurs (v0.1)

| CWE | Vulnerabilite | Methode |
|---|---|---|
| CWE-89 | Injection SQL (concat / f-string / %) | AST |
| CWE-78 | Injection de commande OS (os.system, shell=True) | AST |
| CWE-94 | Injection de code (eval / exec) | AST |
| CWE-502 | Deserialisation non sure (pickle, yaml.load) | AST |
| CWE-327 | Hachage faible (md5 / sha1) | AST |
| CWE-295 | TLS non verifie (verify=False, check_hostname=False) | AST |
| CWE-798 | Secrets en clair (mots de passe, tokens, cles) | AST + regex |
| CWE-330 | Aleatoire non cryptographique pour un secret | AST |
| CWE-489 | Mode debug expose (run(debug=True)) | AST |
| CWE-377 | Fichier temporaire non sur (tempfile.mktemp) | AST |
| CWE-611 | Entites XML externes (XXE, resolve_entities=True) | AST |
| CWE-732 | Permissions trop permissives (chmod monde-inscriptible) | AST |

En complement, la commande `deps` detecte les **dependances vulnerables connues**
en interrogeant la base mondiale **OSV.dev** (CVE / GitHub Advisory / PyPA).

## Usage

```bash
# Scan simple (dossier ou fichier)
azarus-audit scan mon_projet/

# Rapport JSON + SARIF (GitHub code scanning / IDE) + seuil d'echec CI
azarus-audit scan . --json rapport.json --sarif rapport.sarif --fail-on high

# Triage par le modele Azarus (facultatif, necessite l'endpoint)
azarus-audit scan app.py --triage

# Moteur IA : le modele cherche AUSSI des failles (findings marques "(IA)")
azarus-audit scan app.py --ai

# Console interactive 4 quadrants (facultatif : rich + prompt_toolkit)
azarus-audit console

# Dependances vulnerables connues (base mondiale OSV.dev, acces reseau requis)
azarus-audit deps .                 # lit les requirements.txt du projet
azarus-audit deps --installed       # analyse les paquets installes
```

## Dependances vulnerables (OSV.dev)

`deps` croise les dependances epinglees (`name==version`) avec **OSV.dev**, la
base publique qui agrege CVE, GitHub Advisory et PyPA. C'est le mecanisme qui
permet de detecter **toutes les vulnerabilites deja publiees** dans les
composants tiers (la meme approche que pip-audit / Dependabot), avec la version
corrigee pour chaque faille.

> Portee honnete : ceci couvre les failles CONNUES des dependances. Aucun outil
> ne detecte les vulnerabilites inconnues ou toute la logique metier : le
> scanner de code (ci-dessus) couvre des CLASSES de failles (CWE), pas
> l'exhaustivite.

Codes de sortie : `0` aucun finding au-dela du seuil, `1` findings, `2` usage.

### Suppression inline

Une ligne portant `# nosec` ou `# azarus: ignore` est ignoree par le scanner
(utile pour un faux positif assume ou une fixture de test).

## Benchmarks

**Interne (reproductible)** : `python -m azarus_audit.benchmark.run`
Corpus etiquete (cas vulnerables + versions sures) : 24/24, 0 faux positif.

**Externe, donnees publiques reelles** :
`python -m azarus_audit.benchmark.external` (dataset Hugging Face
`CyberNative/Code_Vulnerability_Security_DPO`, 274 Python vulnerables + 274 surs)
-> **~75 % de detection** sur du code reellement vulnerable.

**Faux positifs sur du code mature** : scanne des librairies auditees (Flask,
Jinja2, Werkzeug, Requests, ~120 fichiers) -> une poignee de findings
critique/eleve, **tous de vrais `eval`/`exec`/`pickle`** internes (comme les
signale Bandit), zero faux positif errone.

> Note d'honnetete : sur le dataset externe, le "taux de faux positifs" apparent
> est trompeur car son code "sur" contient souvent encore de vraies failles
> (ex. `eval(user_input)`). La mesure de faux positifs fiable se fait sur du code
> mature audite (ci-dessus).

## Moteur IA (le modele comme moteur, pas comme chat)

Avec `--ai`, le modele open-weights (Azarus) lit le code et renvoie des findings
STRUCTURES (JSON), en COMPLEMENT du coeur deterministe. Il attrape des failles
de logique ou de contexte que les regles ne voient pas.

> Portee honnete : les findings IA sont marques `(IA)`, en confiance moyenne.
> Le modele peut se tromper (ligne imprecise, faux positif) ; ils sont donc
> clairement separables et destines a une revue humaine. Le coeur deterministe
> reste la source fiable ; l'IA est un complement.

## Limitations connues

- Analyse AST **Python** ; les autres langages ne beneficient que de la
  detection de secrets (regex).
- Analyse intra-fichier, sans suivi de flux inter-procedural.
- Couverture en cours d'extension (path traversal, SSRF, XXE a venir).

## Interfaces

- `scan` : rapport texte + JSON + SARIF, code de sortie pour la CI.
- `console` : 4 quadrants interactifs (commandes, resultats, logs, resume).
- `dashboard` : scan unique anime.

Licence : MIT (voir `LICENSE` a la racine).
