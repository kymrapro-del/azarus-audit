<div align="center">

```
   ▄▀█ ▀█ ▄▀█ █▀█ █░█ █▀   ▄▀█ █░█ █▀▄ █ ▀█▀
   █▀█ █▄ █▀█ █▀▄ █▄█ ▄█   █▀█ █▄█ █▄▀ █ ░█░
   ─────────────────────────────────────────
     scanner de sécurité open-source · CWE
```

# azarus-audit

**Scanner de sécurité open-source, déterministe et auto-hébergeable.**
Il détecte des vulnérabilités dans le code, les mappe aux identifiants **CWE**,
et signale les **dépendances vulnérables** (CVE) via la base mondiale OSV.dev.

[![Version](https://img.shields.io/badge/version-0.1.0-10b981.svg?style=flat-square)](VERSION)
[![Licence: MIT](https://img.shields.io/badge/licence-MIT-gray.svg?style=flat-square)](LICENSE)
[![Python: 3.9+](https://img.shields.io/badge/python-3.9%2B-3776ab.svg?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Tests](https://img.shields.io/badge/tests-33_passing-10b981.svg?style=flat-square)](tests/)
[![CI](https://img.shields.io/badge/CI-GitHub_Actions-2088ff.svg?style=flat-square&logo=githubactions&logoColor=white)](.github/workflows/)
[![SARIF](https://img.shields.io/badge/export-SARIF_2.1.0-6b7280.svg?style=flat-square)](azarus_audit/sarif.py)

**Démo en ligne** : https://huggingface.co/spaces/Kymra/azarus-audit

</div>

---

## Pourquoi

La plupart des scanners sérieux sont des **SaaS fermés** (le code part chez un
tiers) ou de simples linters à motifs. `azarus-audit` prend le contre-pied :

- **Déterministe** : analyse **AST** + **analyse de flux (taint)** + secrets.
  Pas de boîte noire, résultats reproductibles.
- **Hors-ligne et souverain** : le cœur ne dépend d'**aucune** IA ni d'aucun
  réseau. Il tourne sur ta machine, ton code ne sort pas.
- **Sans dépendance** : le cœur est en **stdlib Python pure**.
- **Standard** : export **SARIF 2.1.0** (onglet Security de GitHub, IDE).
- **IA optionnelle** : le modèle open-weights *Azarus* ne sert qu'à
  **expliquer et prioriser** (triage). C'est un composant, pas le cœur.

## Installation

```bash
pip install .
# ou, pour la console interactive et le tableau de bord :
pip install ".[tui]"
```

## Démarrage rapide

```bash
azarus-audit scan mon_projet/                 # audit du code (CWE)
azarus-audit scan mon_projet/ --sarif r.sarif # export code scanning / IDE
azarus-audit scan mon_projet/ --markdown r.md # rapport lisible (PR, CI)
azarus-audit deps mon_projet/                 # dépendances vulnérables (OSV)
azarus-audit console                          # interface interactive 4 quadrants
```

Codes de sortie : `0` = rien (selon `--fail-on`), `1` = seuil atteint, `2` = usage.

### Exemple

```
$ azarus-audit scan app.py

app.py
  [ ELEVE ] CWE-798  L12   Clé API en clair
           Clé API détectée en clair. Révoquez-la et stockez-la hors du code.
  [CRITIQUE] CWE-89   L20   Injection SQL
           Requête SQL construite par concaténation de données non fiables.
============================================================
  2 finding(s) dans 1 fichier(s)
  Sévérité : CRITIQUE=1, ELEVE=1
  CWE : CWE-89=1, CWE-798=1
============================================================
```

## Ce que ça détecte

| CWE | Vulnérabilité |
|---|---|
| CWE-89 | Injection SQL (chaînes dynamiques à forte confiance) |
| CWE-78 | Injection de commande OS |
| CWE-94 | Injection de code (`eval` / `exec`) |
| CWE-502 | Désérialisation non sûre (`pickle`, `yaml`) |
| CWE-22 | Path traversal *(via analyse de flux)* |
| CWE-918 | SSRF *(via analyse de flux)* |
| CWE-798 | Secrets / clés en clair |
| CWE-330 | Aléa non cryptographique pour un secret |
| CWE-327 | Cryptographie faible (MD5/SHA1) |
| CWE-295 | Vérification TLS désactivée |
| CWE-611 | XXE (entités externes XML) |
| CWE-489 | Debug activé en production |
| CWE-377 | Fichier temporaire non sûr |
| CWE-732 | Permissions trop larges |

Plus le **scan de dépendances** (OSV.dev) : toutes les CVE connues des
composants tiers de ton projet.

## Fiabilité (chiffres reproductibles)

- **Benchmark interne étiqueté** : 24/24 détectés, 0 faux positif.
- **Dataset public réel** (Hugging Face, code Python) : ~75 % de détection.
- **Code mature audité** (Flask, Jinja2, Werkzeug) : faux positifs quasi nuls.
- **33 tests** unitaires, CI dédiée, auto-scan (le scanner s'audite lui-même).

```bash
python -m azarus_audit.benchmark.run            # benchmark interne (24/24)
python -m azarus_audit.benchmark.external       # dataset public réel
```

## Intégration continue

### GitHub Action réutilisable

```yaml
- uses: kymrapro-del/azarus-audit@main
  with:
    path: .          # dossier à auditer
    fail-on: high    # faire échouer la CI à partir de "high" (défaut: never)
```

Elle produit un rapport **SARIF** (à passer à `github/codeql-action/upload-sarif`)
et un rapport **Markdown**. Le workflow [`pr-audit.yml`](.github/workflows/pr-audit.yml)
montre l'intégration complète : scan de chaque PR → onglet Security → commentaire
de synthèse mis à jour à chaque exécution.

## Arborescence

```
azarus-audit/
├── azarus_audit/          # le scanner
│   ├── detectors.py       #   détecteurs CWE (AST) + analyse de flux (taint)
│   ├── deps.py            #   dépendances vulnérables via OSV.dev
│   ├── sarif.py           #   export SARIF 2.1.0
│   ├── report_md.py       #   rapport Markdown (PR / CI)
│   ├── ai_engine.py       #   moteur IA optionnel (findings structurés)
│   ├── triage.py          #   triage optionnel par le modèle Azarus
│   ├── cli.py / tui.py    #   CLI + console interactive 4 quadrants
│   └── benchmark/         #   évaluation interne + externe reproductible
├── tests/                 # 33 tests unitaires
├── action.yml             # GitHub Action réutilisable
├── .github/workflows/     # CI, audit des PR, release
├── VERSION / CHANGELOG.md # versionnage sémantique
└── LICENSE                # MIT
```

## Versionnage et release

- **SemVer** (`VERSION`), historique dans [`CHANGELOG.md`](CHANGELOG.md).
- **CI** : lint + tests + auto-scan sur chaque push/PR ([`ci.yml`](.github/workflows/ci.yml)).
- **Release** : un tag `vX.Y.Z` publie automatiquement une GitHub Release
  ([`release.yml`](.github/workflows/release.yml)).

```bash
git tag v0.1.0 && git push origin v0.1.0    # déclenche la release
```

## Licence

[MIT](LICENSE). © 2026 Torquéau Mathis. Conçu pour l'audit autorisé, la
sécurisation des infrastructures et la recherche en sécurité défensive.
