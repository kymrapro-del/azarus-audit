# Changelog

Toutes les évolutions notables de ce projet sont documentées ici.
Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/) et le
projet adhère au [versionnage sémantique](https://semver.org/lang/fr/).

## [0.1.0] - 2026-09-10

Première release publique du scanner extrait dans son dépôt dédié.

### Ajouté
- Détecteurs déterministes pour 14 familles **CWE** (injection SQL, commande,
  code, désérialisation, secrets, crypto faible, TLS, XXE, permissions…).
- **Analyse de flux (taint)** intra-fonction : path traversal (CWE-22), SSRF
  (CWE-918).
- **Scan de dépendances** via la base mondiale **OSV.dev** (CVE des composants
  tiers).
- Exports **SARIF 2.1.0**, **JSON** et **Markdown**.
- **GitHub Action réutilisable** (`action.yml`) + workflow d'audit des PR
  (SARIF vers l'onglet Security + commentaire de synthèse).
- CLI, console interactive 4 quadrants et tableau de bord live.
- Triage / moteur IA **optionnels** (modèle open-weights Azarus).
- Suite de **33 tests**, CI, auto-scan, benchmark interne (24/24) et externe
  (dataset public réel, ~75 % de détection).

[0.1.0]: https://github.com/kymrapro-del/azarus-audit/releases/tag/v0.1.0
