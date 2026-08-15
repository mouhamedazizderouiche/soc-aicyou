# Architecture — Moteur Intelligent de Détection d'Intrusions (AICYOU)

**Stagiaire :** Mouhamed Aziz Derouiche
**Encadrant :** Dr. Alaidine Ben Ayed — Stratégie AICYOU Inc.
**Repo :** `soc-aicyou`
**Dernière mise à jour :** 15/08/2026

## 1. Vue d'ensemble

Environnement de lab SOC déployé sur une VM Ubuntu Server 22.04 LTS dédiée, hébergeant une stack Wazuh (SIEM/HIDS) et Suricata (NIDS), orchestrés via Docker Compose. Le système collecte, normalise et analyse des événements de sécurité selon trois couches de détection complémentaires (signatures, comportementale/règles, intelligence artificielle), avec priorisation automatique des alertes et correspondance MITRE ATT&CK, exposées via un tableau de bord Streamlit.

**Portée actuelle** (voir section 8, Limites connues, pour le détail honnête) : les couches signatures et comportementale (Suricata + Wazuh) sont pleinement opérationnelles et validées sur trafic réel. La couche IA (scoring de risque + classification de tactique) est rigoureusement validée sur le jeu de données NSL-KDD, mais n'est pas encore intégrée au flux de données live — un écart de schéma de features architectural, documenté en section 8, reste à combler.

## 2. Infrastructure

| Composant | Détail |
|---|---|
| Hôte | VM Ubuntu Server 22.04 LTS, 16 Go RAM alloués côté host |
| Utilisateur système | `aicyou` (non-root, membre du groupe `docker`) |
| Réseau VM | Interface `ens33`, IP `192.168.1.249/24` (bridge, DHCP — a varié au cours du projet) |
| Orchestration | Docker Engine 29.6.2 + Docker Compose v5.3.1 |
| Pare-feu | UFW — deny incoming par défaut, exceptions ciblées |
| Simulation d'attaque | VM Windows 10 secondaire sur le même sous-réseau (`192.168.1.x`), outils : nmap, Posh-SSH, flood TCP via PowerShell natif |

## 3. Topologie des services
┌──────────────────────────────────────────────────┐
│ VM soc-aicyou (Ubuntu 22.04 LTS) │
│ IP: 192.168.1.249 │
│ │
│ ┌─────────────────┐ ┌──────────────────┐ │
│ │ wazuh.manager │ │ wazuh.indexer │ │
│ │ ports: 1514-1515,│ │ port: 9200 │ │
│ │ 514/udp, 55000 │ │ (interne, UFW) │ │
│ └─────────────────┘ └──────────────────┘ │
│ ┌─────────────────┐ │
│ │ wazuh.dashboard │ │
│ │ port: 443 → 5601 │ (accès restreint réseau │
│ └─────────────────┘ local via UFW) │
│ │
│ ┌─────────────────┐ │
│ │ suricata (NIDS) │ network_mode: host │
│ │ interface: ens33 │ cap: NET_ADMIN/NET_RAW │
│ └─────────────────┘ │
│ │
│ ┌──────────────────────────────────────┐ │
│ │ pipeline/ (Python, hors Docker) │ │
│ │ collecte → normalisation → features │ │
│ │ → scoring de risque → tactique MITRE │ │
│ │ → dashboard Streamlit (port 8501) │ │
│ └──────────────────────────────────────┘ │
└──────────────────────────────────────────────────┘
## 4. Sécurité — mesures appliquées

- **Aucun service exécuté en root** : utilisateur dédié `aicyou`, ajouté au groupe `docker`.
- **Versions épinglées** : `wazuh-docker` intégré en Git submodule, épinglé sur le tag `v4.9.0` ; Suricata épinglé sur `7.0.7`. Jamais `latest`.
- **Secrets hors Git** : mots de passe migrés vers `single-node/.env` (ignoré via `.gitignore` dédié dans le submodule), jamais commités en clair dans `docker-compose.yml`.
- **Mots de passe forts régénérés** : remplacement des identifiants par défaut (`admin/admin`, `kibanaserver/kibanaserver`, API `wazuh-wui`) par des secrets générés (`openssl rand -base64 24`) et hash bcrypt recalculés via l'utilitaire officiel Wazuh.
- **Pare-feu réseau** : UFW actif, politique deny-by-default. Le port 443 (dashboard Wazuh) est restreint au sous-réseau local `192.168.1.0/24`. SSH (22) reste ouvert pour l'administration.
- **Compte de service pipeline à privilèges minimaux** : `wazuh_client.py` utilise un compte dédié en lecture seule sur `wazuh-alerts-*`, jamais le compte administrateur.
- **Limitation connue** : le fichier `wazuh.yml` (config interne dashboard → API) ne supporte pas les variables d'environnement Docker Compose ; le mot de passe API y figure en clair. Ce fichier est donc actuellement commité avec un secret en dur — acceptable pour un repo strictement privé, mais à rotationner avant toute publication future.
- **Fork Git du submodule Wazuh** (correctif du 15/08/2026) : le submodule `docker/wazuh-docker` pointait initialement sur le dépôt officiel `wazuh/wazuh-docker` (accès lecture seule pour ce compte). Conséquence découverte tardivement : tous les commits locaux dans ce submodule (règles SSH brute-force, durcissement des identifiants) n'avaient jamais été effectivement poussés sur GitHub malgré des commits en apparence réussis — ils n'existaient que sur la VM. Corrigé par fork personnel (`github.com/mouhamedazizderouiche/wazuh-docker`), submodule repointé, historique complet récupéré et poussé. Vérifié par clone frais (`git clone --recurse-submodules`).
- **Dashboard sans authentification** : le tableau de bord Streamlit (port 8501) est actuellement accessible à quiconque sur le sous-réseau local, sans couche d'authentification. Acceptable pour un prototype de lab isolé ; à traiter avant toute évolution vers un contexte de production (pertinent notamment pour la conformité Loi 25 du Québec, activité principale d'AICYOU — voir section 8).

## 5. Pipeline de traitement (Phase 2)

| Module | Rôle |
|---|---|
| `wazuh_client.py` | Client API Wazuh Indexer, compte de service en lecture seule sur `wazuh-alerts-*` |
| `normalizer.py` | Unifie les schémas Wazuh/Suricata dans un format commun ; conserve `flow_src_ip`/`flow_dest_ip` (niveau flux) en plus de `src_ip`/`dest_ip` (niveau paquet) pour distinguer correctement le trafic entrant (attaque reçue) du trafic sortant (navigation normale) |
| `collector.py` | Collecte incrémentale par point de reprise (checkpoint), stockage JSON Lines, évite les doublons entre exécutions |
| `feature_extractor.py` | Extraction de caractéristiques comportementales par fenêtre temporelle glissante (1 min pour les rafales/scans, 5 min pour les tendances). Distingue explicitement trafic entrant/sortant. Produit 14 colonnes agrégées : `event_count`, `unique_dest_ips`, `unique_dest_ports`, `distinct_rule_ids`, `avg_rule_level`, `max_rule_level`, `suricata_ratio`, `time_span_seconds`, et les variantes `inbound_*`/`outbound_*` |

## 6. Détection en profondeur — trois couches

### Couche 1 — Signatures (Suricata natif)

Ruleset natif Suricata (40 000+ règles), détection de menaces connues (CVE, malware, exploits). Chargement confirmé au démarrage (8 threads worker).

### Couche 2 — Comportementale (règles custom, indépendantes de l'outil)

Règles Suricata et Wazuh personnalisées, ciblant des **patterns de comportement** plutôt que des signatures d'outil spécifiques — fonctionnent contre n'importe quel outil produisant le même trafic (nmap, masscan, script maison, etc.).

| Règle | Moteur | Détection | Seuil | Statut |
|---|---|---|---|---|
| `sid:9000001` | Suricata | Scan de ports (haute fréquence) | 15 SYN / 10s, même source | ✅ Validé (nmap live, 24/07 + 15/08) |
| `sid:9000002` | Suricata | Scan de ports lent (low-and-slow) | 10 SYN / 60s, même source | ✅ Validé (co-déclenche sur rafales rapides aussi — comportement attendu, voir note ci-dessous) |
| `sid:9000003` | Suricata | Flood volumétrique (DoS) | 50 SYN / 10s, même source, port surveillé | ✅ Validé live (15/08, flood TCP 300 connexions) |
| `100010` | Wazuh | Échecs SSH répétés (brute-force) | 3+ échecs / 120s, même source | ✅ Validé live (Posh-SSH, 04-06/08) |
| `100011` | Wazuh | Succès après échecs répétés (compromission probable) | déclenché par `100010` + succès | ✅ Validé live — signal le plus critique du système, niveau 14 |
| `100012`/`100013` | Wazuh | Escalade de sévérité pour `9000001`/`9000002` | niveau 8 | ✅ Ajouté 15/08 — corrige un angle mort où ces alertes restaient au niveau générique 3, identique au bruit de fond |
| `100014` | Wazuh | Escalade de sévérité pour `9000003` | niveau 12 | ✅ Ajouté 15/08 |

**Note importante — limite connue de la désambiguïsation scan/flood** : Suricata ne dispose d'aucun mécanisme natif de comptage de ports distincts dans sa directive `threshold`. En conséquence, un flood mono-port (`9000003`) déclenche aussi systématiquement les règles de scan (`9000001`/`9000002`), qui ne vérifient que le volume de SYN, pas leur diversité de destination. C'est un comportement **attendu et documenté**, pas un bug : la désambiguïsation fine largeur (scan) vs profondeur (flood) est la responsabilité de la couche 3 (`unique_dest_ports` dans `feature_extractor.py`), qui n'est pas encore intégrée au flux live (voir section 8).

### Couche 3 — Intelligence artificielle

| Composant | Détail |
|---|---|
| `risk_scorer.py` | Ensemble XGBoost (supervisé) + Isolation Forest (non supervisé, entraîné uniquement sur trafic normal). Logique OU : recall 70% → 77.5%, FPR 2.99% → 3.58%. Champ `flagged_by_anomaly_detector` pour la traçabilité des décisions issues d'Isolation Forest |
| `tactic_classifier.py` / `tactic_classifier_smote.py` | Classification multi-classe de la tactique MITRE ATT&CK probable à partir du comportement réseau. SMOTE modéré (pas d'équilibrage total, sur-amplification contre-productive constatée en v1) |
| `playbook.py` | Version structurée (machine-readable) du playbook de réponse aux incidents. `build_recommendation()` génère des recommandations ancrées dans la procédure réelle et les preuves spécifiques de l'alerte (confiance, détecteur responsable), pas un texte générique fixe |
| `analysis_engine.py` | Point d'entrée unique assemblant score de risque + tactique + contexte + recommandation |
| `feature_schema.py` | Contrat de schéma explicite (ajouté 15/08/2026), validé à chaque appel public de `RiskScorer` — voir section 8 |

**Entraînement et validation** : jeu de données NSL-KDD (académique). Ensemble XGBoost+Isolation Forest : recall 77.5% / FPR 3.58%. Classifieur de tactique, après extension de couverture à 39/39 types d'attaque (15/08/2026, voir `docs/journal-technique.md`) : accuracy de généralisation réelle 83.2% (F1 par tactique : Impact 0.93, Reconnaissance 0.70, InitialAccess_CredentialAccess 0.75, PrivilegeEscalation 0.19 — cette dernière catégorie reste faible, traitée en priorité manuelle systématique indépendamment du score par politique documentée dans le playbook).

## 7. Correspondance MITRE ATT&CK — deux mécanismes distincts

Point important pour une lecture honnête du système : le mapping MITRE ATT&CK repose sur **deux mécanismes indépendants**, à des stades de maturité différents.

| Mécanisme | Portée | Statut |
|---|---|---|
| **Basé sur les règles** (Suricata/Wazuh → tag MITRE statique, via `<mitre><id>` dans `local_rules.xml`) | Couvre les types d'attaque détectés par signature/règle comportementale (scan, brute-force SSH, flood) | ✅ **Live, automatique, validé sur trafic réel** (confirmé via `wazuh-logtest`, `mitre.id`/`mitre.tactic` peuplés dès le déclenchement de la règle) |
| **Basé sur l'IA** (`tactic_classifier.py`, apprentissage comportemental généralisant au-delà des signatures connues) | Vise à couvrir tout comportement suspect, y compris des variantes non signées | ⚠️ **Rigoureusement validé sur NSL-KDD (83.2% accuracy de généralisation), jamais exécuté avec succès sur trafic live** — écart de schéma de features, voir section 8 |

Les deux mécanismes répondent chacun à une partie de l'objectif du cahier des charges (*"associer automatiquement les événements détectés aux techniques du référentiel MITRE ATT&CK"*), mais avec des garanties de fiabilité différentes qu'il serait malhonnête de présenter comme équivalentes.

## 8. Limites connues (transparence)

Cette section liste les limites actuelles du système, identifiées par tests rigoureux plutôt que supposées absentes. Philosophie du projet : documenter honnêtement ce qui n'est pas résolu plutôt que le dissimuler.

- **Écart architectural majeur — le moteur IA n'a jamais tourné sur des données live.** `feature_extractor.py` produit 14 colonnes agrégées par fenêtre temporelle (`event_count`, `unique_dest_ports`, etc.), tandis que les modèles sont entraînés sur le schéma NSL-KDD (41 colonnes détaillées par session : `src_bytes`, `num_failed_logins`, `dst_host_serror_rate`, etc.). Aucun recouvrement, deux espaces de features fondamentalement différents. Toute validation ML antérieure (rapports, dashboard, démonstrations) porte exclusivement sur NSL-KDD. `feature_schema.py` (15/08/2026) empêche désormais un échec silencieux ou cryptique (`FeatureSchemaError` avec diagnostic complet), mais ne résout pas l'écart lui-même. Fermeture réelle nécessiterait soit une couche d'adaptation de features, soit un nouveau modèle entraîné directement sur le schéma live — hors du temps restant du stage, à documenter comme axe de poursuite.
- **PrivilegeEscalation reste la catégorie la plus faible du classifieur de tactique** (F1 = 0.19, précision = 0.13 même après SMOTE modéré — seulement 52 exemples d'entraînement réels dans NSL-KDD). Politique de traitement manuel systématique en place, indépendamment du score affiché.
- **Suricata ne distingue pas nativement un flood mono-port d'un scan multi-ports** (voir section 6) — désambiguïsation dépendante de la couche IA, elle-même non intégrée au flux live.
- **Aucune automatisation SOAR** — toutes les actions de confinement documentées dans le playbook restent manuelles à ce stade du prototype.
- **SLA du playbook non applicables automatiquement** — aucun mécanisme d'alerte (email/Slack/webhook), le dashboard est consulté manuellement (pull), pas de garantie de respect des délais cibles (15 min critique / 24h haute priorité).
- **Aucune visibilité sur le contenu du trafic chiffré** au-delà des métadonnées (SNI, JA3, etc.) — limite structurelle de tout NIDS face au chiffrement.
- **Dashboard sans authentification**, ouvert à tout le sous-réseau local (voir section 4).
- **Pas de politique de rétention/purge des données** sur `alerts.jsonl`/`triage_log.json` — pertinent pour une future section conformité Loi 25 (Québec), activité principale d'AICYOU, non encore rédigée dans ce document.
- **Latence pipeline bout-en-bout mesurée sur un seul run, échantillon de 200 alertes** — non une moyenne stabilisée sur plusieurs exécutions (voir `pipeline_latency_note` dans `data/validation_report.json`).

## 9. Décisions techniques notables

| Décision | Justification |
|---|---|
| Git submodule (pas de copie brute) pour Wazuh | Suit les mises à jour amont tout en gardant une version figée et reproductible |
| Pin sur tag, pas branche | Un tag est immuable ; une branche peut évoluer et casser la reproductibilité |
| Fork personnel du submodule Wazuh | Le dépôt officiel est en lecture seule pour ce compte — un fork est nécessaire pour que les commits soient réellement récupérables (voir section 4) |
| `.env` séparé plutôt que variables inline | Sépare la configuration du code, standard 12-factor app, évite la fuite de secrets dans Git |
| UFW restreint au sous-réseau local | Le dashboard n'a pas besoin d'exposition publique pour un lab de développement |
| Suricata en `network_mode: host` | Requis pour la capture de paquets bruts sur l'interface physique de la VM |
| Ensemble XGBoost + Isolation Forest (logique OU) | XGBoost a un plafond de recall structurel sur les types d'attaque absents de l'entraînement ; Isolation Forest, non supervisé, ne partage pas cette limite |
| Recommandations générées dynamiquement (`build_recommendation`) plutôt que table statique | Deux alertes de même bande/tactique peuvent avoir des recommandations différentes si leurs preuves sous-jacentes diffèrent (confiance, détecteur responsable) |
| Contrat de schéma explicite (`feature_schema.py`) au lieu de laisser XGBoost échouer nativement | Transforme un crash cryptique (ou pire, une prédiction silencieuse sur coïncidence de nombre de colonnes) en diagnostic actionnable |

## 10. Prochaines étapes

- Fermer l'écart de schéma de features entre le pipeline live et le modèle ML (couche d'adaptation ou nouveau modèle entraîné sur schéma live) — priorité la plus élevée pour une véritable intégration bout-en-bout.
- Rédaction de la section conformité Loi 25 (Québec) — authentification dashboard, politique de rétention des données.
- Guide d'installation (livrable attendu, non commencé).
- Rapport technique final consolidant l'ensemble du journal technique.
