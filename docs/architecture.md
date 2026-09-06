# Architecture — Moteur Intelligent de Détection d'Intrusions (AICYOU)

**Stagiaire :** Mouhamed Aziz Derouiche
**Encadrant :** Dr. Alaidine Ben Ayed — Stratégie AICYOU Inc.
**Repo :** `soc-aicyou`
**Dernière mise à jour :** 06/09/2026

## 1. Vue d'ensemble

Environnement de lab SOC déployé sur une VM Ubuntu Server 22.04 LTS dédiée, hébergeant une stack Wazuh (SIEM/HIDS) et Suricata (NIDS), orchestrés via Docker Compose. Le système collecte, normalise et analyse des événements de sécurité selon trois couches de détection complémentaires (signatures, comportementale/règles, intelligence artificielle), avec priorisation automatique des alertes et correspondance MITRE ATT&CK, exposées via un tableau de bord Streamlit.

**Portée actuelle** (voir section 8, Limites connues, pour le détail honnête) : les couches signatures et comportementale (Suricata + Wazuh) sont pleinement opérationnelles et validées sur trafic réel. La couche IA (scoring de risque + classification de tactique) est rigoureusement validée sur le jeu de données NSL-KDD, mais n'est pas intégrée au flux de données live — un écart de schéma de features architectural, documenté en section 8. Une voie de résolution (schéma NetFlow standard + modèle entraîné sur NF-CSE-CIC-IDS2018) a été testée le 06/09/2026 et **écartée sur mesure** : rappel de 0 sur 10 440 attaques réelles, AUC-ROC 0,1604.

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

**Mise à jour du 06/09/2026.** Une tentative de rendre le mécanisme IA opérationnel sur le trafic live a été menée et **a échoué de façon mesurée** : voir section 8 et `docs/journal-technique.md`, entrée du 06/09/2026. Le statut du mécanisme basé IA reste donc inchangé — validé sur NSL-KDD, jamais exécuté avec succès sur trafic live. Ce n'est plus une limite seulement identifiée, c'est désormais une limite dont une voie de résolution a été testée et écartée sur preuve.


## 8. Limites connues (transparence)

Cette section liste les limites actuelles du système, identifiées par tests rigoureux plutôt que supposées absentes. Philosophie du projet : documenter honnêtement ce qui n'est pas résolu plutôt que le dissimuler.

- **Écart architectural majeur — le moteur IA n'a jamais tourné sur des données live.** `feature_extractor.py` produit 14 colonnes agrégées par fenêtre temporelle (`event_count`, `unique_dest_ports`, etc.), tandis que les modèles sont entraînés sur le schéma NSL-KDD (41 colonnes détaillées par session). Aucun recouvrement. Toute validation ML (rapports, dashboard, démonstrations) porte exclusivement sur NSL-KDD. `feature_schema.py` (15/08/2026) empêche un échec silencieux ou cryptique, mais ne résout pas l'écart.

  **Une voie de résolution a été testée et écartée sur preuve (06/09/2026).** Plutôt qu'une couche d'adaptation entre deux schémas incompatibles, l'approche consistait à produire depuis le trafic live un schéma *identique* à celui d'un jeu public étiqueté — NetFlow standard v1, 12 features (Sarhan et al., BDTA 2020) — et à y appliquer un modèle entraîné sur NF-CSE-CIC-IDS2018 (8 392 401 flux). Une porte de décision était fixée avant mesure et inscrite dans le code : rappel binaire > 50 % sur scan et DoS.

  **Résultat : 0 attaque détectée sur 10 440** flux réels étiquetés. Et le résultat est plus fort qu'un défaut de généralisation — **AUC-ROC = 0,1604**, très en dessous de 0,5 : le modèle est systématiquement *anti-corrélé*, attribuant une probabilité d'attaque plus basse aux vraies attaques (0,004–0,024) qu'au trafic bénin (0,061). Deux hypothèses concurrentes ont été écartées par la mesure : le pipeline d'inférence est correct (rappel 1,0000 sur les mêmes classes côté jeu source, par le même chemin de code), et ce n'est pas un problème de seuil (l'AUC n'en dépend pas ; descendre à 0,01 ne récupère du rappel qu'au prix de 52,8 % de faux positifs).

  Mécanisme mesuré : deux features portent 91 % de la décision — `OUT_PKTS` (0,6004) et `L4_DST_PORT` (0,3138) — et ce sont précisément celles qui ne transfèrent pas. Les attaques du banc CIC se concentrent à ~90 % sur les ports 53/80/443/8080 ; les nôtres s'étalent sur 1000 ports (scan nmap), avec seulement 16,0 % des flux d'attaque live sur un port déjà vu comme attaque à l'entraînement. Le modèle a appris le profil du banc d'essai, pas un comportement d'attaque transférable.

  Ce qui reste utilisable : `flow_feature_extractor.py` (12 features NetFlow v1 depuis le trafic réel, deux contrats vérifiables) et `netflow_ground_truth.py` (19 209 flux réels étiquetés depuis des sources externes aux features). Détail complet, chiffres et reproduction : `docs/journal-technique.md`, entrée du 06/09/2026.

  **Conséquence de portée.** Trois livrables du cahier des charges — moteur de détection intelligent, module de priorisation, correspondance MITRE ATT&CK — restent partiels pour cette raison unique, et le demeurent après cette tentative. La fermeture réelle passerait par un modèle entraîné sur du trafic du réseau lui-même, ce que les 19 209 flux étiquetés rendent désormais possible mais qui n'a pas été entrepris dans cette session.

- **PrivilegeEscalation reste la catégorie la plus faible du classifieur de tactique** (F1 = 0.19, précision = 0.13 même après SMOTE modéré — seulement 52 exemples d'entraînement réels dans NSL-KDD). Politique de traitement manuel systématique en place, indépendamment du score affiché.
- **Suricata ne distingue pas nativement un flood mono-port d'un scan multi-ports** (voir section 6) — désambiguïsation dépendante de la couche IA, elle-même non intégrée au flux live.
- **Aucune automatisation SOAR** — toutes les actions de confinement documentées dans le playbook restent manuelles à ce stade du prototype.
- **SLA du playbook non applicables automatiquement** — aucun mécanisme d'alerte (email/Slack/webhook), le dashboard est consulté manuellement (pull), pas de garantie de respect des délais cibles (15 min critique / 24h haute priorité).
- **Aucune visibilité sur le contenu du trafic chiffré** au-delà des métadonnées (SNI, JA3, etc.) — limite structurelle de tout NIDS face au chiffrement.
- **Dashboard sans authentification**, ouvert à tout le sous-réseau local (voir section 4).
- **Pas de politique de rétention/purge des données** sur `alerts.jsonl`/`triage_log.json` — pertinent pour une future section conformité Loi 25 (Québec), activité principale d'AICYOU, non encore rédigée dans ce document.
- **Extra Trees entraîné sur un sous-échantillon** (1 M de lignes sur 5 874 680) par contrainte de RAM de la VM (~2 Go utilisables). Ses métriques ne sont donc pas rigoureusement comparables à celles de XGBoost, entraîné sur le jeu complet ; le drapeau `subsampled` figure dans `netflow_training_report.json`.
- **La collecte live est à l'arrêt depuis le 29/07/2026.** `data/checkpoint.txt` est figé à `2026-07-29T21:57:44Z` alors que l'indexeur Wazuh contient des alertes jusqu'à aujourd'hui (vérifié le 06/09/2026 : alerte la plus récente `2026-09-06T13:53:49Z`, 10 000 documents). `collector.py` est un tirage manuel, pas un service — il n'a simplement pas été relancé depuis 39 jours. Tout ce que produisent `feature_extractor.py` et le tableau de bord repose donc sur un instantané de juillet.
- **Les features `inbound_*` sont quasi mortes, et ce n'est pas un problème d'adresse.** Mesuré sur les 9627 alertes de `alerts.jsonl` : 6 événements entrants avec `MONITORED_HOST_IP=192.168.1.112`, **0** avec `192.168.1.249` — alors que les features sortantes comptent respectivement 5013 et 4205 événements. La cause est celle déjà décrite dans l'en-tête de `feature_extractor.py` : Wazuh n'indexe que les événements Suricata de type `alert`, et presque aucune alerte indexée n'a la machine surveillée comme *destination* de flux. `MONITORED_HOST_IP` a été corrigé de `.112` vers `.249` le 06/09/2026 (adresse réelle de `ens33`), ce qui est juste mais ne ranime pas ces features.
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
| Porte de décision chiffrée et inscrite dans le code AVANT la mesure (`netflow_transfer_test.py`, `GATE_MIN_RECALL`) | Un critère fixé après coup s'ajuste au résultat obtenu. Inscrit dans le code, il rend l'arrêt vérifiable plutôt que discrétionnaire |
| Adresses IP exclues de l'entrée des modèles NetFlow (`NETFLOW_V1_MODEL_COLUMNS`) | Les IP sont propres au plan d'adressage du banc d'essai ; un modèle qui les utilise mémorise ce réseau au lieu d'apprendre un comportement |
| Vérité terrain live justifiée par des sources externes aux features (`auth.log`, journal de bord, nombre de ports distincts) | Étiqueter un flux « scan » parce qu'il porte le drapeau SYN seul rendrait circulaire le test du modèle censé apprendre ce signal |
| Chaque constante dérivée d'un jeu de données est accompagnée de son vérificateur exécutable (`--verify-schema`, `--verify-l7`, `verify_parent_mapping`) | Une constante figée dérive silencieusement quand la source change ; un vérificateur transforme la dérive en échec visible |

## 10. Prochaines étapes

- Fermer l'écart de schéma de features — priorité la plus élevée. La voie « modèle public entraîné sur un autre réseau » est mesurée et écartée (section 8). La voie restante est un modèle entraîné sur le trafic du réseau lui-même : les 19 209 flux réels étiquetés au schéma NetFlow v1 (`netflow_ground_truth.py`) la rendent possible, avec une validation croisée temporelle (entraînement sur les campagnes de juillet-août, test sur celle du 31/08). Réserve connue : 56 flux seulement pour la classe force brute.
- Corriger `MONITORED_HOST_IP` dans `pipeline/.env`, et trancher si les features `inbound_*` / `outbound_*` de `feature_extractor.py` conservent une utilité.
- Rédaction de la section conformité Loi 25 (Québec) — authentification dashboard, politique de rétention des données.
- Guide d'installation (livrable attendu, non commencé).
- Rapport technique final consolidant l'ensemble du journal technique.
