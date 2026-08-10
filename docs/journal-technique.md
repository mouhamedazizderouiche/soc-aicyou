# Journal Technique — SOC AICYOU

Ce journal documente les décisions techniques, incidents rencontrés et résolutions, en complément du journal de stage ESPRIT (rempli manuellement).

---

## 21/07/2026 — Kickoff & préparation

- Lecture complète du cahier des charges (offre de stage AICYOU).
- Définition du planning sur 8 semaines (5 phases : environnement, pipeline, moteur IA, MITRE ATT&CK, validation).
- Préparation de l'environnement de travail (VM dédiée Ubuntu Server 22.04 LTS, 16 Go RAM).

## 23/07/2026 — Installation Docker & structuration du projet

- Installation de Docker Engine 29.6.2 + Docker Compose v5.3.1 sur la VM.
- **Incident** : premier essai réalisé en session root, ajoutant `root` au groupe `docker` au lieu de `aicyou`. **Résolution** : suppression du projet créé sous `/root`, recréation propre sous `/home/aicyou`, correction du groupe.
- Initialisation du dépôt Git `soc-aicyou` (structure `docker/`, `docs/`, `scripts/`, `data/`).
- Validation : `docker run hello-world` fonctionne sans `sudo` sous `aicyou`.

## 23/07/2026 — Intégration Wazuh (submodule)

- Ajout de `wazuh-docker` comme Git submodule.
- **Incident** : tentative de pin sur la branche `v4.9.0`, échec car c'est un **tag**, pas une branche. **Résolution** : checkout du tag via `git ls-remote --tags`.
- **Incident secondaire** : résolution DNS temporairement en échec (`Could not resolve host: github.com`), résolu spontanément après nouvelle tentative.

## 23/07/2026 — Hardening sécurité avant premier déploiement

- 5 mots de passe par défaut en clair identifiés dans `docker-compose.yml`.
- Création de `single-node/.env` avec mots de passe forts générés via `openssl rand -base64 24`.
- **Incident** : `.env` non ignoré par Git dans le submodule (dépôt indépendant, `.gitignore` racine non applicable). **Résolution** : `.gitignore` dédié créé dans `docker/wazuh-docker/`.
- Remplacement des valeurs en dur par des références `${VARIABLE}`.
- Génération de nouveaux hash bcrypt via le conteneur officiel `wazuh-indexer`.
- **Incident** : hash inversés entre `admin` et `kibanaserver` lors d'une première édition manuelle — détecté et corrigé par relecture systématique.
- Configuration UFW : deny-by-default, SSH ouvert, port 443 restreint à `192.168.1.0/24`.

## 23/07/2026 — Premier déploiement & résolution d'incident API

- Génération des certificats indexer, premier `docker compose up -d` réussi (3 conteneurs opérationnels).
- **Incident** : statut "Offline" pour l'API dans le dashboard. **Diagnostic** : test direct via `curl` confirmant que l'API manager fonctionnait — le problème venait du fichier interne `wazuh.yml` (config dashboard → API) qui conservait l'ancien mot de passe.
- **Résolution** : réécriture propre du fichier (après une première tentative erronée avec `echo >>` ayant dupliqué le bloc `hosts:`).
- Validation finale : statut API "Online" confirmé.

**Limitation documentée** : `wazuh.yml` ne supporte pas les variables d'environnement Docker Compose — mot de passe API en clair dans ce fichier spécifique.

## 23/07/2026 — Publication GitHub

- Création du dépôt distant privé `soc-aicyou` sur GitHub (compte personnel).
- Configuration de l'authentification via Personal Access Token (scope `repo`, expiration 90 jours).
- Premier push réussi de l'historique complet (structure, submodule Wazuh, documentation).

## 23-24/07/2026 — Déploiement Suricata (NIDS)

- Déploiement de Suricata en conteneur Docker (`jasonish/suricata:7.0.7`), `network_mode: host`, capacités `NET_ADMIN`/`NET_RAW`/`SYS_NICE` pour la capture de paquets bruts sur `ens33`.
- Configuration `HOME_NET` restreinte au sous-réseau réel (`192.168.1.0/24`) plutôt que la plage large par défaut.
- **Incident** : crash-loop au démarrage — le script d'entrée du conteneur tentait un `chown` sur `suricata.yaml`, bloqué par le montage en lecture seule (`:ro`). **Résolution** : retrait du flag `:ro`.
- Validation : moteur Suricata opérationnel (8 threads worker), 40 429 règles de détection chargées, capture confirmée en temps réel (événements DNS, TLS avec JA3/JA3S, flow), 10 alertes générées sur trafic de test normal.
- Commit et push de la configuration Suricata sur GitHub.

---

## Prochaine session

- Connexion Suricata → Wazuh (ingestion des logs `eve.json`).
- Démarrage Phase 2 : pipeline Python de collecte et normalisation des événements.

## 24/07/2026 — Intégration Suricata → Wazuh

- Migration du volume Suricata (nommé) vers un bind mount (`/var/log/suricata`) pour rendre les logs accessibles nativement depuis la VM hôte.
- Installation et enregistrement du Wazuh agent natif (v4.9.0) sur la VM, auto-enrôlé auprès du manager local (`127.0.0.1`).
- Configuration d'un bloc `<localfile>` dans `ossec.conf` (format JSON) pointant vers `/var/log/suricata/eve.json`.
- Validation : Wazuh applique automatiquement son ruleset natif Suricata (groupe de règles `ids, suricata`), sans décodeur additionnel nécessaire. Alertes structurées visibles dans le dashboard (ex: détection QUIC failed decrypt, signature 2231000).
- **Phase 1 (mise en place de l'environnement) complétée.**

## Prochaine session

- Démarrage Phase 2 : pipeline Python de collecte, normalisation des événements Wazuh/Suricata, extraction de caractéristiques comportementales.

## 26/07/2026 — Phase 2 : Pipeline Python (collecte, normalisation, features)

- Mise en place de l'environnement Python (venv, dépendances épinglées) et d'un client d'API Wazuh (`wazuh_client.py`).
- **Sécurité** : bascule vers un compte de service à privilèges minimaux (least-privilege) pour l'accès en lecture au pipeline, plutôt que d'utiliser un compte administrateur.
- Développement du module de normalisation (`normalizer.py`) : uniformisation des alertes Wazuh/Suricata dans un schéma commun exploitable.
- Développement du collecteur incrémental (`collector.py`) : stockage des alertes en JSON Lines, avec gestion de point de reprise (checkpoint) pour éviter les doublons entre exécutions.
- Développement de l'extraction de caractéristiques comportementales (`feature_extractor.py`), première version.

## 26/07/2026 — Phase 3 : Premier modèle de détection

- Entraînement d'un modèle XGBoost baseline pour la classification binaire (normal/attaque) sur le jeu de données NSL-KDD.
- Analyse de seuil de décision (`threshold_analysis.py`) et développement du module de scoring de risque (`risk_scorer.py`), avec bandes de risque (low/medium/high/critical).
- Développement du modèle de classification multi-classe des tactiques MITRE ATT&CK (`tactic_classifier.py` puis version SMOTE pour le rééquilibrage des classes).
- Assemblage du moteur d'analyse de bout en bout (`analysis_engine.py`) combinant score de risque, tactique prédite et recommandation.
- Évaluation complète du pipeline sur le jeu de test (`evaluate_full_pipeline.py`) : taux de détection, faux positifs, temps de traitement.

## 28/07/2026 — Couche 2 : règles Suricata comportementales

- Ajout de règles Suricata personnalisées, indépendantes de l'outil d'attaque, pour la détection de scan de ports (seuil de connexions par IP source sur une fenêtre de temps courte).
- Objectif : détecter le comportement de reconnaissance réseau plutôt qu'une signature d'outil spécifique (fonctionne contre nmap, masscan, ou tout scanner générant le même pattern de trafic).

## 29/07/2026 — Extraction de caractéristiques multi-échelle

- Amélioration de `feature_extractor.py` : distinction du trafic entrant/sortant par direction de flux (`flow_src_ip`/`flow_dest_ip`), pour isoler le vrai signal de reconnaissance du bruit de navigation web normal.
- Ajout de fenêtres temporelles multiples (1 minute pour les rafales/scans, 5 minutes pour les tendances comportementales générales).
- Rédaction du playbook de réponse aux incidents (`docs/playbook-reponse-incidents.md`) : procédures de triage par bande de risque et tactique MITRE.

## 02/08/2026 — Rapport de validation formel

- Développement de `validation_report.py` consolidant les métriques attendues par le cahier des charges : taux de détection, taux de faux positifs, temps de traitement (latence bout-en-bout du pipeline réel), pertinence de la priorisation.
- **Constat notable** : le goulot d'étranglement du pipeline réel n'est pas le calcul du modèle IA (quasi instantané) mais la requête réseau vers l'indexeur Wazuh.

## 04-06/08/2026 — Simulation d'attaque et Couche 2 côté hôte (Wazuh)

- Simulation d'une attaque par force brute SSH depuis une VM Windows dédiée (Posh-SSH), contre un compte de test jetable.
- **Constat** : la règle de corrélation native de Wazuh pour la force brute ne se déclenchait pas sur une attaque courte (sous le seuil par défaut), et une connexion réussie après plusieurs échecs était journalisée au même niveau de sévérité qu'une connexion normale — angle mort de détection.
- Développement de règles Wazuh personnalisées (`local_rules.xml`, règles 100010/100011) : escalade sur échecs répétés, et escalade forte spécifique en cas de succès suivant une série d'échecs (signal de compromission d'identifiants).
- **Difficultés de déploiement résolues** : `docker compose restart` n'applique pas les nouveaux montages de volumes (nécessite `up -d --force-recreate`) ; le mécanisme d'auto-copie de configuration de Wazuh (`/wazuh-config-mount/`) ne s'applique que sur un volume neuf, pas sur un déploiement existant (copie manuelle requise).
- Validation de bout en bout : les deux règles se déclenchent correctement lors d'une attaque réelle rejouée.

## 07-09/08/2026 — Tableau de bord Streamlit et amélioration IA

- Développement du tableau de bord SOC (`dashboard.py`) : vue d'ensemble avec résumé automatique en langage naturel, alertes en direct avec filtres avancés et workflow de triage persistant, cartographie MITRE ATT&CK, démonstration interactive du moteur d'analyse.
- **Amélioration majeure du modèle de détection** : ajout d'un détecteur d'anomalies Isolation Forest (non supervisé, entraîné uniquement sur trafic normal) en complément du XGBoost supervisé.
  - Diagnostic : le plafond de rappel du XGBoost est une limite structurelle de l'apprentissage supervisé (incapable de reconnaître un type d'attaque absent de son entraînement).
  - Isolation Forest ne partage pas cette limite, car il détecte des écarts au comportement normal plutôt que des signatures apprises.
  - Combinaison en ensemble (logique OU) : le rappel global passe de 70 % à 77,5 %, pour un coût modéré en faux positifs (2,99 % → 3,58 %).
  - Ajout d'un indicateur de traçabilité (`flagged_by_anomaly_detector`) affiché dans le tableau de bord, pour expliquer les décisions issues d'Isolation Forest plutôt que de les laisser incohérentes avec la bande de risque affichée.
- Correction de plusieurs incidents techniques : plantage du tableau de bord (conflit de version `pyarrow`), désynchronisation entre `analysis_engine.py` et la nouvelle signature de `risk_scorer.py`, bug de réinitialisation des filtres (perte d'état Streamlit lors de la navigation entre pages).
- **Audit complet du projet** (10/08/2026) : vérification de l'état du dépôt Git (principal et sous-module), de la structure des fichiers, et de la documentation — mise à jour du journal technique et du README suite à ce constat.

## Prochaine session

- Poursuite de l'audit : structure GitHub, couverture de tests, guide d'installation.
- Scénario d'attaque restant à valider : déni de service (Impact/TA0040).
- Rédaction du rapport technique final et préparation de la démonstration.
