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

## 14/08/2026 — Bug de conception découvert lors des tests : recommandations muettes sur les détections Isolation-Forest-seul

En testant `build_recommendation()` sur l'ensemble `X_test` complet (pas
seulement l'échantillon de démo), 1015 alertes sur le total étaient
capturées uniquement par Isolation Forest (`flagged_by_anomaly_detector=1`).
Leur recommandation ne mentionnait jamais ce fait.

**Cause** : `risk_band` est dérivé uniquement du score continu XGBoost
(`risk_scorer.py`). Une alerte captée *seulement* par Isolation Forest a,
par construction, un score XGBoost bas — sinon XGBoost l'aurait déjà
signalée. Ces alertes tombent donc presque systématiquement en bande
`low`/`medium`. La logique initiale de `build_recommendation()` retournait
un texte générique dès la bande basse, avant même de vérifier
`detected_by_anomaly` — masquant le signal précisément là où le principe
documenté dans le playbook ("l'absence de signature connue ne signifie
pas absence de risque") s'applique le plus.

**Correction** : `detected_by_anomaly` est désormais vérifié avant tout
court-circuit de bande. Une alerte low/medium mais anomaly-only reçoit
maintenant une recommandation de vérification L1, pas un message de
surveillance passive silencieux.

**Méthodologie** : trouvé en testant sur l'échantillon complet plutôt que
sur les 10 exemples de démo — un rappel que les tests sur petit échantillon
peuvent manquer des cas structurels qui ne se manifestent qu'à l'échelle.

## 14/08/2026 — Rapport de validation périmé, masquant l'amélioration de l'ensemble

`data/validation_report.json` datait du 02/08 (avant `isolation_forest.pkl`,
créé le 07/08) et affichait donc `detection_rate: 70.05%` — le score
XGBoost seul — alors que le système réel tourne en ensemble depuis le
07/08 (recall documenté : 77.5%). Le dashboard affichait donc un chiffre
inférieur à la réalité sans que rien ne l'indique.

`validation_report.py` lui-même était correct (`AnalysisEngine()` utilise
`use_ensemble=True` par défaut) — le problème était purement l'absence
de ré-exécution après le travail sur l'ensemble. Confirmé par re-run :
77.51% / FPR 3.58%, cohérent avec `ensemble_evaluation.py`.

Effet de bord détecté au passage : `pipeline_e2e_latency_ms` est passé de
775.5ms (run du 02/08) à ~58-62ms (4 runs consécutifs le 14/08) — écart de
~12x. Probablement un artefact de cold-start (premher run après boot/
connexion Wazuh à froid) plutôt qu'une vraie dérive de performance, mais
non confirmé formellement — documenté comme incertitude plutôt que
tranché arbitrairement.

**Correction** : `validation_report.json` inclut désormais `generated_at`
et `pipeline_latency_note` (échantillon 200 alertes, un seul run — pas une
moyenne stabilisée). Le dashboard affiche ces deux informations en
légende sous les métriques, pour qu'un lecteur comprenne qu'il s'agit
d'un instantané et non d'une mesure continue.

**Leçon méthodologique** : deux bugs distincts trouvés aujourd'hui
(recommandations anomaly-only muettes, rapport de validation périmé)
partagent la même cause racine — un composant du système reflète un état
antérieur du modèle/pipeline sans mécanisme pour le signaler. À surveiller
ailleurs dans le système (ex. carte MITRE ATT&CK — les F1-scores affichés
sont-ils à jour ?).

## 14-15/08/2026 — Lacune de couverture MITRE ATT&CK : 29% des attaques du test set jamais évaluées

**Origine** : question directe sur la fiabilité réelle du mapping MITRE
ATT&CK affiché au dashboard. Investigation menée par remise en question
systématique (le modèle a-t-il vraiment vu/évalué ce qu'il prétend
classifier ?) plutôt qu'acceptation des métriques affichées.

**Constat** : `mitre_categories.py` ne couvrait que les 22 types d'attaque
présents dans KDDTrain+. Le jeu de test NSL-KDD est délibérément conçu
pour inclure des types absents de l'entraînement (test de généralisation).
`build_tactic_dataset()` (`tactic_classifier.py`) filtre les labels
"Unknown" — donc 17 types d'attaque supplémentaires, soit **3750
échantillons sur 12833 (29.2%) du test set d'attaques**, n'étaient jamais
soumis à évaluation. Le chiffre documenté de ~94% d'accuracy ne portait
donc que sur les 22 types connus, pas sur la capacité réelle du modèle
à généraliser — alors que c'est précisément ce que le docstring du
module revendiquait ("généralise à des comportements jamais vus sous ce
label exact").

Deux des types non couverts (`mscan` : 996 occurrences, `apache2` : 737
occurrences) avaient déjà été vus prédits à 100% et 99.7% de confiance
lors de tests antérieurs (14/08, session précédente) — confiance jamais
vérifiée contre une vérité terrain.

**Correction** :
1. `mitre_categories.py` étendu à 39 types (couverture complète),
   taxonomie standard NSL-KDD (DoS/Probe/R2L/U2R). Trois cas ambigus
   dans la littérature tranchés explicitement et documentés en
   commentaire plutôt que résolus silencieusement : `worm` → Impact,
   `ps`/`xterm` → PrivilegeEscalation.
2. Ré-entraînement + ré-évaluation (`tactic_classifier.py` et
   `tactic_classifier_smote.py`) sur la couverture complète.
3. `tactic_classifier_smote.py` sauvegarde désormais un rapport JSON
   (`data/tactic_classifier_report.json`, horodaté) au lieu de laisser
   les scores uniquement dans la sortie console.
4. `dashboard.py` (page Carte MITRE ATT&CK) lit désormais ce rapport au
   lieu de scores F1 codés en dur dans le code source — même correctif
   de fond que pour `validation_report.json` (14/08, plus tôt la même
   session).

**Résultats avant/après (F1-score par tactique)** :

| Tactique | Avant (22 types, non-disclosed gap) | Après (39 types, couverture complète) |
|---|---|---|
| Impact | 1.00 | 0.93 |
| Reconnaissance | 0.91 | 0.70 |
| InitialAccess_CredentialAccess | 0.75 | 0.75 |
| PrivilegeEscalation | 0.14 | 0.19 |
| **Accuracy globale** | ~94% (portée limitée) | **83.2%** (couverture complète) |

**Interprétation honnête** : la chute de 94%→83% n'est PAS une
régression du modèle — les données d'entraînement n'ont pas changé
(NSL-KDD place les types inédits uniquement dans le test set par
construction). C'est la première mesure honnête de la capacité de
généralisation réelle du classifieur. Impact et
InitialAccess_CredentialAccess généralisent raisonnablement bien.
Reconnaissance perd en précision (confusion avec
InitialAccess_CredentialAccess sur les nouveaux types R2L proches d'un
scan). PrivilegeEscalation reste faible (précision 0.13) malgré SMOTE —
la politique de traitement manuel systématique documentée dans le
playbook, indépendante du score, absorbe ce risque opérationnellement
sans le résoudre au niveau du modèle.

**Leçon méthodologique** : un filtre de nettoyage de données
(`tactics != "Unknown"`) appliqué de façon identique au train et au test
set peut silencieusement transformer une évaluation de généralisation en
évaluation de mémorisation, sans qu'aucune ligne de code ne mente
explicitement — le biais est dans ce qui est exclu, pas dans ce qui est
calculé. Root cause identique aux deux bugs précédents de la même
journée (recommandations anomaly-only muettes, rapport de validation
périmé) : un composant reflète un sous-ensemble de la réalité sans
mécanisme pour signaler ce qui est hors périmètre.

## 14-15/08/2026 — Session d'investigation approfondie : cinq écarts entre "semble validé" et "réellement testé"

Session initiée par une simple question : "notre modèle peut-il vraiment
détecter, recommander et cartographier MITRE ATT&CK correctement ?" Plutôt
que d'accepter les métriques affichées, chaque composant du pipeline a été
remis en question méthodiquement. Résultat : cinq écarts réels trouvés,
compris, et corrigés -- tous partageant la même cause racine : un
composant reflétait un sous-ensemble de la réalité (données de test
connues, schéma d'entraînement, permissions git) sans mécanisme pour
signaler ce qui restait hors périmètre.

### 1. Recommandations muettes sur les détections Isolation-Forest-seul

`build_recommendation()` court-circuitait sur les bandes low/medium avant
de vérifier `detected_by_anomaly` -- or une alerte captée uniquement par
Isolation Forest a, par construction, un score XGBoost bas, donc tombe
presque systématiquement en bande low/medium. Le principe documenté du
playbook ("l'absence de signature connue ne signifie pas absence de
risque") ne s'appliquait donc jamais aux alertes où il comptait le plus.
1015 alertes concernées sur le jeu de test complet. Corrigé : le
signal anomalie est maintenant vérifié avant tout court-circuit de bande.

### 2. Rapport de validation périmé (12 jours), masquant l'amélioration de l'ensemble

`validation_report.json` datait d'avant la création d'`isolation_forest.pkl`
et affichait donc le recall XGBoost seul (70.05%) au lieu du résultat
ensemble réel (77.51%). Script de génération lui-même correct
(`AnalysisEngine()` utilise `use_ensemble=True` par défaut) -- pure
staleness, sans mécanisme de détection. Effet de bord détecté au passage :
`pipeline_e2e_latency_ms` variait de 775ms (run périmé, probable
cold-start) à ~58-62ms (4 runs frais consécutifs) -- écart non expliqué
formellement, documenté comme incertitude plutôt que tranché arbitrairement.
Corrigé : `generated_at` et `pipeline_latency_note` ajoutés au rapport,
surfacés en légende sur le dashboard.

### 3. Lacune de couverture MITRE ATT&CK : 29% des attaques du test set jamais évaluées

`mitre_categories.py` ne couvrait que 22 des 39 types d'attaque NSL-KDD.
`build_tactic_dataset()` filtre les labels "Unknown" du train ET du test
set de façon identique -- transformant silencieusement une évaluation de
généralisation en évaluation de mémorisation. Le chiffre documenté de
~94% d'accuracy ne portait que sur les types connus. Deux catégories
non couvertes (`mscan`: 996 occurrences, `apache2`: 737 occurrences)
avaient déjà été vues prédites à confiance quasi-parfaite (100%, 99.7%)
sans qu'aucune vérité terrain n'ait jamais validé ces prédictions
précises. Corrigé : couverture étendue à 39/39 types (taxonomie standard
NSL-KDD DoS/Probe/R2L/U2R, 3 cas ambigus tranchés explicitement et
documentés : worm, ps, xterm). Ré-entraînement + ré-évaluation :
accuracy réelle de généralisation = 83.2% (jamais mesurée auparavant),
F1 par tactique : Impact 1.00→0.93, Reconnaissance 0.91→0.70,
InitialAccess_CredentialAccess inchangé à 0.75, PrivilegeEscalation
0.14→0.19. Métriques désormais sauvegardées dans
`data/tactic_classifier_report.json` (horodaté) et lues dynamiquement
par le dashboard au lieu d'être codées en dur.

### 4. Écart architectural : le moteur ML n'a jamais tourné sur des données live

Découverte en tentant de valider le scénario DoS sur le pipeline réel :
`RiskScorer.assess()` plantait avec une erreur XGBoost cryptique sur les
features live (`feature_extractor.py`, 14 colonnes agrégées par fenêtre :
`event_count`, `unique_dest_ports`, etc.) contre le schéma NSL-KDD attendu
(41 colonnes détaillées par session : `src_bytes`, `num_failed_logins`,
`dst_host_serror_rate`, etc.). Aucun recouvrement de nom, deux espaces de
features fondamentalement différents (agrégats temporels vs détail de
session), pas convertibles l'un vers l'autre sans couche d'adaptation.
**Constat majeur** : toute validation antérieure du moteur ML (rapports,
dashboard, démonstrations, la ré-évaluation du point 3 ci-dessus) portait
exclusivement sur des données NSL-KDD -- le moteur n'a jamais produit une
seule prédiction valide sur du trafic réel capturé par Suricata/Wazuh.
Corrigé (partiellement, par nécessité) : nouveau module `feature_schema.py`
avec contrat de schéma explicite, validé à chaque point d'entrée public de
`RiskScorer` (`score`, `_iso_flags`, `assess`). Un appel avec un schéma
incompatible lève désormais `FeatureSchemaError` avec diagnostic complet
(colonnes manquantes/en trop, détection heuristique "ressemble au pipeline
live") au lieu d'un crash cryptique ou -- pire -- d'une prédiction
silencieuse dénuée de sens si le nombre de colonnes coïncidait par hasard.
**Ceci ne résout PAS l'écart architectural** -- fermer ce gap nécessiterait
soit une couche d'adaptation de features, soit un nouveau modèle entraîné
directement sur le schéma live ; les deux options dépassent le temps
restant du stage. Documenté comme limite majeure connue plutôt que
dissimulé.

### 5. Validation live du scénario DoS + gaps découverts en cours de route

Flood TCP de 300 connexions (PowerShell, VM Windows → VM cible, port 22)
a révélé :
- Les règles Suricata existantes (9000001/9000002, "port scan") n'ont
  aucune logique de diversité de ports -- un flood mono-port déclenche la
  même signature qu'un scan multi-ports. Nouvelle règle `sid:9000003`
  ajoutée (`classtype:attempted-dos`, seuil 50 SYN/10s), avec limite
  documentée explicitement : ne résout pas la désambiguïsation
  largeur/profondeur (responsabilité de la couche ML, actuellement
  indisponible sur données live -- voir point 4). Co-déclenchement des
  trois règles sur un flood mono-port est attendu, pas un bug.
- **Toutes** les alertes Suricata custom (y compris 9000001/9000002,
  déjà livrées et "validées" plus tôt dans le projet) étaient noyées au
  niveau générique 3 dans Wazuh -- sévérité identique au bruit de fond
  (échecs de déchiffrement QUIC). Un scan actif et confirmé s'affichait
  donc comme risque LOW sur le dashboard live. Nouvelles règles Wazuh
  100012/100013/100014 (niveaux 8/8/12, alignés sur les SLA du playbook).
  Bug de second ordre trouvé pendant la validation : `$(data.src_ip)`
  copié des règles SSH (qui utilisent le décodeur natif sshd) ne
  fonctionne pas pour les alertes Suricata (décodeur JSON générique,
  champs à la racine) -- confirmé et corrigé via `wazuh-logtest` avant
  redémarrage, évitant un second cycle self-guessing.
- Bruit QUIC (`sid:2231000`) supprimé à la source
  (`docker/suricata/config/threshold.config`) plutôt que seulement filtré
  au niveau UI dashboard -- il gonflait tous les comptages d'événements
  (totaux "Résumé automatique", Top Offenders), pas seulement l'affichage
  d'une page.
- **Découverte hors scope, corrigée séparément** : le submodule
  `docker/wazuh-docker` pointait sur le dépôt officiel `wazuh/wazuh-docker`
  (accès lecture seule) au lieu d'un fork personnel. Conséquence : tous
  les commits précédents dans ce submodule -- y compris les règles SSH
  brute-force (100010/100011) et le durcissement des identifiants,
  livrés plus tôt dans le stage -- n'existaient qu'en local sur la VM,
  jamais réellement accessibles sur GitHub malgré des commits en
  apparence réussis. Fork créé (toutes branches, pas seulement main),
  submodule repointé, historique complet poussé, `.gitmodules` mis à
  jour. Vérifié par clone frais complet (`git clone --recurse-submodules`)
  confirmant la résolution correcte du submodule.

### Leçon méthodologique transversale

Les cinq écarts ci-dessus, bien que dans des couches très différentes du
système (logique applicative, staleness de rapport, couverture de
données, contrat de schéma ML, configuration git), partagent une
structure identique : **un filtre ou une hypothèse implicite exclut
silencieusement une partie de la réalité, et rien ne signale ce qui est
hors périmètre.** Aucun de ces bugs n'était visible par lecture de code
seule -- chacun a été découvert en exécutant le système dans des
conditions qu'il n'avait encore jamais rencontrées (données complètes
plutôt qu'échantillon de démo, schéma live plutôt que NSL-KDD, push
plutôt que commit local). Recommandation pour la suite du projet : tout
composant produisant une métrique, une recommandation, ou un état "validé"
devrait pouvoir répondre explicitement à la question "sur quel sous-
ensemble ceci a-t-il été vérifié, et qu'est-ce qui reste non-couvert ?"

## Addendum 15/08/2026 — Suppression QUIC : deux bugs superposés, pas un

Le point 5 ci-dessus notait la suppression du bruit QUIC (`sid:2231000`)
comme résolue via `threshold.config` + décommentage de `threshold-file`
dans `suricata.yaml`. Vérification a posteriori (tail live + génération
de trafic QUIC réel depuis la VM Windows, pas une simple fenêtre
d'observation passive) a révélé que **la suppression ne fonctionnait
pas** : `docker-compose.yml` ne montait jamais `threshold.config` dans le
conteneur -- `suricata.yaml` pointait correctement vers
`/etc/suricata/threshold.config`, mais Suricata utilisait silencieusement
le fichier gabarit par défaut de l'image (entièrement commenté), jamais
le fichier réel créé sur la VM. Aucune erreur, aucun avertissement au
démarrage -- le fichier par défaut est syntaxiquement valide, donc rien
ne signalait le mount manquant. Corrigé : ligne de volume ajoutée à
`docker-compose.yml`. Reconfirmé par le même test (tail live +
génération de trafic QUIC réel) : silence total sur `sid:2231000`
pendant navigation active.

**Leçon** : un test de config qui passe (`suricata -T`) valide la
syntaxe du fichier chargé, pas l'identité du fichier chargé. Une
vérification "ça a l'air configuré" (fichier créé, directive décommentée,
test de syntaxe propre) n'est pas équivalente à "ça fonctionne" tant que
le comportement réel n'a pas été observé sous charge -- même leçon que
les points 1 à 5, appliquée une sixième fois le même jour.

## 15/08/2026 — Mise à jour de docs/architecture.md

`docs/architecture.md` était figé à l'état de fin de Phase 1 (infrastructure
+ déploiement Suricata uniquement) — aucune mention du pipeline, des
modèles ML, du dashboard, des couches de détection, ni d'aucun des
correctifs de cette session. Réécrit pour refléter l'état réel du système :

- Nouvelle section 5 (pipeline) et section 6 (détection en profondeur,
  trois couches) avec tableau de statut de validation par règle
- Nouvelle section 7 : les deux mécanismes de correspondance MITRE ATT&CK
  (basé règles vs basé IA) présentés séparément avec leur statut de
  validation réel, plutôt que comme une capacité unique et équivalente
- Nouvelle section 8 (Limites connues) : écart de schéma live/NSL-KDD en
  tête de liste, PrivilegeEscalation, désambiguïsation scan/flood,
  absence d'authentification dashboard, absence de politique de
  rétention -- même standard de transparence que le reste du projet
- Section 4 mise à jour avec le correctif de fork du submodule Wazuh
- Sections 9-10 mises à jour (décisions techniques, prochaines étapes)

## Clôture de session — 15/08/2026

Six écarts trouvés et corrigés (ou honnêtement documentés comme non
fermables dans le temps restant) en une session, tous partageant la même
cause racine (voir "Leçon méthodologique transversale" ci-dessus).
`docs/architecture.md` et `docs/journal-technique.md` sont désormais
synchronisés avec l'état réel du code et de l'infrastructure.

**État des livrables du cahier des charges à cette date :**

| Livrable | Statut |
|---|---|
| Code source du prototype | ✅ Complet, poussé (main repo + fork wazuh-docker) |
| Pipeline de collecte/traitement | ✅ Opérationnel, validé live |
| Moteur de détection (signatures + comportemental) | ✅ Opérationnel, validé live (3 scénarios : reconnaissance, credential access, DoS) |
| Moteur de détection (IA) | ⚠️ Validé rigoureusement sur NSL-KDD, non intégré au flux live (voir architecture.md section 8) |
| Module de priorisation des alertes | ✅ Opérationnel (`risk_scorer.py`, bandes de risque) |
| Module de correspondance MITRE ATT&CK | ⚠️ Partiellement live (règles), partiellement NSL-KDD-only (IA) -- voir architecture.md section 7 |
| Tableau de bord de visualisation | ✅ Opérationnel, 4 pages |
| Guide d'installation | ❌ Non commencé |
| Rapport technique final | ❌ Non commencé (matière première complète dans ce journal) |
| Démonstration fonctionnelle | ❌ Non préparée |

**Prochaine session** : guide d'installation et/ou rapport technique final.
