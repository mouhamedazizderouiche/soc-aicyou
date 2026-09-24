# Journal Technique — SOC AICYOU

Ce journal documente les décisions techniques, incidents rencontrés et
résolutions, en complément du journal de stage ESPRIT (rempli
manuellement).

Journal Technique — SOC AICYOU

Ce journal documente les décisions techniques, incidents rencontrés et
résolutions, en complément du journal de stage ESPRIT (rempli
manuellement).

21/07/2026 — Kickoff & préparation

Lecture complète du cahier des charges (offre de stage AICYOU).

Définition du planning sur 8 semaines (5 phases : environnement,
pipeline, moteur IA, MITRE ATT&CK, validation).

Préparation de l’environnement de travail (VM dédiée Ubuntu Server 22.04
LTS, 16 Go RAM).

23/07/2026 — Installation Docker & structuration du projet

Installation de Docker Engine 29.6.2 + Docker Compose v5.3.1 sur la VM.

Incident : premier essai réalisé en session root, ajoutant root au
groupe docker au lieu de aicyou. Résolution : suppression du projet créé
sous /root, recréation propre sous /home/aicyou, correction du groupe.

Initialisation du dépôt Git soc-aicyou (structure docker/, docs/,
scripts/, data/).

Validation : docker run hello-world fonctionne sans sudo sous aicyou.

23/07/2026 — Intégration Wazuh (submodule)

Ajout de wazuh-docker comme Git submodule.

Incident : tentative de pin sur la branche v4.9.0, échec car c’est un
tag, pas une branche. Résolution : checkout du tag via git ls-remote
–tags.

Incident secondaire : résolution DNS temporairement en échec (Could not
resolve host: github.com), résolu spontanément après nouvelle tentative.

23/07/2026 — Hardening sécurité avant premier déploiement

5 mots de passe par défaut en clair identifiés dans docker-compose.yml.

Création de single-node/.env avec mots de passe forts générés via
openssl rand -base64 24.

Incident : .env non ignoré par Git dans le submodule (dépôt indépendant,
.gitignore racine non applicable). Résolution : .gitignore dédié créé
dans docker/wazuh-docker/.

Remplacement des valeurs en dur par des références \${VARIABLE}.

Génération de nouveaux hash bcrypt via le conteneur officiel
wazuh-indexer.

Incident : hash inversés entre admin et kibanaserver lors d’une première
édition manuelle — détecté et corrigé par relecture systématique.

Configuration UFW : deny-by-default, SSH ouvert, port 443 restreint à
192.168.1.0/24.

23/07/2026 — Premier déploiement & résolution d’incident API

Génération des certificats indexer, premier docker compose up -d réussi
(3 conteneurs opérationnels).

Incident : statut “Offline” pour l’API dans le dashboard. Diagnostic :
test direct via curl confirmant que l’API manager fonctionnait — le
problème venait du fichier interne wazuh.yml (config dashboard → API)
qui conservait l’ancien mot de passe.

Résolution : réécriture propre du fichier (après une première tentative
erronée avec echo \>\> ayant dupliqué le bloc hosts:).

Validation finale : statut API “Online” confirmé.

Limitation documentée : wazuh.yml ne supporte pas les variables
d’environnement Docker Compose — mot de passe API en clair dans ce
fichier spécifique.

23/07/2026 — Publication GitHub

Création du dépôt distant privé soc-aicyou sur GitHub (compte
personnel).

Configuration de l’authentification via Personal Access Token (scope
repo, expiration 90 jours).

Premier push réussi de l’historique complet (structure, submodule Wazuh,
documentation).

23-24/07/2026 — Déploiement Suricata (NIDS)

Déploiement de Suricata en conteneur Docker (jasonish/suricata:7.0.7),
network_mode: host, capacités NET_ADMIN/NET_RAW/SYS_NICE pour la capture
de paquets bruts sur ens33.

Configuration HOME_NET restreinte au sous-réseau réel (192.168.1.0/24)
plutôt que la plage large par défaut.

Incident : crash-loop au démarrage — le script d’entrée du conteneur
tentait un chown sur suricata.yaml, bloqué par le montage en lecture
seule (:ro). Résolution : retrait du flag :ro.

Validation : moteur Suricata opérationnel (8 threads worker), 40 429
règles de détection chargées, capture confirmée en temps réel
(événements DNS, TLS avec JA3/JA3S, flow), 10 alertes générées sur
trafic de test normal.

Commit et push de la configuration Suricata sur GitHub.

Prochaine session

Connexion Suricata → Wazuh (ingestion des logs eve.json).

Démarrage Phase 2 : pipeline Python de collecte et normalisation des
événements.

24/07/2026 — Intégration Suricata → Wazuh

Migration du volume Suricata (nommé) vers un bind mount
(/var/log/suricata) pour rendre les logs accessibles nativement depuis
la VM hôte.

Installation et enregistrement du Wazuh agent natif (v4.9.0) sur la VM,
auto-enrôlé auprès du manager local (127.0.0.1).

Configuration d’un bloc <localfile> dans ossec.conf (format JSON)
pointant vers /var/log/suricata/eve.json.

Validation : Wazuh applique automatiquement son ruleset natif Suricata
(groupe de règles ids, suricata), sans décodeur additionnel nécessaire.
Alertes structurées visibles dans le dashboard (ex: détection QUIC
failed decrypt, signature 2231000).

Phase 1 (mise en place de l’environnement) complétée.

Prochaine session

Démarrage Phase 2 : pipeline Python de collecte, normalisation des
événements Wazuh/Suricata, extraction de caractéristiques
comportementales.

26/07/2026 — Phase 2 : Pipeline Python (collecte, normalisation,
features)

Mise en place de l’environnement Python (venv, dépendances épinglées) et
d’un client d’API Wazuh (wazuh_client.py).

Sécurité : bascule vers un compte de service à privilèges minimaux
(least-privilege) pour l’accès en lecture au pipeline, plutôt que
d’utiliser un compte administrateur.

Développement du module de normalisation (normalizer.py) :
uniformisation des alertes Wazuh/Suricata dans un schéma commun
exploitable.

Développement du collecteur incrémental (collector.py) : stockage des
alertes en JSON Lines, avec gestion de point de reprise (checkpoint)
pour éviter les doublons entre exécutions.

Développement de l’extraction de caractéristiques comportementales
(feature_extractor.py), première version.

26/07/2026 — Phase 3 : Premier modèle de détection

Entraînement d’un modèle XGBoost baseline pour la classification binaire
(normal/attaque) sur le jeu de données NSL-KDD.

Analyse de seuil de décision (threshold_analysis.py) et développement du
module de scoring de risque (risk_scorer.py), avec bandes de risque
(low/medium/high/critical).

Développement du modèle de classification multi-classe des tactiques
MITRE ATT&CK (tactic_classifier.py puis version SMOTE pour le
rééquilibrage des classes).

Assemblage du moteur d’analyse de bout en bout (analysis_engine.py)
combinant score de risque, tactique prédite et recommandation.

Évaluation complète du pipeline sur le jeu de test
(evaluate_full_pipeline.py) : taux de détection, faux positifs, temps de
traitement.

28/07/2026 — Couche 2 : règles Suricata comportementales

Ajout de règles Suricata personnalisées, indépendantes de l’outil
d’attaque, pour la détection de scan de ports (seuil de connexions par
IP source sur une fenêtre de temps courte).

Objectif : détecter le comportement de reconnaissance réseau plutôt
qu’une signature d’outil spécifique (fonctionne contre nmap, masscan, ou
tout scanner générant le même pattern de trafic).

29/07/2026 — Extraction de caractéristiques multi-échelle

Amélioration de feature_extractor.py : distinction du trafic
entrant/sortant par direction de flux (flow_src_ip/flow_dest_ip), pour
isoler le vrai signal de reconnaissance du bruit de navigation web
normal.

Ajout de fenêtres temporelles multiples (1 minute pour les
rafales/scans, 5 minutes pour les tendances comportementales générales).

Rédaction du playbook de réponse aux incidents
(docs/playbook-reponse-incidents.md) : procédures de triage par bande de
risque et tactique MITRE.

02/08/2026 — Rapport de validation formel

Développement de validation_report.py consolidant les métriques
attendues par le cahier des charges : taux de détection, taux de faux
positifs, temps de traitement (latence bout-en-bout du pipeline réel),
pertinence de la priorisation.

Constat notable : le goulot d’étranglement du pipeline réel n’est pas le
calcul du modèle IA (quasi instantané) mais la requête réseau vers
l’indexeur Wazuh.

04-06/08/2026 — Simulation d’attaque et Couche 2 côté hôte (Wazuh)

Simulation d’une attaque par force brute SSH depuis une VM Windows
dédiée (Posh-SSH), contre un compte de test jetable.

Constat : la règle de corrélation native de Wazuh pour la force brute ne
se déclenchait pas sur une attaque courte (sous le seuil par défaut), et
une connexion réussie après plusieurs échecs était journalisée au même
niveau de sévérité qu’une connexion normale — angle mort de détection.

Développement de règles Wazuh personnalisées (local_rules.xml, règles
100010/100011) : escalade sur échecs répétés, et escalade forte
spécifique en cas de succès suivant une série d’échecs (signal de
compromission d’identifiants).

Difficultés de déploiement résolues : docker compose restart n’applique
pas les nouveaux montages de volumes (nécessite up -d –force-recreate) ;
le mécanisme d’auto-copie de configuration de Wazuh
(/wazuh-config-mount/) ne s’applique que sur un volume neuf, pas sur un
déploiement existant (copie manuelle requise).

Validation de bout en bout : les deux règles se déclenchent correctement
lors d’une attaque réelle rejouée.

07-09/08/2026 — Tableau de bord Streamlit et amélioration IA

Développement du tableau de bord SOC (dashboard.py) : vue d’ensemble
avec résumé automatique en langage naturel, alertes en direct avec
filtres avancés et workflow de triage persistant, cartographie MITRE
ATT&CK, démonstration interactive du moteur d’analyse.

Amélioration majeure du modèle de détection : ajout d’un détecteur
d’anomalies Isolation Forest (non supervisé, entraîné uniquement sur
trafic normal) en complément du XGBoost supervisé.

Diagnostic : le plafond de rappel du XGBoost est une limite structurelle
de l’apprentissage supervisé (incapable de reconnaître un type d’attaque
absent de son entraînement).

Isolation Forest ne partage pas cette limite, car il détecte des écarts
au comportement normal plutôt que des signatures apprises.

Combinaison en ensemble (logique OU) : le rappel global passe de 70 % à
77,5 %, pour un coût modéré en faux positifs (2,99 % → 3,58 %).

Ajout d’un indicateur de traçabilité (flagged_by_anomaly_detector)
affiché dans le tableau de bord, pour expliquer les décisions issues
d’Isolation Forest plutôt que de les laisser incohérentes avec la bande
de risque affichée.

Correction de plusieurs incidents techniques : plantage du tableau de
bord (conflit de version pyarrow), désynchronisation entre
analysis_engine.py et la nouvelle signature de risk_scorer.py, bug de
réinitialisation des filtres (perte d’état Streamlit lors de la
navigation entre pages).

Audit complet du projet (10/08/2026) : vérification de l’état du dépôt
Git (principal et sous-module), de la structure des fichiers, et de la
documentation — mise à jour du journal technique et du README suite à ce
constat.

Prochaine session

Poursuite de l’audit : structure GitHub, couverture de tests, guide
d’installation.

Scénario d’attaque restant à valider : déni de service (Impact/TA0040).

Rédaction du rapport technique final et préparation de la démonstration.

14/08/2026 — Bug de conception découvert lors des tests :
recommandations muettes sur les détections Isolation-Forest-seul

En testant build_recommendation() sur l’ensemble X_test complet (pas
seulement l’échantillon de démo), 1015 alertes sur le total étaient
capturées uniquement par Isolation Forest
(flagged_by_anomaly_detector=1). Leur recommandation ne mentionnait
jamais ce fait.

Cause : risk_band est dérivé uniquement du score continu XGBoost
(risk_scorer.py). Une alerte captée seulement par Isolation Forest a,
par construction, un score XGBoost bas — sinon XGBoost l’aurait déjà
signalée. Ces alertes tombent donc presque systématiquement en bande
low/medium. La logique initiale de build_recommendation() retournait un
texte générique dès la bande basse, avant même de vérifier
detected_by_anomaly — masquant le signal précisément là où le principe
documenté dans le playbook (“l’absence de signature connue ne signifie
pas absence de risque”) s’applique le plus.

Correction : detected_by_anomaly est désormais vérifié avant tout
court-circuit de bande. Une alerte low/medium mais anomaly-only reçoit
maintenant une recommandation de vérification L1, pas un message de
surveillance passive silencieux.

Méthodologie : trouvé en testant sur l’échantillon complet plutôt que
sur les 10 exemples de démo — un rappel que les tests sur petit
échantillon peuvent manquer des cas structurels qui ne se manifestent
qu’à l’échelle.

14/08/2026 — Rapport de validation périmé, masquant l’amélioration de
l’ensemble

data/validation_report.json datait du 02/08 (avant isolation_forest.pkl,
créé le 07/08) et affichait donc detection_rate: 70.05% — le score
XGBoost seul — alors que le système réel tourne en ensemble depuis le
07/08 (recall documenté : 77.5%). Le dashboard affichait donc un chiffre
inférieur à la réalité sans que rien ne l’indique.

validation_report.py lui-même était correct (AnalysisEngine() utilise
use_ensemble=True par défaut) — le problème était purement l’absence de
ré-exécution après le travail sur l’ensemble. Confirmé par re-run :
77.51% / FPR 3.58%, cohérent avec ensemble_evaluation.py.

Effet de bord détecté au passage : pipeline_e2e_latency_ms est passé de
775.5ms (run du 02/08) à ~58-62ms (4 runs consécutifs le 14/08) — écart
de ~12x. Probablement un artefact de cold-start (premher run après boot/
connexion Wazuh à froid) plutôt qu’une vraie dérive de performance, mais
non confirmé formellement — documenté comme incertitude plutôt que
tranché arbitrairement.

Correction : validation_report.json inclut désormais generated_at et
pipeline_latency_note (échantillon 200 alertes, un seul run — pas une
moyenne stabilisée). Le dashboard affiche ces deux informations en
légende sous les métriques, pour qu’un lecteur comprenne qu’il s’agit
d’un instantané et non d’une mesure continue.

Leçon méthodologique : deux bugs distincts trouvés aujourd’hui
(recommandations anomaly-only muettes, rapport de validation périmé)
partagent la même cause racine — un composant du système reflète un état
antérieur du modèle/pipeline sans mécanisme pour le signaler. À
surveiller ailleurs dans le système (ex. carte MITRE ATT&CK — les
F1-scores affichés sont-ils à jour ?).

14-15/08/2026 — Lacune de couverture MITRE ATT&CK : 29% des attaques du
test set jamais évaluées

Origine : question directe sur la fiabilité réelle du mapping MITRE
ATT&CK affiché au dashboard. Investigation menée par remise en question
systématique (le modèle a-t-il vraiment vu/évalué ce qu’il prétend
classifier ?) plutôt qu’acceptation des métriques affichées.

Constat : mitre_categories.py ne couvrait que les 22 types d’attaque
présents dans KDDTrain+. Le jeu de test NSL-KDD est délibérément conçu
pour inclure des types absents de l’entraînement (test de
généralisation). build_tactic_dataset() (tactic_classifier.py) filtre
les labels “Unknown” — donc 17 types d’attaque supplémentaires, soit
3750 échantillons sur 12833 (29.2%) du test set d’attaques, n’étaient
jamais soumis à évaluation. Le chiffre documenté de ~94% d’accuracy ne
portait donc que sur les 22 types connus, pas sur la capacité réelle du
modèle à généraliser — alors que c’est précisément ce que le docstring
du module revendiquait (“généralise à des comportements jamais vus sous
ce label exact”).

Deux des types non couverts (mscan : 996 occurrences, apache2 : 737
occurrences) avaient déjà été vus prédits à 100% et 99.7% de confiance
lors de tests antérieurs (14/08, session précédente) — confiance jamais
vérifiée contre une vérité terrain.

Correction :

mitre_categories.py étendu à 39 types (couverture complète), taxonomie
standard NSL-KDD (DoS/Probe/R2L/U2R). Trois cas ambigus dans la
littérature tranchés explicitement et documentés en commentaire plutôt
que résolus silencieusement : worm → Impact, ps/xterm →
PrivilegeEscalation.

Ré-entraînement + ré-évaluation (tactic_classifier.py et
tactic_classifier_smote.py) sur la couverture complète.

tactic_classifier_smote.py sauvegarde désormais un rapport JSON
(data/tactic_classifier_report.json, horodaté) au lieu de laisser les
scores uniquement dans la sortie console.

dashboard.py (page Carte MITRE ATT&CK) lit désormais ce rapport au lieu
de scores F1 codés en dur dans le code source — même correctif de fond
que pour validation_report.json (14/08, plus tôt la même session).

Résultats avant/après (F1-score par tactique) :

Tactique Avant (22 types, non-disclosed gap) Après (39 types, couverture
complète)

Impact 1.00 0.93

Reconnaissance 0.91 0.70

InitialAccess_CredentialAccess 0.75 0.75

PrivilegeEscalation 0.14 0.19

Accuracy globale ~94% (portée limitée) 83.2% (couverture complète)

Interprétation honnête : la chute de 94%→83% n’est PAS une régression du
modèle — les données d’entraînement n’ont pas changé (NSL-KDD place les
types inédits uniquement dans le test set par construction). C’est la
première mesure honnête de la capacité de généralisation réelle du
classifieur. Impact et InitialAccess_CredentialAccess généralisent
raisonnablement bien. Reconnaissance perd en précision (confusion avec
InitialAccess_CredentialAccess sur les nouveaux types R2L proches d’un
scan). PrivilegeEscalation reste faible (précision 0.13) malgré SMOTE —
la politique de traitement manuel systématique documentée dans le
playbook, indépendante du score, absorbe ce risque opérationnellement
sans le résoudre au niveau du modèle.

Leçon méthodologique : un filtre de nettoyage de données (tactics !=
“Unknown”) appliqué de façon identique au train et au test set peut
silencieusement transformer une évaluation de généralisation en
évaluation de mémorisation, sans qu’aucune ligne de code ne mente
explicitement — le biais est dans ce qui est exclu, pas dans ce qui est
calculé. Root cause identique aux deux bugs précédents de la même
journée (recommandations anomaly-only muettes, rapport de validation
périmé) : un composant reflète un sous-ensemble de la réalité sans
mécanisme pour signaler ce qui est hors périmètre.

14-15/08/2026 — Session d’investigation approfondie : cinq écarts entre
“semble validé” et “réellement testé”

Session initiée par une simple question : “notre modèle peut-il vraiment
détecter, recommander et cartographier MITRE ATT&CK correctement ?”
Plutôt que d’accepter les métriques affichées, chaque composant du
pipeline a été remis en question méthodiquement. Résultat : cinq écarts
réels trouvés, compris, et corrigés – tous partageant la même cause
racine : un composant reflétait un sous-ensemble de la réalité (données
de test connues, schéma d’entraînement, permissions git) sans mécanisme
pour signaler ce qui restait hors périmètre.

1.  Recommandations muettes sur les détections Isolation-Forest-seul

build_recommendation() court-circuitait sur les bandes low/medium avant
de vérifier detected_by_anomaly – or une alerte captée uniquement par
Isolation Forest a, par construction, un score XGBoost bas, donc tombe
presque systématiquement en bande low/medium. Le principe documenté du
playbook (“l’absence de signature connue ne signifie pas absence de
risque”) ne s’appliquait donc jamais aux alertes où il comptait le plus.
1015 alertes concernées sur le jeu de test complet. Corrigé : le signal
anomalie est maintenant vérifié avant tout court-circuit de bande.

2.  Rapport de validation périmé (12 jours), masquant l’amélioration de
    l’ensemble

validation_report.json datait d’avant la création d’isolation_forest.pkl
et affichait donc le recall XGBoost seul (70.05%) au lieu du résultat
ensemble réel (77.51%). Script de génération lui-même correct
(AnalysisEngine() utilise use_ensemble=True par défaut) – pure
staleness, sans mécanisme de détection. Effet de bord détecté au passage
: pipeline_e2e_latency_ms variait de 775ms (run périmé, probable
cold-start) à ~58-62ms (4 runs frais consécutifs) – écart non expliqué
formellement, documenté comme incertitude plutôt que tranché
arbitrairement. Corrigé : generated_at et pipeline_latency_note ajoutés
au rapport, surfacés en légende sur le dashboard.

3.  Lacune de couverture MITRE ATT&CK : 29% des attaques du test set
    jamais évaluées

mitre_categories.py ne couvrait que 22 des 39 types d’attaque NSL-KDD.
build_tactic_dataset() filtre les labels “Unknown” du train ET du test
set de façon identique – transformant silencieusement une évaluation de
généralisation en évaluation de mémorisation. Le chiffre documenté de
~94% d’accuracy ne portait que sur les types connus. Deux catégories non
couvertes (mscan: 996 occurrences, apache2: 737 occurrences) avaient
déjà été vues prédites à confiance quasi-parfaite (100%, 99.7%) sans
qu’aucune vérité terrain n’ait jamais validé ces prédictions précises.
Corrigé : couverture étendue à 39/39 types (taxonomie standard NSL-KDD
DoS/Probe/R2L/U2R, 3 cas ambigus tranchés explicitement et documentés :
worm, ps, xterm). Ré-entraînement + ré-évaluation : accuracy réelle de
généralisation = 83.2% (jamais mesurée auparavant), F1 par tactique :
Impact 1.00→0.93, Reconnaissance 0.91→0.70,
InitialAccess_CredentialAccess inchangé à 0.75, PrivilegeEscalation
0.14→0.19. Métriques désormais sauvegardées dans
data/tactic_classifier_report.json (horodaté) et lues dynamiquement par
le dashboard au lieu d’être codées en dur.

4.  Écart architectural : le moteur ML n’a jamais tourné sur des données
    live

Découverte en tentant de valider le scénario DoS sur le pipeline réel :
RiskScorer.assess() plantait avec une erreur XGBoost cryptique sur les
features live (feature_extractor.py, 14 caractéristiques numériques
agrégées par fenêtre — dont 11 seulement exploitables, voir l’entrée du
06/09/2026 : event_count, unique_dest_ports, etc.) contre le schéma
NSL-KDD attendu (41 colonnes détaillées par session : src_bytes,
num_failed_logins, dst_host_serror_rate, etc.). Aucun recouvrement de
nom, deux espaces de features fondamentalement différents (agrégats
temporels vs détail de session), pas convertibles l’un vers l’autre sans
couche d’adaptation. Constat majeur : toute validation antérieure du
moteur ML (rapports, dashboard, démonstrations, la ré-évaluation du
point 3 ci-dessus) portait exclusivement sur des données NSL-KDD – le
moteur n’a jamais produit une seule prédiction valide sur du trafic réel
capturé par Suricata/Wazuh. Corrigé (partiellement, par nécessité) :
nouveau module feature_schema.py avec contrat de schéma explicite,
validé à chaque point d’entrée public de RiskScorer (score, \_iso_flags,
assess). Un appel avec un schéma incompatible lève désormais
FeatureSchemaError avec diagnostic complet (colonnes manquantes/en trop,
détection heuristique “ressemble au pipeline live”) au lieu d’un crash
cryptique ou – pire – d’une prédiction silencieuse dénuée de sens si le
nombre de colonnes coïncidait par hasard. Ceci ne résout PAS l’écart
architectural – fermer ce gap nécessiterait soit une couche d’adaptation
de features, soit un nouveau modèle entraîné directement sur le schéma
live ; les deux options dépassent le temps restant du stage. Documenté
comme limite majeure connue plutôt que dissimulé.

5.  Validation live du scénario DoS + gaps découverts en cours de route

Flood TCP de 300 connexions (PowerShell, VM Windows → VM cible, port 22)
a révélé :

Les règles Suricata existantes (9000001/9000002, “port scan”) n’ont
aucune logique de diversité de ports – un flood mono-port déclenche la
même signature qu’un scan multi-ports. Nouvelle règle sid:9000003
ajoutée (classtype:attempted-dos, seuil 50 SYN/10s), avec limite
documentée explicitement : ne résout pas la désambiguïsation
largeur/profondeur (responsabilité de la couche ML, actuellement
indisponible sur données live – voir point 4). Co-déclenchement des
trois règles sur un flood mono-port est attendu, pas un bug.

Toutes les alertes Suricata custom (y compris 9000001/9000002, déjà
livrées et “validées” plus tôt dans le projet) étaient noyées au niveau
générique 3 dans Wazuh – sévérité identique au bruit de fond (échecs de
déchiffrement QUIC). Un scan actif et confirmé s’affichait donc comme
risque LOW sur le dashboard live. Nouvelles règles Wazuh
100012/100013/100014 (niveaux 8/8/12, alignés sur les SLA du playbook).
Bug de second ordre trouvé pendant la validation : \$(data.src_ip) copié
des règles SSH (qui utilisent le décodeur natif sshd) ne fonctionne pas
pour les alertes Suricata (décodeur JSON générique, champs à la racine)
– confirmé et corrigé via wazuh-logtest avant redémarrage, évitant un
second cycle self-guessing.

Bruit QUIC (sid:2231000) supprimé à la source
(docker/suricata/config/threshold.config) plutôt que seulement filtré au
niveau UI dashboard – il gonflait tous les comptages d’événements
(totaux “Résumé automatique”, Top Offenders), pas seulement l’affichage
d’une page.

Découverte hors scope, corrigée séparément : le submodule
docker/wazuh-docker pointait sur le dépôt officiel wazuh/wazuh-docker
(accès lecture seule) au lieu d’un fork personnel. Conséquence : tous
les commits précédents dans ce submodule – y compris les règles SSH
brute-force (100010/100011) et le durcissement des identifiants, livrés
plus tôt dans le stage – n’existaient qu’en local sur la VM, jamais
réellement accessibles sur GitHub malgré des commits en apparence
réussis. Fork créé (toutes branches, pas seulement main), submodule
repointé, historique complet poussé, .gitmodules mis à jour. Vérifié par
clone frais complet (git clone –recurse-submodules) confirmant la
résolution correcte du submodule.

Leçon méthodologique transversale

Les cinq écarts ci-dessus, bien que dans des couches très différentes du
système (logique applicative, staleness de rapport, couverture de
données, contrat de schéma ML, configuration git), partagent une
structure identique : un filtre ou une hypothèse implicite exclut
silencieusement une partie de la réalité, et rien ne signale ce qui est
hors périmètre. Aucun de ces bugs n’était visible par lecture de code
seule – chacun a été découvert en exécutant le système dans des
conditions qu’il n’avait encore jamais rencontrées (données complètes
plutôt qu’échantillon de démo, schéma live plutôt que NSL-KDD, push
plutôt que commit local). Recommandation pour la suite du projet : tout
composant produisant une métrique, une recommandation, ou un état
“validé” devrait pouvoir répondre explicitement à la question “sur quel
sous- ensemble ceci a-t-il été vérifié, et qu’est-ce qui reste
non-couvert ?”

Addendum 15/08/2026 — Suppression QUIC : deux bugs superposés, pas un

Le point 5 ci-dessus notait la suppression du bruit QUIC (sid:2231000)
comme résolue via threshold.config + décommentage de threshold-file dans
suricata.yaml. Vérification a posteriori (tail live + génération de
trafic QUIC réel depuis la VM Windows, pas une simple fenêtre
d’observation passive) a révélé que la suppression ne fonctionnait pas :
docker-compose.yml ne montait jamais threshold.config dans le conteneur
– suricata.yaml pointait correctement vers
/etc/suricata/threshold.config, mais Suricata utilisait silencieusement
le fichier gabarit par défaut de l’image (entièrement commenté), jamais
le fichier réel créé sur la VM. Aucune erreur, aucun avertissement au
démarrage – le fichier par défaut est syntaxiquement valide, donc rien
ne signalait le mount manquant. Corrigé : ligne de volume ajoutée à
docker-compose.yml. Reconfirmé par le même test (tail live + génération
de trafic QUIC réel) : silence total sur sid:2231000 pendant navigation
active.

Leçon : un test de config qui passe (suricata -T) valide la syntaxe du
fichier chargé, pas l’identité du fichier chargé. Une vérification “ça a
l’air configuré” (fichier créé, directive décommentée, test de syntaxe
propre) n’est pas équivalente à “ça fonctionne” tant que le comportement
réel n’a pas été observé sous charge – même leçon que les points 1 à 5,
appliquée une sixième fois le même jour.

15/08/2026 — Mise à jour de docs/architecture.md

docs/architecture.md était figé à l’état de fin de Phase 1
(infrastructure

déploiement Suricata uniquement) — aucune mention du pipeline, des
modèles ML, du dashboard, des couches de détection, ni d’aucun des
correctifs de cette session. Réécrit pour refléter l’état réel du
système :

Nouvelle section 5 (pipeline) et section 6 (détection en profondeur,
trois couches) avec tableau de statut de validation par règle

Nouvelle section 7 : les deux mécanismes de correspondance MITRE ATT&CK
(basé règles vs basé IA) présentés séparément avec leur statut de
validation réel, plutôt que comme une capacité unique et équivalente

Nouvelle section 8 (Limites connues) : écart de schéma live/NSL-KDD en
tête de liste, PrivilegeEscalation, désambiguïsation scan/flood, absence
d’authentification dashboard, absence de politique de rétention – même
standard de transparence que le reste du projet

Section 4 mise à jour avec le correctif de fork du submodule Wazuh

Sections 9-10 mises à jour (décisions techniques, prochaines étapes)

Clôture de session — 15/08/2026

Six écarts trouvés et corrigés (ou honnêtement documentés comme non
fermables dans le temps restant) en une session, tous partageant la même
cause racine (voir “Leçon méthodologique transversale” ci-dessus).
docs/architecture.md et docs/journal-technique.md sont désormais
synchronisés avec l’état réel du code et de l’infrastructure.

État des livrables du cahier des charges à cette date :

Livrable Statut

Code source du prototype ✅ Complet, poussé (main repo + fork
wazuh-docker)

Pipeline de collecte/traitement ✅ Opérationnel, validé live

Moteur de détection (signatures + comportemental) ✅ Opérationnel,
validé live (3 scénarios : reconnaissance, credential access, DoS)

Moteur de détection (IA) ⚠️ Validé rigoureusement sur NSL-KDD, non
intégré au flux live (voir architecture.md section 8)

Module de priorisation des alertes ✅ Opérationnel (risk_scorer.py,
bandes de risque)

Module de correspondance MITRE ATT&CK ⚠️ Partiellement live (règles),
partiellement NSL-KDD-only (IA) – voir architecture.md section 7

Tableau de bord de visualisation ✅ Opérationnel, 4 pages

Guide d’installation ❌ Non commencé

Rapport technique final ❌ Non commencé (matière première complète dans
ce journal)

Démonstration fonctionnelle ❌ Non préparée

Prochaine session : guide d’installation et/ou rapport technique final.

06/09/2026 — Voie NetFlow : porte de décision franchie par la négative

Objectif de la session

Fermer l’écart de schéma identifié le 15/08 (voir architecture.md
section 8) par la seule voie qui ne demande d’inventer aucune feature :
produire depuis le trafic live un schéma identique à celui d’un jeu
public étiqueté, pour qu’un modèle entraîné dessus s’applique
directement, sans couche d’adaptation.

Schéma retenu : NetFlow standard v1, 12 features (Sarhan, Layeghy,
Moustafa, Portmann, NetFlow Datasets for Machine Learning-Based Network
Intrusion Detection Systems, BDTA 2020). Jeu d’entraînement :
NF-CSE-CIC-IDS2018 v1, 8 392 401 flux, 12,14 % d’attaques.

Une porte de décision a été fixée AVANT toute mesure et inscrite dans le
code (netflow_transfer_test.py, constante GATE_MIN_RECALL) pour qu’elle
ne puisse pas être ajustée après coup : rappel binaire \> 50 % sur les
classes scan et DoS du trafic réel. Atteint → intégrer. Non atteint →
arrêter et consigner comme constat de recherche.

Verdict : porte échouée

0 attaque détectée sur 10 440. Rappel 0,0000 sur les trois classes
(Reconnaissance, DoS, BruteForce) au seuil 0,5.

Le résultat est plus fort qu’un simple défaut de généralisation :

Métrique (indépendante du seuil) Valeur Lecture

AUC-ROC global 0,1604 0,5 = hasard ; en dessous = anti-corrélation

AUC-ROC Reconnaissance 0,1307

AUC-ROC DoS 0,3779

AUC-ROC BruteForce 0,3699

Le modèle n’est pas non-informatif : il attribue une probabilité
d’attaque plus basse aux vraies attaques (moyennes 0,004 à 0,024) qu’au
trafic bénin (moyenne 0,061). Il est systématiquement à l’envers sur ce
domaine.

Deux hypothèses concurrentes écartées par la mesure

Un zéro aussi net devait être attaqué avant d’être publié. Les deux
alternatives ont été testées, pas raisonnées
(netflow_transfer_diagnostics.py).

1.  « C’est un bug de mon pipeline d’inférence. » Écarté. Les mêmes
    modèle et chemin de code, appliqués à des flux du jeu source :

Classe source Rappel Probabilité moyenne

SSH-Bruteforce 1,0000 1,0000

FTP-BruteForce 1,0000 1,0000

DDoS attacks-LOIC-HTTP 1,0000 1,0000

DoS attacks-Hulk 1,0000 0,9997

DoS attacks-GoldenEye 1,0000 0,9997

DoS attacks-Slowloris 1,0000 0,9996

Benign (non alerté) 1,0000 0,0775

2.  « C’est un problème de seuil. » Écarté. En descendant jusqu’à 0,01,
    le rappel DoS remonte à 0,6942 — mais au prix de 52,8 % de faux
    positifs sur le trafic bénin, moins bon qu’un tirage à pile ou face.
    Le rappel BruteForce reste à 0,0179. L’AUC, qui ne dépend d’aucun
    seuil, tranche définitivement.

Mécanisme mesuré

Deux features portent 91 % de la décision du modèle binaire :

Feature Importance

OUT_PKTS 0,6004

L4_DST_PORT 0,3138

(huit autres) 0,0858 au total

Ces deux features sont précisément celles qui ne transfèrent pas :

Ports. Les attaques du banc CIC se concentrent à ~90 % sur les ports 53
(36,0 %), 80 (30,8 %), 443 (14,5 %) et 8080 (9,2 %). Nos attaques
réelles s’étalent sur 1000 ports (scan nmap). 17 ports communs seulement
; 16,0 % des flux d’attaque live portent un port déjà vu comme attaque à
l’entraînement.

OUT_PKTS. Nos floods TCP complets (médiane 3) et notre force brute SSH
(médiane 11) ressemblent au trafic bénin du jeu source (médiane 2), pas
à ses attaques (médiane 1). Nos scans, eux, ont OUT_PKTS = 0 à 97,5 % —
un profil que le jeu source ne contient pas.

Le modèle a appris le profil du banc d’essai CIC — quels ports y sont
attaqués, avec quel volume de retour — et non un comportement d’attaque
transférable. C’est exactement la limite que Sarhan et al. identifient
eux-mêmes comme motivation d’un jeu de features standard : le schéma
commun rend les jeux comparables, il ne rend pas les modèles portables.

Asymétrie de classes, constatée après coup

NF-CSE-CIC-IDS2018 ne contient aucune classe de reconnaissance ou de
scan de ports. Or 88 % de nos flux d’attaque réels sont des scans nmap.
Même avec un transfert parfait, le modèle multi-classe n’aurait pas pu
les étiqueter : la bonne réponse n’existe pas dans son vocabulaire. Ce
point aurait dû être vérifié dans la distribution du jeu avant de lancer
le chantier, pas découvert au moment d’écrire l’évaluation.

Deux défauts du jeu source, relevés au passage

FLOW_DURATION_MILLISECONDS sature à 4 294 967 ms, soit 2³² microsecondes
exprimées en millisecondes, sur 41,27 % des flux : débordement d’un
compteur 32 bits côté nProbe. Sans effet sur nos conclusions, le modèle
n’utilisant presque pas cette feature (importance 0,0016).

DoS attacks-SlowHTTPTest a un rappel de 0,0000 en domaine : ses 31 665
échantillons de test sont tous prédits FTP-BruteForce, qui affiche en
miroir un rappel de 1,0000 pour une précision de 0,6468. Les deux
classes sont strictement indiscernables dans l’espace NetFlow v1.

Bug de ma propre chaîne, détecté et corrigé avant conclusion

netflow_domain_shift.py a révélé L7_PROTO = 0 sur 100 % du jeu live —
impossible avec la table de correspondance. Cause :
live_flows_labelled.csv avait été construit avant l’insertion de la
table, donc avec un dictionnaire vide. Jeu reconstruit (61,5 % de zéros,
contre 65,5 % côté source : alignement correct) et porte rejouée.
Verdict inchangé — mais conclure sur un artefact de ma propre chaîne
aurait invalidé tout le constat.

Même nature d’erreur sur le test lui-même : il comparait les prédictions
à “DoS” / “BruteForce”, alors que la colonne Attack du CSV contient 15
classes fines (DoS attacks-Hulk, SSH-Bruteforce…) et non les 7
catégories annoncées sur la page de publication. Le test aurait rendu 0
% d’exactitude multi-classe par pur artefact de nommage — et ce zéro
serait allé dans le sens de l’hypothèse testée, donc n’aurait éveillé
aucun soupçon. C’est le cas le plus dangereux : un faux résultat qui
confirme ce qu’on attend.

Résultats en domaine (pour référence)

Test sur 2 517 721 flux jamais vus. L’exactitude globale n’est jamais
citée seule : 87,86 % du jeu est bénin.

Modèle Résultat

XGBoost binaire rappel attaques 0,9478, précision 0,9932, FPR 0,0009

XGBoost multi-classe macro-F1 0,6723

Extra Trees multi-classe macro-F1 0,7211

Extra Trees est entraîné sur 1 M de lignes (sous-échantillon stratifié)
et non sur les 5 874 680 du jeu d’entraînement : contrainte de RAM de la
VM (~2 Go utilisables). Les deux algorithmes ne sont donc pas
rigoureusement comparables entre eux ; le drapeau subsampled figure dans
netflow_training_report.json.

L’écart entre 0,9478 en domaine et 0,0000 hors domaine est le résultat
de ce chantier.

Conséquence

Conformément au cadrage, l’étape d’intégration (analysis_engine.py,
dashboard.py, correspondance MITRE) n’est pas entamée. Le cadrage
NSL-KDD existant est conservé : il est validé sur son jeu et démontré
sur la page « Moteur d’analyse ». La voie NetFlow est consignée comme
résultat négatif mesuré, pas comme travail inachevé.

Ce que le chantier laisse d’utilisable :

flow_feature_extractor.py produit les 12 features NetFlow v1 depuis le
trafic réel, avec deux contrats vérifiables (–verify-schema,
–verify-l7). Cet extracteur reste valide indépendamment du modèle : il
est le prérequis de toute reprise sur un jeu d’entraînement plus proche
du domaine.

netflow_ground_truth.py fournit 19 209 flux réels étiquetés (9184
reconnaissance, 8769 bénins, 1200 DoS, 56 force brute), chacun justifié
par une source externe aux features — auth.log pour la force brute,
journal de bord pour les floods, nombre de ports distincts pour les
scans. Étiqueter un flux « scan » parce qu’il porte le drapeau SYN seul
aurait rendu le test circulaire.

Piste qu’ouvre ce résultat

Le trafic étiqueté local existe désormais au schéma NetFlow v1. Un
modèle entraîné sur ce trafic (validation croisée temporelle,
entraînement sur les campagnes de juillet-août, test sur celle du 31/08)
répondrait à une question différente et mieux posée que celle du
transfert : non pas « un modèle CIC-2018 généralise-t-il ici ? » —
mesuré, la réponse est non — mais « le comportement d’attaque de ce
réseau est-il apprenable à partir de ses propres flux ? ». Les 56 flux
de force brute resteront toutefois un échantillon trop mince pour cette
classe.

Constat sur les 56 flux de force brute

Le rappel BruteForce repose sur 56 flux seulement. C’est trop peu pour
un intervalle de confiance utile, et ce chiffre ne doit pas être lu au
même niveau que ceux du scan (9184 flux) ou du DoS (1200 flux). Il est
rapporté parce qu’il va dans le même sens que les deux autres, pas parce
qu’il est solide isolément.

Reproduire

cd pipeline

./venv/bin/python flow_feature_extractor.py –verify-schema
data/netflow/NF-CSE-CIC-IDS2018.csv

./venv/bin/python flow_feature_extractor.py –verify-l7
data/netflow/NF-CSE-CIC-IDS2018.csv

./venv/bin/python build_live_flow_dataset.py

./venv/bin/python train_netflow_model.py –resume

./venv/bin/python netflow_transfer_test.py \# code de sortie 2 = porte
échouée

./venv/bin/python netflow_transfer_diagnostics.py

./venv/bin/python netflow_domain_shift.py

Jeu de données :
https://rdm.uq.edu.au/files/650f1fa0-ef9c-11ed-b5f6-b1a04f482c13 (accès
ouvert). Intégrité vérifiée contre le manifeste BagIt fourni
(pipeline/data/netflow/manifest-sha1.txt).

Constat annexe — .env obsolète, et ce qu’il cachait

Point de départ : pipeline/.env déclarait encore
MONITORED_HOST_IP=192.168.1.112 alors que ens33 porte 192.168.1.249.
J’ai d’abord écrit que les features inbound\_\* / outbound\_\* « valent
zéro sur tout trafic récent ». C’était inexact, et la mesure a révélé
deux problèmes plus sérieux que l’adresse.

Mesure sur les 9627 alertes de alerts.jsonl :

MONITORED_HOST_IP événements entrants événements sortants

192.168.1.112 (ancienne valeur) 6 5013

192.168.1.249 (adresse réelle) 0 4205

Les features sortantes ne valaient donc pas zéro, y compris avec
l’ancienne adresse : les deux IP apparaissent comme flow_src_ip dans ce
corpus. Ma formulation initiale était fausse.

Problème réel n° 1 — la collecte est à l’arrêt depuis le 29/07/2026.
data/checkpoint.txt est figé à 2026-07-29T21:57:44Z, tandis que
l’indexeur Wazuh contient des alertes jusqu’au 2026-09-06T13:53:49Z.
collector.py est un tirage manuel, pas un service, et n’a pas été
relancé depuis 39 jours. Tout ce qu’affichent feature_extractor.py et le
tableau de bord repose sur un instantané de juillet — ce qui explique
aussi que les campagnes d’attaque d’août (flood du 15/08, scan du 31/08)
soient absentes de ce corpus alors qu’elles sont bien dans eve.json.

Problème réel n° 2 — les features inbound\_\* sont structurellement
mortes. 6 événements entrants sur 9627 alertes avec l’ancienne adresse,
0 avec la nouvelle. La cause n’est pas l’IP : c’est la limite déjà
écrite dans l’en-tête de feature_extractor.py — Wazuh n’indexe que les
événements Suricata de type alert, et presque aucune alerte indexée n’a
la machine surveillée comme destination de flux. Les alertes indexées
portent le trafic sortant de la machine (anomalies QUIC/TLS,
retransmissions), pas les connexions entrantes d’un scan.

MONITORED_HOST_IP a été corrigé vers 192.168.1.249 (sauvegarde
.env.bak-20260906). C’est juste, mais cela ne ranime pas les features
entrantes. Les deux problèmes ci-dessus restent ouverts.

État des livrables du cahier des charges au 06/09/2026

Livrable Statut

Code source du prototype ✅ Complet, poussé (main repo + fork
wazuh-docker)

Pipeline de collecte/traitement ✅ Opérationnel, validé live

Moteur de détection (signatures + comportemental) ✅ Opérationnel,
validé live (3 scénarios)

Moteur de détection (IA) ⚠️ Validé sur NSL-KDD, non intégré au live.
Voie NetFlow testée le 06/09 et écartée sur mesure (rappel 0/10 440, AUC
0,1604)

Module de priorisation des alertes ✅ Opérationnel (risk_scorer.py), sur
schéma NSL-KDD

Module de correspondance MITRE ATT&CK ⚠️ Live via règles, NSL-KDD-only
via IA — statut inchangé

Tableau de bord de visualisation ✅ Opérationnel, 4 pages

Guide d’installation ✅ docs/guide-installation.md

Rapport technique final ❌ Non commencé (matière première complète dans
ce journal)

Démonstration fonctionnelle ❌ Non préparée

Le statut de trois livrables est inchangé par cette session. C’est le
résultat attendu d’une porte de décision honnête : elle n’améliore pas
le prototype, elle établit qu’une voie envisagée ne l’améliorerait pas,
et elle le documente avec les mesures qui le prouvent.

06/09/2026 (suite) — L’AUC 0,16 mis en doute, puis confirmé ; et une
cause racine unique

1.  L’AUC 0,16 est-il une inversion de polarité ?

Objection soulevée en revue, et elle était sérieuse. Un AUC de 0,16
n’est pas un échec aléatoire — l’aléatoire donne 0,50. Retourné, 0,16
vaut 0,84 : le profil d’un modèle correct dont on aurait permuté les
étiquettes. Si c’était le cas, la voie NetFlow n’était pas morte et la
conclusion de la session précédente était à jeter.

Test discriminant. Une inversion de polarité est une propriété globale
du code d’étiquetage et de scoring : elle retournerait les deux domaines
ensemble. Il suffit donc de mesurer l’AUC sur le jeu de test source par
le même chemin de code.

Conventions vérifiées explicitement, les trois coïncident :

Côté Convention constatée

Source NF-CSE-CIC-IDS2018 Label=0 → {Benign} ; Label=1 → 14 classes
d’attaque

Vérité terrain locale Label=0 → {Benign} ; Label=1 → {BruteForce, DoS,
Reconnaissance}

Modèle XGBoost classes\_=\[0 1\], donc predict_proba\[:,1\] = P(attaque)

Domaine AUC-ROC

Source (test tenu à l’écart, n = 2 517 721) 0,9913

Local (n = 19 209) 0,1604

Local si polarité inversée 0,8396

Verdict : ce n’est pas un bug de polarité. À 0,9913 côté source avec le
même code, la même convention et le même modèle, l’orientation est
correcte de bout en bout. La conclusion précédente tient : l’échec de
transfert est réel. Test rejouable via
netflow_transfer_diagnostics.py::polarity_check().

2.  Pourquoi sous 0,5 et non autour ?

Une anti-corrélation régulière demande une cause régulière. Elle est
mesurable.

Les attaques du jeu source se concentrent sur les ports 21, 53, 80, 123,
135, 443, 445, 500, 3389, 8080 — c’est-à-dire les ports de service
ordinaires. Or c’est là que vit notre trafic bénin :

Classe locale n % sur un port-attaque CIC Score moyen

Benign 8769 85,7 % 0,0610

Reconnaissance 9184 3,3 % 0,0094

DoS 1200 0,0 % 0,0235

BruteForce 56 0,0 % 0,0044

Sur ces ports : score moyen 0,0727 pour 3,9 % d’attaques réelles. Hors
de ces ports : score moyen 0,0072 pour 89,0 % d’attaques réelles. L’a
priori appris est exactement à l’envers de la réalité de ce réseau —
d’où une inversion régulière plutôt que du bruit.

Ablation. Neutraliser OUT_PKTS ramène l’AUC de 0,1604 à 0,4680, soit le
hasard : c’est cette caractéristique qui porte l’inversion. Neutraliser
L4_DST_PORT seul ne change presque rien (0,1664). Une ablation qui
ramène vers 0,50 — et non vers 0,84 — confirme une dernière fois qu’il
n’y a pas de signal correct caché sous une permutation d’étiquettes.

3.  Cause racine unique : le pipeline lit des alertes, pas des flux

Trois défauts jusqu’ici consignés séparément n’en font qu’un.

Constat A — les caractéristiques inbound\_\* sont structurellement
mortes. Mesuré sur 10 627 alertes / 315 fenêtres d’une minute :

Caractéristique Fenêtres non nulles Max Total

inbound_event_count 0 / 315 0 0

inbound_unique_src_ips 0 / 315 0 0

inbound_unique_ports 0 / 315 0 0

outbound_event_count 131 / 315 243 4693

outbound_unique_ports 131 / 315 24 563

feature_extractor.py produit 16 colonnes, dont 2 identifiants et 14
caractéristiques numériques. Trois étant toujours nulles, le jeu
effectif compte 11 variables utiles, non 14. La distinction
entrant/sortant, présentée comme un point de conception dans l’entrée du
29/07, ne fonctionne pas en pratique. Les mentions de « 14 colonnes »
dans architecture.md et dans ce journal ont été corrigées.

Constat B — la collecte est manuelle et non continue. collector.py tire
500 alertes par exécution ; ce n’est pas un service. Son checkpoint est
resté figé au 29/07 pendant 39 jours. Couverture réelle du fichier au
06/09 : 10 627 alertes du 23/07 au 14/08.

Le retard n’est pas rattrapé, délibérément. La période 29/07–15/08 est
dominée à 87,5 % par du bruit QUIC — 9297 alertes « SURICATA QUIC failed
decrypt » sur 10 627 — précisément la nuisance supprimée à la source le
15/08 (commit 82a88c4). Rattraper gonflerait le volume sans ajouter de
signal. La couverture est documentée telle qu’elle est.

La convergence. Ces deux constats et l’écart de schéma NSL-KDD ont la
même cause : la chaîne collector.py → normalizer.py →
feature_extractor.py s’alimente à l’index wazuh-alerts-\*, et Wazuh
n’indexe que les événements Suricata de type alert. Tout ce qui n’a
déclenché aucune règle est invisible en aval, quelle que soit la qualité
du code de caractéristiques.

L’information entrante n’est pas absente du système — elle est hors
d’atteinte par ce chemin. 8684 flux TCP entrants vers la machine
surveillée sont présents dans eve.json sur la seule fenêtre du scan du
31/08 (23:45–23:49), sous event_type: flow. Aucun n’atteint le pipeline,
car aucun n’est un événement alert.

Ce n’est donc pas un manque de données mais un manque de chemin vers les
données. Ce qui désigne le correctif : brancher la collecte sur eve.json
plutôt que sur l’index d’alertes — exactement ce que fait
flow_feature_extractor.py, qui reste valide indépendamment de l’échec du
transfert inter-domaine mesuré plus haut.

Formulé autrement : l’échec de la voie NetFlow porte sur le modèle
(entraîné sur un autre réseau), pas sur l’extracteur. La partie du
chantier qui adresse la cause racine tient toujours.

///////////////////////////////////////////////////


07/09/2026 — Constitution du jeu de données de flux réels étiquetés

Suite au constat du 06/09 (le modèle NetFlow entraîné sur un autre
réseau ne généralise pas), pivot vers l'entraînement direct sur le
trafic réel du laboratoire.

Développement de run_attack_campaign.py : orchestration des campagnes
d'attaque avec trois modes (plan, record, verify) et attribution d'un
identifiant de campagne à granularité (tactique, source, jour), destiné
à garantir une validation croisée sans fuite.

Incident : le script record ne retrouvait aucun flux alors que le trafic
d'attaque était bien capturé par Suricata. Diagnostic : le filtrage
temporel se faisait sur le champ timestamp (heure de clôture du flux,
décalée jusqu'à 600 s par le timeout TCP established) au lieu de
flow.start (début réel du flux). Résolution : filtrage sur flow.start.

Génération de plusieurs campagnes distinctes (scans nmap variés,
force-brute SSH, floods) depuis la VM attaquante, chacune enregistrée
séparément pour former des groupes de validation indépendants.

Jeu final étiqueté : Benign (8 769 flux, 4 campagnes), Reconnaissance
(11 183 flux, 3 campagnes), Impact/DoS (1 200 flux, 3 campagnes),
InitialAccess_CredentialAccess (96 flux, 3 campagnes).

08/09/2026 — Entraînement du modèle sur trafic réel avec validation sans fuite

Développement de train_local_flow_model.py, entraînant deux modèles sur
le schéma de flux local (features NetFlow v1) : un binaire (bénin/attaque)
et un multi-classe (tactique).

Point méthodologique central : les flux d'une même campagne étant
fortement corrélés, une validation croisée naïve produirait des scores
artificiellement parfaits. Mise en place d'une validation par plis
groupés par campagne (StratifiedGroupKFold) — aucun flux d'une même
campagne des deux côtés d'un pli. Les deux modes (groupé et naïf) sont
mesurés côte à côte pour rendre l'écart visible.

Incident : plantage en validation groupée multi-classe (« Invalid classes
inferred ... Expected [0 1 2], got [0 2 3] »). Cause : avec peu de
campagnes par classe, un pli d'entraînement pouvait ne pas contenir
toutes les classes, cassant l'encodage contigu exigé par XGBoost.
Résolution : ré-encodage local des classes par pli, puis reprojection
des prédictions dans l'espace global — une classe absente d'un pli n'y
est jamais prédite, ce qui se reflète honnêtement dans un rappel dégradé
plutôt qu'en plantage.

Résultat (validation groupée, mesure honnête) : binaire F1 macro 0,99 ;
multi-classe F1 élevé sur les classes disposant d'assez de campagnes.
L'écart faible entre modes groupé et naïf confirme que le modèle
généralise et n'apprend pas par cœur les campagnes. Limites documentées :
jeu de taille réduite, environnement de laboratoire aux signatures
d'attaque nettement séparées, faible nombre de campagnes bornant le
nombre de plis.

Pour la première fois du projet, un modèle d'intelligence artificielle
produit des prédictions valides sur le trafic réel du système.

10/09/2026 — Branchement du modèle live sur le tableau de bord

Développement de live_flow_scoring.py, reliant le modèle flux-locaux aux
alertes de la page « Alertes en direct », en remplacement du proxy de
sévérité level_to_band().

Reconstruction, par alerte, des features NetFlow v1 à partir du bloc
data.flow présent dans les alertes Suricata indexées. Vérifié : 281 des
300 alertes d'un échantillon récent portent ce bloc, soit 87 alertes
réellement scorées par le modèle sur 300.

Deux limites mesurées et documentées : les alertes indexées ne portent
ni flow.end ni tcp.tcp_flags — deux features forcées à 0 (poids cumulé
~1,1 % de l'importance du modèle binaire, impact négligeable puisque le
score repose à 83 % sur IN_BYTES et 13 % sur L4_DST_PORT).

Repli explicite : si le modèle est absent, si le schéma ne valide pas,
ou si une alerte ne porte pas de bloc de flux exploitable, la ligne
retombe sur level_to_band(). Le repli n'est jamais silencieux — chaque
ligne porte son band_source (« model » ou « fallback ») et un bandeau
indique combien d'alertes ont été scorées par le modèle.

Ce branchement constitue le lien direct, jusque-là manquant, entre le
moteur d'intelligence artificielle et l'affichage opérationnel.

14/09/2026 — Détection SSH : correction de la surveillance d'auth.log

Incident découvert lors de la préparation de la démonstration : les
tentatives de force-brute SSH, pourtant bien enregistrées dans
/var/log/auth.log, ne remontaient pas dans le système d'alertes.

Diagnostic étape par étape : (1) les échecs sont bien présents dans
auth.log ; (2) le décodeur SSH de Wazuh parse correctement ces lignes
(vérifié via wazuh-logtest, règle 5760 déclenchée avec mitre.id
T1110.001) ; (3) mais la configuration de l'agent ne comportait aucune
directive <localfile> pointant vers auth.log — l'agent ne lisait donc
jamais ce fichier.

Résolution : ajout du bloc de surveillance d'auth.log dans la
configuration de l'agent, puis redémarrage. Après une nouvelle attaque,
les alertes remontent correctement : règle native 5760 (T1110) et règle
personnalisée 100010 (force-brute par échecs répétés, niveau 10),
validées en conditions réelles.

Enseignement : une source de log correctement produite et un décodeur
fonctionnel ne suffisent pas — encore faut-il que l'agent soit
explicitement configuré pour lire le fichier. Étape ajoutée au guide
d'installation.

///////////////////////////////////////////////////
