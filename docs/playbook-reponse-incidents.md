# Playbook de Réponse aux Incidents — SOC AICYOU

**Version 2** — Structure alignée sur les pratiques SOC L1/L2 standard
(référence : formats de playbooks MITRE ATT&CK open-source, voir Sources
en fin de document).

Ce document est la source de vérité humaine des procédures de réponse.
Le module `pipeline/playbook.py` en est la version structurée
(machine-readable), utilisée par `analysis_engine.py` pour générer des
recommandations ancrées dans la procédure réelle plutôt qu'un texte
générique déconnecté.

**Portée** : prototype de lab. À adapter (contacts d'astreinte, SLA
contractuels, outils de ticketing réels) avant tout déploiement en
production.

**Référentiel** : ce playbook suit le cycle de vie NIST SP 800-61r2
(Préparation → Détection/Analyse → Confinement/Éradication/Récupération
→ Post-Incident), adapté à l'échelle d'un prototype de lab (un hôte
surveillé), pas d'un environnement multi-clients en production.

## Préparation

**Actifs** : 1 VM Ubuntu Server (hôte surveillé), stack Wazuh (manager,
indexer, dashboard), Suricata (NIDS).

**Outils d'accès** : dashboard Wazuh (https://<IP>:443), tableau de bord
Streamlit (http://<IP>:8501), accès SSH à la VM.

**Sources de détection** : règles Suricata natives + custom
(`docker/suricata/config/rules/local.rules`), règles Wazuh natives +
custom
(`docker/wazuh-docker/single-node/config/wazuh_cluster/custom_rules/local_rules.xml`),
et journaux d'authentification `/var/log/auth.log` surveillés par
l'agent Wazuh.

## Principe de triage — bandes de risque

Le score de risque (`risk_scorer.py`, ensemble XGBoost + Isolation
Forest ; ou modèle flux-locaux pour les alertes live scorées) détermine
la bande :

- **low (<0.2)** → Log seul, aucune action (bruit de fond attendu)
- **medium (0.2-0.5)** → Surveillance passive
- **high (0.5-0.8)** → Vérification L1 sous 24h ouvrées
- **critical (>0.8)** → Investigation immédiate (SLA cible : 15 min)

**Note sur la confiance** : si l'alerte est détectée uniquement par le
détecteur d'anomalies (Isolation Forest, champ
`flagged_by_anomaly_detector`) plutôt que par signature XGBoost connue,
traiter avec un biais de vérification renforcé — l'absence de signature
connue ne signifie pas absence de risque.

**Note sur la source du score (live)** : sur la page « Alertes en
direct », la bande peut provenir soit du modèle flux-locaux
(`band_source: model`), soit d'un repli sur la sévérité Wazuh
(`band_source: fallback`) quand l'alerte ne porte pas de flux
exploitable. Le champ indique lequel, pour une lecture honnête du score.

## Playbook 1 — Impact (TA0040) — Déni de service

| Champ | Détail |
| --- | --- |
| Tactique MITRE | Impact |
| Technique(s) | T1498 (Network DoS), T1499 (Endpoint DoS) |
| Sources de log | Suricata eve.json (event_type=alert, flow), Wazuh alertes agrégées, métriques système (CPU/réseau) |
| Indicateurs clés | Pic de volume de connexions, unique_dest_ports/event_count élevés sur fenêtre courte (1 min), alerte Suricata flood (sid 9000003) |
| Critère d'escalade | Service indisponible confirmé, OU volume >3x la baseline, OU alerte critical avec confiance modèle >90% |

**Actions L1** : confirmer l'impact réel (curl/healthcheck sur le
service ciblé) ; identifier la/les IP source(s) via
`analysis_engine.py` ; vérifier whois/reverse DNS avant toute action
(éviter de bloquer un service légitime — CDN, load balancer) ;
documenter (horodatage, IP, volume).

**Actions L2 / confinement** : si trafic externe illégitime confirmé,
bloquer temporairement via UFW (`ufw deny from <IP>`) ; si le trafic
persiste (IP spoofée / botnet distribué), escalader vers l'équipe réseau
pour filtrage amont ; post-incident, évaluer un rate-limiting permanent.

## Playbook 2 — Reconnaissance (TA0043) — Scan / sondage

| Champ | Détail |
| --- | --- |
| Tactique MITRE | Reconnaissance |
| Technique(s) | T1595 (Active Scanning) |
| Sources de log | Suricata règles custom sid 9000001/9000002, feature_extractor.py (unique_dest_ports, fenêtre 1 min) |
| Indicateurs clés | Une même source contacte de nombreux ports distincts en peu de temps ; alerte « CUSTOM Possible port scan detected » |
| Critère d'escalade | Source externe non identifiée, OU scan suivi d'une tentative de connexion applicative dans les heures suivantes |

**Actions L1** : identifier la source réelle via `flow_src_ip` (pas
`src_ip` — voir note technique) ; vérifier si c'est un outil d'audit
interne autorisé ; documenter la source pour corrélation future (ne pas
bloquer un scan seul sans confirmation).

**Actions L2 / confinement** : si source interne non autorisée,
contacter le propriétaire de la machine (poste potentiellement
compromis) ; si source externe, surveillance renforcée 24-48h, corréler
avec toute tentative d'authentification ultérieure de la même IP. Un
scan seul n'est pas une compromission — ne pas escalader en critique
sans signal complémentaire.

**Note technique** : `feature_extractor.py` distingue le trafic entrant
(flow_dest_ip = machine surveillée) du trafic sortant, pour éviter de
confondre un scan reçu avec le bruit de navigation normal (voir
journal-technique.md, 29/07).

## Playbook 3 — Initial Access / Credential Access (TA0001/TA0006)

| Champ | Détail |
| --- | --- |
| Tactique MITRE | Initial Access / Credential Access |
| Technique(s) | T1110 (Brute Force), T1078 (Valid Accounts) |
| Sources de log | Wazuh règles natives (5760, 5503, 5715) + custom 100010/100011, /var/log/auth.log |
| Indicateurs clés | Échecs d'authentification répétés depuis une même source (règle 100010) ; succès après série d'échecs (règle 100011, niveau 14 — signal le plus critique) |
| Critère d'escalade | Règle 100011 déclenchée (succès après échecs) → escalade immédiate et automatique |

**Actions L1** : vérifier les journaux d'authentification du système
ciblé ; confirmer si une authentification a réussi après la séquence
d'échecs ; identifier le compte concerné et son niveau de privilège.

**Actions L2 / confinement** : si compromission confirmée (règle
100011), forcer la rotation immédiate des identifiants ; si échecs seuls
(règle 100010), envisager un verrouillage temporaire du compte ou un
rate-limiting SSH ; documenter la méthode (brute-force simple
vs. credential stuffing) ; vérifier tout mouvement latéral depuis la
session.

**Incident réel documenté** (voir journal-technique.md, 04-06/08 et
14/09) : la règle native Wazuh ne s'est pas déclenchée sur une attaque
courte (sous son seuil par défaut), et un succès après échecs était
initialement journalisé au même niveau qu'une connexion normale. Les
règles custom 100010/100011 corrigent cet angle mort — elles sont la
source de vérité prioritaire pour cette tactique. Prérequis vérifié le
14/09 : l'agent Wazuh doit surveiller /var/log/auth.log, sans quoi
aucune de ces règles ne se déclenche (voir guide-installation.md,
section 4.3).

## Playbook 4 — Privilege Escalation (TA0004)

| Champ | Détail |
| --- | --- |
| Tactique MITRE | Privilege Escalation |
| Technique(s) | T1548 (Abuse Elevation Control Mechanism), T1068 (Exploitation for Privilege Escalation) |
| Sources de log | Wazuh (modifications /etc/passwd, /etc/sudoers, binaires SUID inhabituels, tâches cron) |
| Indicateurs clés | Modification de permissions, nouveau compte à privilèges, processus inhabituel exécuté avec élévation |
| Critère d'escalade | Systématique — voir limite du modèle ci-dessous |

**⚠️ Limite critique documentée** : le classifieur de tactique a la
performance la plus faible sur cette catégorie (F1 = 0,19, précision
0,13 même après SMOTE modéré — seulement 52 exemples d'entraînement
réels dans NSL-KDD). De plus, cette tactique n'est pas couverte par le
modèle entraîné sur trafic réel (aucune campagne d'élévation de
privilèges dans le jeu local). Toute alerte de cette catégorie doit être
traitée en priorité manuelle systématique, indépendamment du score de
confiance affiché. Le score ne doit jamais être le seul filtre de
décision pour cette tactique.

**Actions L1** : traiter comme prioritaire quel que soit le score ;
vérifier l'intégrité du système (processus en cours, modifications
récentes de /etc/passwd, /etc/sudoers, tâches cron).

**Actions L2 / confinement** : isoler la machine du réseau si
compromission confirmée, avant investigation ; conserver un
snapshot/image du système avant remédiation (preuve forensique) ;
vérifier toute la chaîne de privilèges (comptes créés, groupes
modifiés).

## Procédure générale de documentation d'incident

Chaque incident traité (high ou critical) doit être consigné avec :
horodatage de détection et de traitement ; score de risque, tactique
prédite, détecteur responsable (XGBoost signature vs. Isolation Forest
anomalie) ; IP source(s) et destination(s) ; action prise et
justification ; statut final (faux positif / confirmé / sous
investigation). Cette trace alimente le dataset labellisé réel et sert
de preuve d'audit.

## Lessons Learned (post-incident)

Après tout incident critical confirmé, documenter : qu'est-ce qui s'est
passé (résumé factuel) ; qu'avons-nous bien fait (détection, temps de
réponse) ; qu'aurions-nous pu faire mieux (angle mort, délai) ; que
ferons-nous différemment (règle à ajouter, seuil à ajuster). C'est ce
processus qui a mené à la création des règles custom 100010/100011
(Playbook 3), documenté comme méthodologie reproductible.

## Limites actuelles du système (transparence)

- Le pipeline par alertes dépend des alertes déjà déclenchées par
  Suricata/Wazuh — un flux ne correspondant à aucune règle n'était
  jamais analysé par ce chemin. Le modèle flux-locaux
  (`live_flow_scoring.py`) réduit cette limite en scorant directement
  les flux des alertes live.
- Aucune visibilité sur le contenu du trafic chiffré au-delà des
  métadonnées (SNI, JA3).
- PrivilegeEscalation non couverte par le modèle sur trafic réel —
  traitement manuel systématique.
- Pas d'automatisation SOAR — toutes les actions restent manuelles à ce
  stade du prototype.

## Sources et références

Structure inspirée des formats de playbooks SOC open-source :
- **austinsonger/Incident-Playbook** — cycle de vie NIST/SANS
  (Préparation → Investigation → Confinement/Éradication → Récupération →
  Retour d'expérience)
- **CodeByHarri/MITRE-ATT&CK-Playbooks** — format de triage L1/L2
  (sources de log, indicateurs, critères d'escalade)
