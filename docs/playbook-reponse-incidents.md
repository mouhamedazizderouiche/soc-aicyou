# Playbook de Réponse aux Incidents — SOC AICYOU

**Version 2** — Structure alignée sur les pratiques SOC L1/L2 standard (référence :
formats de playbooks MITRE ATT&CK open-source — voir Sources en fin de document).

Ce document est la **source de vérité humaine** des procédures de réponse.
Le module `pipeline/playbook.py` en est la version structurée (machine-readable),
utilisée par `analysis_engine.py` pour générer des recommandations ancrées dans
la procédure réelle plutôt qu'un texte générique déconnecté.

**Portée** : prototype de lab. À adapter (contacts d'astreinte, SLA contractuels,
outils de ticketing réels) avant tout déploiement en production.

---

**Référentiel** : ce playbook suit le cycle de vie NIST SP 800-61r2 (Préparation → Détection/Analyse → Confinement/Éradication/Récupération → Post-Incident), adapté à l'échelle d'un prototype de lab (un hôte surveillé), pas d'un environnement multi-clients en production.

## Préparation

- **Actifs** : 1 VM Ubuntu Server (hôte surveillé), stack Wazuh (manager, indexer, dashboard), Suricata (NIDS)
- **Outils d'accès** : dashboard Wazuh (`https://<IP>:443`), tableau de bord Streamlit (`http://<IP>:8501`), accès SSH à la VM
- **Sources de détection** : règles Suricata natives + custom (`docker/suricata/config/rules/local.rules`), règles Wazuh natives + custom (`docker/wazuh-docker/single-node/config/wazuh_cluster/custom_rules/local_rules.xml`)

## Principe de triage — bandes de risque

```
Score de risque (risk_scorer.py, ensemble XGBoost + Isolation Forest)
    │
    ├── low (<0.2)      → Log seul, aucune action (bruit de fond attendu)
    ├── medium (0.2-0.5) → Surveillance passive
    ├── high (0.5-0.8)   → Vérification L1 sous 24h ouvrées
    └── critical (>0.8)  → Investigation immédiate (SLA cible : 15 min)
```

**Note sur la confiance** : si l'alerte est détectée **uniquement** par le
détecteur d'anomalies (Isolation Forest, champ `flagged_by_anomaly_detector`)
plutôt que par signature XGBoost connue, traiter avec un biais de vérification
renforcé — l'absence de signature connue ne signifie pas absence de risque.

---

## Playbook 1 — Impact (TA0040) — Déni de service

| Champ | Détail |
|---|---|
| **Tactique MITRE** | Impact |
| **Technique(s)** | T1498 (Network DoS), T1499 (Endpoint DoS) |
| **Sources de log à investiguer** | Suricata `eve.json` (event_type=alert, flow), Wazuh alertes agrégées, métriques système (charge CPU/réseau) |
| **Indicateurs clés** | Pic de volume de connexions, `unique_dest_ports`/`event_count` élevés sur fenêtre courte (1 min), alerte Suricata QUIC/flood |
| **Questions d'analyse (L1)** | Les services ciblés répondent-ils toujours ? Le volume est-il légitime (pic de trafic normal) ou anormal ? La source est-elle unique ou distribuée ? |
| **Critère d'escalade** | Service indisponible confirmé, OU volume >3x la baseline habituelle, OU alerte `critical` avec confiance modèle >90% |

**Actions L1 :**
1. Confirmer l'impact réel (`curl`/healthcheck sur le service ciblé)
2. Identifier la/les IP(s) source(s) via `analysis_engine.py` (champ `mitre_id: TA0040`)
3. Vérifier `whois`/reverse DNS avant toute action (éviter de bloquer un service légitime — CDN, load balancer)
4. Documenter (horodatage, IP, volume observé)

**Actions L2 / confinement :**
1. Si trafic externe illégitime confirmé : bloquer temporairement via UFW (`ufw deny from <IP>`)
2. Si le trafic persiste après blocage (IP spoofée / botnet distribué) : escalader vers l'équipe réseau pour filtrage en amont
3. Post-incident : évaluer si un rate-limiting permanent est justifié

---

## Playbook 2 — Reconnaissance (TA0043) — Scan / sondage

| Champ | Détail |
|---|---|
| **Tactique MITRE** | Reconnaissance |
| **Technique(s)** | T1595 (Active Scanning) |
| **Sources de log à investiguer** | Suricata règles custom `sid 9000001`/`9000002` (`docker/suricata/config/rules/local.rules`), `feature_extractor.py` (`inbound_unique_ports`, fenêtre 1 min) |
| **Indicateurs clés** | Une même source (`flow_src_ip`) contacte de nombreux ports distincts en peu de temps ; alerte "CUSTOM Possible port scan detected" |
| **Questions d'analyse (L1)** | La source est-elle interne (poste d'audit connu/planifié) ou externe ? Le scan cible-t-il un seul hôte ou plusieurs (balayage réseau) ? |
| **Critère d'escalade** | Source externe non identifiée, OU scan suivi d'une tentative de connexion applicative dans les heures suivantes (corrélation) |

**Actions L1 :**
1. Identifier la source réelle via `flow_src_ip` (pas `src_ip` — voir note technique ci-dessous)
2. Vérifier si la source est un outil d'audit interne autorisé
3. Documenter la source pour corrélation future (ne pas bloquer un scan seul sans confirmation)

**Actions L2 / confinement :**
1. Si source interne non autorisée : contacter le propriétaire de la machine (poste potentiellement compromis)
2. Si source externe : surveillance renforcée 24-48h, corréler avec toute tentative d'authentification ultérieure de la même IP
3. Un scan **seul** n'est pas une compromission — ne pas escalader en incident critique sans signal complémentaire

**Note technique :** `feature_extractor.py` distingue le trafic entrant (`flow_dest_ip` = machine surveillée) du trafic sortant (`flow_src_ip` = machine surveillée) pour éviter de confondre un scan reçu avec le bruit de navigation web normal (voir `docs/journal-technique.md`, entrée 29/07).

---

## Playbook 3 — Initial Access / Credential Access (TA0001/TA0006)

| Champ | Détail |
|---|---|
| **Tactique MITRE** | Initial Access / Credential Access |
| **Technique(s)** | T1110 (Brute Force), T1078 (Valid Accounts) |
| **Sources de log à investiguer** | Wazuh règles natives (5760, 5503, 5715) + règles custom `100010`/`100011` (`docker/wazuh-docker/single-node/config/wazuh_cluster/custom_rules/local_rules.xml`), journaux d'authentification (`journalctl -u ssh`) |
| **Indicateurs clés** | Échecs d'authentification répétés depuis une même source (règle 100010) ; **succès après une série d'échecs** (règle 100011, niveau 14 — signal le plus critique) |
| **Questions d'analyse (L1)** | Une authentification a-t-elle **réussi** après les échecs ? Le compte concerné a-t-il des privilèges élevés ? La source est-elle géographiquement/réseau cohérente avec l'utilisateur légitime ? |
| **Critère d'escalade** | Règle 100011 déclenchée (succès après échecs) → escalade **immédiate et automatique**, quel que soit le contexte |

**Actions L1 :**
1. Vérifier les journaux d'authentification du système ciblé
2. Confirmer si une authentification a réussi après la séquence d'échecs
3. Identifier le compte concerné et son niveau de privilège

**Actions L2 / confinement :**
1. Si compromission confirmée (règle 100011) : forcer la rotation immédiate des identifiants du compte concerné
2. Si échecs seuls (règle 100010, pas de succès) : envisager un verrouillage temporaire du compte ou rate-limiting SSH
3. Documenter la méthode (brute-force simple à faible diversité de mots de passe vs. credential stuffing avec liste connue)
4. Vérifier si le compte compromis a été utilisé pour du mouvement latéral (autres connexions sortantes depuis cette session)

**Incident réel documenté** (voir `docs/journal-technique.md`, 04-06/08/2026) : la règle native Wazuh 5710 ne s'est pas déclenchée sur une attaque courte (sous son seuil par défaut), et un succès après échecs était initialement journalisé au **même niveau qu'une connexion normale** (level 3). Les règles custom 100010/100011 corrigent cet angle mort — **c'est pourquoi ces règles custom sont la source de vérité prioritaire pour cette tactique, pas les règles natives seules**.

---

## Playbook 4 — Privilege Escalation (TA0004)

| Champ | Détail |
|---|---|
| **Tactique MITRE** | Privilege Escalation |
| **Technique(s)** | T1548 (Abuse Elevation Control Mechanism), T1068 (Exploitation for Privilege Escalation) |
| **Sources de log à investiguer** | Wazuh (modifications `/etc/passwd`, `/etc/sudoers`, exécution de binaires SUID inhabituels, tâches cron) |
| **Indicateurs clés** | Modification de permissions, nouveau compte à privilèges, processus inhabituel exécuté avec élévation |
| **Questions d'analyse (L1)** | Le processus/la modification est-il planifié (changement légitime documenté) ? Le compte à l'origine est-il un compte de service ou un utilisateur humain ? |
| **Critère d'escalade** | **Systématique** — voir limite du modèle ci-dessous |

**⚠️ Limite critique du modèle documentée** : le classifieur de tactique a la performance la plus faible sur cette catégorie (F1 = 0,14 sur XGBoost, 52 exemples d'entraînement réels seulement — voir `docs/journal-technique.md`). **Toute alerte de cette catégorie doit être traitée en priorité manuelle systématique, même à faible score de confiance du modèle.** Le score ne doit pas être le seul filtre de décision pour cette tactique spécifiquement.

**Actions L1 :**
1. Traiter comme prioritaire indépendamment du score de confiance affiché
2. Vérifier l'intégrité du système : processus en cours, modifications récentes de `/etc/passwd`/`/etc/sudoers`, tâches cron

**Actions L2 / confinement :**
1. Isoler la machine du réseau si compromission confirmée, avant investigation approfondie
2. Conserver une image/snapshot du système avant toute remédiation (preuve forensique)
3. Vérifier l'intégrité de l'ensemble de la chaîne de privilèges (comptes créés, groupes modifiés)

---

## Procédure générale de documentation d'incident

Chaque incident traité (`high` ou `critical`) doit être consigné avec :
- Horodatage de détection et de traitement
- Score de risque, tactique prédite, détecteur responsable (XGBoost signature vs. Isolation Forest anomalie)
- IP(s) source(s) et destination(s)
- Action prise et justification
- Statut final (faux positif / confirmé / sous investigation)

Cette trace alimente le futur dataset labellisé réel (Phase 5) et sert de preuve d'audit.

---

## Lessons Learned (post-incident)

Après tout incident `critical` confirmé, documenter :
1. Qu'est-ce qui s'est passé ? (résumé factuel)
2. Qu'avons-nous bien fait ? (détection, temps de réponse)
3. Qu'aurions-nous pu faire mieux ? (angle mort, délai)
4. Que ferons-nous différemment ? (règle à ajouter, seuil à ajuster)

C'est ce processus qui a mené à la création des règles custom 100010/100011 (Playbook 3) — documenté comme méthodologie reproductible, pas comme correction ponctuelle isolée.

---

## Limites actuelles du système (transparence)

- Le pipeline dépend des alertes déjà déclenchées par Suricata/Wazuh — un flux réseau ne correspondant à aucune règle n'est jamais analysé par le moteur ML (voir `feature_extractor.py`).
- Aucune visibilité sur le contenu du trafic chiffré au-delà des métadonnées (SNI, JA3).
- Le modèle de tactique a été entraîné sur NSL-KDD (académique) ; sa performance sur du trafic réel à grande échelle reste à valider au-delà des tests ponctuels.
- Pas d'automatisation SOAR — toutes les actions de ce document restent manuelles à ce stade du prototype.

---

## Sources et références

Structure inspirée des formats de playbooks SOC open-source suivants :
- [austinsonger/Incident-Playbook](https://github.com/austinsonger/Incident-Playbook) — cycle de vie NIST/SANS (Préparation → Investigation → Confinement/Éradication → Récupération → Retour d'expérience)
- [CodeByHarri/MITRE-ATT_CK-Playbooks](https://github.com/CodeByHarri/MITRE-ATT_CK-Playbooks) — format de triage L1/L2 (sources de log, indicateurs, critères d'escalade)
