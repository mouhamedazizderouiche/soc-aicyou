# Playbook de Réponse aux Incidents — SOC AICYOU

Ce document formalise les procédures de réponse pour chaque combinaison
(bande de risque × tactique MITRE) produite par `analysis_engine.py`.
Il complète les recommandations automatiques (une ligne) avec une
procédure étape par étape, destinée à un analyste SOC humain.

**Portée** : ce playbook couvre le prototype de lab actuel. Il devra
être adapté (contacts d'astreinte, outils de ticketing réels, SLA
contractuels) avant tout déploiement en environnement de production.

---

## Principe général de triage

```
Alerte reçue
    │
    ▼
Score de risque (risk_scorer.py)
    │
    ├── low (<0.2)      → Log seul, pas d'action (bruit de fond attendu)
    ├── medium (0.2-0.5) → Surveillance passive, pas d'escalade immédiate
    ├── high (0.5-0.8)   → Vérification manuelle sous 24h ouvrées
    └── critical (>0.8)  → Investigation immédiate (SLA cible : 15 min)
```

---

## Procédures par tactique (cas `critical` ou `high`)

### 1. Impact (TA0040) — Déni de service

**Déclencheurs typiques** : pics de volume de connexions, `neptune`/`smurf`-like patterns, alertes Suricata de flood.

**Procédure** :
1. Confirmer l'impact réel : les services ciblés répondent-ils toujours ? (`curl`, healthcheck applicatif)
2. Identifier la/les IP(s) source(s) via `analysis_engine.py` → `mitre_id: TA0040`
3. Si trafic externe illégitime confirmé : bloquer temporairement via UFW (`ufw deny from <IP>`)
4. Documenter l'incident (horodatage, IP, volume observé, action prise)
5. Si le trafic persiste après blocage (IP spoofée / botnet distribué) : escalader vers l'équipe réseau pour un filtrage en amont (routeur/FAI)

**Ce qu'on ne fait PAS** : bloquer une IP sans vérifier qu'elle n'est pas un service légitime (ex: load balancer, CDN) — vérifier `whois`/reverse DNS avant action.

---

### 2. Reconnaissance (TA0043) — Scan / sondage

**Déclencheurs typiques** : règles custom `sid 9000001`/`9000002` (voir `docker/suricata/config/rules/local.rules`), `inbound_unique_ports` élevé sur fenêtre courte.

**Procédure** :
1. Identifier la source (`flow_src_ip` dans les données normalisées)
2. Vérifier si la source est interne (poste de travail connu, outil d'audit autorisé) ou externe
3. Si interne et non planifiée : contacter le propriétaire de la machine (poste compromis possible)
4. Si externe : documenter, surveiller les 24h suivantes pour une éventuelle escalade (le scan précède souvent une tentative d'exploitation)
5. Ne pas bloquer systématiquement — un scan seul n'est pas une compromission, mais un signal d'alerte précoce

**Corrélation recommandée** : croiser avec les logs des jours suivants pour la même IP source — un scan suivi d'une tentative d'authentification (`InitialAccess_CredentialAccess`) élève fortement la priorité.

---

### 3. InitialAccess / CredentialAccess (TA0001/TA0006) — Accès non autorisé / vol d'identifiants

**Déclencheurs typiques** : `guess_passwd`-like patterns, tentatives d'authentification répétées.

**Procédure** :
1. Vérifier les journaux d'authentification du système ciblé (`journalctl`, logs applicatifs)
2. Identifier si une authentification a **réussi** après la séquence d'échecs (signal de compromission réelle, priorité maximale)
3. Si compromission confirmée : forcer la rotation immédiate des identifiants concernés
4. Si échecs seuls : envisager un verrouillage temporaire du compte / rate-limiting sur le service exposé
5. Documenter la source et la méthode (brute-force simple vs credential stuffing avec liste de mots de passe connus)

---

### 4. PrivilegeEscalation (TA0004) — Élévation de privilèges

**Déclencheurs typiques** : modifications suspectes de permissions, exécution de binaires SUID inhabituels.

**⚠️ Limite connue documentée** : notre modèle actuel a la performance la plus faible sur cette catégorie (F1=0.14, cf. `docs/journal-technique.md`) en raison du faible volume d'exemples d'entraînement. **Toute alerte de cette catégorie doit être traitée avec un biais vers la vérification manuelle**, même à faible score de confiance.

**Procédure** :
1. Traiter comme prioritaire même si le score de confiance du modèle est modéré (compenser la faiblesse connue du modèle par la vigilance humaine)
2. Vérifier l'intégrité du système : processus en cours, modifications récentes de `/etc/passwd`, `/etc/sudoers`, tâches cron
3. Isoler la machine du réseau si compromission confirmée (avant investigation approfondie, pour limiter la propagation)
4. Conserver une image/snapshot du système avant remédiation (pour analyse forensique éventuelle)

---

## Procédure générale de documentation d'incident

Chaque incident traité (`high` ou `critical`) doit être consigné avec :
- Horodatage de détection et de traitement
- Score de risque et tactique prédite (sortie brute de `analysis_engine.py`)
- IP(s) source(s) et destination(s)
- Action prise
- Statut final (faux positif / confirmé / sous investigation)

Cette trace alimente à la fois le futur dataset labellisé réel (Phase 5) et sert de preuve d'activité pour audit.

---

## Limites actuelles du système (transparence)

- Le pipeline dépend des alertes Suricata déjà déclenchées — un flux réseau qui ne matche aucune règle n'est jamais analysé par le moteur ML (voir `feature_extractor.py`, section limite documentée)
- Aucune visibilité sur le trafic chiffré au-delà des métadonnées (SNI, JA3) — pas d'inspection de contenu
- Le modèle de tactique n'a pas encore été validé sur du trafic réel à grande échelle, uniquement sur NSL-KDD (académique) et des tests ponctuels
- Pas de playbook automatisé (SOAR) — toutes les actions de ce document restent manuelles à ce stade du prototype
