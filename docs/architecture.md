# Architecture — Moteur Intelligent de Détection d'Intrusions (AICYOU)

**Stagiaire :** Mouhamed Aziz Derouiche
**Encadrant :** Dr. Alaidine Ben Ayed — Stratégie AICYOU Inc.
**Repo :** `soc-aicyou`

## 1. Vue d'ensemble

Environnement de lab SOC déployé sur une VM Ubuntu Server 22.04 LTS dédiée, hébergeant une stack Wazuh (SIEM/HIDS) et Suricata (NIDS), orchestrés via Docker Compose. Objectif : collecter, normaliser et analyser des événements de sécurité, avec à terme un moteur de scoring de risque basé sur un modèle XGBoost et une correspondance automatique MITRE ATT&CK.

## 2. Infrastructure

| Composant | Détail |
|---|---|
| Hôte | VM Ubuntu Server 22.04 LTS, 16 Go RAM alloués côté host |
| Utilisateur système | `aicyou` (non-root, membre du groupe `docker`) |
| Réseau VM | Interface `ens33`, IP `192.168.1.249/24` (bridge) |
| Orchestration | Docker Engine 29.6.2 + Docker Compose v5.3.1 |
| Pare-feu | UFW — deny incoming par défaut, exceptions ciblées |

## 3. Topologie des services
──────────────────────────────────────────────────┐
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
└──────────────────────────────────────────────────┘
## 4. Sécurité — mesures appliquées

- **Aucun service exécuté en root** : utilisateur dédié `aicyou`, ajouté au groupe `docker`.
- **Versions épinglées** : `wazuh-docker` intégré en Git submodule, épinglé sur le tag `v4.9.0` ; Suricata épinglé sur `7.0.7`. Jamais `latest`.
- **Secrets hors Git** : mots de passe migrés vers `single-node/.env` (ignoré via `.gitignore` dédié dans le submodule), jamais commités en clair dans `docker-compose.yml`.
- **Mots de passe forts régénérés** : remplacement des identifiants par défaut (`admin/admin`, `kibanaserver/kibanaserver`, API `wazuh-wui`) par des secrets générés (`openssl rand -base64 24`) et hash bcrypt recalculés via l'utilitaire officiel Wazuh.
- **Pare-feu réseau** : UFW actif, politique deny-by-default. Le port 443 (dashboard) est restreint au sous-réseau local `192.168.1.0/24`. SSH (22) reste ouvert pour l'administration.
- **Limitation connue** : le fichier `wazuh.yml` (config interne dashboard → API) ne supporte pas les variables d'environnement Docker Compose ; le mot de passe API y figure en clair. Ce fichier est donc actuellement commité avec un secret en dur — acceptable pour un repo strictement privé, mais à rotationner avant toute publication future.

## 5. Décisions techniques notables

| Décision | Justification |
|---|---|
| Git submodule (pas de copie brute) | Suit les mises à jour amont de Wazuh tout en gardant une version figée et reproductible |
| Pin sur tag, pas branche | Un tag est immuable ; une branche peut évoluer et casser la reproductibilité |
| `.env` séparé plutôt que variables inline | Sépare la configuration du code, standard 12-factor app, évite la fuite de secrets dans Git |
| UFW restreint au sous-réseau local | Le dashboard n'a pas besoin d'exposition publique pour un lab de développement |
| Suricata en `network_mode: host` | Requis pour la capture de paquets bruts sur l'interface physique de la VM |

## 6. Prochaines étapes

- Connexion Suricata → Wazuh (ingestion `eve.json`)
- Phase 2 : pipeline Python de collecte, normalisation et extraction de caractéristiques comportementales
