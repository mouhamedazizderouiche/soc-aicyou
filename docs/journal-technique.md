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
