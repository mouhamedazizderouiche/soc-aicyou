# Guide d'installation — SOC AICYOU

**Objectif** : déployer le prototype complet (infrastructure Wazuh/Suricata,
pipeline Python, moteur de détection, tableau de bord) sur une VM neuve.

**Portée et limites de ce guide** : ce guide couvre le déploiement complet
tel qu'il existe actuellement. Certaines étapes (notamment la création du
compte de service `pipeline_svc`) documentent l'état *actuellement vérifié*
du système plutôt qu'un historique exact de commandes — voir les notes
inline. Pour les limites fonctionnelles du système une fois installé
(notamment l'écart entre le moteur IA et les données live), voir
`docs/architecture.md`, section 8.

---

## 0. Prérequis

| Élément | Version utilisée / testée |
|---|---|
| OS | Ubuntu Server 22.04 LTS |
| RAM | 16 Go recommandés (Wazuh + Suricata + pipeline Python) |
| Docker Engine | 29.6.2 |
| Docker Compose | v5.3.1 |
| Python | 3.12.3 |
| Git | toute version récente avec support des submodules |

Une VM secondaire (n'importe quel OS avec un client réseau) sur le même
sous-réseau est nécessaire pour générer du trafic de test/attaque
(nmap, tentatives SSH, flood TCP) — le système ne peut pas se valider
lui-même en boucle sur son propre trafic.

---

## 1. Cloner le dépôt

```bash
git clone --recurse-submodules https://github.com/mouhamedazizderouiche/soc-aicyou.git
cd soc-aicyou
```

**Important** : le submodule `docker/wazuh-docker` pointe vers un fork
personnel (`github.com/mouhamedazizderouiche/wazuh-docker`, branche
`v4.9.0-lock`), pas vers le dépôt officiel Wazuh — celui-ci contient des
règles de corrélation et des durcissements de sécurité spécifiques à ce
projet, absents du dépôt officiel. `--recurse-submodules` est nécessaire
dès le clone ; sans cette option, `docker/wazuh-docker/` reste vide.

Si le clone initial a été fait sans `--recurse-submodules` :
```bash
git submodule update --init --recursive
```

---

## 2. Déployer la stack Wazuh

### 2.1 Générer les secrets

```bash
cd docker/wazuh-docker/single-node
cp .env.example .env   # si absent, créer manuellement (voir variables ci-dessous)
```

Éditer `.env` et renseigner des valeurs fortes générées, par exemple :
```bash
openssl rand -base64 24
```

Variables requises dans `.env` :
INDEXER_USERNAME=admin
INDEXER_PASSWORD=<généré>
API_USERNAME=wazuh-wui
API_PASSWORD=<généré>
DASHBOARD_USERNAME=kibanaserver
DASHBOARD_PASSWORD=<généré>
WAZUH_VERSION=4.9.0
**Ne jamais utiliser les mots de passe par défaut du dépôt officiel**
(`admin/admin`, `kibanaserver/kibanaserver`) — c'est le premier
durcissement appliqué dans ce projet.

### 2.2 Générer les certificats et démarrer

```bash
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d
```

Attendre ~1-2 minutes que les 3 conteneurs (`manager`, `indexer`,
`dashboard`) soient opérationnels :
```bash
docker ps --format "table {{.Names}}\t{{.Status}}"
```

### 2.3 Vérifier le statut de l'API

Le dashboard Wazuh dépend d'un fichier de configuration interne
(`wazuh.yml`) qui ne supporte **pas** les variables d'environnement
Docker Compose — le mot de passe API doit y être renseigné en clair
manuellement si le statut affiche "Offline" :

```bash
docker exec single-node-wazuh.dashboard-1 cat /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml
```

Si le mot de passe ne correspond pas à `API_PASSWORD` défini en 2.1,
l'éditer directement dans le conteneur puis redémarrer :
```bash
docker restart single-node-wazuh.dashboard-1
```

Vérifier ensuite dans l'interface (`https://<IP_VM>:443`) que le statut
de l'API passe à "Online".

**Limitation connue** : ce fichier reste avec un secret en clair — non
paramétrable autrement dans cette version de Wazuh. Acceptable pour un
dépôt privé, à rotationner avant toute publication.

---

## 3. Déployer Suricata

```bash
cd ~/soc-aicyou/docker/suricata
```

### 3.1 Adapter la configuration réseau

Éditer `config/suricata.yaml` : définir `HOME_NET` sur le sous-réseau
réel de la VM (pas la plage large par défaut), et confirmer l'interface
réseau (`ens33` ou équivalent — vérifier avec `ip -br a`).

### 3.2 Démarrer

```bash
docker compose up -d
```

**Piège connu** : le script d'entrée du conteneur tente un `chown` sur
`suricata.yaml`. Si ce fichier est monté en lecture seule (`:ro` dans
`docker-compose.yml`), le conteneur part en crash-loop. Le montage ne
doit **pas** avoir le flag `:ro`.

### 3.3 Valider le chargement des règles

```bash
docker exec suricata suricata -T -c /etc/suricata/suricata.yaml
```

Doit se terminer par `Configuration provided was successfully loaded.`
Confirmer aussi le nombre de règles chargées dans les logs de démarrage :
```bash
docker logs suricata 2>&1 | grep -i "rule.*loaded\|threads"
```

### 3.4 Piège connu — montages de volumes manquants

`docker-compose.yml` doit monter **tous** les fichiers de config
référencés par `suricata.yaml`, notamment `threshold.config` (utilisé
pour supprimer le bruit d'alertes non pertinentes, ex. échecs de
déchiffrement QUIC). Un fichier de config créé sur l'hôte mais non monté
dans le `volumes:` du compose est silencieusement ignoré — Suricata
charge alors le gabarit par défaut de l'image sans aucune erreur. Après
toute modification des volumes :
```bash
docker compose up -d --force-recreate
```
`docker compose restart` seul **n'applique pas** les nouveaux montages.

---

## 4. Connecter Suricata → Wazuh

### 4.1 Installer l'agent Wazuh natif sur la VM hôte

```bash
curl -so wazuh-agent.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.9.0-1_amd64.deb
sudo WAZUH_MANAGER='127.0.0.1' dpkg -i ./wazuh-agent.deb
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

### 4.2 Configurer l'ingestion des logs Suricata

Ajouter à `/var/ossec/etc/ossec.conf` (dans le bloc `<ossec_config>`) :
```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>
```

Redémarrer l'agent :
```bash
sudo systemctl restart wazuh-agent
```

Wazuh applique automatiquement son ruleset natif Suricata (groupe
`ids, suricata`) — aucun décodeur additionnel n'est nécessaire pour les
alertes de base. Vérifier dans le dashboard que des alertes Suricata
apparaissent (ex. `SURICATA QUIC failed decrypt`, signature `2231000`,
si suppression non encore activée à cette étape).

---

## 5. Déployer les règles personnalisées

### 5.1 Règles Suricata (couche comportementale)

Les règles personnalisées (`sid:9000001`-`9000003` : détection de scan
de ports et de flood volumétrique) sont déjà présentes dans
`docker/suricata/config/rules/local.rules`, monté automatiquement.
Valider après tout changement :
```bash
docker exec suricata suricata -T -c /etc/suricata/suricata.yaml
```

### 5.2 Règles Wazuh (corrélation + escalade de sévérité)

Les règles personnalisées (`100010`-`100014` : brute-force SSH, succès
après échecs, escalade de sévérité pour les signatures Suricata custom)
sont dans
`docker/wazuh-docker/single-node/config/wazuh_cluster/custom_rules/local_rules.xml`.

**Piège connu** : le mécanisme d'auto-copie de configuration de Wazuh
(`/wazuh-config-mount/`) ne s'applique que sur un volume neuf, jamais
sur un déploiement déjà initialisé. Sur une VM où Wazuh tourne déjà,
toute modification de `local_rules.xml` doit être copiée manuellement :
```bash
docker cp docker/wazuh-docker/single-node/config/wazuh_cluster/custom_rules/local_rules.xml \
  single-node-wazuh.manager-1:/var/ossec/etc/rules/local_rules.xml
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart
```

Valider une règle avant redémarrage complet (évite un cycle
redémarrage-et-espère) :
```bash
docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
```

---

## 6. Créer le compte de service pipeline (`pipeline_svc`)

Le pipeline Python n'utilise **jamais** le compte administrateur Wazuh —
un compte de service dédié, en lecture seule et scopé à l'index des
alertes uniquement, est requis.

> **Note sur cette section** : les commandes ci-dessous documentent la
> méthode standard pour reproduire les permissions **actuellement
> vérifiées et en place** sur le système (rôle + utilisateur confirmés
> via l'API de sécurité OpenSearch, testés le 15/08/2026 — voir
> `docs/journal-technique.md`). Elles ne prétendent pas reproduire
> exactement l'historique des commandes originales, non retrouvé dans
> l'historique shell.

```bash
ADMIN_PASSWORD=$(grep INDEXER_PASSWORD docker/wazuh-docker/single-node/.env | cut -d= -f2)
SVC_PASSWORD=$(openssl rand -base64 24)

# 1. Créer le rôle en lecture seule, scopé à wazuh-alerts-*
docker exec single-node-wazuh.indexer-1 curl -k -s -u admin:$ADMIN_PASSWORD \
  -X PUT "https://127.0.0.1:9200/_plugins/_security/api/roles/pipeline_alerts_read" \
  -H "Content-Type: application/json" \
  -d '{
    "cluster_permissions": ["cluster_composite_ops_ro"],
    "index_permissions": [{
      "index_patterns": ["wazuh-alerts-*"],
      "allowed_actions": ["read", "indices:admin/mappings/get", "indices:data/read/search"]
    }]
  }'

# 2. Créer le compte de service
docker exec single-node-wazuh.indexer-1 curl -k -s -u admin:$ADMIN_PASSWORD \
  -X PUT "https://127.0.0.1:9200/_plugins/_security/api/internalusers/pipeline_svc" \
  -H "Content-Type: application/json" \
  -d "{\"password\": \"$SVC_PASSWORD\", \"backend_roles\": [], \"description\": \"Service account read-only pour le pipeline Python\"}"

# 3. Lier le compte au rôle
docker exec single-node-wazuh.indexer-1 curl -k -s -u admin:$ADMIN_PASSWORD \
  -X PUT "https://127.0.0.1:9200/_plugins/_security/api/rolesmapping/pipeline_alerts_read" \
  -H "Content-Type: application/json" \
  -d '{"users": ["pipeline_svc"]}'

echo "Mot de passe pipeline_svc généré : $SVC_PASSWORD (à reporter dans pipeline/.env, étape 7)"
```

**Vérification recommandée** (confirme le scoping, pas juste l'existence
du compte) :
```bash
# Doit réussir (lecture sur wazuh-alerts-*)
docker exec single-node-wazuh.indexer-1 curl -k -s -u pipeline_svc:$SVC_PASSWORD \
  "https://127.0.0.1:9200/wazuh-alerts-*/_search?size=1"

# Doit échouer en 403 (index hors périmètre)
docker exec single-node-wazuh.indexer-1 curl -k -s -o /dev/null -w "%{http_code}\n" \
  -u pipeline_svc:$SVC_PASSWORD "https://127.0.0.1:9200/.opensearch-observability/_search"
```

---

## 7. Configurer le pipeline Python

### 7.1 Fichier `.env`

Créer `pipeline/.env` :
WAZUH_INDEXER_URL=https://127.0.0.1:9200
WAZUH_INDEXER_USER=pipeline_svc
WAZUH_INDEXER_PASSWORD=<mot de passe généré à l'étape 6>
MONITORED_HOST_IP=<IP de la VM hôte sur le sous-réseau>
### 7.2 Environnement virtuel

```bash
cd pipeline
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**Piège connu** : `pyarrow` version 25.0.0 provoque un segfault
(`libarrow.so`) sur certaines configurations. `requirements.txt` épingle
`pyarrow==17.0.0` — ne pas mettre à jour ce paquet isolément sans retester.

---

## 8. Obtenir le jeu de données NSL-KDD

```bash
mkdir -p pipeline/data/nsl-kdd
```

Télécharger `KDDTrain+.txt` et `KDDTest+.txt` depuis une source NSL-KDD
académique standard (dataset original : University of New Brunswick,
CIC — voir `https://www.unb.ca/cic/datasets/nsl.html`) et les placer
dans `pipeline/data/nsl-kdd/`.

> Note : la provenance exacte (URL précise utilisée lors du
> développement initial) n'a pas pu être confirmée depuis l'historique
> shell de ce projet — toute source NSL-KDD standard contenant les deux
> fichiers avec les colonnes attendues (voir `preprocess.py`) convient.

---

## 9. Entraîner les modèles

Les artefacts de modèle (`.json`, `.pkl`) ne sont **pas** versionnés
(`pipeline/data/*` est dans `.gitignore`, à l'exception des rapports
JSON) — ils doivent être générés localement. Ordre requis :

```bash
cd pipeline
source venv/bin/activate

python3 train_model.py              # baseline XGBoost -> data/xgboost_baseline.json
python3 train_isolation_forest.py   # -> data/isolation_forest.pkl
python3 tactic_classifier_smote.py  # -> data/xgboost_tactic_classifier_final.json,
                                     #    data/tactic_label_encoder.pkl,
                                     #    data/tactic_classifier_report.json
```

Vérifier que les 4 fichiers modèle existent :
```bash
ls -la data/xgboost_baseline.json data/isolation_forest.pkl \
       data/xgboost_tactic_classifier_final.json data/tactic_label_encoder.pkl
```

Les scripts suivants sont des outils d'investigation ponctuels utilisés
pendant le développement (analyse de features, false positives, comparaison
d'ensemble, test d'hypothèse) — **non requis** pour un déploiement
fonctionnel : `analyze_model.py`, `false_positive_analysis.py`,
`ensemble_evaluation.py`, `isolation_forest_hypothesis_test.py`.

**Attention** : `explore_dataset.py`, bien que son nom suggère un usage
exploratoire ponctuel, est en réalité une dépendance requise —
`preprocess.py` (utilisé par la quasi-totalité du pipeline) importe
`load_nsl_kdd` et `COLUMN_NAMES` depuis ce module (`from explore_dataset
import load_nsl_kdd, COLUMN_NAMES`). Vérifié le 15/08/2026 par recherche
directe dans le code plutôt que par convention de nommage — un fichier
au nom "exploratoire" n'est pas nécessairement optionnel. Ce fichier
**doit** être présent pour que l'entraînement des modèles fonctionne.

---

## 10. Générer le rapport de validation initial

```bash
python3 validation_report.py
```

Produit `data/validation_report.json`, lu par le dashboard (Vue
d'ensemble). À relancer après toute modification d'un modèle — ce
fichier n'est pas régénéré automatiquement (voir
`docs/journal-technique.md`, 14/08/2026, pour l'incident historique lié
à l'absence de ce réflexe).

---

## 11. Lancer le tableau de bord

```bash
cd pipeline
source venv/bin/activate
streamlit run dashboard.py --server.address 0.0.0.0 --server.port 8501
```

Accessible depuis le sous-réseau local à `http://<IP_VM>:8501`.

**Limitation connue** : aucune authentification sur cette interface à ce
stade du prototype — voir `docs/architecture.md`, section 8.

---

## 12. Vérification de bout en bout

1. Générer du trafic de test depuis la VM secondaire (ex. `nmap -sS <IP_VM>`).
2. Confirmer l'alerte dans `docker exec suricata tail -f /var/log/suricata/eve.json`.
3. Confirmer la remontée dans Wazuh (`docker exec single-node-wazuh.manager-1 tail -f /var/ossec/logs/alerts/alerts.json`).
4. Confirmer l'affichage dans le dashboard, page "Alertes en direct".
5. Ouvrir la page "Moteur d'analyse" et lancer une analyse sur échantillon NSL-KDD pour confirmer que le moteur IA répond (voir limitation en section 8 de `architecture.md` concernant l'absence d'intégration IA sur données live à ce jour).

---

## 13. Pour aller plus loin

- `docs/architecture.md` — architecture complète, décisions techniques, limites connues
- `docs/journal-technique.md` — historique chronologique complet des incidents et résolutions
- `docs/playbook-reponse-incidents.md` — procédures de réponse aux incidents par tactique MITRE ATT&CK
