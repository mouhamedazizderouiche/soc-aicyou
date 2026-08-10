# SOC AICYOU — Moteur Intelligent de Détection d'Intrusions

Prototype de recherche et développement d'un moteur de détection d'intrusions basé sur l'analyse comportementale, le machine learning et le référentiel MITRE ATT&CK, développé dans le cadre d'un stage chez **Stratégie AICYOU Inc.**

**Stagiaire :** Mouhamed Aziz Derouiche (ESPRIT — Tunisie)
**Encadrant :** Dr. Alaidine Ben Ayed

---

## Vue d'ensemble

Ce projet construit, de bout en bout, un pipeline de détection de menaces combinant :

- Un environnement SOC réel (**Wazuh** + **Suricata**) déployé en conteneurs Docker
- Un pipeline Python de collecte, normalisation et extraction de caractéristiques comportementales
- Un moteur de détection combinant un modèle supervisé (**XGBoost**) et un détecteur d'anomalies non supervisé (**Isolation Forest**) en ensemble
- Une classification automatique de la tactique **MITRE ATT&CK** probable, indépendante d'un simple lookup statique
- Un tableau de bord **Streamlit** interactif pour l'analyse et le triage des alertes

## Architecture de détection en profondeur

```
┌─────────────────────────────────────────────────────────┐
│  Couche 1 — Signatures natives                           │
│  Ruleset Suricata (40 000+ règles) : CVE, malware, exploits │
├─────────────────────────────────────────────────────────┤
│  Couche 2 — Règles comportementales personnalisées        │
│  Suricata : détection de scan de ports (seuil, tool-agnostic)│
│  Wazuh : détection de force brute SSH avec escalade        │
├─────────────────────────────────────────────────────────┤
│  Couche 3 — Intelligence artificielle                     │
│  XGBoost (score de risque) + Isolation Forest (anomalies)  │
│  + classification de tactique MITRE ATT&CK                 │
└─────────────────────────────────────────────────────────┘
```

## Résultats clés

| Métrique | Valeur |
|---|---|
| Taux de détection (ensemble XGBoost + Isolation Forest) | 77,5 % |
| Taux de faux positifs | 3,58 % |
| Débit du moteur ML | ~127 000 événements/seconde |
| Précision de la classification tactique (sur vrais positifs) | 100 % |

Voir `docs/journal-technique.md` pour l'historique complet des expérimentations, incidents résolus et décisions techniques.

## Structure du dépôt

```
soc-aicyou/
├── docker/
│   ├── wazuh-docker/        # Sous-module Git — déploiement Wazuh (manager, indexer, dashboard)
│   └── suricata/             # Déploiement Suricata + règles personnalisées
├── pipeline/
│   ├── wazuh_client.py       # Client API Wazuh (authentification, requêtes)
│   ├── normalizer.py         # Normalisation des alertes Wazuh/Suricata
│   ├── collector.py          # Collecte incrémentale (checkpoint-based)
│   ├── feature_extractor.py  # Extraction de caractéristiques comportementales
│   ├── preprocess.py         # Prétraitement du jeu de données NSL-KDD
│   ├── train_model.py        # Entraînement XGBoost (score de risque)
│   ├── train_isolation_forest.py  # Entraînement du détecteur d'anomalies
│   ├── tactic_classifier_smote.py # Classification multi-classe MITRE ATT&CK
│   ├── risk_scorer.py        # Ensemble XGBoost + Isolation Forest
│   ├── analysis_engine.py    # Moteur d'analyse de bout en bout
│   ├── validation_report.py  # Rapport de validation formel
│   └── dashboard.py          # Tableau de bord Streamlit
├── docs/
│   ├── architecture.md
│   ├── journal-technique.md
│   └── playbook-reponse-incidents.md
└── data/                     # Données et modèles entraînés (non versionnés)
```

## Prérequis

- Docker et Docker Compose
- Python 3.12
- Une VM Linux dédiée (le projet a été développé et testé sur Ubuntu Server 22.04 LTS)

## Installation

```bash
git clone --recurse-submodules https://github.com/mouhamedazizderouiche/soc-aicyou.git
cd soc-aicyou
```

Voir le guide d'installation détaillé dans `docs/` *(à compléter)* pour la configuration complète (certificats Wazuh, variables d'environnement, déploiement des conteneurs).

## Lancer le tableau de bord

```bash
cd pipeline
source venv/bin/activate
streamlit run dashboard.py --server.address 0.0.0.0 --server.port 8501
```

## Limites connues

- La classification de la tactique **PrivilegeEscalation** reste faible (F1 = 0,14) en raison du faible nombre d'exemples d'entraînement disponibles — traitée en priorité manuelle systématique dans le playbook de réponse.
- Le pipeline dépend des alertes déjà déclenchées par Suricata/Wazuh ; un flux réseau ne correspondant à aucune règle n'est pas analysé par le moteur ML.
- Le modèle a été entraîné sur le jeu de données académique NSL-KDD ; sa performance sur du trafic réel à grande échelle reste à valider au-delà des tests ponctuels réalisés.

Voir `docs/journal-technique.md` pour le détail de chaque limite identifiée et son analyse.

## Licence et cadre

Projet développé dans le cadre d'un stage académique (ESPRIT) en partenariat avec Stratégie AICYOU Inc. Usage interne au projet de stage.
