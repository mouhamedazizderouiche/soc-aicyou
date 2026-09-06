# Suite de tests

```bash
cd pipeline
./venv/bin/python -m pytest          # toute la suite
./venv/bin/python -m pytest -v       # détail par test
```

## Périmètre

| Fichier | Module couvert | Ce qui est verrouillé |
|---|---|---|
| `test_feature_schema.py` | `feature_schema.py` | Schéma NSL-KDD accepté, schéma live rejeté, qualité du diagnostic, absence de recouvrement entre les deux schémas |
| `test_playbook.py` | `playbook.py` | Toutes combinaisons bande × tactique × drapeau d'anomalie ; le cas low/medium + anomalie seule ; escalade L1/L2 ; limites connues affichées |
| `test_mitre_categories.py` | `mitre_categories.py` | Couverture des 39 types, taxonomie DoS/Probe/R2L/U2R, choix ambigus figés, repli `Unknown` |
| `test_risk_scorer.py` | `risk_scorer.py` | Table de vérité du OU, seuil opérationnel, traçabilité du rattrapage Isolation Forest, bandes de risque contiguës, contrat de schéma sur chaque méthode publique |
| `test_flow_feature_extractor.py` | `flow_feature_extractor.py` | Les 12 features NetFlow v1, cas limites (ICMP sans ports, UDP sans bloc TCP), rejets comptabilisés, exclusion des IP de l'entrée modèle |

## Principes

**Aucune dépendance aux artefacts d'entraînement.** La suite tourne sur
un clone neuf, sans modèles `.pkl`/`.json`, sans NSL-KDD et sans
NF-CSE-CIC-IDS2018. `test_risk_scorer.py` utilise des modèles factices à
sorties imposées : ce qui est testé est la logique de combinaison, pas la
qualité des modèles. Charger les vrais modèles rendrait le test
dépendant de leurs performances, donc incapable d'isoler une régression.

**Les tests portent sur les propriétés dont dépend une décision**, pas
sur la formulation exacte des textes — celle-ci évoluera avec le
playbook, les propriétés non.

## Ce qui n'est PAS couvert, et pourquoi

- `dashboard.py` : interface Streamlit, testable seulement par
  automatisation de navigateur — hors périmètre du prototype.
- `collector.py`, `wazuh_client.py` : dépendent d'un indexeur Wazuh
  joignable. Testables avec un serveur factice, non fait à ce stade.
- Entraînement et évaluation des modèles : couverts par les
  vérificateurs exécutables (`--verify-schema`, `--verify-l7`,
  `verify_parent_mapping`, `polarity_check`) plutôt que par pytest, car
  ils supposent la présence des jeux de données.
