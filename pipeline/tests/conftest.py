"""
conftest.py

Rend les modules de `pipeline/` importables depuis les tests sans
installer le projet comme paquet. Le projet est un ensemble de scripts
exécutés depuis `pipeline/`, pas une distribution : les modules
s'importent entre eux à plat (`from feature_schema import ...`), et
c'est ce chemin d'import réel que les tests doivent exercer.
"""

import os
import sys

PIPELINE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PIPELINE_DIR not in sys.path:
    sys.path.insert(0, PIPELINE_DIR)
