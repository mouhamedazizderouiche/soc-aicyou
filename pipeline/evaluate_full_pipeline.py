"""
evaluate_full_pipeline.py

Évaluation complète du moteur d'analyse (AnalysisEngine) sur
l'ensemble du test set NSL-KDD (22544 échantillons).

Mesure la performance du système bout-en-bout : détection binaire,
puis qualité de la classification de tactique sur les cas détectés.
"""

import time
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix

from preprocess import preprocess
from analysis_engine import AnalysisEngine
from mitre_categories import label_to_tactic

X_train, y_train, X_test, y_test, train_labels, test_labels, encoders = preprocess(
    "data/nsl-kdd/KDDTrain+.txt",
    "data/nsl-kdd/KDDTest+.txt",
)

engine = AnalysisEngine()

print(f"Analyse de {len(X_test)} échantillons en cours...\n")
start = time.time()
results = engine.analyze(X_test, true_labels=test_labels)
elapsed = time.time() - start

print(f"Terminé en {elapsed:.2f}s ({len(X_test) / elapsed:.0f} événements/sec)\n")

# === 1. Performance de la détection binaire (risque) ===
print("=" * 60)
print("1. DÉTECTION BINAIRE (normal vs attaque)")
print("=" * 60)
print(classification_report(y_test, results["is_attack"], target_names=["normal", "attack"]))

# === 2. Répartition par bande de risque ===
print("=" * 60)
print("2. RÉPARTITION PAR BANDE DE RISQUE")
print("=" * 60)
print(results["risk_band"].value_counts())
print()

# === 3. Performance de la classification de tactique (sur les vrais positifs uniquement) ===
print("=" * 60)
print("3. CLASSIFICATION DE TACTIQUE (sur détections correctes)")
print("=" * 60)

true_positives_mask = (results["is_attack"] == 1) & (y_test == 1)
tp_results = results[true_positives_mask].copy()
tp_results["true_tactic"] = test_labels[true_positives_mask].apply(label_to_tactic)

known_tactic_mask = tp_results["true_tactic"] != "Unknown"
tp_known = tp_results[known_tactic_mask]

print(f"Vrais positifs analysés : {len(tp_results)}")
print(f"Avec tactique connue    : {len(tp_known)}\n")

print(classification_report(
    tp_known["true_tactic"],
    tp_known["predicted_tactic"],
    zero_division=0,
))

# === 4. Cas critiques manqués (faux négatifs à haut risque potentiel) ===
print("=" * 60)
print("4. FAUX NÉGATIFS PAR TYPE D'ATTAQUE RÉELLE")
print("=" * 60)
false_negatives_mask = (results["is_attack"] == 0) & (y_test == 1)
fn_labels = test_labels[false_negatives_mask]
print(fn_labels.value_counts())

# === 5. Sauvegarde des résultats complets ===
output_path = "data/full_pipeline_evaluation.csv"
results.to_csv(output_path, index=False)
print(f"\nRésultats complets sauvegardés dans {output_path}")
