"""
validation_report.py

Rapport de validation formel, consolidant les métriques demandées par
le cahier des charges (section 3, Phase 5) :
- Taux de détection
- Taux de faux positifs
- Temps de traitement (latence bout-en-bout)
- Pertinence de la priorisation (cohérence risque/tactique)
"""

import time
import json
from datetime import datetime, timezone
import pandas as pd
from sklearn.metrics import confusion_matrix

from preprocess import preprocess
from analysis_engine import AnalysisEngine
from wazuh_client import WazuhIndexerClient
from normalizer import normalize_alert
from feature_extractor import extract_features, load_alerts

print("=" * 70)
print("RAPPORT DE VALIDATION — SOC AICYOU")
print("=" * 70)

# =========================================================
# 1. TAUX DE DÉTECTION ET FAUX POSITIFS (sur NSL-KDD test set)
# =========================================================
print("\n--- 1. Taux de détection et faux positifs (modèle de risque) ---\n")

X_train, y_train, X_test, y_test, train_labels, test_labels, encoders = preprocess(
    "data/nsl-kdd/KDDTrain+.txt",
    "data/nsl-kdd/KDDTest+.txt",
)

engine = AnalysisEngine()
results = engine.analyze(X_test, true_labels=test_labels)

cm = confusion_matrix(y_test, results["is_attack"])
tn, fp, fn, tp = cm.ravel()

detection_rate = tp / (tp + fn)  # recall / sensibilité
false_positive_rate = fp / (fp + tn)

print(f"Vrais positifs (attaques détectées)  : {tp}")
print(f"Faux négatifs (attaques manquées)    : {fn}")
print(f"Vrais négatifs (normal correct)      : {tn}")
print(f"Faux positifs (normal mal classé)    : {fp}")
print(f"\nTaux de détection (recall)   : {detection_rate:.2%}")
print(f"Taux de faux positifs        : {false_positive_rate:.2%}")

# =========================================================
# 2. TEMPS DE TRAITEMENT — latence du moteur d'analyse (modèle)
# =========================================================
print("\n--- 2. Temps de traitement (moteur d'analyse ML) ---\n")

start = time.time()
_ = engine.analyze(X_test)
elapsed = time.time() - start

throughput = len(X_test) / elapsed
latency_per_event_ms = (elapsed / len(X_test)) * 1000

print(f"Échantillons traités          : {len(X_test)}")
print(f"Temps total                   : {elapsed:.3f}s")
print(f"Débit                         : {throughput:.0f} événements/sec")
print(f"Latence moyenne par événement : {latency_per_event_ms:.4f} ms")

# =========================================================
# 3. TEMPS DE TRAITEMENT — latence bout-en-bout pipeline réel
# (collecte Wazuh -> normalisation -> extraction de features)
# =========================================================
print("\n--- 3. Temps de traitement (pipeline réel, données live) ---\n")

client = WazuhIndexerClient()

start = time.time()
raw_result = client.search_alerts(size=200)
collect_time = time.time() - start

hits = raw_result["hits"]["hits"]

start = time.time()
normalized = [normalize_alert(hit["_source"]) for hit in hits]
normalize_time = time.time() - start

start = time.time()
features_df = extract_features(normalized, window_minutes=5)
feature_time = time.time() - start

total_pipeline_time = collect_time + normalize_time + feature_time

print(f"Échantillons (alertes réelles)      : {len(hits)}")
print(f"Temps de collecte (requête Indexer) : {collect_time*1000:.1f} ms")
print(f"Temps de normalisation              : {normalize_time*1000:.1f} ms")
print(f"Temps d'extraction de features      : {feature_time*1000:.1f} ms")
print(f"Temps total (bout-en-bout)          : {total_pipeline_time*1000:.1f} ms")
print(f"Débit pipeline réel                 : {len(hits)/total_pipeline_time:.0f} événements/sec")

# =========================================================
# 4. PERTINENCE DE LA PRIORISATION
# (cohérence entre score de risque et tactique assignée)
# =========================================================
print("\n--- 4. Pertinence de la priorisation ---\n")

results_with_tactic = results[results["predicted_tactic"].notna()]
critical_with_tactic = (results_with_tactic["risk_band"] == "critical").sum()
total_critical = (results["risk_band"] == "critical").sum()

print(f"Alertes 'critical' générées                    : {total_critical}")
print(f"Alertes 'critical' avec tactique assignée      : {critical_with_tactic}")
print(f"Cohérence risque->tactique (% critical avec contexte) : "
      f"{critical_with_tactic/total_critical:.1%}" if total_critical else "N/A")

avg_confidence_critical = results_with_tactic[
    results_with_tactic["risk_band"] == "critical"
]["tactic_confidence"].mean()
print(f"Confiance moyenne de la tactique (cas critical) : {avg_confidence_critical:.2%}")

# =========================================================
# Sauvegarde du rapport consolidé
# =========================================================
report = {
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "detection_rate": round(detection_rate, 4),
    "false_positive_rate": round(false_positive_rate, 4),
    "ml_throughput_events_per_sec": round(throughput, 0),
    "ml_latency_ms_per_event": round(latency_per_event_ms, 4),
    "pipeline_e2e_latency_ms": round(total_pipeline_time * 1000, 1),
    "pipeline_throughput_events_per_sec": round(len(hits) / total_pipeline_time, 0) if total_pipeline_time > 0 else None,
    "pipeline_latency_sample_size": len(hits),
    "pipeline_latency_note": (
        "Mesure sur un seul run, echantillon de "
        f"{len(hits)} alertes live -- sensible aux conditions reseau/Indexer "
        "au moment de l'execution, pas une moyenne stabilisee sur plusieurs runs."
    ),
    "critical_alerts_count": int(total_critical),
    "critical_with_tactic_pct": round(critical_with_tactic / total_critical, 4) if total_critical else None,
    "avg_tactic_confidence_critical": round(float(avg_confidence_critical), 4) if not pd.isna(avg_confidence_critical) else None,
}

with open("data/validation_report.json", "w") as f:
    json.dump(report, f, indent=2)

print("\n" + "=" * 70)
print("Rapport sauvegardé dans data/validation_report.json")
print("=" * 70)
