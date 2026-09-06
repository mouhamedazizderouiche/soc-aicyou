"""
netflow_domain_shift.py

Compare, feature par feature, la distribution du jeu d'entraînement
(NF-CSE-CIC-IDS2018, banc CIC 2018, sondes nProbe) à celle du trafic réel
capturé sur cette VM (2026, sonde Suricata).

Diagnostic, pas décision : ce module n'entraîne ni ne prédit rien. Il
sert à EXPLIQUER le résultat du test de transfert, dans un sens comme
dans l'autre. Si le transfert échoue, il montre où ; s'il réussit, il
montre sur quelles features l'accord est réel plutôt que fortuit.

Deux écarts sont attendus par construction et à vérifier en premier :
  1. FLOW_DURATION_MILLISECONDS — Suricata clôt un flux TCP established
     après 600 s (suricata.yaml), nProbe applique ses propres délais.
     Une même session longue est donc découpée différemment.
  2. L7_PROTO — nDPI laisse 65,5% du jeu d'entraînement à 0 (« non
     identifié »), là où Suricata renseigne app_proto bien plus souvent.
"""

import argparse
import os

import numpy as np
import pandas as pd

from flow_feature_extractor import NETFLOW_V1_MODEL_COLUMNS

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "netflow")

QUANTILES = [0.01, 0.25, 0.50, 0.75, 0.95, 0.99]


def summarise(df: pd.DataFrame, name: str) -> pd.DataFrame:
    rows = {}
    for column in NETFLOW_V1_MODEL_COLUMNS:
        series = df[column].astype("float64")
        stats = {"moyenne": series.mean(), "écart-type": series.std()}
        for q in QUANTILES:
            stats[f"q{int(q * 100):02d}"] = series.quantile(q)
        stats["% à zéro"] = float((series == 0).mean() * 100)
        rows[column] = stats
    out = pd.DataFrame(rows).T
    out.columns = pd.MultiIndex.from_product([[name], out.columns])
    return out


def main():
    parser = argparse.ArgumentParser(description="Décalage de domaine entraînement / live.")
    parser.add_argument("--train-csv", default=os.path.join(DATA_DIR, "NF-CSE-CIC-IDS2018.csv"))
    parser.add_argument("--live-csv", default=os.path.join(DATA_DIR, "live_flows_labelled.csv"))
    parser.add_argument("--sample", type=int, default=2_000_000,
                        help="lignes du jeu d'entraînement à échantillonner (RAM)")
    args = parser.parse_args()

    usecols = NETFLOW_V1_MODEL_COLUMNS + ["Attack"]
    train = pd.read_csv(args.train_csv, usecols=usecols, nrows=args.sample)
    live = pd.read_csv(args.live_csv, usecols=usecols)

    print(f"Entraînement : {len(train)} lignes (échantillon de tête)")
    print(f"Live         : {len(live)} lignes\n")

    # --- Comparaison globale ------------------------------------------
    comparison = pd.concat([summarise(train, "CIC-2018"), summarise(live, "live-2026")], axis=1)
    pd.set_option("display.width", 200)
    print("=== Distribution par feature ===")
    for column in NETFLOW_V1_MODEL_COLUMNS:
        print(f"\n-- {column}")
        block = comparison.loc[column].unstack(level=0)
        print(block.to_string(float_format=lambda v: f"{v:,.2f}"))

    # --- Les deux écarts attendus, isolés ------------------------------
    print("\n\n=== Écart 1 : L7_PROTO non identifié ===")
    for name, df in (("CIC-2018", train), ("live-2026", live)):
        share = float((df["L7_PROTO"].astype("float64") == 0).mean())
        print(f"  {name:<10} L7_PROTO = 0 : {share:.1%}")
    print("  Un écart marqué signifie que le modèle voit, sur le trafic live,")
    print("  une valeur de L7_PROTO qu'il a rarement rencontrée à l'entraînement.")

    print("\n=== Écart 2 : durée de flux ===")
    for name, df in (("CIC-2018", train), ("live-2026", live)):
        d = df["FLOW_DURATION_MILLISECONDS"].astype("float64")
        over = float((d > 600_000).mean())
        print(f"  {name:<10} médiane={d.median():>12,.0f} ms   "
              f"q99={d.quantile(0.99):>12,.0f} ms   > 600 s : {over:.2%}")
    print("  Suricata plafonne les flux TCP established à 600 s ; toute masse")
    print("  au-delà côté CIC-2018 est structurellement inatteignable en live.")

    print("\n=== Écart 3 : TCP_FLAGS ===")
    for name, df in (("CIC-2018", train), ("live-2026", live)):
        top = df["TCP_FLAGS"].value_counts(normalize=True).head(6)
        print(f"  {name:<10} " + "  ".join(f"{int(k)}:{v:.1%}" for k, v in top.items()))

    print("\n=== Classes communes aux deux domaines ===")
    print(f"  CIC-2018  : {sorted(train['Attack'].unique())}")
    print(f"  live-2026 : {sorted(live['Attack'].unique())}")
    common = sorted(set(train["Attack"].unique()) & set(live["Attack"].unique()))
    only_live = sorted(set(live["Attack"].unique()) - set(train["Attack"].unique()))
    print(f"  communes  : {common}")
    print(f"  live seulement (aucune vérité apprenable) : {only_live}")


if __name__ == "__main__":
    main()
