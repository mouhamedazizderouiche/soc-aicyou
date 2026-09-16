"""
dashboard.py

Tableau de bord SOC interactif :
- Cartes de risque cliquables (filtrage automatique du tableau)
- Sélection de ligne -> panneau de détail complet (drill-down)
- Recherche libre, export CSV, timeline cliquable, auto-refresh

Lancement : streamlit run dashboard.py
"""

import json
import os
import time
from datetime import datetime
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from wazuh_client import WazuhIndexerClient
from normalizer import normalize_batch
from analysis_engine import AnalysisEngine
from preprocess import preprocess

TRIAGE_LOG_PATH = os.path.join(os.path.dirname(__file__), "data", "triage_log.json")


def load_triage_log() -> dict:
    """Charge l'état de triage persistant (Nouveau/Investigation/FP/Confirmé)."""
    if os.path.exists(TRIAGE_LOG_PATH):
        with open(TRIAGE_LOG_PATH) as f:
            return json.load(f)
    return {}


def save_triage_log(log: dict) -> None:
    os.makedirs(os.path.dirname(TRIAGE_LOG_PATH), exist_ok=True)
    with open(TRIAGE_LOG_PATH, "w") as f:
        json.dump(log, f, indent=2)

st.set_page_config(
    page_title="SOC AICYOU — Moteur de Détection Intelligent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

    /* ===== Base ===== */
    #MainMenu, footer, header {visibility: hidden;}
    .stApp { background: radial-gradient(1400px 700px at 15% -10%, #101826 0%, #0a0e15 60%); }
    html, body, [class*="css"], .stMarkdown, p, span, div { font-family: 'Inter', 'Segoe UI', system-ui, sans-serif; }
    .main .block-container { padding-top: 1.4rem; padding-bottom: 2rem; max-width: 100%; }

    h1,h2,h3,h4 { color:#f1f5f9 !important; font-weight:700 !important; letter-spacing:-0.4px; }
    .soc-subtitle { color:#64748b; font-size:14px; margin-top:-6px; margin-bottom:10px; }

    /* ===== Header horizontal ===== */
    .soc-header {
        display:flex; align-items:center; justify-content:space-between;
        background: linear-gradient(90deg, #121a26 0%, #0d1119 100%);
        border:1px solid #1e2634; border-radius:16px;
        padding:18px 26px; margin-bottom:22px;
        box-shadow: 0 6px 24px rgba(0,0,0,0.35);
    }
    .soc-header-title { font-size:22px; font-weight:800; color:#f1f5f9; }
    .soc-header-sub   { font-size:12px; color:#64748b; margin-top:2px; }
    .soc-status {
        display:inline-flex; align-items:center; gap:8px;
        background:#0f2a1a; border:1px solid #1e5f3a; color:#4ade80;
        padding:7px 16px; border-radius:22px; font-size:12px; font-weight:600;
    }
    .soc-chip {
        display:inline-flex; align-items:center; gap:8px;
        border:1px solid #1e2634; color:#94a3b8;
        padding:7px 16px; border-radius:22px; font-size:12px;
    }

    /* ===== Cartes metriques ===== */
    div[data-testid="stMetric"] {
        background: linear-gradient(145deg, #151b26, #0f141d);
        border: 1px solid #1e2634; border-radius: 14px; padding: 16px 18px;
        box-shadow: 0 4px 18px rgba(0,0,0,0.30);
    }
    div[data-testid="stMetricLabel"] { font-size: 12px; color:#64748b; }
    div[data-testid="stMetricValue"] { font-size: 26px; font-weight:800; color:#f1f5f9; }

    /* ===== Badges ===== */
    .badge { display:inline-block; padding:3px 12px; border-radius:20px;
             font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:0.5px; }
    .badge-critical { background:#3d1216; color:#ff5c5c; border:1px solid #ff5c5c66; }
    .badge-high     { background:#3d2612; color:#ff9d42; border:1px solid #ff9d4266; }
    .badge-medium   { background:#3d3512; color:#ffd166; border:1px solid #ffd16666; }
    .badge-low      { background:#0f3d24; color:#06d6a0; border:1px solid #06d6a066; }

    /* ===== SIDEBAR ===== */
    section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0d1119 0%, #090c12 100%);
        border-right:1px solid #1a2230; width: 260px !important;
    }
    section[data-testid="stSidebar"] .block-container { padding-top: 1.6rem; }

    /* Nav radio -> items de menu avec fond, coins arrondis, etat actif */
    section[data-testid="stSidebar"] div[role="radiogroup"] { gap:4px; }
    section[data-testid="stSidebar"] div[role="radiogroup"] > label {
        display:flex; align-items:center; width:100%;
        padding:11px 16px; margin:2px 0; border-radius:11px;
        cursor:pointer; transition:all 0.15s ease;
        border:1px solid transparent; color:#94a3b8; font-weight:500;
    }
    section[data-testid="stSidebar"] div[role="radiogroup"] > label:hover {
        background:#141c28; color:#e2e8f0;
    }
    /* Masquer le petit rond radio, garder juste le texte-item */
    section[data-testid="stSidebar"] div[role="radiogroup"] > label > div:first-child { display:none; }
    /* Item selectionne (Streamlit met aria-checked) */
    section[data-testid="stSidebar"] div[role="radiogroup"] > label:has(input:checked) {
        background: linear-gradient(90deg, #1d4ed8 0%, #1e40af 100%);
        color:#ffffff; border-color:#2563eb;
        box-shadow: 0 4px 14px rgba(37,99,235,0.35);
    }

    /* ===== Boutons ===== */
    div[data-testid="stButton"] > button {
        width:100%; border-radius:12px; padding:16px 12px;
        border:1px solid #1e2634; background:linear-gradient(145deg,#151b26,#0f141d);
        color:#e2e8f0; font-weight:600; transition:all 0.18s ease;
    }
    div[data-testid="stButton"] > button:hover {
        border-color:#3b82f6; transform:translateY(-2px);
        box-shadow:0 6px 20px rgba(59,130,246,0.15);
    }

    /* ===== Tableaux ===== */
    div[data-testid="stDataFrame"] { border-radius:12px; overflow:hidden; border:1px solid #1e2634; }

    /* ===== Dot pulsante ===== */
    @keyframes pulse { 0%{opacity:1;} 50%{opacity:0.35;} 100%{opacity:1;} }
    .live-dot { display:inline-block; width:8px; height:8px; border-radius:50%;
        background:#4ade80; animation:pulse 1.4s infinite; margin-right:6px;
        box-shadow:0 0 8px #4ade80; }
</style>
""", unsafe_allow_html=True)

RISK_COLORS = {"critical": "#ff5c5c", "high": "#ff9d42", "medium": "#ffd166", "low": "#06d6a0"}
RISK_ICONS = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}


# ============================================================
# Chargement des données
# ============================================================
@st.cache_resource
def get_engine():
    return AnalysisEngine()


@st.cache_data(ttl=60)
def load_validation_report():
    path = "data/validation_report.json"
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return None
@st.cache_data(ttl=60)
def load_tactic_report():
    path = "data/tactic_classifier_report.json"
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return None

@st.cache_data(ttl=30)
def load_live_alerts(size: int = 300):
    client = WazuhIndexerClient()
    result = client.search_alerts(size=size)
    hits = result["hits"]["hits"]
    normalized = normalize_batch(hits)
    return pd.DataFrame(normalized), result["hits"]["total"]["value"]


def risk_badge(band: str) -> str:
    return f'<span class="badge badge-{band}">{band}</span>'


# Assigner une bande de risque approximative aux alertes live (proxy sur rule_level,
# car ces alertes réelles n'ont pas encore été scorées par le modèle NSL-KDD)
def level_to_band(level):
    if pd.isna(level):
        return "low"
    if level >= 12:
        return "critical"
    if level >= 8:
        return "high"
    if level >= 5:
        return "medium"
    return "low"


def extract_alert_id(raw) -> str:
    """Extrait l'identifiant unique Wazuh depuis le champ raw, pour le triage."""
    if isinstance(raw, dict):
        return str(raw.get("id", ""))
    return ""


def generate_ai_summary(alerts_df: pd.DataFrame) -> dict:
    """
    Génère un résumé en langage naturel à partir des vraies statistiques
    du jour — pas d'appel LLM, uniquement des templates sur données réelles,
    pour rester honnête sur ce que le système observe effectivement.
    """
    if alerts_df.empty:
        return {"level": "low", "text": "Aucune activité récente à analyser.",
                "recommendation": "Aucune action requise.", "top_ip": None, "top_rule": None}

    critical_count = (alerts_df["risk_band"] == "critical").sum()
    high_count = (alerts_df["risk_band"] == "high").sum()
    total = len(alerts_df)

    top_ip_series = alerts_df["src_ip"].dropna().value_counts()
    top_ip = top_ip_series.index[0] if not top_ip_series.empty else None
    top_ip_count = int(top_ip_series.iloc[0]) if not top_ip_series.empty else 0

    top_rule_series = alerts_df["rule_description"].dropna().value_counts()
    top_rule = top_rule_series.index[0] if not top_rule_series.empty else None

    # Détection d'un pattern de scan connu (nos règles custom, sid 9000001/9000002)
    # -> permet une recommandation plus précise que le niveau seul.
    scan_pattern = alerts_df["rule_description"].fillna("").str.contains(
        "port scan", case=False
    ).any()

    if critical_count > 5:
        level = "critical"
        text = (f"{critical_count} alertes critiques détectées sur {total} événements analysés. "
                f"Source la plus active : {top_ip} ({top_ip_count} occurrences). "
                f"Règle la plus déclenchée : \"{top_rule}\".")
        recommendation = (
            f"Investigation immédiate sous 15 min recommandée sur {top_ip}. "
            "Vérifier si le trafic est légitime (whois/reverse DNS) avant tout blocage. "
            "Voir le playbook de réponse aux incidents, section correspondant à la tactique dominante."
        )
    elif scan_pattern and (critical_count > 0 or high_count > 0):
        level = "high"
        text = (f"Activité de sondage réseau détectée depuis {top_ip} ({top_ip_count} occurrences). "
                f"{critical_count} alerte(s) critique(s), {high_count} de niveau élevé.")
        recommendation = (
            f"Reconnaissance probable (procédure Reconnaissance / TA0043) : documenter {top_ip}, "
            "vérifier si la source est interne connue ou externe. Surveiller les 24h suivantes pour "
            "une éventuelle escalade vers une tentative d'exploitation."
        )
    elif critical_count > 0 or high_count > 3:
        level = "high"
        text = (f"{critical_count} alerte(s) critique(s) et {high_count} de niveau élevé sur {total} événements. "
                f"Source la plus active : {top_ip} ({top_ip_count} occurrences).")
        recommendation = f"Vérification manuelle recommandée sous 24h ouvrées pour {top_ip}."
    else:
        level = "low"
        text = (f"Activité nominale — {total} événements analysés, aucun signal critique dominant. "
                f"Source la plus active : {top_ip or 'N/A'} ({top_ip_count} occurrences), "
                f"cohérente avec du trafic de fond habituel.")
        recommendation = "Surveillance de routine — aucune action immédiate requise."

    return {"level": level, "text": text, "recommendation": recommendation,
            "top_ip": top_ip, "top_rule": top_rule}


# ============================================================
# État de session (filtres persistants entre interactions)
# ============================================================
if "active_band_filter" not in st.session_state:
    st.session_state.active_band_filter = None
if "selected_alert_idx" not in st.session_state:
    st.session_state.selected_alert_idx = None


# ============================================================
# Sidebar
# ============================================================
with st.sidebar:
    st.markdown("### 🛡️ SOC AICYOU")
    st.caption("Moteur intelligent de détection d'intrusions")
    st.divider()
    page = st.radio(
        "Navigation",
        ["📊 Vue d'ensemble", "🔴 Alertes en direct", "🗺️ Carte MITRE ATT&CK", "🧠 Moteur d'analyse"],
        label_visibility="collapsed",
    )
    st.divider()
    auto_refresh = st.checkbox("🔄 Actualisation auto (30s)", value=False)
    if auto_refresh:
        st.caption("Actualisation active — la page se recharge automatiquement.")
    st.divider()
    st.caption("**Stagiaire** : Mouhamed Aziz Derouiche")
    st.caption("**Encadrant** : Dr. Alaidine Ben Ayed")
    st.caption("**Organisme** : Stratégie AICYOU Inc.")

report = load_validation_report()

# ============================================================
# PAGE 1 — Vue d'ensemble
# ============================================================
if page == "📊 Vue d'ensemble":
    from datetime import timezone
    _now = datetime.now(timezone.utc).strftime("%d/%m/%Y  %H:%M UTC")
    st.markdown(f"""
    <div class="soc-header">
        <div>
            <div class="soc-header-title">SOC AICYOU</div>
            <div class="soc-header-sub">Moteur intelligent de détection d'intrusions</div>
        </div>
        <div style="display:flex; align-items:center; gap:12px;">
            <span class="soc-status"><span class="live-dot"></span> Système actif</span>
            <span class="soc-chip">🕐 {_now}</span>
        </div>
    </div>
    """, unsafe_allow_html=True)
    st.write("")
    if report:
        # --- Rangee de 7 cartes metriques, style maquette ---
        conf = report.get('avg_tactic_confidence_critical')
        cards = [
            ("Taux de detection",         f"{report['detection_rate']:.1%}",                "#3b82f6"),
            ("Taux de faux positifs",     f"{report['false_positive_rate']:.1%}",           "#ef4444"),
            ("Debit moteur ML",           f"{report['ml_throughput_events_per_sec']:,.0f}", "#06b6d4"),
            ("Confiance tactique",        f"{conf:.1%}" if conf else "N/A",                 "#8b5cf6"),
            ("Latence pipeline",          f"{report.get('pipeline_e2e_latency_ms', 0):.0f} ms", "#f59e0b"),
            ("Alertes critiques",         f"{report.get('critical_alerts_count', 0):,}",    "#ec4899"),
            ("Coherence risque->tactique",f"{report.get('critical_with_tactic_pct', 0):.0%}", "#10b981"),
        ]
        cols = st.columns(len(cards))
        for col, (label, value, color) in zip(cols, cards):
            col.markdown(f"""
            <div style="background:linear-gradient(145deg,#161a23,#12151d);
                        border:1px solid #232733;border-top:2px solid {color};
                        border-radius:12px;padding:16px 14px;height:110px;">
                <div style="font-size:12px;color:#8b93a7;line-height:1.3;
                            margin-bottom:8px;min-height:32px;">{label}</div>
                <div style="font-size:26px;font-weight:800;color:#e6e6e6;">{value}</div>
            </div>
            """, unsafe_allow_html=True)

        st.write("")
        generated_at_raw = report.get("generated_at")
        try:
            generated_label = datetime.fromisoformat(generated_at_raw).strftime("%d/%m/%Y a %H:%M UTC")
        except (ValueError, TypeError):
            generated_label = "date inconnue"
        st.caption(
            f"Instantane du {generated_label} -- metriques du modele sur jeu de validation, "
            "pas une mesure temps reel."
        )
    else:
        st.warning("Metriques de validation indisponibles.")


    # ============================================================
    # Rangee du milieu : activite dans le temps + repartition source
    # ============================================================
    st.write("")
    try:
        _alerts_mid, _total_mid = load_live_alerts(size=500)
        col_g, col_d = st.columns([2, 1])

        with col_g:
            st.markdown("#### Activite des alertes")
            _df = _alerts_mid.copy()
            _df["ts"] = pd.to_datetime(_df["timestamp"], errors="coerce", utc=True)
            _df = _df.dropna(subset=["ts"])
            if not _df.empty:
                serie = _df.set_index("ts").resample("30min").size().reset_index(name="alertes")
                fig = px.area(serie, x="ts", y="alertes")
                fig.update_traces(line_color="#3b82f6", fillcolor="rgba(59,130,246,0.18)")
                fig.update_layout(
                    height=300, margin=dict(l=10, r=10, t=10, b=10),
                    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                    font_color="#8b93a7", xaxis_title=None, yaxis_title=None,
                    xaxis=dict(gridcolor="#1e222c"), yaxis=dict(gridcolor="#1e222c"),
                )
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("Pas de donnees temporelles exploitables.")

        with col_d:
            st.markdown("#### Repartition par source")
            if "source_type" in _alerts_mid.columns and not _alerts_mid.empty:
                src = _alerts_mid["source_type"].fillna("Inconnu").value_counts().reset_index()
                src.columns = ["source", "count"]
                fig2 = go.Figure(data=[go.Pie(
                    labels=src["source"], values=src["count"], hole=0.6,
                    marker=dict(colors=["#3b82f6", "#06b6d4", "#8b5cf6", "#64748b"]),
                )])
                fig2.update_layout(
                    height=300, margin=dict(l=10, r=10, t=10, b=10),
                    paper_bgcolor="rgba(0,0,0,0)", font_color="#8b93a7",
                    showlegend=True, legend=dict(orientation="v", x=1, y=0.5),
                    annotations=[dict(text=f"{len(_alerts_mid)}<br>alertes",
                                      x=0.5, y=0.5, font_size=16, showarrow=False,
                                      font_color="#e6e6e6")],
                )
                st.plotly_chart(fig2, use_container_width=True)
            else:
                st.info("Source indisponible.")

        # --- Top attaquants (vraies IP sources) ---
        st.markdown("#### Top attaquants")
        ip_col = "src_ip" if "src_ip" in _alerts_mid.columns else None
        if ip_col:
            top = _alerts_mid[ip_col].dropna().value_counts().head(5).reset_index()
            top.columns = ["IP source", "Occurrences"]
            st.dataframe(top, use_container_width=True, hide_index=True)
        else:
            st.info("IP sources indisponibles.")
    except Exception as e:
        st.info(f"Section activite indisponible ({e})")

    st.write("")
    st.markdown("#### 🤖 Résumé automatique")
    try:
        _alerts_preview, _ = load_live_alerts(size=300)
        _alerts_preview["risk_band"] = _alerts_preview["rule_level"].apply(level_to_band)
        summary = generate_ai_summary(_alerts_preview)
        band_color = RISK_COLORS.get(summary["level"], "#8b93a7")
        st.markdown(f"""
        <div style="background:linear-gradient(145deg,#161a23,#12151d);border:1px solid #232733;
                    border-left:4px solid {band_color}; border-radius:10px; padding:18px 20px;">
            <div style="font-size:12px;color:#8b93a7;text-transform:uppercase;letter-spacing:1px;">
                Niveau de menace estimé
            </div>
            <div style="font-size:22px;font-weight:800;color:{band_color};margin:4px 0 10px 0;">
                {summary['level'].upper()}
            </div>
            <div style="color:#c9cfdb;font-size:14px;line-height:1.5;margin-bottom:12px;">{summary['text']}</div>
            <div style="border-top:1px solid #232733;padding-top:10px;">
                <div style="font-size:11px;color:#8b93a7;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px;">
                    Recommandation
                </div>
                <div style="color:#e6e6e6;font-size:14px;line-height:1.5;">💡 {summary['recommendation']}</div>
            </div>
        </div>
        """, unsafe_allow_html=True)
    except Exception as e:
        st.info(f"Résumé indisponible pour le moment ({e})")

    st.write("")
    st.markdown("#### Répartition MITRE ATT&CK")
    st.markdown('<p class="soc-subtitle">Tactiques réellement détectées dans le trafic récent</p>', unsafe_allow_html=True)
    try:
        _alerts_mitre, _ = load_live_alerts(size=500)
        # mitre_tactics peut être une liste ou une chaîne selon la normalisation
        from collections import Counter
        tac_counter = Counter()
        if "mitre_tactics" in _alerts_mitre.columns:
            for val in _alerts_mitre["mitre_tactics"].dropna():
                if isinstance(val, (list, tuple)):
                    for t in val:
                        if t:
                            tac_counter[str(t)] += 1
                elif isinstance(val, str) and val.strip():
                    for t in val.split(","):
                        t = t.strip()
                        if t:
                            tac_counter[t] += 1

        if tac_counter:
            total_tac = sum(tac_counter.values())
            palette = ["#ef4444", "#f59e0b", "#8b5cf6", "#06b6d4", "#10b981", "#ec4899"]
            rows_html = ""
            for i, (tac, cnt) in enumerate(tac_counter.most_common()):
                pct = cnt / total_tac * 100
                color = palette[i % len(palette)]
                rows_html += f'''
                <div style="display:flex;align-items:center;margin-bottom:10px;">
                    <div style="width:230px;color:#c9cfdb;font-size:13px;">{tac}</div>
                    <div style="flex:1;background:#1e222c;border-radius:6px;height:14px;overflow:hidden;">
                        <div style="width:{pct:.0f}%;background:{color};height:14px;"></div>
                    </div>
                    <div style="width:55px;text-align:right;color:#8b93a7;font-size:13px;">{pct:.0f}%</div>
                </div>'''
            st.markdown(f'''<div style="background:linear-gradient(145deg,#161a23,#12151d);
                        border:1px solid #232733;border-radius:12px;padding:18px 20px;">{rows_html}</div>''',
                        unsafe_allow_html=True)
            st.caption(f"{len(tac_counter)} tactique(s) MITRE ATT&CK détectée(s) sur {total_tac} alerte(s) taguée(s).")
        else:
            st.info("Aucune tactique MITRE ATT&CK dans les alertes récentes.")
    except Exception as e:
        st.info(f"Répartition MITRE indisponible ({e})")

    st.divider()
    st.markdown("#### Architecture de détection en profondeur")
    col_a, col_b, col_c = st.columns(3)
    with col_a:
        st.info("**Couche 1 — Signatures**\n\nRuleset Suricata natif (40 000+ règles), détection de menaces connues (CVE, malware, exploits).")
    with col_b:
        st.info("**Couche 2 — Comportementale**\n\nRègles Suricata custom, indépendantes de l'outil (seuils de connexion), détection de scans/reconnaissance.")
    with col_c:
        st.info("**Couche 3 — Intelligence Artificielle**\n\nXGBoost (score de risque) + classification multi-classe (tactique MITRE ATT&CK), généralisation à l'inconnu.")

# ============================================================
# PAGE 2 — Alertes en direct (INTERACTIF : cartes cliquables + drill-down)
# ============================================================
elif page == "🔴 Alertes en direct":
    st.markdown('<span class="live-dot"></span> **Flux en direct**', unsafe_allow_html=True)
    st.markdown("## Alertes en direct")
    st.markdown('<p class="soc-subtitle">Cliquez sur une carte pour filtrer, sur une ligne pour le détail</p>', unsafe_allow_html=True)
    st.write("")

    with st.spinner("Chargement des alertes..."):
        try:
            alerts_df, total_alerts = load_live_alerts()
            # --- Branchement du modele IA flux-locaux (repli level_to_band par ligne) ---
            from live_flow_scoring import score_alerts
            _scoring = score_alerts(alerts_df, base_dir=".")
            alerts_df["risk_band"] = _scoring["risk_band"]
            alerts_df["risk_score"] = _scoring["risk_score"]
            alerts_df["predicted_tactic"] = _scoring["predicted_tactic"]
            alerts_df["band_source"] = _scoring["band_source"]
            _scoring_meta = _scoring["meta"]
            alerts_df["alert_id"] = alerts_df["raw"].apply(extract_alert_id)
            st.caption(f"{total_alerts:,} alertes indexées au total — {len(alerts_df)} plus récentes chargées")
            _m = _scoring_meta
            if _m["method"] == "model+fallback":
                st.markdown(
                    f'<div style="background:#0f1a2e;border:1px solid #1e3a5f;border-radius:10px;'
                    f'padding:10px 16px;margin:8px 0;font-size:13px;color:#93c5fd;">'
                    f'\U0001F9E0 Bandes de risque calculées par le <b>modèle IA flux-locaux</b> : '
                    f'{_m["n_model"]} alerte(s) scorée(s) par le modèle, {_m["n_fallback"]} en repli sévérité.'
                    f'</div>', unsafe_allow_html=True)
            else:
                st.markdown(
                    f'<div style="background:#2a1e0f;border:1px solid #5f4a1e;border-radius:10px;'
                    f'padding:10px 16px;margin:8px 0;font-size:13px;color:#fbbf24;">'
                    f'\u26A0\uFE0F Bandes de risque en repli sévérité (modèle indisponible : {_m["reason"]}).'
                    f'</div>', unsafe_allow_html=True)
        except Exception as e:
            st.error(f"Connexion à l'Indexer impossible : {e}")
            alerts_df = pd.DataFrame()

    if not alerts_df.empty:
        # --- Top Offenders : premier réflexe de triage avant d'ouvrir une seule alerte ---
        st.markdown("#### 🎯 Top Offenders")
        to1, to2 = st.columns(2)
        with to1:
            top_ips = alerts_df["src_ip"].dropna().value_counts().head(5).reset_index()
            top_ips.columns = ["Source IP", "Occurrences"]
            st.dataframe(top_ips, use_container_width=True, hide_index=True, height=200)
        with to2:
            top_rules = alerts_df["rule_description"].dropna().value_counts().head(5).reset_index()
            top_rules.columns = ["Règle déclenchée", "Occurrences"]
            st.dataframe(top_rules, use_container_width=True, hide_index=True, height=200)
        st.write("")

        # --- Cartes cliquables : filtrent automatiquement le tableau ---
        band_counts = alerts_df["risk_band"].value_counts().to_dict()
        cols = st.columns(4)
        for col, band in zip(cols, ["critical", "high", "medium", "low"]):
            count = band_counts.get(band, 0)
            is_active = st.session_state.active_band_filter == band
            label = f"{RISK_ICONS[band]}  {band.upper()}\n\n{count} alertes"
            with col:
                if st.button(label, key=f"card_{band}", use_container_width=True):
                    st.session_state.active_band_filter = None if is_active else band
                    st.rerun()

        if st.session_state.active_band_filter:
            st.success(f"Filtre actif : **{st.session_state.active_band_filter.upper()}** "
                       f"— cliquez à nouveau sur la carte pour le retirer.")

        # --- Filtres additionnels ---
        # NOTE: chaque widget a une key= explicite - sans cela, Streamlit
        # peut conserver un ancien etat (ex: selection vide) au lieu de
        # reappliquer default= apres une navigation entre pages, ce qui
        # causait le bug "0 alertes" observe precedemment.
        reset_col, _ = st.columns([1, 5])
        with reset_col:
            if st.button("\U0001F504 R\u00e9initialiser les filtres"):
                for k in ["flt_source", "flt_agent", "flt_rule", "flt_level", "flt_search"]:
                    st.session_state.pop(k, None)
                st.rerun()

        f1, f2, f3 = st.columns(3)
        with f1:
            source_filter = st.multiselect(
                "Source", alerts_df["source_type"].unique(),
                default=list(alerts_df["source_type"].unique()), key="flt_source",
            )
        with f2:
            agent_filter = st.multiselect(
                "Agent", alerts_df["agent_name"].dropna().unique(),
                default=list(alerts_df["agent_name"].dropna().unique()), key="flt_agent",
            )
        with f3:
            search_text = st.text_input("\U0001F50D Recherche (IP, description...)", "", key="flt_search")

        NOISY_RULES_DEFAULT = ["Suricata: Alert - SURICATA QUIC failed decrypt"]
        all_rules = sorted(alerts_df["rule_description"].dropna().unique())
        default_rules = [r for r in all_rules if r not in NOISY_RULES_DEFAULT]

        f4, f5 = st.columns([2, 1])
        with f4:
            rule_filter = st.multiselect(
                "R\u00e8gle d\u00e9clench\u00e9e (bruit connu exclu par d\u00e9faut)",
                all_rules, default=default_rules, key="flt_rule",
            )
        with f5:
            level_range = st.slider(
                "Plage de niveau de r\u00e8gle", 0, 15, (0, 15), key="flt_level",
            )

        # --- Application des filtres ---
        # Garde-fou : un multiselect vide ne doit jamais filtrer -> tout
        # exclure silencieusement ; on retombe sur "tout" dans ce cas.
        effective_source = source_filter if source_filter else list(alerts_df["source_type"].unique())
        effective_agent = agent_filter if agent_filter else list(alerts_df["agent_name"].dropna().unique())
        effective_rule = rule_filter if rule_filter else all_rules

        filtered = alerts_df[
            alerts_df["source_type"].isin(effective_source)
            & alerts_df["agent_name"].isin(effective_agent)
            & alerts_df["rule_description"].isin(effective_rule)
            & alerts_df["rule_level"].fillna(0).between(level_range[0], level_range[1])
        ]
        if st.session_state.active_band_filter:
            filtered = filtered[filtered["risk_band"] == st.session_state.active_band_filter]
        if search_text:
            mask = (
                filtered["rule_description"].fillna("").str.contains(search_text, case=False)
                | filtered["src_ip"].fillna("").str.contains(search_text, case=False)
                | filtered["dest_ip"].fillna("").str.contains(search_text, case=False)
            )
            filtered = filtered[mask]
        st.caption(f"**{len(filtered)}** alertes correspondent aux filtres actifs "
                   f"(sur {len(alerts_df)} charg\u00e9es)")

    # --- Tableau avec sélection de ligne (drill-down) ---
    display_cols = ["timestamp", "risk_band", "agent_name", "source_type",
                     "rule_description", "rule_level", "src_ip", "dest_ip", "dest_port"]
    display_df = filtered[display_cols + ["alert_id"]].sort_values(
        "timestamp", ascending=False
    ).reset_index(drop=True)

    event = st.dataframe(
        display_df,
        use_container_width=True, height=340,
        on_select="rerun", selection_mode="single-row",
        column_order=display_cols,  # alert_id reste dans les données, caché à l'affichage
    )

    # --- Panneau de détail (drill-down au clic sur une ligne) ---
    if event.selection and event.selection.get("rows"):
        sel_idx = event.selection["rows"][0]
        row = display_df.iloc[sel_idx]

        with st.expander("🔎 Détail de l'alerte sélectionnée", expanded=True):
            dc1, dc2, dc3 = st.columns(3)
            dc1.markdown(f"**Horodatage**\n\n{row['timestamp']}")
            dc1.markdown(f"**Bande de risque**\n\n{risk_badge(row['risk_band'])}", unsafe_allow_html=True)
            dc2.markdown(f"**Agent**\n\n{row['agent_name']}")
            dc2.markdown(f"**Source**\n\n{row['source_type']}")
            dc3.markdown(f"**IP source → destination**\n\n{row['src_ip']} → {row['dest_ip']}:{row['dest_port']}")
            dc3.markdown(f"**Niveau de règle**\n\n{row['rule_level']}")
            st.markdown(f"**Description**\n\n{row['rule_description']}")

            st.divider()

            # --- Workflow de triage (persistant, comme un vrai poste analyste) ---
            st.markdown("**Statut de triage**")
            triage_log = load_triage_log()
            current_status = triage_log.get(row["alert_id"], {}).get("status", "Nouveau")
            st.caption(f"Statut actuel : **{current_status}**")

            tcol1, tcol2, tcol3, tcol4 = st.columns(4)
            status_map = {
                tcol1: "Nouveau", tcol2: "En investigation",
                tcol3: "Faux positif", tcol4: "Confirmé",
            }
            for col, status in status_map.items():
                with col:
                    if st.button(status, key=f"triage_{row['alert_id']}_{status}",
                                 use_container_width=True,
                                 type="primary" if current_status == status else "secondary"):
                        triage_log[row["alert_id"]] = {
                            "status": status,
                            "updated_at": pd.Timestamp.utcnow().isoformat(),
                        }
                        save_triage_log(triage_log)
                        st.rerun()

            st.divider()

            # --- Corrélation par entité : que fait cette IP ailleurs ? ---
            st.markdown(f"**🔗 Activité corrélée pour `{row['src_ip']}`**")
            if row["src_ip"]:
                related = alerts_df[alerts_df["src_ip"] == row["src_ip"]]
                st.caption(f"{len(related)} événement(s) de cette source dans la fenêtre chargée")
                if len(related) > 1:
                    related_display = related[["timestamp", "rule_description", "dest_ip", "dest_port"]] \
                        .sort_values("timestamp", ascending=False).head(10)
                    st.dataframe(related_display, use_container_width=True, hide_index=True, height=180)
            else:
                st.caption("Pas d'IP source disponible pour cette alerte.")

        # --- Export CSV ---
        csv = filtered[display_cols].to_csv(index=False).encode("utf-8")
        st.download_button("⬇️ Exporter en CSV", csv, "alertes_soc.csv", "text/csv")

        st.divider()

        # --- Timeline + répartitions ---
        col_t1, col_t2 = st.columns([2, 1])
        with col_t1:
            timeline = filtered.copy()
            timeline["timestamp"] = pd.to_datetime(timeline["timestamp"], errors="coerce")
            timeline_counts = timeline.set_index("timestamp").resample("1min").size().reset_index(name="count")
            fig_t = px.area(timeline_counts, x="timestamp", y="count", title="Activité dans le temps")
            fig_t.update_traces(line_color="#ff5c5c", fillcolor="rgba(255,92,92,0.15)")
            fig_t.update_layout(paper_bgcolor="#0b0e14", plot_bgcolor="#0b0e14", font_color="#e6e6e6", height=280)
            st.plotly_chart(fig_t, use_container_width=True)

        with col_t2:
            bc = filtered["risk_band"].value_counts().reset_index()
            bc.columns = ["risk_band", "count"]
            fig_b = go.Figure(data=[go.Pie(
                labels=bc["risk_band"], values=bc["count"],
                marker_colors=[RISK_COLORS.get(b, "#888") for b in bc["risk_band"]], hole=0.5,
            )])
            fig_b.update_layout(title="Par bande de risque", paper_bgcolor="#0b0e14",
                                 font_color="#e6e6e6", height=280, showlegend=True)
            st.plotly_chart(fig_b, use_container_width=True)
    else:
        st.info("Aucune alerte disponible.")

# ============================================================
# PAGE 3 — Carte MITRE ATT&CK
# ============================================================
elif page == "🗺️ Carte MITRE ATT&CK":
    st.markdown("## Cartographie MITRE ATT&CK")
    st.markdown('<p class="soc-subtitle">Tactiques couvertes par le moteur de classification</p>', unsafe_allow_html=True)
    st.write("")

    TACTIC_DESCRIPTIONS_STATIC = {
        "Impact": {"id": "TA0040", "desc": "Perturbation de disponibilité (DoS)"},
        "Reconnaissance": {"id": "TA0043", "desc": "Sondage / collecte d'information"},
        "InitialAccess_CredentialAccess": {"id": "TA0001/TA0006", "desc": "Accès non autorisé / vol d'identifiants"},
        "PrivilegeEscalation": {"id": "TA0004", "desc": "Élévation de privilèges"},
    }

    tactic_report = load_tactic_report()

    if tactic_report:
        tactic_info = {
            tactic: {
                "id": TACTIC_DESCRIPTIONS_STATIC[tactic]["id"],
                "desc": TACTIC_DESCRIPTIONS_STATIC[tactic]["desc"],
                "f1": tactic_report["per_tactic"][tactic]["f1_score"],
            }
            for tactic in TACTIC_DESCRIPTIONS_STATIC
            if tactic in tactic_report.get("per_tactic", {})
        }

        try:
            generated_dt = datetime.fromisoformat(tactic_report["generated_at"])
            generated_label = generated_dt.strftime("%d/%m/%Y à %H:%M UTC")
        except (ValueError, TypeError, KeyError):
            generated_label = tactic_report.get("generated_at", "date inconnue")

        coverage = tactic_report.get("attack_type_coverage", {})
        st.caption(
            f"📸 Métriques générées le **{generated_label}** — "
            f"{coverage.get('total_types_mapped', '?')} types d'attaque NSL-KDD couverts. "
            "Métriques issues de la dernière validation du modèle."
        )
    else:
        # Repli sur les valeurs figées si le rapport n'existe pas encore
        # (ex: avant la première exécution de tactic_classifier_smote.py)
        tactic_info = {
            "Impact": {"id": "TA0040", "desc": "Perturbation de disponibilité (DoS)", "f1": 1.00},
            "Reconnaissance": {"id": "TA0043", "desc": "Sondage / collecte d'information", "f1": 0.91},
            "InitialAccess_CredentialAccess": {"id": "TA0001/TA0006", "desc": "Accès non autorisé / vol d'identifiants", "f1": 0.75},
            "PrivilegeEscalation": {"id": "TA0004", "desc": "Élévation de privilèges", "f1": 0.14},
        }
        st.warning("Métriques du modèle indisponibles — valeurs de référence affichées.")

    cols = st.columns(4)
    for col, (tactic, info) in zip(cols, tactic_info.items()):
        with col:
            color = "#06d6a0" if info["f1"] >= 0.8 else "#ffd166" if info["f1"] >= 0.5 else "#ff5c5c"
            st.markdown(f"""
            <div style="background:#161a23;border:1px solid #232733;border-radius:10px;padding:16px;height:190px;">
                <div style="color:#8b93a7;font-size:12px;">{info['id']}</div>
                <div style="font-weight:700;font-size:15px;margin:6px 0;">{tactic.replace('_', ' / ')}</div>
                <div style="color:#8b93a7;font-size:12px;margin-bottom:10px;">{info['desc']}</div>
                <div style="color:{color};font-size:22px;font-weight:700;">F1 = {info['f1']:.2f}</div>
                <div style="color:#8b93a7;font-size:11px;">performance du modèle</div>
            </div>
            """, unsafe_allow_html=True)

    st.write("")
    pe_precision = tactic_info.get("PrivilegeEscalation", {}).get("f1")
    pe_note = f" (F1 = {pe_precision:.2f})" if pe_precision is not None else ""
    st.warning(f"⚠️ **PrivilegeEscalation** reste la catégorie la plus faible{pe_note} — "
               "52 exemples d'entraînement réels, précision faible même après SMOTE modéré — "
               "traitée en priorité manuelle systématique quel que soit le score, voir le playbook de réponse aux incidents.")

    df_tactic = pd.DataFrame([{"Tactique": k, "F1-score": v["f1"]} for k, v in tactic_info.items()])
    fig = px.bar(df_tactic, x="F1-score", y="Tactique", orientation="h",
                 color="F1-score", color_continuous_scale=["#ff5c5c", "#ffd166", "#06d6a0"], range_color=[0, 1])
    fig.update_layout(paper_bgcolor="#0b0e14", plot_bgcolor="#0b0e14", font_color="#e6e6e6", height=300)
    st.plotly_chart(fig, use_container_width=True)

# ============================================================
# PAGE 4 — Moteur d'analyse
# ============================================================
elif page == "🧠 Moteur d'analyse":
    st.markdown("## Moteur d'analyse — Score & Tactique")
    st.markdown('<p class="soc-subtitle">Démonstration sur échantillon du jeu de test NSL-KDD</p>', unsafe_allow_html=True)
    st.write("")

    sample_size = st.slider("Nombre d'échantillons à analyser", 10, 200, 50)

    if st.button("▶ Lancer l'analyse", type="primary"):
        with st.spinner("Analyse en cours..."):
            X_train, y_train, X_test, y_test, train_labels, test_labels, encoders = preprocess(
                "data/nsl-kdd/KDDTrain+.txt", "data/nsl-kdd/KDDTest+.txt",
            )
            engine = get_engine()
            idx = X_test.sample(n=sample_size, random_state=42).index
            analysis = engine.analyze(X_test.loc[idx], true_labels=test_labels.loc[idx])
            st.session_state.last_analysis = analysis

    if "last_analysis" in st.session_state:
        analysis = st.session_state.last_analysis
        col_r1, col_r2 = st.columns([2, 1])
        with col_r1:
            display = analysis[["true_label", "risk_score", "risk_band",
                                 "flagged_by_anomaly_detector",
                                 "predicted_tactic", "tactic_confidence", "mitre_id", "recommendation"]].copy()
            display["risk_score"] = display["risk_score"].round(3)
            display["tactic_confidence"] = display["tactic_confidence"].round(3)
            display["flagged_by_anomaly_detector"] = display["flagged_by_anomaly_detector"].map(
                {1: "🔍 Isolation Forest", 0: ""}
            )
            display = display.rename(columns={"flagged_by_anomaly_detector": "detecte_par"})
            def style_risk_band(val):
                colors = {"critical": "#ff5c5c", "high": "#ff9d42", "medium": "#ffd166", "low": "#06d6a0"}
                c = colors.get(val, "#8b93a7")
                return f"background-color:{c}22; color:{c}; font-weight:700;"
            styled = display.style.applymap(style_risk_band, subset=["risk_band"])
            st.dataframe(styled, use_container_width=True, height=420, hide_index=True)

        with col_r2:
            bc = analysis["risk_band"].value_counts().reset_index()
            bc.columns = ["risk_band", "count"]
            fig = go.Figure(data=[go.Pie(
                labels=bc["risk_band"], values=bc["count"],
                marker_colors=[RISK_COLORS.get(b, "#888") for b in bc["risk_band"]], hole=0.5,
            )])
            fig.update_layout(title="Bandes de risque", paper_bgcolor="#0b0e14", font_color="#e6e6e6", height=320)
            st.plotly_chart(fig, use_container_width=True)

st.divider()
st.caption("SOC AICYOU — Prototype de recherche & développement — Threat Intelligence basée sur l'IA")

# Auto-refresh : ne s'applique pas sur la page "Moteur d'analyse" (éviterait
# d'interrompre une analyse en cours ou de perdre le résultat affiché).
if auto_refresh and page != "🧠 Moteur d'analyse":
    time.sleep(30)
    st.rerun()
