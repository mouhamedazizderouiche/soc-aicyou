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
    #MainMenu, footer, header {visibility: hidden;}
    .main { background-color: #0b0e14; }
    .block-container { padding-top: 1.2rem; }

    div[data-testid="stMetric"] {
        background: linear-gradient(145deg, #161a23, #12151d);
        border: 1px solid #232733; border-radius: 10px; padding: 14px 16px;
    }
    div[data-testid="stMetricLabel"] { font-size: 13px; color: #8b93a7; }
    div[data-testid="stMetricValue"] { font-size: 24px; font-weight: 700; }

    .badge {
        display: inline-block; padding: 3px 10px; border-radius: 20px;
        font-size: 11px; font-weight: 700; text-transform: uppercase;
    }
    .badge-critical { background:#3d1216; color:#ff5c5c; border:1px solid #ff5c5c66; }
    .badge-high     { background:#3d2612; color:#ff9d42; border:1px solid #ff9d4266; }
    .badge-medium   { background:#3d3512; color:#ffd166; border:1px solid #ffd16666; }
    .badge-low      { background:#0f3d24; color:#06d6a0; border:1px solid #06d6a066; }

    .soc-subtitle { color:#8b93a7; font-size:15px; margin-top:-8px; }
    section[data-testid="stSidebar"] { background-color: #0f1219; border-right:1px solid #1e222c; }

    /* Cartes de filtre cliquables */
    div[data-testid="stButton"] > button {
        width: 100%; border-radius: 10px; padding: 18px 10px;
        border: 1px solid #232733; background: #161a23; color: #e6e6e6;
        font-weight: 600; transition: all 0.15s ease;
    }
    div[data-testid="stButton"] > button:hover {
        border-color: #ff5c5c; transform: translateY(-2px);
    }

    @keyframes pulse { 0% {opacity:1;} 50% {opacity:0.4;} 100% {opacity:1;} }
    .live-dot {
        display:inline-block; width:8px; height:8px; border-radius:50%;
        background:#ff5c5c; animation: pulse 1.4s infinite; margin-right:6px;
    }
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
            "Voir docs/playbook-reponse-incidents.md, section correspondant à la tactique dominante."
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
    st.markdown('<span class="live-dot"></span> **Système actif**', unsafe_allow_html=True)
    st.markdown("## Vue d'ensemble du système")
    st.markdown('<p class="soc-subtitle">Performance consolidée du pipeline de détection</p>', unsafe_allow_html=True)
    st.write("")
    if report:
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Taux de détection", f"{report['detection_rate']:.1%}", help="Recall sur le jeu de test NSL-KDD")
        c2.metric("Taux de faux positifs", f"{report['false_positive_rate']:.1%}")
        c3.metric("Débit moteur ML", f"{report['ml_throughput_events_per_sec']:,.0f}", "évt/s")
        conf = report.get('avg_tactic_confidence_critical')
        c4.metric("Confiance tactique", f"{conf:.1%}" if conf else "N/A", help="Cas critiques uniquement")

        st.write("")
        c5, c6, c7 = st.columns(3)
        c5.metric("Latence pipeline (bout-en-bout)", f"{report.get('pipeline_e2e_latency_ms', 0):.0f} ms")
        c6.metric("Alertes critiques analysées", f"{report.get('critical_alerts_count', 0):,}")
        c7.metric("Cohérence risque → tactique", f"{report.get('critical_with_tactic_pct', 0):.0%}")

        # Transparence : ces métriques sont un instantané figé (snapshot),
        # pas des valeurs live -- elles ne changent qu'en relançant
        # validation_report.py. Sans cette date, un lecteur pourrait
        # raisonnablement croire qu'elles sont recalculées en continu.
        generated_at_raw = report.get("generated_at")
        if generated_at_raw:
            try:
                generated_dt = datetime.fromisoformat(generated_at_raw)
                generated_label = generated_dt.strftime("%d/%m/%Y à %H:%M UTC")
            except (ValueError, TypeError):
                generated_label = generated_at_raw
        else:
            generated_label = "date inconnue (rapport généré avant l'ajout de l'horodatage)"

        st.caption(
            f"📸 Instantané généré le **{generated_label}** — pas une mesure live. "
            "Relancer `python validation_report.py` après toute mise à jour du modèle "
            "pour rafraîchir ces chiffres."
        )

        pipeline_note = report.get("pipeline_latency_note")
        if pipeline_note:
            st.caption(f"⚠️ {pipeline_note}")
    else:
        st.warning("Rapport de validation introuvable — lancer `python validation_report.py`.")

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
            alerts_df["risk_band"] = alerts_df["rule_level"].apply(level_to_band)
            alerts_df["alert_id"] = alerts_df["raw"].apply(extract_alert_id)
            st.caption(f"{total_alerts:,} alertes indexées au total — {len(alerts_df)} plus récentes chargées")
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
            "Relancer `python tactic_classifier_smote.py` après toute mise à jour du modèle."
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
        st.warning("Rapport de métriques introuvable — valeurs figées affichées. Lancer `python tactic_classifier_smote.py`.")

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
               "traitée en priorité manuelle systématique quel que soit le score, voir `docs/playbook-reponse-incidents.md`.")

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
