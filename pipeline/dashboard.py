"""
dashboard.py

SOC AICYOU — Professional SOC Dashboard
UI/UX redesign only.

IMPORTANT:
- Existing Wazuh data source preserved
- Existing normalization preserved
- Existing AI scoring preserved
- Existing MITRE reports preserved
- Existing triage persistence preserved
- Existing filters / drill-down / CSV export preserved
- No fake data added

Lancement :
    streamlit run dashboard.py
"""

import json
import os
import re
import time
from datetime import datetime, timezone
from collections import Counter

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from wazuh_client import WazuhIndexerClient
from normalizer import normalize_batch
from analysis_engine import AnalysisEngine
from preprocess import preprocess


# ============================================================
# FIX — HTML affiché comme texte brut
# ============================================================
# Streamlit utilise un moteur Markdown (CommonMark). Toute ligne
# indentée de 4 espaces ou plus est interprétée comme un bloc de
# code littéral, AVANT même que unsafe_allow_html=True ne soit pris
# en compte. Comme tout le HTML de ce fichier est écrit avec une
# indentation "propre" pour rester lisible, Streamlit affichait les
# balises telles quelles au lieu de les rendre.
#
# On patch st.markdown une seule fois ici : si l'appel est fait avec
# unsafe_allow_html=True, on retire l'indentation de chaque ligne
# avant de l'envoyer au vrai st.markdown. Aucun des appels plus bas
# dans le fichier n'a besoin d'être modifié.
_original_markdown = st.markdown


def _patched_markdown(body, *args, **kwargs):
    if isinstance(body, str) and kwargs.get("unsafe_allow_html"):
        body = re.sub(r"(?m)^[ \t]+", "", body)
    return _original_markdown(body, *args, **kwargs)


st.markdown = _patched_markdown


# ============================================================
# CONFIGURATION
# ============================================================

TRIAGE_LOG_PATH = os.path.join(
    os.path.dirname(__file__),
    "data",
    "triage_log.json"
)

st.set_page_config(
    page_title="SOC AICYOU — Security Operations Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# DESIGN SYSTEM
# ============================================================

COLORS = {
    "bg": "#080B10",
    "bg_2": "#0A0F15",
    "panel": "#0D131B",
    "panel_2": "#111923",
    "panel_3": "#151F2B",
    "border": "#1C2936",
    "border_light": "#263545",

    "text": "#E8EEF5",
    "text_soft": "#C5D0DC",
    "muted": "#7D8A99",
    "muted_2": "#5D6A78",

    "blue": "#3B82F6",
    "cyan": "#06B6D4",
    "purple": "#8B5CF6",

    "critical": "#FF4D5A",
    "high": "#FF9F43",
    "medium": "#F5C542",
    "low": "#19D3AE",

    "success": "#22C55E",
}


RISK_COLORS = {
    "critical": COLORS["critical"],
    "high": COLORS["high"],
    "medium": COLORS["medium"],
    "low": COLORS["low"],
}

RISK_ICONS = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
}


# ============================================================
# GLOBAL CSS
# ============================================================

st.markdown(
    f"""
<style>

@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

/* ==========================================================
   GLOBAL
   ========================================================== */

html, body, [class*="css"] {{
    font-family: 'Inter', 'Segoe UI', sans-serif;
}}

.stApp {{
    background:
        radial-gradient(
            1000px 500px at 10% -10%,
            rgba(59,130,246,0.08),
            transparent 65%
        ),
        radial-gradient(
            900px 500px at 100% 0%,
            rgba(6,182,212,0.05),
            transparent 65%
        ),
        {COLORS["bg"]};
    color: {COLORS["text"]};
}}

#MainMenu,
footer,
header {{
    visibility: hidden;
}}

.main .block-container {{
    max-width: 1600px;
    padding-top: 1.5rem;
    padding-bottom: 3rem;
    padding-left: 2rem;
    padding-right: 2rem;
}}

h1, h2, h3, h4 {{
    color: {COLORS["text"]} !important;
    font-weight: 700 !important;
    letter-spacing: -0.4px;
}}

h1 {{
    font-size: 30px !important;
}}

h2 {{
    font-size: 23px !important;
}}

h3 {{
    font-size: 18px !important;
}}

h4 {{
    font-size: 15px !important;
}}

p {{
    color: {COLORS["text_soft"]};
}}


/* ==========================================================
   SIDEBAR
   ========================================================== */

section[data-testid="stSidebar"] {{
    background:
        linear-gradient(
            180deg,
            #0B1017 0%,
            #080C12 100%
        );
    border-right: 1px solid {COLORS["border"]};
}}

section[data-testid="stSidebar"] .block-container {{
    padding: 1.5rem 1rem;
}}

.sidebar-brand {{
    padding: 10px 8px 20px 8px;
}}

.sidebar-logo {{
    width: 42px;
    height: 42px;
    border-radius: 12px;
    display: flex;
    align-items: center;
    justify-content: center;
    background:
        linear-gradient(
            135deg,
            rgba(59,130,246,0.22),
            rgba(6,182,212,0.12)
        );
    border: 1px solid rgba(59,130,246,0.30);
    font-size: 21px;
    margin-bottom: 12px;
}}

.sidebar-title {{
    color: {COLORS["text"]};
    font-size: 17px;
    font-weight: 800;
}}

.sidebar-subtitle {{
    color: {COLORS["muted"]};
    font-size: 11px;
    line-height: 1.5;
    margin-top: 4px;
}}

.sidebar-section {{
    color: {COLORS["muted_2"]};
    text-transform: uppercase;
    letter-spacing: 1.3px;
    font-size: 10px;
    font-weight: 700;
    margin: 18px 8px 8px;
}}


/* ==========================================================
   RADIO NAVIGATION
   ========================================================== */

section[data-testid="stSidebar"] div[role="radiogroup"] {{
    gap: 4px;
}}

section[data-testid="stSidebar"]
div[role="radiogroup"] > label {{
    display: flex;
    align-items: center;
    width: 100%;
    padding: 11px 12px;
    margin: 2px 0;
    border-radius: 10px;
    cursor: pointer;
    border: 1px solid transparent;
    color: {COLORS["muted"]};
    font-size: 13px;
    font-weight: 500;
    transition: all 0.15s ease;
}}

section[data-testid="stSidebar"]
div[role="radiogroup"] > label:hover {{
    background: #111923;
    color: {COLORS["text"]};
    border-color: {COLORS["border"]};
}}

section[data-testid="stSidebar"]
div[role="radiogroup"] > label:has(input:checked) {{
    background:
        linear-gradient(
            90deg,
            rgba(59,130,246,0.20),
            rgba(59,130,246,0.06)
        );
    color: #FFFFFF;
    border-color: rgba(59,130,246,0.35);
    box-shadow:
        inset 3px 0 0 {COLORS["blue"]};
}}

section[data-testid="stSidebar"]
div[role="radiogroup"] > label > div:first-child {{
    display: none;
}}


/* ==========================================================
   HEADER
   ========================================================== */

.soc-header {{
    display: flex;
    justify-content: space-between;
    align-items: center;

    background:
        linear-gradient(
            135deg,
            rgba(17,25,35,0.98),
            rgba(10,15,22,0.98)
        );

    border: 1px solid {COLORS["border"]};
    border-radius: 16px;

    padding: 20px 24px;
    margin-bottom: 22px;

    box-shadow:
        0 15px 40px rgba(0,0,0,0.25);
}}

.header-left {{
    display: flex;
    align-items: center;
    gap: 14px;
}}

.header-icon {{
    width: 48px;
    height: 48px;
    border-radius: 13px;

    display: flex;
    align-items: center;
    justify-content: center;

    background:
        linear-gradient(
            135deg,
            rgba(59,130,246,0.18),
            rgba(6,182,212,0.08)
        );

    border: 1px solid rgba(59,130,246,0.30);
    font-size: 23px;
}}

.header-title {{
    font-size: 21px;
    font-weight: 800;
    color: {COLORS["text"]};
}}

.header-subtitle {{
    color: {COLORS["muted"]};
    font-size: 12px;
    margin-top: 3px;
}}

.header-right {{
    display: flex;
    align-items: center;
    gap: 9px;
}}

.status-pill {{
    display: inline-flex;
    align-items: center;
    gap: 7px;

    padding: 7px 12px;
    border-radius: 20px;

    background: rgba(34,197,94,0.08);
    border: 1px solid rgba(34,197,94,0.25);

    color: #4ADE80;
    font-size: 11px;
    font-weight: 700;
}}

.time-pill {{
    padding: 7px 12px;
    border-radius: 20px;

    background: #111923;
    border: 1px solid {COLORS["border"]};

    color: {COLORS["muted"]};
    font-size: 11px;
    font-family: 'JetBrains Mono', monospace;
}}


/* ==========================================================
   LIVE DOT
   ========================================================== */

@keyframes pulse {{
    0% {{
        opacity: 1;
        transform: scale(1);
    }}

    50% {{
        opacity: 0.4;
        transform: scale(0.85);
    }}

    100% {{
        opacity: 1;
        transform: scale(1);
    }}
}}

.live-dot {{
    display: inline-block;
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: {COLORS["success"]};
    box-shadow: 0 0 9px rgba(34,197,94,0.8);
    animation: pulse 1.5s infinite;
}}


/* ==========================================================
   SECTION HEADER
   ========================================================== */

.section-header {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin: 24px 0 12px;
}}

.section-title {{
    color: {COLORS["text"]};
    font-size: 15px;
    font-weight: 700;
}}

.section-description {{
    color: {COLORS["muted"]};
    font-size: 11px;
    margin-top: 3px;
}}


/* ==========================================================
   KPI CARDS
   ========================================================== */

.kpi-card {{
    position: relative;
    overflow: hidden;

    background:
        linear-gradient(
            145deg,
            {COLORS["panel_2"]},
            {COLORS["panel"]}
        );

    border: 1px solid {COLORS["border"]};
    border-radius: 13px;

    padding: 16px;
    min-height: 105px;

    box-shadow:
        0 7px 20px rgba(0,0,0,0.18);
}}

.kpi-card::after {{
    content: "";
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 2px;
    background: var(--accent);
}}

.kpi-label {{
    color: {COLORS["muted"]};
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    font-weight: 700;
    margin-bottom: 10px;
}}

.kpi-value {{
    color: {COLORS["text"]};
    font-size: 25px;
    font-weight: 800;
    line-height: 1;
}}

.kpi-footer {{
    color: {COLORS["muted_2"]};
    font-size: 10px;
    margin-top: 8px;
}}


/* ==========================================================
   PANELS
   ========================================================== */

.soc-panel {{
    background:
        linear-gradient(
            145deg,
            rgba(17,25,35,0.95),
            rgba(11,16,23,0.95)
        );

    border: 1px solid {COLORS["border"]};
    border-radius: 14px;

    padding: 17px;

    box-shadow:
        0 8px 28px rgba(0,0,0,0.18);
}}

.panel-title {{
    color: {COLORS["text"]};
    font-size: 13px;
    font-weight: 700;
    margin-bottom: 3px;
}}

.panel-subtitle {{
    color: {COLORS["muted"]};
    font-size: 10px;
}}


/* ==========================================================
   ALERT BADGES
   ========================================================== */

.badge {{
    display: inline-block;
    padding: 4px 9px;
    border-radius: 6px;

    font-size: 9px;
    font-weight: 800;

    text-transform: uppercase;
    letter-spacing: 0.6px;
}}

.badge-critical {{
    color: {COLORS["critical"]};
    background: rgba(255,77,90,0.10);
    border: 1px solid rgba(255,77,90,0.25);
}}

.badge-high {{
    color: {COLORS["high"]};
    background: rgba(255,159,67,0.10);
    border: 1px solid rgba(255,159,67,0.25);
}}

.badge-medium {{
    color: {COLORS["medium"]};
    background: rgba(245,197,66,0.10);
    border: 1px solid rgba(245,197,66,0.25);
}}

.badge-low {{
    color: {COLORS["low"]};
    background: rgba(25,211,174,0.10);
    border: 1px solid rgba(25,211,174,0.25);
}}


/* ==========================================================
   BUTTONS
   ========================================================== */

div[data-testid="stButton"] > button {{
    border-radius: 9px;

    border: 1px solid {COLORS["border"]};
    background: {COLORS["panel"]};

    color: {COLORS["text_soft"]};

    font-size: 12px;
    font-weight: 600;

    transition: all 0.15s ease;
}}

div[data-testid="stButton"] > button:hover {{
    border-color: rgba(59,130,246,0.5);
    color: #FFFFFF;

    transform: translateY(-1px);

    box-shadow:
        0 6px 18px rgba(59,130,246,0.10);
}}


/* ==========================================================
   DATAFRAME
   ========================================================== */

div[data-testid="stDataFrame"] {{
    border:
        1px solid {COLORS["border"]};

    border-radius: 12px;
    overflow: hidden;

    box-shadow:
        0 8px 25px rgba(0,0,0,0.18);
}}


/* ==========================================================
   INPUTS
   ========================================================== */

div[data-baseweb="input"] > div,
div[data-baseweb="select"] > div {{
    background: {COLORS["panel"]} !important;
    border-color: {COLORS["border"]} !important;
    border-radius: 9px !important;
}}

input {{
    color: {COLORS["text"]} !important;
}}

label {{
    color: {COLORS["muted"]} !important;
    font-size: 11px !important;
}}


/* ==========================================================
   EXPANDER
   ========================================================== */

div[data-testid="stExpander"] {{
    background: {COLORS["panel"]};
    border: 1px solid {COLORS["border"]};
    border-radius: 12px;
}}


/* ==========================================================
   ALERT / INFO
   ========================================================== */

div[data-testid="stAlert"] {{
    border-radius: 10px;
}}


/* ==========================================================
   DIVIDER
   ========================================================== */

hr {{
    border-color: {COLORS["border"]};
}}


/* ==========================================================
   FOOTER
   ========================================================== */

.soc-footer {{
    text-align: center;
    color: {COLORS["muted_2"]};
    font-size: 10px;
    padding: 20px 0 5px;
    letter-spacing: 0.3px;
}}


/* ==========================================================
   TOP OFFENDER ROW
   ========================================================== */

.offender-row {{
    display: flex;
    align-items: center;
    justify-content: space-between;

    padding: 9px 0;

    border-bottom: 1px solid rgba(255,255,255,0.04);
}}

.offender-ip {{
    font-family: 'JetBrains Mono', monospace;
    color: {COLORS["text_soft"]};
    font-size: 11px;
}}

.offender-count {{
    color: {COLORS["muted"]};
    font-size: 10px;
}}


/* ==========================================================
   AI SUMMARY
   ========================================================== */

.ai-summary {{
    background:
        linear-gradient(
            135deg,
            rgba(59,130,246,0.08),
            rgba(6,182,212,0.03)
        );

    border: 1px solid rgba(59,130,246,0.18);
    border-radius: 13px;

    padding: 18px;
}}

.ai-label {{
    color: {COLORS["muted"]};
    text-transform: uppercase;
    letter-spacing: 1px;
    font-size: 9px;
    font-weight: 700;
}}

.ai-level {{
    font-size: 22px;
    font-weight: 800;
    margin: 5px 0 10px;
}}

.ai-text {{
    color: {COLORS["text_soft"]};
    font-size: 12px;
    line-height: 1.6;
}}

.ai-recommendation {{
    margin-top: 14px;
    padding-top: 12px;

    border-top: 1px solid {COLORS["border"]};

    color: {COLORS["text_soft"]};
    font-size: 11px;
    line-height: 1.6;
}}


/* ==========================================================
   MITRE
   ========================================================== */

.mitre-card {{
    background: {COLORS["panel"]};
    border: 1px solid {COLORS["border"]};
    border-radius: 12px;

    padding: 15px;

    min-height: 175px;
}}

.mitre-id {{
    color: {COLORS["muted"]};
    font-family: 'JetBrains Mono', monospace;
    font-size: 10px;
}}

.mitre-name {{
    color: {COLORS["text"]};
    font-size: 14px;
    font-weight: 700;
    margin-top: 7px;
}}

.mitre-desc {{
    color: {COLORS["muted"]};
    font-size: 10px;
    line-height: 1.5;
    margin-top: 6px;
}}

.mitre-f1 {{
    color: {COLORS["cyan"]};
    font-size: 21px;
    font-weight: 800;
    margin-top: 14px;
}}


/* ==========================================================
   TRIAGE
   ========================================================== */

.triage-label {{
    color: {COLORS["muted"]};
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    margin-bottom: 7px;
}}


/* ==========================================================
   RESPONSIVE
   ========================================================== */

@media (max-width: 900px) {{
    .main .block-container {{
        padding-left: 1rem;
        padding-right: 1rem;
    }}

    .soc-header {{
        flex-direction: column;
        align-items: flex-start;
        gap: 15px;
    }}

    .header-right {{
        flex-wrap: wrap;
    }}
}}

</style>
""",
    unsafe_allow_html=True,
)


# ============================================================
# HELPERS — DATA
# ============================================================

def load_triage_log() -> dict:
    """Charge l'état de triage persistant."""
    if os.path.exists(TRIAGE_LOG_PATH):
        with open(TRIAGE_LOG_PATH, encoding="utf-8") as f:
            return json.load(f)

    return {}


def save_triage_log(log: dict) -> None:
    os.makedirs(
        os.path.dirname(TRIAGE_LOG_PATH),
        exist_ok=True
    )

    with open(TRIAGE_LOG_PATH, "w", encoding="utf-8") as f:
        json.dump(log, f, indent=2)


@st.cache_resource
def get_engine():
    return AnalysisEngine()


@st.cache_data(ttl=60)
def load_validation_report():
    path = "data/validation_report.json"

    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)

    return None


@st.cache_data(ttl=60)
def load_tactic_report():
    path = "data/tactic_classifier_report.json"

    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)

    return None


@st.cache_data(ttl=30)
def load_live_alerts(size: int = 300):
    client = WazuhIndexerClient()

    result = client.search_alerts(size=size)

    hits = result["hits"]["hits"]

    normalized = normalize_batch(hits)

    return (
        pd.DataFrame(normalized),
        result["hits"]["total"]["value"]
    )


def risk_badge(band: str) -> str:
    return (
        f'<span class="badge badge-{band}">'
        f'{band}'
        f'</span>'
    )


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
    if isinstance(raw, dict):
        return str(raw.get("id", ""))

    return ""


def generate_ai_summary(alerts_df: pd.DataFrame) -> dict:

    if alerts_df.empty:
        return {
            "level": "low",
            "text": "Aucune activité récente à analyser.",
            "recommendation": "Aucune action requise.",
            "top_ip": None,
            "top_rule": None,
        }

    critical_count = (
        alerts_df["risk_band"] == "critical"
    ).sum()

    high_count = (
        alerts_df["risk_band"] == "high"
    ).sum()

    total = len(alerts_df)

    top_ip_series = (
        alerts_df["src_ip"]
        .dropna()
        .value_counts()
    )

    top_ip = (
        top_ip_series.index[0]
        if not top_ip_series.empty
        else None
    )

    top_ip_count = (
        int(top_ip_series.iloc[0])
        if not top_ip_series.empty
        else 0
    )

    top_rule_series = (
        alerts_df["rule_description"]
        .dropna()
        .value_counts()
    )

    top_rule = (
        top_rule_series.index[0]
        if not top_rule_series.empty
        else None
    )

    scan_pattern = (
        alerts_df["rule_description"]
        .fillna("")
        .str.contains(
            "port scan",
            case=False
        )
        .any()
    )

    if critical_count > 5:

        level = "critical"

        text = (
            f"{critical_count} alertes critiques détectées "
            f"sur {total} événements analysés. "
            f"Source la plus active : {top_ip} "
            f"({top_ip_count} occurrences). "
            f'Règle la plus déclenchée : "{top_rule}".'
        )

        recommendation = (
            f"Investigation immédiate sous 15 min recommandée "
            f"sur {top_ip}. Vérifier si le trafic est légitime "
            "(whois/reverse DNS) avant tout blocage. "
            "Voir le playbook de réponse aux incidents."
        )

    elif scan_pattern and (
        critical_count > 0 or high_count > 0
    ):

        level = "high"

        text = (
            f"Activité de sondage réseau détectée depuis "
            f"{top_ip} ({top_ip_count} occurrences). "
            f"{critical_count} alerte(s) critique(s), "
            f"{high_count} de niveau élevé."
        )

        recommendation = (
            f"Documenter {top_ip}, vérifier si la source est "
            "interne connue ou externe et surveiller les "
            "24 prochaines heures."
        )

    elif critical_count > 0 or high_count > 3:

        level = "high"

        text = (
            f"{critical_count} alerte(s) critique(s) et "
            f"{high_count} de niveau élevé sur {total} événements. "
            f"Source la plus active : {top_ip} "
            f"({top_ip_count} occurrences)."
        )

        recommendation = (
            f"Vérification manuelle recommandée sous 24h "
            f"ouvrées pour {top_ip}."
        )

    else:

        level = "low"

        text = (
            f"Activité nominale — {total} événements analysés, "
            "aucun signal critique dominant. "
            f"Source la plus active : {top_ip or 'N/A'} "
            f"({top_ip_count} occurrences)."
        )

        recommendation = (
            "Surveillance de routine — aucune action "
            "immédiate requise."
        )

    return {
        "level": level,
        "text": text,
        "recommendation": recommendation,
        "top_ip": top_ip,
        "top_rule": top_rule,
    }


# ============================================================
# UI HELPERS
# ============================================================

def section_header(title, description=None):

    desc = (
        f'<div class="section-description">{description}</div>'
        if description
        else ""
    )

    st.markdown(
        f"""
        <div class="section-header">
            <div>
                <div class="section-title">{title}</div>
                {desc}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_header(title, subtitle):

    now = datetime.now(
        timezone.utc
    ).strftime("%d/%m/%Y  %H:%M UTC")

    st.markdown(
        f"""
        <div class="soc-header">

            <div class="header-left">

                <div class="header-icon">
                    🛡️
                </div>

                <div>
                    <div class="header-title">
                        {title}
                    </div>

                    <div class="header-subtitle">
                        {subtitle}
                    </div>
                </div>

            </div>

            <div class="header-right">

                <span class="status-pill">
                    <span class="live-dot"></span>
                    SYSTEM ACTIVE
                </span>

                <span class="time-pill">
                    🕐 {now}
                </span>

            </div>

        </div>
        """,
        unsafe_allow_html=True,
    )


def render_kpis(report):

    if not report:
        st.warning(
            "Métriques de validation indisponibles."
        )
        return

    conf = report.get(
        "avg_tactic_confidence_critical"
    )

    cards = [

        (
            "Taux de détection",
            f"{report['detection_rate']:.1%}",
            "Validation model",
            COLORS["blue"],
        ),

        (
            "Faux positifs",
            f"{report['false_positive_rate']:.1%}",
            "Validation model",
            COLORS["critical"],
        ),

        (
            "Débit moteur",
            f"{report['ml_throughput_events_per_sec']:,.0f}",
            "events / sec",
            COLORS["cyan"],
        ),

        (
            "Confiance tactique",
            f"{conf:.1%}" if conf else "N/A",
            "Critical alerts",
            COLORS["purple"],
        ),

        (
            "Latence pipeline",
            f"{report.get('pipeline_e2e_latency_ms', 0):.0f} ms",
            "End-to-end",
            COLORS["high"],
        ),

        (
            "Alertes critiques",
            f"{report.get('critical_alerts_count', 0):,}",
            "Validation dataset",
            COLORS["critical"],
        ),

        (
            "Risque → tactique",
            f"{report.get('critical_with_tactic_pct', 0):.0%}",
            "Consistency",
            COLORS["low"],
        ),
    ]

    cols = st.columns(len(cards))

    for col, (
        label,
        value,
        footer,
        accent,
    ) in zip(cols, cards):

        with col:

            st.markdown(
                f"""
                <div class="kpi-card"
                     style="--accent:{accent};">

                    <div class="kpi-label">
                        {label}
                    </div>

                    <div class="kpi-value">
                        {value}
                    </div>

                    <div class="kpi-footer">
                        {footer}
                    </div>

                </div>
                """,
                unsafe_allow_html=True,
            )


def make_plot_layout(fig, height=300):

    fig.update_layout(

        height=height,

        margin=dict(
            l=10,
            r=10,
            t=15,
            b=10,
        ),

        paper_bgcolor="rgba(0,0,0,0)",

        plot_bgcolor="rgba(0,0,0,0)",

        font=dict(
            family="Inter",
            color=COLORS["muted"],
            size=10,
        ),

        xaxis=dict(
            gridcolor="rgba(255,255,255,0.045)",
            zeroline=False,
        ),

        yaxis=dict(
            gridcolor="rgba(255,255,255,0.045)",
            zeroline=False,
        ),

        hoverlabel=dict(
            bgcolor=COLORS["panel_3"],
            font_color=COLORS["text"],
        ),
    )

    return fig


# ============================================================
# SESSION STATE
# ============================================================

if "active_band_filter" not in st.session_state:
    st.session_state.active_band_filter = None

if "selected_alert_idx" not in st.session_state:
    st.session_state.selected_alert_idx = None


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.markdown(
        """
        <div class="sidebar-brand">

            <div class="sidebar-logo">
                🛡️
            </div>

            <div class="sidebar-title">
                SOC AICYOU
            </div>

            <div class="sidebar-subtitle">
                Threat Detection & Intelligence Platform
            </div>

        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        '<div class="sidebar-section">Navigation</div>',
        unsafe_allow_html=True,
    )

    page = st.radio(
        "Navigation",
        [
            "📊 Vue d'ensemble",
            "🔴 Alertes en direct",
            "🗺️ Carte MITRE ATT&CK",
            "🧠 Moteur d'analyse",
        ],
        label_visibility="collapsed",
    )

    st.markdown(
        '<div class="sidebar-section">System</div>',
        unsafe_allow_html=True,
    )

    auto_refresh = st.checkbox(
        "🔄 Actualisation automatique",
        value=False,
    )

    if auto_refresh:
        st.caption(
            "Actualisation active toutes les 30 secondes."
        )

    st.markdown(
        '<div class="sidebar-section">Projet</div>',
        unsafe_allow_html=True,
    )

    st.caption(
        "**Stagiaire**  \n"
        "Mouhamed Aziz Derouiche"
    )

    st.caption(
        "**Encadrant**  \n"
        "Dr. Alaidine Ben Ayed"
    )

    st.caption(
        "**Organisme**  \n"
        "Stratégie AICYOU Inc."
    )


report = load_validation_report()


# ============================================================
# PAGE 1 — OVERVIEW
# ============================================================

if page == "📊 Vue d'ensemble":

    render_header(
        "SOC AICYOU",
        "Moteur intelligent de détection d'intrusions"
    )

    # --------------------------------------------------------
    # KPI
    # --------------------------------------------------------

    render_kpis(report)

    if report:

        generated_at_raw = report.get(
            "generated_at"
        )

        try:

            generated_label = (
                datetime.fromisoformat(
                    generated_at_raw
                ).strftime(
                    "%d/%m/%Y à %H:%M UTC"
                )
            )

        except (
            ValueError,
            TypeError,
        ):

            generated_label = "date inconnue"

        st.caption(
            f"Snapshot du {generated_label} — "
            "métriques du modèle sur jeu de validation, "
            "pas une mesure temps réel."
        )

    # --------------------------------------------------------
    # LIVE DATA
    # --------------------------------------------------------

    try:

        alerts_mid, total_mid = load_live_alerts(
            size=500
        )

        # ====================================================
        # ACTIVITY + SOURCE
        # ====================================================

        st.write("")

        col_activity, col_source = st.columns(
            [2.2, 1]
        )

        with col_activity:

            section_header(
                "Activité des alertes",
                "Volume d'événements observés dans le temps",
            )

            df = alerts_mid.copy()

            df["ts"] = pd.to_datetime(
                df["timestamp"],
                errors="coerce",
                utc=True,
            )

            df = df.dropna(
                subset=["ts"]
            )

            if not df.empty:

                serie = (
                    df.set_index("ts")
                    .resample("30min")
                    .size()
                    .reset_index(
                        name="alertes"
                    )
                )

                fig = px.area(
                    serie,
                    x="ts",
                    y="alertes",
                )

                fig.update_traces(
                    line_color=COLORS["blue"],
                    fillcolor="rgba(59,130,246,0.14)",
                    line_width=2,
                )

                fig.update_layout(
                    title=None,
                    xaxis_title=None,
                    yaxis_title=None,
                )

                fig = make_plot_layout(
                    fig,
                    305
                )

                st.markdown(
                    '<div class="soc-panel">',
                    unsafe_allow_html=True,
                )

                st.plotly_chart(
                    fig,
                    use_container_width=True,
                    config={
                        "displayModeBar": False
                    },
                )

                st.markdown(
                    "</div>",
                    unsafe_allow_html=True,
                )

            else:

                st.info(
                    "Pas de données temporelles exploitables."
                )

        with col_source:

            section_header(
                "Répartition par source",
                "Origine des événements collectés",
            )

            if (
                "source_type" in alerts_mid.columns
                and not alerts_mid.empty
            ):

                src = (
                    alerts_mid["source_type"]
                    .fillna("Inconnu")
                    .value_counts()
                    .reset_index()
                )

                src.columns = [
                    "source",
                    "count",
                ]

                fig2 = go.Figure(
                    data=[
                        go.Pie(
                            labels=src["source"],
                            values=src["count"],
                            hole=0.67,
                            marker=dict(
                                colors=[
                                    COLORS["blue"],
                                    COLORS["cyan"],
                                    COLORS["purple"],
                                    COLORS["muted_2"],
                                ]
                            ),
                            textinfo="percent",
                            textfont=dict(
                                size=10
                            ),
                        )
                    ]
                )

                fig2.update_layout(
                    showlegend=True,
                    legend=dict(
                        orientation="v",
                        x=0.98,
                        y=0.5,
                        font=dict(
                            size=9
                        ),
                    ),
                    annotations=[
                        dict(
                            text=(
                                f"<b>{len(alerts_mid)}</b>"
                                "<br>events"
                            ),
                            x=0.5,
                            y=0.5,
                            showarrow=False,
                            font=dict(
                                size=14,
                                color=COLORS["text"],
                            ),
                        )
                    ],
                )

                fig2 = make_plot_layout(
                    fig2,
                    305
                )

                st.markdown(
                    '<div class="soc-panel">',
                    unsafe_allow_html=True,
                )

                st.plotly_chart(
                    fig2,
                    use_container_width=True,
                    config={
                        "displayModeBar": False
                    },
                )

                st.markdown(
                    "</div>",
                    unsafe_allow_html=True,
                )

            else:

                st.info(
                    "Source indisponible."
                )

        # ====================================================
        # TOP OFFENDERS
        # ====================================================

        st.write("")

        col_offenders, col_rules = st.columns(
            2
        )

        with col_offenders:

            section_header(
                "Top Offenders",
                "Sources générant le plus d'événements",
            )

            if (
                "src_ip" in alerts_mid.columns
                and not alerts_mid.empty
            ):

                top_ips = (
                    alerts_mid["src_ip"]
                    .dropna()
                    .value_counts()
                    .head(5)
                )

                html = ""

                for ip, count in top_ips.items():

                    html += f"""
                    <div class="offender-row">

                        <div class="offender-ip">
                            {ip}
                        </div>

                        <div class="offender-count">
                            {count:,} events
                        </div>

                    </div>
                    """

                st.markdown(
                    f"""
                    <div class="soc-panel">
                        {html}
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            else:

                st.info(
                    "IP sources indisponibles."
                )

        with col_rules:

            section_header(
                "Règles les plus déclenchées",
                "Détections observées récemment",
            )

            if (
                "rule_description" in alerts_mid.columns
                and not alerts_mid.empty
            ):

                top_rules = (
                    alerts_mid[
                        "rule_description"
                    ]
                    .dropna()
                    .value_counts()
                    .head(5)
                )

                html = ""

                for rule, count in top_rules.items():

                    html += f"""
                    <div class="offender-row">

                        <div class="offender-ip"
                             style="font-family:Inter; max-width:80%;">

                            {rule}

                        </div>

                        <div class="offender-count">
                            {count:,}
                        </div>

                    </div>
                    """

                st.markdown(
                    f"""
                    <div class="soc-panel">
                        {html}
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            else:

                st.info(
                    "Règles indisponibles."
                )

        # ====================================================
        # AI SUMMARY
        # ====================================================

        st.write("")

        section_header(
            "Résumé automatique",
            "Synthèse calculée à partir des événements réellement observés",
        )

        alerts_preview = alerts_mid.copy()

        if not alerts_preview.empty:

            alerts_preview["risk_band"] = (
                alerts_preview[
                    "rule_level"
                ].apply(
                    level_to_band
                )
            )

            summary = generate_ai_summary(
                alerts_preview
            )

            band_color = RISK_COLORS.get(
                summary["level"],
                COLORS["muted"],
            )

            st.markdown(
                f"""
                <div class="ai-summary"
                     style="border-left:3px solid {band_color};">

                    <div class="ai-label">
                        Niveau de menace estimé
                    </div>

                    <div class="ai-level"
                         style="color:{band_color};">

                        {summary["level"].upper()}

                    </div>

                    <div class="ai-text">
                        {summary["text"]}
                    </div>

                    <div class="ai-recommendation">

                        <span style="color:{COLORS["muted"]};">
                            RECOMMANDATION
                        </span>

                        <br><br>

                        💡 {summary["recommendation"]}

                    </div>

                </div>
                """,
                unsafe_allow_html=True,
            )

        # ====================================================
        # MITRE
        # ====================================================

        st.write("")

        section_header(
            "MITRE ATT&CK",
            "Tactiques réellement présentes dans les alertes récentes",
        )

        tac_counter = Counter()

        if "mitre_tactics" in alerts_mid.columns:

            for val in alerts_mid[
                "mitre_tactics"
            ].dropna():

                if isinstance(
                    val,
                    (list, tuple)
                ):

                    for tactic in val:

                        if tactic:
                            tac_counter[
                                str(tactic)
                            ] += 1

                elif isinstance(
                    val,
                    str
                ) and val.strip():

                    for tactic in val.split(","):

                        tactic = tactic.strip()

                        if tactic:
                            tac_counter[
                                tactic
                            ] += 1

        if tac_counter:

            total_tac = sum(
                tac_counter.values()
            )

            rows_html = ""

            palette = [
                COLORS["critical"],
                COLORS["high"],
                COLORS["purple"],
                COLORS["cyan"],
                COLORS["low"],
                "#EC4899",
            ]

            for i, (
                tactic,
                count
            ) in enumerate(
                tac_counter.most_common()
            ):

                pct = (
                    count /
                    total_tac *
                    100
                )

                color = palette[
                    i % len(palette)
                ]

                rows_html += f"""
                <div style="
                    display:grid;
                    grid-template-columns:220px 1fr 55px;
                    gap:14px;
                    align-items:center;
                    margin-bottom:13px;
                ">

                    <div style="
                        color:{COLORS["text_soft"]};
                        font-size:11px;
                    ">
                        {tactic}
                    </div>

                    <div style="
                        background:#18212B;
                        height:7px;
                        border-radius:10px;
                        overflow:hidden;
                    ">

                        <div style="
                            width:{pct:.0f}%;
                            height:7px;
                            background:{color};
                            border-radius:10px;
                        "></div>

                    </div>

                    <div style="
                        text-align:right;
                        color:{COLORS["muted"]};
                        font-size:10px;
                    ">
                        {pct:.0f}%
                    </div>

                </div>
                """

            st.markdown(
                f"""
                <div class="soc-panel">
                    {rows_html}
                </div>
                """,
                unsafe_allow_html=True,
            )

            st.caption(
                f"{len(tac_counter)} tactique(s) MITRE "
                f"détectée(s) sur {total_tac} alerte(s) taguée(s)."
            )

        else:

            st.info(
                "Aucune tactique MITRE ATT&CK "
                "dans les alertes récentes."
            )

        # ====================================================
        # ARCHITECTURE
        # ====================================================

        st.write("")

        section_header(
            "Architecture de détection",
            "Defense-in-depth : signatures → comportement → intelligence",
        )

        col1, col2, col3 = st.columns(3)

        architecture = [

            (
                col1,
                "01",
                "SIGNATURES",
                "Ruleset Suricata natif",
                "Détection des menaces connues, CVE, malware et exploits.",
                COLORS["blue"],
            ),

            (
                col2,
                "02",
                "COMPORTEMENTALE",
                "Règles Suricata custom",
                "Détection de scans, reconnaissance et comportements anormaux.",
                COLORS["cyan"],
            ),

            (
                col3,
                "03",
                "INTELLIGENCE",
                "Machine Learning",
                "XGBoost pour le risque et classification multi-classe MITRE.",
                COLORS["purple"],
            ),
        ]

        for (
            col,
            number,
            title,
            name,
            description,
            color,
        ) in architecture:

            with col:

                st.markdown(
                    f"""
                    <div class="soc-panel"
                         style="min-height:150px;">

                        <div style="
                            color:{color};
                            font-family:'JetBrains Mono';
                            font-size:10px;
                            font-weight:700;
                        ">
                            LAYER {number}
                        </div>

                        <div style="
                            color:{COLORS["text"]};
                            font-size:14px;
                            font-weight:700;
                            margin-top:7px;
                        ">
                            {title}
                        </div>

                        <div style="
                            color:{COLORS["text_soft"]};
                            font-size:11px;
                            font-weight:600;
                            margin-top:8px;
                        ">
                            {name}
                        </div>

                        <div style="
                            color:{COLORS["muted"]};
                            font-size:10px;
                            line-height:1.5;
                            margin-top:6px;
                        ">
                            {description}
                        </div>

                    </div>
                    """,
                    unsafe_allow_html=True,
                )

    except Exception as e:

        st.info(
            f"Section activité indisponible ({e})"
        )


# ============================================================
# PAGE 2 — LIVE ALERTS
# ============================================================

elif page == "🔴 Alertes en direct":

    render_header(
        "Alertes en direct",
        "Flux temps réel — analyse, filtrage et triage"
    )

    with st.spinner(
        "Chargement des alertes..."
    ):

        try:

            alerts_df, total_alerts = (
                load_live_alerts()
            )

            # ------------------------------------------------
            # EXISTING AI PIPELINE
            # ------------------------------------------------

            from live_flow_scoring import score_alerts

            scoring = score_alerts(
                alerts_df,
                base_dir="."
            )

            alerts_df["risk_band"] = (
                scoring["risk_band"]
            )

            alerts_df["risk_score"] = (
                scoring["risk_score"]
            )

            alerts_df["predicted_tactic"] = (
                scoring["predicted_tactic"]
            )

            alerts_df["band_source"] = (
                scoring["band_source"]
            )

            scoring_meta = scoring["meta"]

            alerts_df["alert_id"] = (
                alerts_df["raw"]
                .apply(extract_alert_id)
            )

            st.caption(
                f"{total_alerts:,} alertes indexées — "
                f"{len(alerts_df)} plus récentes chargées"
            )

            meta = scoring_meta

            if meta["method"] == "model+fallback":

                st.markdown(
                    f"""
                    <div class="soc-panel"
                         style="
                         border-color:
                         rgba(59,130,246,0.25);
                         margin-bottom:15px;
                         ">

                        🧠 <b>Modèle IA flux-locaux actif</b>

                        <span style="
                        color:{COLORS["muted"]};
                        ">

                        — {meta["n_model"]}
                        alerte(s) scorée(s) par le modèle,
                        {meta["n_fallback"]}
                        en repli sévérité.

                        </span>

                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            else:

                st.warning(
                    "⚠️ Bandes de risque en repli "
                    f"sévérité — modèle indisponible : "
                    f"{meta['reason']}"
                )

        except Exception as e:

            st.error(
                f"Connexion à l'Indexer impossible : {e}"
            )

            alerts_df = pd.DataFrame()

    # ========================================================
    # ALERT CONTENT
    # ========================================================

    if not alerts_df.empty:

        # ----------------------------------------------------
        # RISK SUMMARY
        # ----------------------------------------------------

        section_header(
            "Risk overview",
            "Cliquez sur une catégorie pour filtrer les alertes",
        )

        band_counts = (
            alerts_df["risk_band"]
            .value_counts()
            .to_dict()
        )

        cols = st.columns(4)

        for col, band in zip(
            cols,
            [
                "critical",
                "high",
                "medium",
                "low",
            ],
        ):

            count = band_counts.get(
                band,
                0
            )

            active = (
                st.session_state
                .active_band_filter
                == band
            )

            with col:

                st.markdown(
                    f"""
                    <div class="kpi-card"
                         style="
                         --accent:
                         {RISK_COLORS[band]};
                         min-height:95px;
                         ">

                        <div class="kpi-label">
                            {RISK_ICONS[band]}
                            {band.upper()}
                        </div>

                        <div class="kpi-value"
                             style="
                             color:
                             {RISK_COLORS[band]};
                             ">

                            {count:,}

                        </div>

                        <div class="kpi-footer">
                            {"FILTER ACTIVE" if active
                             else "click to filter"}
                        </div>

                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                if st.button(
                    f"Filtrer {band.upper()}",
                    key=f"card_{band}",
                    use_container_width=True,
                ):

                    st.session_state.active_band_filter = (
                        None
                        if active
                        else band
                    )

                    st.rerun()

        if st.session_state.active_band_filter:

            st.success(
                f"Filtre actif : "
                f"**{st.session_state.active_band_filter.upper()}**"
            )

        # ----------------------------------------------------
        # FILTERS
        # ----------------------------------------------------

        section_header(
            "Filtres",
            "Affinez les événements avant l'investigation",
        )

        reset_col, _ = st.columns(
            [1, 5]
        )

        with reset_col:

            if st.button(
                "↻ Réinitialiser",
                use_container_width=True,
            ):

                for key in [
                    "flt_source",
                    "flt_agent",
                    "flt_rule",
                    "flt_level",
                    "flt_search",
                ]:

                    st.session_state.pop(
                        key,
                        None
                    )

                st.session_state.active_band_filter = None

                st.rerun()

        f1, f2, f3 = st.columns(3)

        with f1:

            source_filter = st.multiselect(
                "Source",
                alerts_df[
                    "source_type"
                ].unique(),
                default=list(
                    alerts_df[
                        "source_type"
                    ].unique()
                ),
                key="flt_source",
            )

        with f2:

            agent_filter = st.multiselect(
                "Agent",
                alerts_df[
                    "agent_name"
                ].dropna()
                .unique(),
                default=list(
                    alerts_df[
                        "agent_name"
                    ].dropna()
                    .unique()
                ),
                key="flt_agent",
            )

        with f3:

            search_text = st.text_input(
                "⌕ Recherche",
                "",
                placeholder=(
                    "IP, règle, destination..."
                ),
                key="flt_search",
            )

        NOISY_RULES_DEFAULT = [
            "Suricata: Alert - SURICATA QUIC failed decrypt"
        ]

        all_rules = sorted(
            alerts_df[
                "rule_description"
            ]
            .dropna()
            .unique()
        )

        default_rules = [
            rule
            for rule in all_rules
            if rule not in NOISY_RULES_DEFAULT
        ]

        f4, f5 = st.columns(
            [2, 1]
        )

        with f4:

            rule_filter = st.multiselect(
                "Règles",
                all_rules,
                default=default_rules,
                key="flt_rule",
            )

        with f5:

            level_range = st.slider(
                "Niveau de règle",
                0,
                15,
                (0, 15),
                key="flt_level",
            )

        # ----------------------------------------------------
        # APPLY FILTERS
        # ----------------------------------------------------

        effective_source = (
            source_filter
            if source_filter
            else list(
                alerts_df[
                    "source_type"
                ].unique()
            )
        )

        effective_agent = (
            agent_filter
            if agent_filter
            else list(
                alerts_df[
                    "agent_name"
                ].dropna()
                .unique()
            )
        )

        effective_rule = (
            rule_filter
            if rule_filter
            else all_rules
        )

        filtered = alerts_df[
            alerts_df[
                "source_type"
            ].isin(effective_source)

            & alerts_df[
                "agent_name"
            ].isin(effective_agent)

            & alerts_df[
                "rule_description"
            ].isin(effective_rule)

            & alerts_df[
                "rule_level"
            ]
            .fillna(0)
            .between(
                level_range[0],
                level_range[1]
            )
        ]

        if st.session_state.active_band_filter:

            filtered = filtered[
                filtered["risk_band"]
                ==
                st.session_state.active_band_filter
            ]

        if search_text:

            mask = (

                filtered[
                    "rule_description"
                ]
                .fillna("")
                .str.contains(
                    search_text,
                    case=False,
                    na=False,
                )

                |

                filtered[
                    "src_ip"
                ]
                .fillna("")
                .str.contains(
                    search_text,
                    case=False,
                    na=False,
                )

                |

                filtered[
                    "dest_ip"
                ]
                .fillna("")
                .str.contains(
                    search_text,
                    case=False,
                    na=False,
                )
            )

            filtered = filtered[mask]

        st.caption(
            f"**{len(filtered)}** alertes "
            f"correspondent aux filtres "
            f"(sur {len(alerts_df)} chargées)"
        )

        # ----------------------------------------------------
        # ALERT TABLE
        # ----------------------------------------------------

        section_header(
            "Event stream",
            "Sélectionnez une ligne pour ouvrir le drill-down",
        )

        display_cols = [
            "timestamp",
            "risk_band",
            "agent_name",
            "source_type",
            "rule_description",
            "rule_level",
            "src_ip",
            "dest_ip",
            "dest_port",
        ]

        display_df = (
            filtered[
                display_cols
                + ["alert_id"]
            ]
            .sort_values(
                "timestamp",
                ascending=False,
            )
            .reset_index(
                drop=True
            )
        )

        event = st.dataframe(
            display_df,
            use_container_width=True,
            height=430,
            on_select="rerun",
            selection_mode="single-row",
            column_order=display_cols,
            hide_index=True,
        )

        # ----------------------------------------------------
        # DRILL DOWN
        # ----------------------------------------------------

        if (
            event.selection
            and event.selection.get("rows")
        ):

            sel_idx = (
                event.selection["rows"][0]
            )

            row = display_df.iloc[
                sel_idx
            ]

            st.write("")

            section_header(
                "Alert investigation",
                "Analyse détaillée de l'événement sélectionné",
            )

            st.markdown(
                f"""
                <div class="soc-panel">

                    <div style="
                        display:flex;
                        justify-content:space-between;
                        align-items:center;
                        margin-bottom:16px;
                    ">

                        <div>

                            <div style="
                                color:{COLORS["muted"]};
                                font-size:9px;
                                text-transform:uppercase;
                                letter-spacing:1px;
                            ">
                                ALERT ID
                            </div>

                            <div style="
                                color:{COLORS["text"]};
                                font-family:'JetBrains Mono';
                                font-size:12px;
                                margin-top:4px;
                            ">
                                {row["alert_id"]}
                            </div>

                        </div>

                        <div>
                            {risk_badge(row["risk_band"])}
                        </div>

                    </div>

                </div>
                """,
                unsafe_allow_html=True,
            )

            dc1, dc2, dc3, dc4 = st.columns(4)

            with dc1:

                st.markdown(
                    f"""
                    <div class="soc-panel">

                        <div class="kpi-label">
                            TIMESTAMP
                        </div>

                        <div style="
                            color:{COLORS["text"]};
                            font-family:'JetBrains Mono';
                            font-size:11px;
                        ">
                            {row["timestamp"]}
                        </div>

                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            with dc2:

                st.markdown(
                    f"""
                    <div class="soc-panel">

                        <div class="kpi-label">
                            AGENT
                        </div>

                        <div style="
                            color:{COLORS["text"]};
                            font-size:12px;
                        ">
                            {row["agent_name"]}
                        </div>

                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            with dc3:

                st.markdown(
                    f"""
                    <div class="soc-panel">

                        <div class="kpi-label">
                            SOURCE
                        </div>

                        <div style="
                            color:{COLORS["text"]};
                            font-size:12px;
                        ">
                            {row["source_type"]}
                        </div>

                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            with dc4:

                st.markdown(
                    f"""
                    <div class="soc-panel">

                        <div class="kpi-label">
                            RULE LEVEL
                        </div>

                        <div style="
                            color:{COLORS["high"]};
                            font-size:20px;
                            font-weight:800;
                        ">
                            {row["rule_level"]}
                        </div>

                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            st.write("")

            st.markdown(
                f"""
                <div class="soc-panel">

                    <div class="kpi-label">
                        NETWORK FLOW
                    </div>

                    <div style="
                        font-family:'JetBrains Mono';
                        color:{COLORS["text_soft"]};
                        font-size:12px;
                    ">
                        {row["src_ip"]}
                        <span style="
                            color:{COLORS["cyan"]};
                        ">
                            →
                        </span>
                        {row["dest_ip"]}
                        :
                        {row["dest_port"]}
                    </div>

                    <div style="
                        margin-top:15px;
                        padding-top:12px;
                        border-top:
                        1px solid {COLORS["border"]};
                    ">

                        <div class="kpi-label">
                            DETECTION
                        </div>

                        <div style="
                            color:{COLORS["text"]};
                            font-size:13px;
                            font-weight:600;
                        ">
                            {row["rule_description"]}
                        </div>

                    </div>

                </div>
                """,
                unsafe_allow_html=True,
            )

            # ------------------------------------------------
            # TRIAGE
            # ------------------------------------------------

            st.write("")

            triage_log = load_triage_log()

            current_status = (
                triage_log
                .get(
                    row["alert_id"],
                    {}
                )
                .get(
                    "status",
                    "Nouveau"
                )
            )

            section_header(
                "Triage",
                f"Statut actuel : {current_status}",
            )

            tcol1, tcol2, tcol3, tcol4 = (
                st.columns(4)
            )

            status_map = {

                tcol1: "Nouveau",

                tcol2: "En investigation",

                tcol3: "Faux positif",

                tcol4: "Confirmé",
            }

            for col, status in (
                status_map.items()
            ):

                with col:

                    if st.button(
                        status,
                        key=(
                            f"triage_"
                            f"{row['alert_id']}_"
                            f"{status}"
                        ),
                        use_container_width=True,
                        type=(
                            "primary"
                            if current_status == status
                            else "secondary"
                        ),
                    ):

                        triage_log[
                            row["alert_id"]
                        ] = {

                            "status": status,

                            "updated_at":
                                pd.Timestamp
                                .utcnow()
                                .isoformat(),
                        }

                        save_triage_log(
                            triage_log
                        )

                        st.rerun()

            # ------------------------------------------------
            # CORRELATED ACTIVITY
            # ------------------------------------------------

            st.write("")

            section_header(
                f"Activité corrélée — {row['src_ip']}",
                "Autres événements provenant de la même source",
            )

            if row["src_ip"]:

                related = alerts_df[
                    alerts_df["src_ip"]
                    ==
                    row["src_ip"]
                ]

                st.caption(
                    f"{len(related)} événement(s) "
                    "dans la fenêtre chargée"
                )

                if len(related) > 1:

                    related_display = (
                        related[
                            [
                                "timestamp",
                                "rule_description",
                                "dest_ip",
                                "dest_port",
                            ]
                        ]
                        .sort_values(
                            "timestamp",
                            ascending=False,
                        )
                        .head(10)
                    )

                    st.dataframe(
                        related_display,
                        use_container_width=True,
                        hide_index=True,
                        height=220,
                    )

            else:

                st.caption(
                    "Pas d'IP source disponible."
                )

        # ----------------------------------------------------
        # EXPORT
        # ----------------------------------------------------

        st.write("")

        csv = (
            filtered[
                display_cols
            ]
            .to_csv(
                index=False
            )
            .encode("utf-8")
        )

        st.download_button(
            "⬇️ Exporter les alertes filtrées",
            csv,
            "alertes_soc.csv",
            "text/csv",
            use_container_width=False,
        )

        # ----------------------------------------------------
        # TIMELINE + RISK
        # ----------------------------------------------------

        st.write("")

        col_timeline, col_risk = st.columns(
            [2, 1]
        )

        with col_timeline:

            section_header(
                "Alert timeline",
                "Évolution du volume d'événements",
            )

            timeline = filtered.copy()

            timeline["timestamp"] = (
                pd.to_datetime(
                    timeline["timestamp"],
                    errors="coerce",
                )
            )

            timeline = timeline.dropna(
                subset=["timestamp"]
            )

            if not timeline.empty:

                timeline_counts = (
                    timeline
                    .set_index("timestamp")
                    .resample("1min")
                    .size()
                    .reset_index(
                        name="count"
                    )
                )

                fig_t = px.area(
                    timeline_counts,
                    x="timestamp",
                    y="count",
                )

                fig_t.update_traces(
                    line_color=COLORS["critical"],
                    fillcolor="rgba(255,77,90,0.12)",
                )

                fig_t = make_plot_layout(
                    fig_t,
                    290
                )

                st.plotly_chart(
                    fig_t,
                    use_container_width=True,
                    config={
                        "displayModeBar": False
                    },
                )

        with col_risk:

            section_header(
                "Risk distribution",
                "Répartition des bandes de risque",
            )

            if not filtered.empty:

                bc = (
                    filtered[
                        "risk_band"
                    ]
                    .value_counts()
                    .reset_index()
                )

                bc.columns = [
                    "risk_band",
                    "count",
                ]

                fig_b = go.Figure(
                    data=[
                        go.Pie(
                            labels=bc[
                                "risk_band"
                            ],
                            values=bc[
                                "count"
                            ],
                            hole=0.62,
                            marker_colors=[
                                RISK_COLORS.get(
                                    band,
                                    COLORS["muted"]
                                )
                                for band in bc[
                                    "risk_band"
                                ]
                            ],
                            textinfo="percent",
                        )
                    ]
                )

                fig_b.update_layout(
                    showlegend=True,
                    legend=dict(
                        font=dict(
                            size=9
                        )
                    ),
                )

                fig_b = make_plot_layout(
                    fig_b,
                    290
                )

                st.plotly_chart(
                    fig_b,
                    use_container_width=True,
                    config={
                        "displayModeBar": False
                    },
                )


# ============================================================
# PAGE 3 — MITRE ATT&CK
# ============================================================

elif page == "🗺️ Carte MITRE ATT&CK":

    render_header(
        "MITRE ATT&CK",
        "Cartographie des tactiques couvertes par le moteur"
    )

    TACTIC_DESCRIPTIONS_STATIC = {

        "Impact": {
            "id": "TA0040",
            "desc":
                "Perturbation de disponibilité (DoS)",
        },

        "Reconnaissance": {
            "id": "TA0043",
            "desc":
                "Sondage / collecte d'information",
        },

        "InitialAccess_CredentialAccess": {
            "id":
                "TA0001/TA0006",
            "desc":
                "Accès non autorisé / "
                "vol d'identifiants",
        },

        "PrivilegeEscalation": {
            "id": "TA0004",
            "desc":
                "Élévation de privilèges",
        },
    }

    tactic_report = (
        load_tactic_report()
    )

    if tactic_report:

        tactic_info = {

            tactic: {

                "id":
                    TACTIC_DESCRIPTIONS_STATIC[
                        tactic
                    ]["id"],

                "desc":
                    TACTIC_DESCRIPTIONS_STATIC[
                        tactic
                    ]["desc"],

                "f1":
                    tactic_report[
                        "per_tactic"
                    ][tactic][
                        "f1_score"
                    ],
            }

            for tactic
            in TACTIC_DESCRIPTIONS_STATIC

            if tactic in
            tactic_report.get(
                "per_tactic",
                {}
            )
        }

        try:

            generated_dt = (
                datetime.fromisoformat(
                    tactic_report[
                        "generated_at"
                    ]
                )
            )

            generated_label = (
                generated_dt.strftime(
                    "%d/%m/%Y à %H:%M UTC"
                )
            )

        except (
            ValueError,
            TypeError,
            KeyError,
        ):

            generated_label = (
                tactic_report.get(
                    "generated_at",
                    "date inconnue"
                )
            )

        coverage = (
            tactic_report.get(
                "attack_type_coverage",
                {}
            )
        )

        st.caption(
            f"Métriques générées le "
            f"**{generated_label}** — "
            f"{coverage.get('total_types_mapped', '?')} "
            "types d'attaque NSL-KDD couverts."
        )

    else:

        tactic_info = {

            "Impact": {
                "id": "TA0040",
                "desc":
                    "Perturbation de disponibilité (DoS)",
                "f1": 1.00,
            },

            "Reconnaissance": {
                "id": "TA0043",
                "desc":
                    "Sondage / collecte d'information",
                "f1": 0.91,
            },

            "InitialAccess_CredentialAccess": {
                "id":
                    "TA0001/TA0006",
                "desc":
                    "Accès non autorisé / vol d'identifiants",
                "f1": 0.75,
            },

            "PrivilegeEscalation": {
                "id": "TA0004",
                "desc":
                    "Élévation de privilèges",
                "f1": 0.14,
            },
        }

        st.warning(
            "Métriques du modèle indisponibles — "
            "valeurs de référence affichées."
        )

    # --------------------------------------------------------
    # TACTIC CARDS
    # --------------------------------------------------------

    section_header(
        "Tactic coverage",
        "Performance du classificateur par tactique",
    )

    cols = st.columns(
        len(tactic_info)
    )

    for col, (
        tactic,
        info
    ) in zip(
        cols,
        tactic_info.items()
    ):

        with col:

            if info["f1"] >= 0.8:

                color = COLORS["low"]

            elif info["f1"] >= 0.5:

                color = COLORS["medium"]

            else:

                color = COLORS["critical"]

            st.markdown(
                f"""
                <div class="mitre-card"
                     style="
                     border-top:
                     2px solid {color};
                     ">

                    <div class="mitre-id">
                        {info["id"]}
                    </div>

                    <div class="mitre-name">
                        {tactic.replace("_", " / ")}
                    </div>

                    <div class="mitre-desc">
                        {info["desc"]}
                    </div>

                    <div class="mitre-f1"
                         style="color:{color};">

                        {info["f1"]:.2f}

                    </div>

                    <div style="
                        color:{COLORS["muted_2"]};
                        font-size:9px;
                        margin-top:3px;
                    ">
                        F1 SCORE
                    </div>

                </div>
                """,
                unsafe_allow_html=True,
            )

    # --------------------------------------------------------
    # PERFORMANCE CHART
    # --------------------------------------------------------

    st.write("")

    section_header(
        "Model performance",
        "F1-score mesuré lors de la validation",
    )

    df_tactic = pd.DataFrame(
        [
            {
                "Tactique":
                    k.replace(
                        "_",
                        " / "
                    ),

                "F1-score":
                    v["f1"],
            }

            for k, v
            in tactic_info.items()
        ]
    )

    fig = px.bar(
        df_tactic,
        x="F1-score",
        y="Tactique",
        orientation="h",
        range_x=[0, 1],
        text="F1-score",
    )

    fig.update_traces(
        texttemplate="%{text:.2f}",
        textposition="outside",
        marker_color=COLORS["blue"],
    )

    fig.update_layout(
        xaxis=dict(
            range=[0, 1],
            tickformat=".0%",
        ),
        yaxis=dict(
            categoryorder="total ascending"
        ),
    )

    fig = make_plot_layout(
        fig,
        320
    )

    st.plotly_chart(
        fig,
        use_container_width=True,
        config={
            "displayModeBar": False
        },
    )

    # --------------------------------------------------------
    # NOTE
    # --------------------------------------------------------

    pe_precision = (
        tactic_info
        .get(
            "PrivilegeEscalation",
            {}
        )
        .get(
            "f1"
        )
    )

    if pe_precision is not None:

        st.warning(
            f"⚠️ **PrivilegeEscalation** "
            f"présente un F1 de "
            f"**{pe_precision:.2f}**. "
            "Cette catégorie nécessite une "
            "attention manuelle systématique "
            "dans l'interprétation des résultats."
        )


# ============================================================
# PAGE 4 — ANALYSIS ENGINE
# ============================================================

elif page == "🧠 Moteur d'analyse":

    render_header(
        "Moteur d'analyse",
        "Analyse ML et classification tactique sur NSL-KDD"
    )

    # --------------------------------------------------------
    # CONTROL PANEL
    # --------------------------------------------------------

    section_header(
        "Analysis workspace",
        "Lancez une analyse sur un échantillon du jeu de test",
    )

    st.markdown(
        '<div class="soc-panel">',
        unsafe_allow_html=True,
    )

    sample_size = st.slider(
        "Nombre d'échantillons à analyser",
        10,
        200,
        50,
    )

    st.markdown(
        f"""
        <div style="
            display:flex;
            justify-content:space-between;
            margin-top:8px;
            color:{COLORS["muted"]};
            font-size:10px;
        ">

            <span>
                NSL-KDD test dataset
            </span>

            <span>
                {sample_size} samples
            </span>

        </div>
        """,
        unsafe_allow_html=True,
    )

    st.write("")

    if st.button(
        "▶  Lancer l'analyse",
        type="primary",
        use_container_width=True,
    ):

        with st.spinner(
            "Analyse ML en cours..."
        ):

            X_train, y_train, X_test, y_test, train_labels, test_labels, encoders = preprocess(
                "data/nsl-kdd/KDDTrain+.txt",
                "data/nsl-kdd/KDDTest+.txt",
            )

            engine = get_engine()

            idx = (
                X_test
                .sample(
                    n=sample_size,
                    random_state=42,
                )
                .index
            )

            analysis = engine.analyze(
                X_test.loc[idx],
                true_labels=
                    test_labels.loc[idx],
            )

            st.session_state[
                "last_analysis"
            ] = analysis

    st.markdown(
        "</div>",
        unsafe_allow_html=True,
    )

    # --------------------------------------------------------
    # RESULTS
    # --------------------------------------------------------

    if "last_analysis" in st.session_state:

        analysis = (
            st.session_state[
                "last_analysis"
            ]
        )

        st.write("")

        # ----------------------------------------------------
        # QUICK METRICS
        # ----------------------------------------------------

        total_samples = len(
            analysis
        )

        critical_count = (
            analysis[
                "risk_band"
            ]
            .eq("critical")
            .sum()
        )

        high_count = (
            analysis[
                "risk_band"
            ]
            .eq("high")
            .sum()
        )

        anomaly_count = (
            analysis[
                "flagged_by_anomaly_detector"
            ]
            .eq(1)
            .sum()
        )

        section_header(
            "Analysis results",
            f"{total_samples} événements analysés",
        )

        m1, m2, m3, m4 = st.columns(4)

        metrics = [

            (
                m1,
                "ÉCHANTILLONS",
                total_samples,
                COLORS["blue"],
            ),

            (
                m2,
                "CRITICAL",
                critical_count,
                COLORS["critical"],
            ),

            (
                m3,
                "HIGH",
                high_count,
                COLORS["high"],
            ),

            (
                m4,
                "ANOMALIES",
                anomaly_count,
                COLORS["purple"],
            ),
        ]

        for (
            col,
            label,
            value,
            color,
        ) in metrics:

            with col:

                st.markdown(
                    f"""
                    <div class="kpi-card"
                         style="--accent:{color};">

                        <div class="kpi-label">
                            {label}
                        </div>

                        <div class="kpi-value">
                            {value}
                        </div>

                    </div>
                    """,
                    unsafe_allow_html=True,
                )

        # ----------------------------------------------------
        # TABLE + CHART
        # ----------------------------------------------------

        st.write("")

        col_table, col_chart = st.columns(
            [2.3, 1]
        )

        with col_table:

            section_header(
                "Analyzed events",
                "Résultats détaillés du moteur",
            )

            display = analysis[
                [
                    "true_label",
                    "risk_score",
                    "risk_band",
                    "flagged_by_anomaly_detector",
                    "predicted_tactic",
                    "tactic_confidence",
                    "mitre_id",
                    "recommendation",
                ]
            ].copy()

            display[
                "risk_score"
            ] = display[
                "risk_score"
            ].round(3)

            display[
                "tactic_confidence"
            ] = display[
                "tactic_confidence"
            ].round(3)

            display[
                "flagged_by_anomaly_detector"
            ] = display[
                "flagged_by_anomaly_detector"
            ].map(
                {
                    1:
                        "🔍 Isolation Forest",
                    0:
                        "",
                }
            )

            display = display.rename(
                columns={
                    "true_label":
                        "True label",

                    "risk_score":
                        "Risk score",

                    "risk_band":
                        "Risk",

                    "flagged_by_anomaly_detector":
                        "Anomaly detector",

                    "predicted_tactic":
                        "MITRE tactic",

                    "tactic_confidence":
                        "Confidence",

                    "mitre_id":
                        "MITRE ID",

                    "recommendation":
                        "Recommendation",
                }
            )

            st.dataframe(
                display,
                use_container_width=True,
                height=500,
                hide_index=True,
            )

        with col_chart:

            section_header(
                "Risk distribution",
                "Répartition des scores",
            )

            bc = (
                analysis[
                    "risk_band"
                ]
                .value_counts()
                .reset_index()
            )

            bc.columns = [
                "risk_band",
                "count",
            ]

            fig = go.Figure(
                data=[
                    go.Pie(
                        labels=bc[
                            "risk_band"
                        ],
                        values=bc[
                            "count"
                        ],
                        hole=0.64,
                        marker_colors=[
                            RISK_COLORS.get(
                                band,
                                COLORS["muted"],
                            )
                            for band in bc[
                                "risk_band"
                            ]
                        ],
                        textinfo="percent",
                    )
                ]
            )

            fig.update_layout(
                showlegend=True,
                legend=dict(
                    font=dict(
                        size=9
                    )
                ),
            )

            fig = make_plot_layout(
                fig,
                340
            )

            st.plotly_chart(
                fig,
                use_container_width=True,
                config={
                    "displayModeBar": False
                },
            )

            # ----------------------------------------------
            # TACTIC DISTRIBUTION
            # ----------------------------------------------

            section_header(
                "Predicted tactics",
                "Classification MITRE du modèle",
            )

            if (
                "predicted_tactic"
                in analysis.columns
            ):

                tactic_counts = (
                    analysis[
                        "predicted_tactic"
                    ]
                    .fillna("Unknown")
                    .value_counts()
                    .head(8)
                )

                for tactic, count in (
                    tactic_counts.items()
                ):

                    percentage = (
                        count /
                        len(analysis)
                        * 100
                    )

                    st.markdown(
                        f"""
                        <div style="
                            margin-bottom:10px;
                        ">

                            <div style="
                                display:flex;
                                justify-content:space-between;
                                color:{COLORS["text_soft"]};
                                font-size:10px;
                                margin-bottom:4px;
                            ">

                                <span>
                                    {tactic}
                                </span>

                                <span>
                                    {count}
                                </span>

                            </div>

                            <div style="
                                height:5px;
                                background:#18212B;
                                border-radius:5px;
                            ">

                                <div style="
                                    width:{percentage:.0f}%;
                                    height:5px;
                                    background:{COLORS["cyan"]};
                                    border-radius:5px;
                                "></div>

                            </div>

                        </div>
                        """,
                        unsafe_allow_html=True,
                    )


# ============================================================
# FOOTER
# ============================================================

st.markdown(
    """
    <div class="soc-footer">
        SOC AICYOU · Threat Intelligence & AI Detection
        · Research & Development Prototype
    </div>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# AUTO REFRESH
# ============================================================

if (
    auto_refresh
    and page != "🧠 Moteur d'analyse"
):

    time.sleep(30)

    st.rerun()
