"""CloudGuard | Azure Cloud Security & Compliance Platform - Dashboard SOC.

Couche de présentation en LECTURE SEULE.
Elle lit uniquement l'historique local ``data/audits.json`` produit par le
backend FastAPI. Elle n'appelle jamais Azure, ne déclenche aucun audit et ne
modifie ni le moteur de règles, ni le calcul de conformité, ni le stockage.

Lancement (depuis la racine du projet, pour que .streamlit/config.toml soit lu) :
    streamlit run dashboard/app.py
"""

from __future__ import annotations

import json
import math
import os
from collections import Counter
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

# =============================================================================
# Constantes
# =============================================================================
PROJECT_ROOT = Path(__file__).resolve().parents[1]
HISTORY_FILE = PROJECT_ROOT / "data" / "audits.json"
LOGO_FILE = PROJECT_ROOT / "assets" / "cloudguard-logo.png"
API_URL_ENV = "CLOUDGUARD_API_URL"  # optionnel : ex. http://127.0.0.1:8000

PALETTE = {
    "bg": "#F4F7FB",
    "panel": "#FFFFFF",
    "panel2": "#F7FAFE",
    "border": "#DCE5F0",
    "text": "#142849",
    "muted": "#607798",
    "cyan": "#1677FF",
    "green": "#0FAF8A",
    "red": "#F0445E",
    "amber": "#E99418",
    "purple": "#7C67E8",
    "slate": "#91A4BE",
}

STATUS_ORDER = ["PASS", "FAIL", "UNKNOWN", "ERROR", "NOT_APPLICABLE"]
STATUS_LABELS = {
    "PASS": "Conforme",
    "FAIL": "Échec",
    "UNKNOWN": "Inconnu",
    "ERROR": "Erreur",
    "NOT_APPLICABLE": "Non applicable",
}
STATUS_COLORS = {
    "PASS": PALETTE["green"],
    "FAIL": PALETTE["red"],
    "UNKNOWN": PALETTE["amber"],
    "ERROR": PALETTE["purple"],
    "NOT_APPLICABLE": PALETTE["slate"],
}
# Ordre de tri dans les tables : ce qui demande une action d'abord.
STATUS_SORT = ["FAIL", "ERROR", "UNKNOWN", "PASS", "NOT_APPLICABLE"]
ACTIONABLE_STATUSES = ["FAIL", "UNKNOWN", "ERROR"]

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_NONE = "N/D"
SEVERITY_COLORS = {
    "CRITICAL": "#C8102E",
    "HIGH": PALETTE["red"],
    "MEDIUM": PALETTE["amber"],
    "LOW": PALETTE["cyan"],
    "INFO": PALETTE["muted"],
    SEVERITY_NONE: PALETTE["slate"],
}

PAGES = ["Vue globale", "Findings & remédiation", "Ressources", "Historique"]
NOT_PROVIDED = "Non renseigné"

# Pastilles colorées dans les tableaux HTML (valeur affichée -> teinte).
BADGE_TONES = {
    "Conforme": "ok",
    "Échec": "bad",
    "Inconnu": "warn",
    "Erreur": "purple",
    "Non applicable": "muted",
    "CRITICAL": "crit",
    "HIGH": "bad",
    "MEDIUM": "warn",
    "LOW": "info",
    "INFO": "muted",
    "Nouvel échec": "bad",
    "Corrigé": "ok",
    "Persistant": "warn",
    "Statut modifié": "info",
    "Absent de l'audit comparé": "muted",
    "Absent": "muted",
    "Amélioration": "ok",
    "Dégradation": "bad",
    "Stable": "muted",
}
BADGE_COLUMNS = {
    "Statut",
    "Gravité",
    "Gravité max (échecs)",
    "Évolution",
    "Tendance",
    "Avant",
    "Après",
}

# Icônes (style Lucide, tracé 24x24) pour les cartes KPI.
ICONS = {
    "shield": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>',
    "server": '<rect x="2" y="3" width="20" height="8" rx="2"/><rect x="2" y="13" width="20" height="8" rx="2"/><path d="M6 7h.01M6 17h.01"/>',
    "x": '<circle cx="12" cy="12" r="10"/><path d="m15 9-6 6M9 9l6 6"/>',
    "alert": '<path d="m21.7 18-8-14a2 2 0 0 0-3.4 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.7-3z"/><path d="M12 9v4M12 17h.01"/>',
    "check": '<circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/>',
    "search": '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>',
}

CSS = """
:root, .stApp { color-scheme: light; }
.stApp { background: #F4F7FB; color: #142849;
  font-family: Inter, "Segoe UI Variable", "Segoe UI", system-ui, sans-serif; }

/* ---------- Structure générale ---------- */
[data-testid="stHeader"] { background: transparent !important; height: 0 !important; min-height: 0 !important; border: 0 !important; box-shadow: none !important; }
[data-testid="stToolbar"] { top: .35rem !important; right: .65rem !important; z-index: 1000 !important; }
[data-testid="stAppDeployButton"], .stDeployButton { display: none !important; }
[data-testid="stMainBlockContainer"], .block-container { max-width: 1500px; padding: 1.5rem 2rem 2.5rem !important; }
hr { border-color: #E2EAF4; }

[data-testid="stMain"] [data-testid="stMarkdownContainer"],
[data-testid="stMain"] h1, [data-testid="stMain"] h2, [data-testid="stMain"] h3, [data-testid="stMain"] h4 { color: #142849; }
[data-testid="stMain"] [data-testid="stCaptionContainer"], [data-testid="stMain"] [data-testid="stCaptionContainer"] * { color: #526B8D !important; opacity: 1 !important; }
[data-testid="stMain"] [data-testid="stWidgetLabel"] p { font-size: .76rem !important; font-weight: 700 !important; color: #526B8D !important; margin-bottom: .3rem !important; }
.stAlert p, [data-testid="stAlert"] p { color: #263F5F !important; }
[data-testid="stAlert"] { border-radius: 11px; border: 1px solid #D7E3F2; }

/* ---------- En-têtes de page ---------- */
.cg-eyebrow { color: #1677FF; font-size: .68rem; font-weight: 800; letter-spacing: 1.8px; text-transform: uppercase; }
.cg-title { font-size: 2rem; font-weight: 820; letter-spacing: -.8px; color: #142849; margin: .18rem 0 .25rem; line-height: 1.15; }
.cg-subtitle { color: #607798; font-size: .88rem; margin-bottom: 1rem; }
.cg-context { display: flex; flex-wrap: wrap; gap: .45rem 1.4rem; background: #FFFFFF; border: 1px solid #DCE6F2; border-radius: 12px; padding: .75rem 1rem; margin: .3rem 0 1.1rem; font-size: .77rem; color: #607798; }
.cg-context b { color: #203B60; font-weight: 700; margin-left: .35rem; overflow-wrap: anywhere; }
.cg-section { font-size: 1.04rem; font-weight: 780; color: #142849; margin: 1.5rem 0 .15rem; }
.cg-section-sub { font-size: .78rem; color: #7186A4; margin-bottom: .7rem; }

/* ---------- Barre latérale ---------- */
[data-testid="stSidebar"], [data-testid="stSidebar"] > div:first-child {
  background: linear-gradient(180deg, #0F3F7A 0%, #0A2F60 100%) !important; }
[data-testid="stSidebar"] { border-right: 1px solid #0A2B57 !important; }
[data-testid="stSidebar"][aria-expanded="true"] { width: 300px !important; min-width: 300px !important; }
[data-testid="stSidebar"] > div:first-child { padding: 1rem .9rem 1.5rem !important; }
[data-testid="stSidebar"] [data-testid="stMarkdownContainer"],
[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p,
[data-testid="stSidebar"] [data-testid="stWidgetLabel"],
[data-testid="stSidebar"] [data-testid="stWidgetLabel"] p,
[data-testid="stSidebar"] label { color: #EAF3FF !important; }
[data-testid="stSidebar"] [data-testid="stWidgetLabel"] p { font-size: .72rem !important; font-weight: 700 !important; color: #AFCDF5 !important; }

/* Logo : posé sur une carte blanche arrondie, intégrée à la barre. */
[data-testid="stSidebar"] [data-testid="stImage"] {
  background: #FFFFFF; border-radius: 14px; padding: .65rem .8rem;
  margin: .2rem 0 .5rem; box-shadow: 0 6px 18px rgba(0,16,45,.22); }
[data-testid="stSidebar"] [data-testid="stImage"] img { display: block; margin: 0 auto; border-radius: 6px; }
[data-testid="stSidebar"] [data-testid="StyledFullScreenButton"],
[data-testid="stSidebar"] [data-testid="stElementToolbar"],
[data-testid="stSidebar"] [data-testid="stImage"] button,
[data-testid="stSidebar"] button[title="View fullscreen"] { display: none !important; }
[data-testid="stSidebar"] [data-testid="stImage"] img { pointer-events: none; user-select: none; }
[data-testid="stSidebarCollapseButton"] button, [data-testid="stSidebarCollapsedControl"] button { color: #CFE2FA !important; }
.cg-brand { font-size: 1.6rem; font-weight: 850; letter-spacing: -.7px; color: #FFFFFF; line-height: 1.1; padding: .4rem .2rem 0; }
.cg-brand span { color: #6DB4FF; }
.cg-brand-sub { font-size: .64rem; color: #BCD5F4 !important; letter-spacing: 1.3px; margin: .3rem .2rem 1.1rem; text-transform: uppercase; }

.cg-side-label { font-size: .66rem; color: #9CC2F2 !important; font-weight: 800; letter-spacing: 1.25px; text-transform: uppercase; margin: 1.5rem 0 .55rem; }
[data-testid="stSidebar"] .cg-side-box { background: rgba(255,255,255,.08); border: 1px solid rgba(255,255,255,.18); border-radius: 11px; padding: .7rem .8rem; font-size: .76rem; color: #D5E5FB !important; line-height: 1.65; overflow-wrap: anywhere; }
[data-testid="stSidebar"] .cg-side-box b { color: #FFFFFF !important; font-weight: 700; }

/* Navigation : vrais boutons, aucun radio visible. */
[data-testid="stSidebar"] [data-testid^="stBaseButton"], [data-testid="stSidebar"] .stButton button {
  width: 100%; min-height: 2.7rem; justify-content: flex-start !important; padding: .55rem .85rem !important;
  margin: .12rem 0; border-radius: 9px !important; border: 1px solid transparent !important;
  background: transparent !important; box-shadow: none !important; }
[data-testid="stSidebar"] [data-testid^="stBaseButton"] > div, [data-testid="stSidebar"] .stButton button > div { justify-content: flex-start !important; text-align: left; width: 100%; }
[data-testid="stSidebar"] [data-testid^="stBaseButton"] p, [data-testid="stSidebar"] .stButton button p { color: #EAF3FF !important; font-weight: 600; font-size: .9rem; }
[data-testid="stSidebar"] [data-testid^="stBaseButton"]:hover, [data-testid="stSidebar"] .stButton button:hover {
  background: rgba(255,255,255,.12) !important; border-color: rgba(255,255,255,.18) !important; }
[data-testid="stSidebar"] [data-testid="stBaseButton-primary"], [data-testid="stSidebar"] button[kind="primary"] {
  background: #FFFFFF !important; border-color: #FFFFFF !important; box-shadow: inset 4px 0 0 #1677FF !important; }
[data-testid="stSidebar"] [data-testid="stBaseButton-primary"] [data-testid="stMarkdownContainer"] p,
[data-testid="stSidebar"] button[kind="primary"] [data-testid="stMarkdownContainer"] p,
[data-testid="stSidebar"] [data-testid="stBaseButton-primary"] p { color: #0B3B78 !important; font-weight: 800; }
.st-key-refresh_btn button { justify-content: center !important; border: 1px solid rgba(255,255,255,.35) !important; margin-top: .6rem; }
.st-key-refresh_btn button > div { justify-content: center !important; }

/* ---------- Champs de saisie et filtres ---------- */
[data-baseweb="input"], [data-baseweb="base-input"], [data-baseweb="textarea"] {
  background: #FFFFFF !important; border-color: #C8D7EA !important; border-radius: 10px !important; }
[data-baseweb="input"] { border: 1px solid #C8D7EA !important; min-height: 2.65rem; box-shadow: 0 1px 2px rgba(16,42,76,.04); transition: border-color .15s, box-shadow .15s; }
[data-baseweb="base-input"] { border: 0 !important; background: transparent !important; }
[data-baseweb="input"]:focus-within, [data-baseweb="select"] > div:focus-within {
  border-color: #3285F6 !important; box-shadow: 0 0 0 3px rgba(22,119,255,.14) !important; }
[data-baseweb="input"] input, [data-baseweb="textarea"] textarea {
  background: transparent !important; color: #17365D !important; padding: .55rem .8rem !important; }
input::placeholder, textarea::placeholder { color: #8A9CB4 !important; opacity: 1 !important; }

/* Listes déroulantes : tous les descendants transparents, seul le conteneur est blanc. */
[data-baseweb="select"] div { background-color: transparent !important; }
[data-baseweb="select"] > div {
  background-color: #FFFFFF !important; border: 1px solid #C8D7EA !important; border-radius: 10px !important;
  min-height: 2.65rem; box-shadow: 0 1px 2px rgba(16,42,76,.04); transition: border-color .15s, box-shadow .15s; }
[data-baseweb="select"] span, [data-baseweb="select"] input, [data-baseweb="select"] div { color: #17365D; }
[data-baseweb="select"] input { background: transparent !important; }
[data-baseweb="select"] svg { fill: #607798 !important; color: #607798 !important; }
[data-baseweb="select"] [data-baseweb="tag"] {
  background-color: #E7F0FF !important; border: 1px solid #C6DAF8 !important; border-radius: 6px !important; }
[data-baseweb="select"] [data-baseweb="tag"] div { background-color: transparent !important; }
[data-baseweb="select"] [data-baseweb="tag"] span, [data-baseweb="select"] [data-baseweb="tag"] div, [data-baseweb="select"] [data-baseweb="tag"] svg { color: #164B86 !important; fill: #164B86 !important; }
/* Dans la barre latérale les valeurs restent sombres sur fond blanc. */
[data-testid="stSidebar"] [data-baseweb="select"] > div { border-color: rgba(255,255,255,.55) !important; }

/* Menus déroulants : rendus dans un portail hors de .stApp, donc sans préfixe. */
[data-baseweb="popover"], [data-baseweb="popover"] > div, [data-baseweb="menu"], ul[role="listbox"] {
  background: #FFFFFF !important; color: #17365D !important; }
[data-baseweb="popover"] > div { border: 1px solid #D7E3F2 !important; border-radius: 10px !important; box-shadow: 0 10px 28px rgba(16,42,76,.16) !important; }
li[role="option"], li[role="option"] div, li[role="option"] span { background: transparent !important; color: #17365D !important; }
li[role="option"] { padding: .55rem .8rem !important; }
li[role="option"]:hover, li[role="option"][aria-selected="true"] { background: #EAF3FF !important; }

/* Panneau de filtres */
[class*="st-key-filters_panel"] { background: #FFFFFF; border: 1px solid #DCE6F2; border-radius: 14px; padding: 1rem 1.2rem .6rem; margin-bottom: 1rem; box-shadow: 0 1px 3px rgba(20,50,90,.04); }

/* ---------- Boutons ---------- */
[data-testid="stMain"] .stButton button, [data-testid="stMain"] .stDownloadButton button, [data-testid="stLinkButton"] a {
  border-radius: 10px; border: 1px solid #CFDDEE; background: #FFFFFF; color: #244267; font-weight: 650; min-height: 2.6rem; transition: all .16s ease; }
[data-testid="stMain"] .stButton button:hover, [data-testid="stMain"] .stDownloadButton button:hover, [data-testid="stLinkButton"] a:hover {
  border-color: #1677FF; color: #1265D8; background: #EFF6FF; }
.stTabs [data-baseweb="tab"] { color: #607798; font-weight: 650; }
.stTabs [aria-selected="true"] { color: #1677FF; }

/* ---------- Expanders et code ---------- */
[data-testid="stExpander"] { border: 1px solid #DCE5F0; border-radius: 12px; background: #FFFFFF; overflow: hidden; margin: .25rem 0 .45rem; }
[data-testid="stExpander"] details, [data-testid="stExpander"] details > div { background: #FFFFFF !important; }
[data-testid="stExpander"] summary { background: #F7FAFE !important; }
[data-testid="stExpander"] summary:hover { background: #EEF5FF !important; }
[data-testid="stExpander"] summary, [data-testid="stExpander"] summary p, [data-testid="stExpander"] summary span { color: #17365D !important; font-weight: 650; }
.stApp .stCode, .stApp pre, .stApp pre code { background: #F4F7FB !important; color: #193454 !important; border-radius: 9px; }
.stApp [data-testid="stCode"] { border: 1px solid #DCE5F0; border-radius: 10px; }
[data-testid="stCode"] pre, [data-testid="stCode"] code { white-space: pre-wrap !important; word-break: break-all !important; }

/* ---------- Cartes KPI ---------- */
.cg-kpi { position: relative; display: flex; flex-direction: column; height: 156px; margin-bottom: .9rem; box-sizing: border-box;
  background: #FFFFFF; border: 1px solid #E0E8F3; border-radius: 16px; padding: 1rem 1.05rem .95rem;
  box-shadow: 0 1px 2px rgba(20,50,90,.04), 0 6px 18px rgba(20,50,90,.05); transition: box-shadow .18s ease, transform .18s ease; }
.cg-kpi:hover { transform: translateY(-2px); box-shadow: 0 2px 4px rgba(20,50,90,.05), 0 12px 26px rgba(20,50,90,.09); }
.cg-kpi-top { display: flex; align-items: center; justify-content: space-between; gap: .6rem; }
.cg-kpi-label { font-size: .68rem; font-weight: 800; letter-spacing: .8px; text-transform: uppercase; color: #5E7393; line-height: 1.3; }
.cg-kpi-icon { flex: 0 0 auto; width: 34px; height: 34px; border-radius: 10px; display: inline-flex; align-items: center; justify-content: center; background: #EDF1F6; color: #5E7393; }
.cg-kpi-icon svg { width: 18px; height: 18px; }
.cg-kpi-value { font-size: 2.05rem; font-weight: 820; letter-spacing: -.9px; color: #102A4C; line-height: 1.1; margin: .7rem 0 .25rem; }
.cg-kpi-note { font-size: .74rem; color: #607798; line-height: 1.4; margin-top: auto; }
.cg-kpi-bar { height: 6px; border-radius: 999px; background: #E8EEF6; margin-top: .65rem; overflow: hidden; }
.cg-kpi-bar span { display: block; height: 100%; border-radius: 999px; background: #8BA4C4; }
.cg-kpi.cg-info .cg-kpi-icon { background: #E6F0FF; color: #1677FF; }
.cg-kpi.cg-ok .cg-kpi-icon { background: #DDF5EE; color: #0A9474; }
.cg-kpi.cg-bad .cg-kpi-icon { background: #FDE8EC; color: #D8344F; }
.cg-kpi.cg-warn .cg-kpi-icon { background: #FDF0D8; color: #C77A06; }
.cg-kpi.cg-info .cg-kpi-bar span { background: #1677FF; }
.cg-kpi.cg-ok .cg-kpi-bar span { background: #0FAF8A; }
.cg-kpi.cg-bad .cg-kpi-bar span { background: #F0445E; }
.cg-kpi.cg-warn .cg-kpi-bar span { background: #E99418; }

[data-testid="stMetric"] { background: #FFFFFF; border: 1px solid #E0E8F3; border-radius: 14px; padding: .85rem 1rem; min-height: 92px;
  box-shadow: 0 1px 2px rgba(20,50,90,.04), 0 4px 12px rgba(20,50,90,.04); }
[data-testid="stMetricLabel"] p { color: #607798 !important; font-weight: 700 !important; font-size: .74rem !important; text-transform: uppercase; letter-spacing: .5px; }
[data-testid="stMetricValue"] { color: #102A4C; font-weight: 800; letter-spacing: -.5px; }

/* ---------- Tableaux HTML ---------- */
.cg-table-wrap { width: 100%; overflow: auto; border: 1px solid #D7E2EF; border-radius: 12px; background: #FFFFFF; margin: .35rem 0 .75rem; }
.cg-data-table { width: 100%; border-collapse: separate; border-spacing: 0; background: #FFFFFF; color: #193454; font-size: .8rem; line-height: 1.5; }
.cg-data-table thead tr { text-align: left !important; }
.cg-data-table thead th { position: sticky; top: 0; z-index: 1; background: #EDF4FC; color: #183A63; font-weight: 750; font-size: .74rem; text-align: left !important; padding: .72rem .8rem; border-bottom: 1px solid #D2DFEF; white-space: nowrap; }
.cg-data-table tbody td { background: #FFFFFF; color: #203B5C; padding: .62rem .8rem; border-bottom: 1px solid #E8EEF6; vertical-align: top; min-width: 70px; }
.cg-data-table tbody tr:nth-child(even) td { background: #F8FAFD; }
.cg-data-table tbody tr:hover td { background: #EEF6FF; }
.cg-data-table tbody tr:last-child td { border-bottom: 0; }
.cg-data-table td, .cg-data-table th { overflow-wrap: break-word; }
.cg-id { display: inline-block; min-width: 240px; max-width: 520px; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: .72rem; color: #3A5578; word-break: break-all; }
.cg-nowrap { white-space: nowrap; }
.cg-badge { display: inline-block; padding: .12rem .6rem; border-radius: 999px; font-size: .72rem; font-weight: 700; white-space: nowrap; }
.cg-b-bad { background: #FDE8EC; color: #B3213A; }
.cg-b-crit { background: #F8D2DA; color: #8E1229; }
.cg-b-ok { background: #DDF5EE; color: #0A7A60; }
.cg-b-warn { background: #FDF0D8; color: #9A5F06; }
.cg-b-purple { background: #EBE7FC; color: #4F3CB5; }
.cg-b-info { background: #E3EFFF; color: #1257B8; }
.cg-b-muted { background: #EDF1F6; color: #52667F; }

.stApp button:focus-visible, .stApp a:focus-visible { outline: 2px solid #1677FF !important; outline-offset: 2px !important; }

@media (max-width: 1100px) {
  [data-testid="stMainBlockContainer"], .block-container { padding-left: 1.25rem !important; padding-right: 1.25rem !important; }
  .cg-title { font-size: 1.7rem; }
  .cg-kpi { height: 150px; }
}
@media (max-width: 900px) {
  .cg-title { font-size: 1.5rem; }
  .cg-data-table { font-size: .74rem; }
  .cg-data-table thead th, .cg-data-table tbody td { padding: .5rem .6rem; }
}
"""


# =============================================================================
# Compatibilité Streamlit
# =============================================================================
def _streamlit_version() -> tuple[int, int]:
    parts: list[int] = []
    for chunk in str(getattr(st, "__version__", "0.0")).split(".")[:2]:
        digits = "".join(ch for ch in chunk if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    while len(parts) < 2:
        parts.append(0)
    return parts[0], parts[1]


_STRETCH_NEW: dict[str, Any] = {"width": "stretch"}
_STRETCH_OLD: dict[str, Any] = {"use_container_width": True}
_STRETCH_ORDER = (
    (_STRETCH_NEW, _STRETCH_OLD)
    if _streamlit_version() >= (1, 50)
    else (_STRETCH_OLD, _STRETCH_NEW)
)


def stretch(func: Any, *args: Any, **kwargs: Any) -> Any:
    """Appelle un composant en pleine largeur, quelle que soit la version."""
    for option in _STRETCH_ORDER:
        try:
            return func(*args, **kwargs, **option)
        except TypeError:
            continue
    return func(*args, **kwargs)


def panel(key: str) -> Any:
    """Conteneur stylé via CSS (clé -> classe ``st-key-…``)."""
    try:
        return st.container(key=key)
    except TypeError:
        return st.container(border=True)


# =============================================================================
# Normalisation défensive des valeurs issues des rapports
# =============================================================================
def as_int(value: Any, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return int(value)
    return default


def as_float(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


def clean_text(value: Any, default: str = NOT_PROVIDED) -> str:
    if value is None:
        return default
    result = str(value).strip()
    return result or default


def normalize_status(value: Any) -> str:
    """Statut connu, sinon UNKNOWN (jamais considéré comme conforme)."""
    status = str(value or "").strip().upper()
    return status if status in STATUS_ORDER else "UNKNOWN"


def normalize_severity(value: Any) -> str:
    severity = str(value or "").strip().upper()
    return severity if severity in SEVERITY_ORDER else SEVERITY_NONE


def severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else 99


def parse_dt(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    raw = value.strip()
    if raw[-1] in "Zz":
        raw = raw[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def fmt_dt(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S UTC") if value else "Date inconnue"


def fmt_pct(value: float | None) -> str:
    return f"{value:.2f}%" if value is not None else "Non disponible"


def fmt_int(value: int) -> str:
    return f"{value:,}".replace(",", " ")


def md_safe(value: Any) -> str:
    """Échappe le Markdown : les chaînes des rapports ne sont jamais interprétées."""
    special = "\\`*_{}[]()#+-.!|<>~$&"
    return "".join(f"\\{ch}" if ch in special else ch for ch in str(value))


def csv_safe(value: Any) -> Any:
    """Neutralise l'injection de formules dans Excel/LibreOffice."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


# =============================================================================
# Chargement des données
# =============================================================================
@st.cache_data(show_spinner=False)
def read_history(
    path_str: str, mtime_ns: int
) -> tuple[list[dict[str, Any]], str | None, str | None]:
    """Retourne (audits triés du plus récent au plus ancien, erreur, avis).

    ``mtime_ns`` ne sert qu'à invalider le cache quand le fichier change.
    """
    del mtime_ns
    path = Path(path_str)
    if not path.exists():
        return [], "missing", None
    try:
        raw = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError):
        return [], "unreadable", None
    if not raw.strip():
        return [], "empty", None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return [], "invalid_json", None
    if not isinstance(data, list):
        return [], "invalid_format", None

    valid = [item for item in data if isinstance(item, dict)]
    skipped = len(data) - len(valid)
    notice = (
        f"{skipped} entrée(s) ignorée(s) car ce ne sont pas des rapports d'audit."
        if skipped
        else None
    )
    indexed = list(enumerate(valid))
    floor = datetime.min.replace(tzinfo=timezone.utc)
    indexed.sort(
        key=lambda pair: (parse_dt(pair[1].get("audited_at")) or floor, pair[0]),
        reverse=True,
    )
    return [audit for _, audit in indexed], None, notice


LOAD_ERRORS = {
    "missing": "Aucun fichier d'historique trouvé.",
    "unreadable": "Le fichier d'historique ne peut pas être lu (droits ou encodage).",
    "empty": "Le fichier d'historique est vide.",
    "invalid_json": "Le fichier d'historique n'est pas un JSON valide.",
    "invalid_format": "Format invalide : une liste de rapports d'audit est attendue.",
}


def history_mtime_ns() -> int:
    try:
        return HISTORY_FILE.stat().st_mtime_ns
    except OSError:
        return 0


# =============================================================================
# Indicateurs dérivés (aucune logique métier modifiée : on relit le rapport)
# =============================================================================
def audit_findings(audit: dict[str, Any]) -> list[dict[str, Any]]:
    raw = audit.get("findings")
    return [f for f in raw if isinstance(f, dict)] if isinstance(raw, list) else []


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def compute_stats(audit: dict[str, Any]) -> dict[str, Any]:
    """Indicateurs d'un audit, en privilégiant les valeurs persistées."""
    findings = audit_findings(audit)
    summary = _as_dict(audit.get("summary"))
    metrics = _as_dict(audit.get("metrics"))
    derived = Counter(normalize_status(f.get("status")) for f in findings)
    counts = {
        s: max(0, as_int(summary.get(s), derived.get(s, 0))) for s in STATUS_ORDER
    }

    if findings:
        failed_sev = Counter(
            normalize_severity(f.get("severity"))
            for f in findings
            if normalize_status(f.get("status")) == "FAIL"
        )
    else:
        stored = _as_dict(audit.get("failed_findings_by_severity"))
        failed_sev = Counter({lvl: as_int(stored.get(lvl)) for lvl in SEVERITY_ORDER})
    severity = {lvl: int(failed_sev.get(lvl, 0)) for lvl in SEVERITY_ORDER}
    if failed_sev.get(SEVERITY_NONE):
        severity[SEVERITY_NONE] = int(failed_sev[SEVERITY_NONE])

    total_results = as_int(audit.get("total_findings"), len(findings))
    evaluated = as_int(
        metrics.get("evaluated_findings"), counts["PASS"] + counts["FAIL"]
    )
    applicable = as_int(
        metrics.get("applicable_findings"), total_results - counts["NOT_APPLICABLE"]
    )
    if "compliance_rate" in metrics:
        rate = as_float(metrics.get("compliance_rate"))
        compliance = max(0.0, min(100.0, rate)) if rate is not None else None
    else:
        pf = counts["PASS"] + counts["FAIL"]
        compliance = round(counts["PASS"] / pf * 100, 2) if pf else None

    resource_ids = {clean_text(f.get("resource_id"), "") for f in findings} - {""}
    audited_at = parse_dt(audit.get("audited_at"))
    return {
        "audit_id": clean_text(audit.get("audit_id"), "N/D"),
        "subscription": clean_text(audit.get("subscription_id"), "N/D"),
        "audited_at": audited_at,
        "date_label": fmt_dt(audited_at),
        "counts": counts,
        "severity": severity,
        "compliance": compliance,
        "resources": as_int(audit.get("total_resources"), len(resource_ids)),
        "results": total_results,
        "applicable": applicable,
        "evaluated": evaluated,
        "findings_loaded": len(findings),
        "summary_total": sum(counts.values()),
    }


def findings_frame(findings: list[dict[str, Any]]) -> pd.DataFrame:
    """Findings normalisés dans un DataFrame, triés par priorité d'action."""
    rows: list[dict[str, Any]] = []
    for pos, item in enumerate(findings):
        evidence = item.get("evidence")
        row = {
            "pos": pos,
            "status": normalize_status(item.get("status")),
            "severity": normalize_severity(item.get("severity")),
            "rule_id": clean_text(item.get("rule_id")),
            "title": clean_text(item.get("title")),
            "resource_name": clean_text(item.get("resource_name")),
            "resource_type": clean_text(item.get("resource_type")),
            "resource_id": clean_text(item.get("resource_id"), "unknown-resource"),
            "description": clean_text(item.get("description"), ""),
            "rationale": clean_text(item.get("rationale"), ""),
            "remediation": clean_text(item.get("remediation"), ""),
            "evidence": evidence if isinstance(evidence, (dict, list)) else None,
        }
        row["search"] = " ".join(
            str(row[k]).casefold()
            for k in (
                "status",
                "severity",
                "rule_id",
                "title",
                "resource_name",
                "resource_type",
                "resource_id",
                "description",
                "rationale",
                "remediation",
            )
        )
        rows.append(row)
    columns = [
        "pos",
        "status",
        "severity",
        "rule_id",
        "title",
        "resource_name",
        "resource_type",
        "resource_id",
        "description",
        "rationale",
        "remediation",
        "evidence",
        "search",
    ]
    frame = pd.DataFrame(rows, columns=columns)
    if frame.empty:
        return frame
    frame["_s"] = frame["status"].map(STATUS_SORT.index)
    frame["_v"] = frame["severity"].map(severity_rank)
    frame["_n"] = frame["resource_name"].str.casefold()
    frame = frame.sort_values(["_s", "_v", "_n", "rule_id"], kind="stable")
    return frame.drop(columns=["_s", "_v", "_n"]).reset_index(drop=True)


@st.cache_data(show_spinner=False)
def frame_for(mtime_ns: int, position: int) -> pd.DataFrame:
    audits, _, _ = read_history(str(HISTORY_FILE), mtime_ns)
    if not 0 <= position < len(audits):
        return findings_frame([])
    return findings_frame(audit_findings(audits[position]))


def display_table(frame: pd.DataFrame, with_status: bool = True) -> pd.DataFrame:
    table = pd.DataFrame(
        {
            "Gravité": frame["severity"],
            "Règle": frame["rule_id"],
            "Contrôle": frame["title"],
            "Ressource": frame["resource_name"],
            "Type": frame["resource_type"],
        }
    )
    if with_status:
        table.insert(0, "Statut", frame["status"].map(STATUS_LABELS))
    return table


def filter_findings(
    frame: pd.DataFrame,
    statuses: list[str],
    severities: list[str],
    rules: list[str],
    resources: list[str],
    query: str,
) -> pd.DataFrame:
    mask = frame["status"].isin(statuses) & frame["severity"].isin(severities)
    if rules:
        mask &= frame["rule_id"].isin(rules)
    if resources:
        mask &= frame["resource_id"].isin(resources)
    if query:
        mask &= frame["search"].str.contains(query.casefold(), regex=False)
    return frame[mask]


def build_resource_table(frame: pd.DataFrame) -> pd.DataFrame:
    """Inventaire dérivé des findings (pas un inventaire Azure indépendant)."""
    columns = [
        "Ressource",
        "Type",
        "Resource ID",
        "Résultats",
        "Conformes",
        "Échecs",
        "Inconnus",
        "Erreurs",
        "Gravité max (échecs)",
    ]
    if frame.empty:
        return pd.DataFrame(columns=columns)
    records: dict[str, dict[str, Any]] = {}
    for row in frame.itertuples(index=False):
        rec = records.setdefault(
            row.resource_id,
            {
                "Ressource": row.resource_name,
                "Type": row.resource_type,
                "Resource ID": row.resource_id,
                "Résultats": 0,
                "Conformes": 0,
                "Échecs": 0,
                "Inconnus": 0,
                "Erreurs": 0,
                "_rank": 99,
            },
        )
        rec["Résultats"] += 1
        if row.status == "PASS":
            rec["Conformes"] += 1
        elif row.status == "FAIL":
            rec["Échecs"] += 1
            rec["_rank"] = min(rec["_rank"], severity_rank(row.severity))
        elif row.status == "UNKNOWN":
            rec["Inconnus"] += 1
        elif row.status == "ERROR":
            rec["Erreurs"] += 1
    for rec in records.values():
        rank = rec.pop("_rank")
        rec["Gravité max (échecs)"] = (
            SEVERITY_ORDER[rank]
            if rank < len(SEVERITY_ORDER)
            else ("—" if rec["Échecs"] == 0 else SEVERITY_NONE)
        )
    table = pd.DataFrame(list(records.values()), columns=columns)
    table["_k"] = table["Ressource"].str.casefold()
    table = table.sort_values(
        ["Échecs", "Erreurs", "Inconnus", "_k"],
        ascending=[False, False, False, True],
        kind="stable",
    )
    return table.drop(columns="_k").reset_index(drop=True)


def history_table(audits: list[dict[str, Any]]) -> pd.DataFrame:
    rows = []
    for position, audit in enumerate(audits):
        s = compute_stats(audit)
        rows.append(
            {
                "pos": position,
                "Date": s["audited_at"],
                "Date UTC": s["date_label"],
                "Audit ID": s["audit_id"],
                "Abonnement": s["subscription"],
                "Ressources": s["resources"],
                "Résultats": s["results"],
                "Conformité (%)": s["compliance"],
                "Échecs": s["counts"]["FAIL"],
                "Inconnus": s["counts"]["UNKNOWN"],
                "Erreurs": s["counts"]["ERROR"],
            }
        )
    return pd.DataFrame(rows)


def compare_failures(old: dict[str, Any], new: dict[str, Any]) -> pd.DataFrame:
    """Évolution des échecs, par couple (règle, ressource), entre deux audits."""

    def index(audit: dict[str, Any]) -> dict[tuple[str, str], dict[str, str]]:
        result: dict[tuple[str, str], dict[str, str]] = {}
        for f in audit_findings(audit):
            key = (clean_text(f.get("rule_id")), clean_text(f.get("resource_id")))
            result[key] = {
                "status": normalize_status(f.get("status")),
                "severity": normalize_severity(f.get("severity")),
                "name": clean_text(f.get("resource_name")),
            }
        return result

    before, after = index(old), index(new)
    rows = []
    for key in before.keys() | after.keys():
        b, a = before.get(key), after.get(key)
        b_status = b["status"] if b else None
        a_status = a["status"] if a else None
        if b_status != "FAIL" and a_status != "FAIL":
            continue
        if b_status == "FAIL" and a_status == "FAIL":
            change = "Persistant"
        elif a_status == "FAIL":
            change = "Nouvel échec"
        elif a_status == "PASS":
            change = "Corrigé"
        elif a_status is None:
            change = "Absent de l'audit comparé"
        else:
            change = "Statut modifié"
        info = a or b or {}
        rows.append(
            {
                "Évolution": change,
                "Gravité": info.get("severity", SEVERITY_NONE),
                "Règle": key[0],
                "Ressource": info.get("name", NOT_PROVIDED),
                "Avant": STATUS_LABELS.get(b_status or "", "Absent"),
                "Après": STATUS_LABELS.get(a_status or "", "Absent"),
            }
        )
    table = pd.DataFrame(
        rows, columns=["Évolution", "Gravité", "Règle", "Ressource", "Avant", "Après"]
    )
    if table.empty:
        return table
    order = [
        "Nouvel échec",
        "Persistant",
        "Statut modifié",
        "Absent de l'audit comparé",
        "Corrigé",
    ]
    table["_e"] = table["Évolution"].map(
        lambda v: order.index(v) if v in order else len(order)
    )
    table["_v"] = table["Gravité"].map(severity_rank)
    table = table.sort_values(["_e", "_v", "Ressource"], kind="stable")
    return table.drop(columns=["_e", "_v"]).reset_index(drop=True)


def trend_label(
    old: float | None, new: float | None, higher_is_better: bool | None
) -> str:
    if higher_is_better is None or old is None or new is None:
        return "—"
    if new == old:
        return "Stable"
    improved = (new > old) == higher_is_better
    return "Amélioration" if improved else "Dégradation"


def comparison_rows(old: dict[str, Any], new: dict[str, Any]) -> pd.DataFrame:
    """Tableau comparatif ; la tendance n'est jugée que pour les indicateurs
    dont le sens favorable est sans ambiguïté."""
    specs: list[tuple[str, float | None, float | None, bool | None]] = [
        ("Ressources auditées", old["resources"], new["resources"], None),
        ("Résultats", old["results"], new["results"], None),
        ("Conformité (%)", old["compliance"], new["compliance"], True),
        ("Contrôles conformes", old["counts"]["PASS"], new["counts"]["PASS"], True),
        ("Échecs", old["counts"]["FAIL"], new["counts"]["FAIL"], False),
        (
            "Échecs critiques + élevés",
            old["severity"]["CRITICAL"] + old["severity"]["HIGH"],
            new["severity"]["CRITICAL"] + new["severity"]["HIGH"],
            False,
        ),
        ("Inconnus", old["counts"]["UNKNOWN"], new["counts"]["UNKNOWN"], False),
        ("Erreurs", old["counts"]["ERROR"], new["counts"]["ERROR"], False),
    ]
    def num(value: float | None) -> str:
        if value is None:
            return "N/D"
        if float(value).is_integer():
            return str(int(value))
        return f"{value:.2f}"

    rows = []
    for label, a, b, better in specs:
        delta = None if a is None or b is None else round(b - a, 2)
        if delta is None:
            gap = "N/D"
        elif delta == 0:
            gap = "0"
        else:
            gap = f"{delta:+.2f}".rstrip("0").rstrip(".")
        rows.append(
            {
                "Indicateur": label,
                "Référence": num(a),
                "Comparé": num(b),
                "Écart": gap,
                "Tendance": trend_label(a, b, better),
            }
        )
    return pd.DataFrame(rows)

# =============================================================================
# Exports
# =============================================================================
def to_csv_bytes(frame: pd.DataFrame) -> bytes:
    safe = frame.copy()
    for column in safe.columns:
        if safe[column].dtype == object:
            safe[column] = safe[column].map(csv_safe)
    return safe.to_csv(index=False).encode("utf-8-sig")


def findings_export(frame: pd.DataFrame) -> pd.DataFrame:
    export = pd.DataFrame(
        {
            "status": frame["status"],
            "severity": frame["severity"],
            "rule_id": frame["rule_id"],
            "title": frame["title"],
            "resource_name": frame["resource_name"],
            "resource_type": frame["resource_type"],
            "resource_id": frame["resource_id"],
            "description": frame["description"],
            "rationale": frame["rationale"],
            "remediation": frame["remediation"],
            "evidence": frame["evidence"].map(
                lambda v: json.dumps(v, ensure_ascii=False) if v is not None else ""
            ),
        }
    )
    return export


def to_json_bytes(payload: Any) -> bytes:
    return json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")


# =============================================================================
# Composants de présentation
# =============================================================================
def inject_css() -> None:
    st.markdown(f"<style>{CSS}</style>", unsafe_allow_html=True)


def page_header(title: str, subtitle: str) -> None:
    st.markdown(
        '<div class="cg-eyebrow">Cloud Security · Azure</div>'
        f'<div class="cg-title">{escape(title)}</div>'
        f'<div class="cg-subtitle">{escape(subtitle)}</div>',
        unsafe_allow_html=True,
    )


def context_bar(stats: dict[str, Any]) -> None:
    items = [
        ("Audit actif", stats["date_label"]),
        ("ID", stats["audit_id"]),
        ("Abonnement", stats["subscription"]),
        ("Source", "rapport enregistré, pas de données temps réel"),
    ]
    html = "".join(f"<span>{escape(k)}<b>{escape(v)}</b></span>" for k, v in items)
    st.markdown(f'<div class="cg-context">{html}</div>', unsafe_allow_html=True)


def section(title: str, caption: str = "") -> None:
    st.markdown(
        f'<div class="cg-section">{escape(title)}</div>'
        f'<div class="cg-section-sub">{escape(caption)}</div>',
        unsafe_allow_html=True,
    )


def kpi_card(
    label: str,
    value: str,
    note: str,
    tone: str = "neutral",
    icon: str = "shield",
    progress: float | None = None,
) -> None:
    """Carte KPI : libellé, pastille d'icône, valeur, note, barre optionnelle."""
    svg = (
        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" '
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
        f"{ICONS.get(icon, ICONS['shield'])}</svg>"
    )
    bar = ""
    if progress is not None:
        width = max(0.0, min(100.0, progress))
        bar = f'<div class="cg-kpi-bar"><span style="width:{width:.1f}%"></span></div>'
    st.markdown(
        f'<div class="cg-kpi cg-{escape(tone)}">'
        f'<div class="cg-kpi-top"><span class="cg-kpi-label">{escape(label)}</span>'
        f'<span class="cg-kpi-icon">{svg}</span></div>'
        f'<div class="cg-kpi-value">{escape(value)}</div>'
        f'<div class="cg-kpi-note">{escape(note)}</div>{bar}</div>',
        unsafe_allow_html=True,
    )


def table_height(rows: int, maximum: int = 520) -> int:
    return int(min(maximum, 56 + 47 * max(rows, 1)))


def white_dataframe(
    frame: pd.DataFrame, height: int | None = None, **_kwargs: Any
) -> None:
    """Tableau HTML clair, lisible, avec pastilles de statut/gravité.

    Toutes les valeurs sont échappées ; seules les pastilles générées ici
    contiennent du HTML. ``height`` borne la hauteur (défilement interne).
    """
    if frame is None:
        return
    safe = frame.copy().astype(object)
    safe = safe.where(safe.notna(), "N/D")

    def render(value: Any, column: str) -> str:
        if isinstance(value, (dict, list, tuple)):
            value = json.dumps(value, ensure_ascii=False, default=str)
        text = escape(str(value))
        tone = BADGE_TONES.get(str(value)) if column in BADGE_COLUMNS else None
        if tone:
            return f'<span class="cg-badge cg-b-{tone}">{text}</span>'
        if column == "Resource ID":
            return f'<span class="cg-id">{text}</span>'
        if column == "Type":
            return f'<span class="cg-nowrap">{text}</span>'
        return text

    for column in list(safe.columns):
        safe[column] = safe[column].map(lambda v, c=column: render(v, c))
    safe.columns = [escape(str(c)) for c in safe.columns]
    table_html = safe.to_html(
        index=False, escape=False, classes="cg-data-table", border=0
    ).replace("\n", "")
    style = f' style="max-height:{int(height)}px"' if height else ""
    st.markdown(
        f'<div class="cg-table-wrap"{style}>{table_html}</div>',
        unsafe_allow_html=True,
    )


def style_figure(fig: go.Figure, height: int) -> go.Figure:
    fig.update_layout(
        height=height,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={
            "family": "Inter, Segoe UI, sans-serif",
            "color": PALETTE["text"],
            "size": 12,
        },
        margin={"l": 10, "r": 30, "t": 10, "b": 10},
        showlegend=False,
        hoverlabel={
            "bgcolor": "#FFFFFF",
            "bordercolor": PALETTE["border"],
            "font": {"color": PALETTE["text"]},
        },
    )
    fig.update_xaxes(
        showgrid=True,
        gridcolor="rgba(138,155,184,.18)",
        zeroline=False,
        tickfont={"color": PALETTE["muted"]},
        automargin=True,
    )
    fig.update_yaxes(
        showgrid=False,
        zeroline=False,
        tickfont={"color": PALETTE["text"]},
        automargin=True,
    )
    return fig


def show_chart(fig: go.Figure) -> None:
    stretch(st.plotly_chart, fig, config={"displayModeBar": False})


def horizontal_bars(
    labels: list[str], values: list[int], colors: list[str], hover: str
) -> go.Figure:
    top = max(values, default=0)
    fig = go.Figure(
        go.Bar(
            x=values,
            y=labels,
            orientation="h",
            marker={"color": colors, "line": {"width": 0}},
            text=[str(v) for v in values],
            textposition="outside",
            textfont={"color": PALETTE["text"]},
            cliponaxis=False,
            hovertemplate=hover + "<extra></extra>",
        )
    )
    style_figure(fig, 36 * len(labels) + 40)
    fig.update_layout(bargap=0.45)
    fig.update_yaxes(autorange="reversed")
    fig.update_xaxes(
        range=[0, max(2, top * 1.18)], showticklabels=False, showgrid=False
    )
    return fig


def donut_figure(counts: dict[str, int], compliance: float | None) -> go.Figure:
    """Répartition des contrôles évalués ou à investiguer (hors non applicables)."""
    statuses = [s for s in ("PASS", "FAIL", "UNKNOWN", "ERROR") if counts.get(s, 0) > 0]
    fig = go.Figure(
        go.Pie(
            labels=[f"{STATUS_LABELS[s]} · {counts[s]}" for s in statuses],
            values=[counts[s] for s in statuses],
            hole=0.66,
            sort=False,
            direction="clockwise",
            marker={
                "colors": [STATUS_COLORS[s] for s in statuses],
                "line": {"color": "#FFFFFF", "width": 3},
            },
            textinfo="value",
            textfont={"color": "#FFFFFF", "size": 13},
            hovertemplate="%{label}<br>%{percent}<extra></extra>",
        )
    )
    style_figure(fig, 260)
    fig.update_layout(
        showlegend=True,
        legend={"orientation": "v", "x": 1.0, "y": 0.5, "font": {"size": 13}},
        margin={"l": 10, "r": 170, "t": 10, "b": 10},
    )
    if compliance is not None:
        fig.add_annotation(
            text=(
                f"<b>{compliance:.1f}%</b><br>"
                f"<span style='font-size:12px;color:{PALETTE['muted']}'>conformité</span>"
            ),
            x=0.5,
            y=0.5,
            xref="paper",
            yref="paper",
            showarrow=False,
            font={"size": 26, "color": PALETTE["text"]},
        )
    return fig


def trend_figure(frame: pd.DataFrame) -> go.Figure:
    fig = go.Figure()
    colors = [
        PALETTE["cyan"],
        PALETTE["green"],
        PALETTE["purple"],
        PALETTE["amber"],
        PALETTE["red"],
    ]
    for index, (subscription, part) in enumerate(
        frame.groupby("Abonnement", sort=False)
    ):
        color = colors[index % len(colors)]
        fig.add_trace(
            go.Scatter(
                x=part["Date"],
                y=part["Conformité (%)"],
                mode="lines+markers+text",
                name=str(subscription),
                text=[f"{v:.1f}%" for v in part["Conformité (%)"]],
                textposition="top center",
                textfont={"size": 11, "color": color},
                line={"color": color, "width": 2.5},
                marker={"size": 8, "color": color},
                customdata=part[["Audit ID"]].to_numpy(),
                hovertemplate=(
                    "%{x|%Y-%m-%d %H:%M:%S}<br>Conformité : %{y:.2f}%"
                    "<br>%{customdata[0]}<extra></extra>"
                ),
            )
        )
    low = float(frame["Conformité (%)"].min())
    high = float(frame["Conformité (%)"].max())
    lo = max(0.0, math.floor(low / 10) * 10 - 10)
    hi = min(100.0, math.ceil(high / 10) * 10 + 10)
    if hi - lo < 30:
        lo, hi = max(0.0, hi - 30), min(100.0, max(hi, lo + 30))
    style_figure(fig, 300)
    fig.update_yaxes(
        range=[lo, hi],
        ticksuffix="%",
        showgrid=True,
        gridcolor="rgba(138,155,184,.18)",
    )
    fig.update_xaxes(tickformat="%d/%m<br>%H:%M", hoverformat="%Y-%m-%d %H:%M:%S")
    fig.update_layout(
        showlegend=frame["Abonnement"].nunique() > 1,
        legend={"orientation": "h", "y": 1.12},
        margin={"l": 10, "r": 30, "t": 25, "b": 10},
    )
    return fig


def trend_frame(table: pd.DataFrame) -> pd.DataFrame:
    """Points exploitables : conformité calculable et date valide."""
    points = table.dropna(subset=["Conformité (%)", "Date"])
    return points.sort_values("Date").reset_index(drop=True)


def keep_state_alive() -> None:
    """Conserve filtres et sélections quand on change de page."""
    for key in list(st.session_state.keys()):
        if isinstance(key, str) and key.startswith(("f_", "r_", "h_")):
            st.session_state[key] = st.session_state[key]


def valid_choice(key: str, options: list[Any], multi: bool = False) -> None:
    """Retire de l'état toute valeur qui n'existe plus dans les options."""
    if key not in st.session_state:
        return
    current = st.session_state[key]
    if multi:
        st.session_state[key] = [v for v in current if v in options]
    elif current not in options:
        del st.session_state[key]


# =============================================================================
# Rendu : détail d'un finding
# =============================================================================
def render_finding_detail(row: Any) -> None:
    label = f"{row.severity} · {row.title} · {row.resource_name}"
    label = md_safe(label if len(label) <= 140 else label[:137] + "...")
    status_label = STATUS_LABELS.get(row.status, row.status)
    with st.expander(f"{status_label} — {label}"):
        left, right = st.columns([1.15, 1], gap="large")
        with left:
            st.markdown("**Description**")
            st.markdown(
                md_safe(row.description)
                if row.description
                else "_Aucune description dans le rapport._"
            )
            st.markdown("**Analyse / justification**")
            st.markdown(
                md_safe(row.rationale)
                if row.rationale
                else "_Aucune justification dans le rapport._"
            )
            if row.status in ACTIONABLE_STATUSES:
                st.markdown("**Remédiation recommandée**")
            else:
                st.markdown("**Rappel du contrôle (aucune action requise)**")
            st.markdown(
                md_safe(row.remediation)
                if row.remediation
                else "_Aucune remédiation fournie dans le rapport._"
            )
        with right:
            st.markdown("**Contexte**")
            st.caption(f"Statut : {status_label} · Gravité : {row.severity}")
            st.caption(f"Règle : {row.rule_id}")
            st.caption(f"Type : {row.resource_type}")
            st.code(row.resource_id, language=None)
            st.markdown("**Éléments de preuve**")
            if row.evidence:
                st.code(
                    json.dumps(row.evidence, ensure_ascii=False, indent=2, default=str),
                    language="json",
                )
            else:
                st.caption("Aucune preuve fournie dans le rapport.")


# =============================================================================
# Pages
# =============================================================================
def page_overview(
    stats: dict[str, Any], frame: pd.DataFrame, history: pd.DataFrame
) -> None:
    page_header(
        "Security Operations Center",
        "Posture de sécurité Azure issue du dernier rapport d'audit sélectionné.",
    )
    context_bar(stats)

    counts, sev = stats["counts"], stats["severity"]
    failed, unknown, errors = counts["FAIL"], counts["UNKNOWN"], counts["ERROR"]
    not_evaluated = unknown + errors
    high_plus = sev["CRITICAL"] + sev["HIGH"]

    if stats["evaluated"] == 0:
        st.warning(
            "Aucun contrôle évalué (ni conforme, ni en échec) : la conformité "
            "n'est pas calculable pour cet audit."
        )
    elif not_evaluated:
        st.warning(
            f"{not_evaluated} contrôle(s) n'ont pas pu être conclus "
            f"({unknown} inconnu(s), {errors} erreur(s)). Ils sont exclus du "
            "taux de conformité et ne doivent pas être considérés comme conformes."
        )
    if stats["findings_loaded"] != stats["summary_total"]:
        st.caption(
            f"Remarque : le résumé annonce {stats['summary_total']} résultat(s) "
            f"mais {stats['findings_loaded']} sont détaillés dans le rapport."
        )

    cols = st.columns(6, gap="small")
    compliance = stats["compliance"]
    if compliance is None:
        compliance_tone = "neutral"
    elif compliance >= 80:
        compliance_tone = "ok"
    elif compliance >= 50:
        compliance_tone = "warn"
    else:
        compliance_tone = "bad"
    with cols[0]:
        kpi_card(
            "Conformité",
            fmt_pct(compliance) if compliance is not None else "N/D",
            f"{counts['PASS']} conformes sur {stats['evaluated']} évalués"
            if compliance is not None
            else "Non calculable pour cet audit",
            compliance_tone,
            "shield",
            progress=compliance,
        )
    with cols[1]:
        kpi_card(
            "Ressources auditées",
            fmt_int(stats["resources"]),
            f"{fmt_int(stats['results'])} résultats de contrôle",
            "info",
            "server",
        )
    with cols[2]:
        kpi_card(
            "Échecs",
            fmt_int(failed),
            f"sur {fmt_int(stats['applicable'])} contrôles applicables",
            "bad" if failed else "ok",
            "x",
        )
    with cols[3]:
        kpi_card(
            "Critiques & élevés",
            fmt_int(high_plus),
            f"{sev['CRITICAL']} critiques · {sev['HIGH']} élevés",
            "bad" if high_plus else "ok",
            "alert",
        )
    with cols[4]:
        kpi_card(
            "Contrôles conformes",
            fmt_int(counts["PASS"]),
            f"{fmt_int(counts['NOT_APPLICABLE'])} non applicables exclus",
            "ok",
            "check",
        )
    with cols[5]:
        kpi_card(
            "À investiguer",
            fmt_int(not_evaluated),
            f"{unknown} inconnus · {errors} erreurs",
            "warn" if not_evaluated else "ok",
            "search",
        )

    with st.expander("Comment la conformité est-elle calculée ?"):
        st.markdown(
            "Taux de conformité = **contrôles conformes ÷ (conformes + échecs)**, "
            "tel que calculé par le backend et enregistré dans le rapport.\n\n"
            "Les résultats **inconnus**, **en erreur** et **non applicables** "
            "sont exclus du calcul : ils ne sont jamais comptés comme conformes. "
            "Si aucun contrôle n'est évalué, le taux est affiché « N/D »."
        )

    left, right = st.columns(2, gap="large")
    with left:
        section(
            "Répartition des contrôles",
            "Conformes, échecs et résultats à investiguer (hors non applicables).",
        )
        if sum(counts[s] for s in ("PASS", "FAIL", "UNKNOWN", "ERROR")):
            show_chart(donut_figure(counts, compliance))
        else:
            st.info("Aucun contrôle applicable dans cet audit.")
        st.caption(
            f"{fmt_int(counts['NOT_APPLICABLE'])} contrôle(s) non applicable(s) "
            "non représenté(s)."
        )
    with right:
        section("Échecs par gravité", "Uniquement les contrôles en échec.")
        levels = [lvl for lvl in SEVERITY_ORDER + [SEVERITY_NONE] if lvl in sev]
        if sum(sev.values()) == 0:
            st.success("Aucun échec dans cet audit.")
        else:
            fig = horizontal_bars(
                levels,
                [sev[lvl] for lvl in levels],
                [
                    SEVERITY_COLORS[lvl] if sev[lvl] else "rgba(145,164,190,.35)"
                    for lvl in levels
                ],
                "%{y} : %{x} échec(s)",
            )
            show_chart(fig)

    section(
        "Risques prioritaires",
        "Échecs triés par gravité, puis résultats à investiguer.",
    )
    tab_fail, tab_inv = st.tabs(["Échecs", "Inconnus et erreurs"])
    with tab_fail:
        failed_rows = frame[frame["status"] == "FAIL"] if not frame.empty else frame
        if failed_rows.empty:
            st.success("Aucun échec dans le détail de cet audit.")
        else:
            top = failed_rows.head(10)
            white_dataframe(
                display_table(top, with_status=False), height=table_height(len(top))
            )
            if len(failed_rows) > 10:
                st.caption(
                    f"10 premiers échecs sur {len(failed_rows)} — voir "
                    "« Findings & remédiation » pour la liste complète."
                )
    with tab_inv:
        pending = (
            frame[frame["status"].isin(["UNKNOWN", "ERROR"])]
            if not frame.empty
            else frame
        )
        if pending.empty:
            st.success("Aucun résultat inconnu ou en erreur dans le détail.")
        else:
            top = pending.head(10)
            white_dataframe(display_table(top), height=table_height(len(top)))
            if len(pending) > 10:
                st.caption(f"10 premiers résultats sur {len(pending)}.")

    section(
        "Évolution de la conformité",
        "Audits du même abonnement dont la conformité est calculable.",
    )
    points = trend_frame(history[history["Abonnement"] == stats["subscription"]])
    if len(points) >= 2:
        show_chart(trend_figure(points))
    else:
        st.info(
            "Historique insuffisant : au moins deux audits avec une conformité "
            "calculable sont nécessaires pour tracer une évolution."
        )


def page_findings(stats: dict[str, Any], frame: pd.DataFrame, scope: str) -> None:
    page_header(
        "Findings & remédiation",
        "Investiguez les résultats, inspectez les preuves et priorisez les corrections.",
    )
    context_bar(stats)
    if frame.empty:
        st.info("Cet audit ne contient aucun résultat détaillé.")
        return

    present_status = [s for s in STATUS_ORDER if (frame["status"] == s).any()]
    present_sev = [
        s for s in SEVERITY_ORDER + [SEVERITY_NONE] if (frame["severity"] == s).any()
    ]
    rules = sorted(frame["rule_id"].unique())
    resource_names = (
        frame.drop_duplicates("resource_id")
        .set_index("resource_id")
        .apply(lambda r: f"{r['resource_name']} ({r['resource_type']})", axis=1)
    )
    resource_ids = sorted(
        resource_names.index, key=lambda i: resource_names[i].casefold()
    )

    k_status, k_sev = f"f_status_{scope}", f"f_sev_{scope}"
    k_rule, k_res = f"f_rule_{scope}", f"f_res_{scope}"
    for key, options in (
        (k_status, present_status),
        (k_sev, present_sev),
        (k_rule, rules),
        (k_res, resource_ids),
    ):
        valid_choice(key, options, multi=True)

    with panel("filters_panel"):
        only_failed = st.toggle(
            "Afficher uniquement les échecs", value=False, key=f"f_only_{scope}"
        )
        c1, c2, c3 = st.columns([1.2, 1, 1.4], gap="medium")
        with c1:
            default_status = [s for s in ACTIONABLE_STATUSES if s in present_status]
            selected_status = st.multiselect(
                "Statut",
                present_status,
                default=default_status,
                key=k_status,
                format_func=lambda s: STATUS_LABELS.get(s, s),
                disabled=only_failed,
            )
        with c2:
            selected_sev = st.multiselect(
                "Gravité", present_sev, default=present_sev, key=k_sev
            )
        with c3:
            query = st.text_input(
                "Recherche globale",
                key=f"f_q_{scope}",
                placeholder="Règle, ressource, type, texte, remédiation…",
            ).strip()
        c4, c5 = st.columns(2, gap="medium")
        with c4:
            selected_rules = st.multiselect(
                "Règles", rules, key=k_rule, placeholder="Toutes les règles"
            )
        with c5:
            selected_res = st.multiselect(
                "Ressources",
                resource_ids,
                key=k_res,
                placeholder="Toutes les ressources",
                format_func=lambda i: resource_names.get(i, i),
            )

    effective_status = ["FAIL"] if only_failed else selected_status
    filtered = filter_findings(
        frame, effective_status, selected_sev, selected_rules, selected_res, query
    )
    hidden = frame[~frame["status"].isin(effective_status)]
    if not only_failed and len(hidden):
        st.caption(
            f"{len(hidden)} résultat(s) masqués par le filtre de statut "
            "(par défaut : échecs, inconnus et erreurs)."
        )

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Résultats filtrés", fmt_int(len(filtered)))
    m2.metric("Ressources concernées", fmt_int(filtered["resource_id"].nunique()))
    m3.metric("Échecs", fmt_int(int((filtered["status"] == "FAIL").sum())))
    m4.metric(
        "Inconnus + erreurs",
        fmt_int(int(filtered["status"].isin(["UNKNOWN", "ERROR"]).sum())),
    )

    if filtered.empty:
        st.info("Aucun résultat ne correspond aux filtres sélectionnés.")
        return
    white_dataframe(display_table(filtered), height=table_height(len(filtered), 440))
    stretch(
        st.download_button,
        "Exporter les résultats filtrés (CSV)",
        to_csv_bytes(findings_export(filtered)),
        file_name=f"cloudguard_findings_{stats['audit_id']}.csv",
        mime="text/csv",
    )

    section("Détails et remédiation")
    limit_col, _spacer = st.columns([1, 3])
    with limit_col:
        limit = st.selectbox(
            "Nombre de détails affichés",
            [10, 25, 50, 100],
            index=0,
            key=f"f_limit_{scope}",
        )
    for row in filtered.head(int(limit)).itertuples(index=False):
        render_finding_detail(row)
    if len(filtered) > int(limit):
        st.caption(f"{int(limit)} détails affichés sur {len(filtered)} résultats.")


def page_resources(stats: dict[str, Any], frame: pd.DataFrame, scope: str) -> None:
    page_header(
        "Ressources",
        "Ressources représentées dans les résultats de l'audit actif.",
    )
    context_bar(stats)
    st.info(
        "Cet inventaire est **dérivé des résultats de règles** de l'audit : il ne "
        "remplace pas l'inventaire Azure. Une ressource absente ici n'est pas "
        "forcément absente d'Azure."
    )
    table = build_resource_table(frame)
    if table.empty:
        st.info("Aucune ressource ne peut être dérivée des résultats de cet audit.")
        return
    if stats["resources"] != len(table):
        st.caption(
            f"Le rapport annonce {stats['resources']} ressource(s) ; "
            f"{len(table)} apparaissent dans les résultats détaillés."
        )

    with panel("filters_panel_res"):
        c1, c2 = st.columns([2, 1.3], gap="medium")
        with c1:
            query = (
                st.text_input(
                    "Rechercher",
                    key=f"r_q_{scope}",
                    placeholder="Nom, type ou identifiant",
                )
                .strip()
                .casefold()
            )
        with c2:
            scope_filter = st.selectbox(
                "Filtre",
                ["Toutes les ressources", "Avec échecs", "Avec inconnus ou erreurs"],
                key=f"r_filter_{scope}",
            )
    visible = table
    if query:
        haystack = (
            visible["Ressource"] + " " + visible["Type"] + " " + visible["Resource ID"]
        ).str.casefold()
        visible = visible[haystack.str.contains(query, regex=False)]
    if scope_filter == "Avec échecs":
        visible = visible[visible["Échecs"] > 0]
    elif scope_filter == "Avec inconnus ou erreurs":
        visible = visible[(visible["Inconnus"] + visible["Erreurs"]) > 0]

    m1, m2, m3 = st.columns(3)
    m1.metric("Ressources visibles", fmt_int(len(visible)))
    m2.metric("Avec au moins un échec", fmt_int(int((visible["Échecs"] > 0).sum())))
    m3.metric("Échecs cumulés", fmt_int(int(visible["Échecs"].sum())))
    st.caption(
        "« Gravité max » porte uniquement sur les contrôles en échec "
        "(« — » si la ressource n'a aucun échec)."
    )

    if visible.empty:
        st.info("Aucune ressource ne correspond aux filtres.")
        return
    white_dataframe(visible, height=table_height(len(visible), 460))
    stretch(
        st.download_button,
        "Exporter les ressources (CSV)",
        to_csv_bytes(visible),
        file_name=f"cloudguard_resources_{stats['audit_id']}.csv",
        mime="text/csv",
    )

    section("Analyser une ressource")
    ids = visible["Resource ID"].tolist()
    names = dict(
        zip(
            visible["Resource ID"],
            visible["Ressource"] + " — " + visible["Type"],
            strict=False,
        )
    )
    key = f"r_sel_{scope}"
    valid_choice(key, ids)
    chosen = st.selectbox(
        "Ressource", ids, key=key, format_func=lambda i: names.get(i, i)
    )
    related = frame[frame["resource_id"] == chosen]
    st.markdown("**Identifiant complet**")
    st.code(chosen, language=None)
    show_na = st.toggle(
        "Inclure les contrôles non applicables", value=False, key=f"r_na_{scope}"
    )
    if not show_na:
        related = related[related["status"] != "NOT_APPLICABLE"]
    if related.empty:
        st.info("Aucun contrôle applicable pour cette ressource.")
    else:
        white_dataframe(display_table(related), height=table_height(len(related), 360))
        for row in related.itertuples(index=False):
            if row.status in ACTIONABLE_STATUSES:
                render_finding_detail(row)


def page_history(
    audits: list[dict[str, Any]], history: pd.DataFrame, active: dict[str, Any]
) -> None:
    page_header(
        "Historique des audits",
        "Exploitez les rapports enregistrés localement et comparez deux exécutions.",
    )
    subs = sorted(history["Abonnement"].unique())
    valid_choice("h_subs", subs, multi=True)
    selected = st.multiselect(
        "Abonnements affichés",
        subs,
        key="h_subs",
        default=[active["subscription"]] if active["subscription"] in subs else subs,
    )
    shown = history[history["Abonnement"].isin(selected)]
    m1, m2, m3 = st.columns(3)
    m1.metric("Audits enregistrés (total)", fmt_int(len(history)))
    m2.metric("Audits affichés", fmt_int(len(shown)))
    latest = shown.iloc[0] if len(shown) else None
    m3.metric(
        "Dernière conformité affichée",
        fmt_pct(latest["Conformité (%)"])
        if latest is not None and pd.notna(latest["Conformité (%)"])
        else "Non disponible",
    )
    if shown.empty:
        st.info("Aucun audit pour les abonnements sélectionnés.")
        return

    section(
        "Évolution de la conformité",
        "Un point par audit dont la conformité est calculable.",
    )
    points = trend_frame(shown)
    if len(points) >= 2:
        show_chart(trend_figure(points))
    else:
        st.info(
            "Historique insuffisant pour tracer une évolution (moins de deux "
            "audits avec une conformité calculable)."
        )

    section("Tableau chronologique", "Du plus récent au plus ancien.")
    export = shown.drop(columns=["pos", "Date"]).reset_index(drop=True)
    white_dataframe(export, height=table_height(len(export), 420))
    d1, d2 = st.columns(2)
    with d1:
        stretch(
            st.download_button,
            "Exporter l'historique (CSV)",
            to_csv_bytes(export),
            file_name="cloudguard_audit_history.csv",
            mime="text/csv",
        )
    with d2:
        reports = [audits[int(p)] for p in shown["pos"]]
        stretch(
            st.download_button,
            "Exporter les rapports complets (JSON)",
            to_json_bytes(reports),
            file_name="cloudguard_audits.json",
            mime="application/json",
        )

    section(
        "Comparer deux audits",
        "Sélectionnez deux audits distincts parmi ceux affichés.",
    )
    if len(shown) < 2:
        st.info("Au moins deux audits sont nécessaires pour une comparaison.")
        return
    positions = [int(p) for p in shown["pos"]]
    labels = {
        int(p): f"{d} · {i}"
        for p, d, i in zip(
            shown["pos"], shown["Date UTC"], shown["Audit ID"], strict=False
        )
    }
    valid_choice("h_old", positions)
    valid_choice("h_new", positions)
    ca, cb = st.columns(2)
    with ca:
        old_pos = st.selectbox(
            "Audit de référence",
            positions,
            index=min(1, len(positions) - 1),
            key="h_old",
            format_func=lambda p: labels.get(p, str(p)),
        )
    with cb:
        new_pos = st.selectbox(
            "Audit comparé",
            positions,
            index=0,
            key="h_new",
            format_func=lambda p: labels.get(p, str(p)),
        )
    if old_pos == new_pos:
        st.warning("Sélectionnez deux audits distincts pour lancer la comparaison.")
        return

    old_audit, new_audit = audits[old_pos], audits[new_pos]
    old, new = compute_stats(old_audit), compute_stats(new_audit)
    if (
        old["audited_at"]
        and new["audited_at"]
        and old["audited_at"] > new["audited_at"]
    ):
        st.info(
            "L'audit de référence est plus récent que l'audit comparé : "
            "les tendances sont lues dans ce sens."
        )
    same_scope = old["subscription"] == new["subscription"]
    if not same_scope:
        st.warning(
            "Les deux audits portent sur des abonnements différents : "
            "la comparaison n'est pas fiable et reste indicative."
        )
    elif old["resources"] != new["resources"]:
        st.warning(
            "Le nombre de ressources auditées diffère : le périmètre a "
            "changé, interprétez les écarts avec prudence."
        )
    elif old["results"] != new["results"]:
        st.warning(
            "Le nombre de résultats diffère : le jeu de règles a changé, "
            "interprétez les écarts avec prudence."
        )

    white_dataframe(comparison_rows(old, new))
    if old["compliance"] is not None and new["compliance"] is not None:
        delta = new["compliance"] - old["compliance"]
        message = (
            f"Conformité : {old['compliance']:.2f}% → {new['compliance']:.2f}% "
            f"({delta:+.2f} point(s))."
        )
        (st.success if delta > 0 else st.warning if delta < 0 else st.info)(message)
    else:
        st.info(
            "La conformité n'est calculable que pour l'un des audits (ou aucun) : "
            "aucun écart de conformité n'est affiché."
        )

    if same_scope:
        evolution = compare_failures(old_audit, new_audit)
        c1, c2, c3 = st.columns(3)
        c1.metric(
            "Nouveaux échecs", int((evolution["Évolution"] == "Nouvel échec").sum())
        )
        c2.metric("Échecs corrigés", int((evolution["Évolution"] == "Corrigé").sum()))
        c3.metric(
            "Échecs persistants", int((evolution["Évolution"] == "Persistant").sum())
        )
        if evolution.empty:
            st.info("Aucun échec dans l'un ou l'autre des deux audits.")
        else:
            white_dataframe(evolution, height=table_height(len(evolution), 360))
            st.caption(
                "Comparaison par couple (règle, ressource). « Absent de "
                "l'audit comparé » : la ressource ou la règle n'y figure plus."
            )


# =============================================================================
# Sidebar et orchestration
# =============================================================================
def api_docs_url() -> str | None:
    raw = os.environ.get(API_URL_ENV, "").strip().rstrip("/")
    parsed = urlparse(raw)
    if parsed.scheme in ("http", "https") and parsed.netloc:
        return f"{raw}/docs"
    return None


def render_sidebar(
    audits: list[dict[str, Any]], modified: datetime | None
) -> int | None:
    with st.sidebar:
        if LOGO_FILE.exists():
            # La carte blanche arrondie est appliquée en CSS sur stImage.
            stretch(st.image, str(LOGO_FILE))
        else:
            st.markdown(
                '<div class="cg-brand">Cloud<span>Guard</span></div>'
                '<div class="cg-brand-sub">Azure Security &amp; Compliance</div>',
                unsafe_allow_html=True,
            )
        st.markdown(
            '<div class="cg-side-label">Navigation</div>', unsafe_allow_html=True
        )
        if "page" not in st.session_state or st.session_state["page"] not in PAGES:
            st.session_state["page"] = PAGES[0]
        for index, page_name in enumerate(PAGES):
            is_active = st.session_state["page"] == page_name
            if stretch(
                st.button,
                page_name,
                key=f"nav_{index}",
                type="primary" if is_active else "secondary",
            ):
                st.session_state["page"] = page_name
                st.rerun()

        position: int | None = None
        if audits:
            st.markdown(
                '<div class="cg-side-label">Périmètre d\'audit</div>',
                unsafe_allow_html=True,
            )
            options = list(range(len(audits)))
            valid_choice("audit_pos", options)

            def label(pos: int) -> str:
                s = compute_stats(audits[pos])
                when = s["audited_at"]
                short = when.strftime("%Y-%m-%d %H:%M") if when else "Date inconnue"
                return f"{short} · {s['audit_id'][-8:]}"

            position = st.selectbox(
                "Audit actif", options, index=0, key="audit_pos", format_func=label
            )
            stats = compute_stats(audits[position])
            st.markdown(
                '<div class="cg-side-box">'
                f"Abonnement<br><b>{escape(stats['subscription'])}</b><br>"
                f"Ressources · <b>{stats['resources']}</b><br>"
                f"Résultats · <b>{stats['results']}</b></div>",
                unsafe_allow_html=True,
            )

        st.markdown(
            '<div class="cg-side-label">Source des données</div>',
            unsafe_allow_html=True,
        )
        st.markdown(
            '<div class="cg-side-box">Lecture seule · aucun appel Azure<br>'
            f"Fichier : <b>{escape(HISTORY_FILE.name)}</b><br>"
            f"Modifié : <b>{escape(fmt_dt(modified))}</b></div>",
            unsafe_allow_html=True,
        )
        if stretch(st.button, "Actualiser les données", key="refresh_btn"):
            st.cache_data.clear()
            st.rerun()
        docs = api_docs_url()
        if docs:
            stretch(st.link_button, "Ouvrir l'API (Swagger)", docs)
    return position


def render_empty_state(error: str | None) -> None:
    page_header("Security Operations Center", "Aucun audit exploitable pour le moment.")
    message = LOAD_ERRORS.get(error or "", "Aucun audit enregistré.")
    (
        st.error
        if error in ("unreadable", "invalid_json", "invalid_format")
        else st.info
    )(message)
    st.markdown(
        "Lancez `POST /audit` depuis Swagger (backend FastAPI) pour produire un "
        "audit, puis cliquez sur **Actualiser les données**."
    )
    st.caption(f"Fichier attendu : {HISTORY_FILE}")


def main() -> None:
    st.set_page_config(
        page_title="CloudGuard | Security Operations Center",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    inject_css()
    if "page" not in st.session_state:
        st.session_state["page"] = PAGES[0]
    keep_state_alive()

    mtime_ns = history_mtime_ns()
    audits, error, notice = read_history(str(HISTORY_FILE), mtime_ns)
    modified = (
        datetime.fromtimestamp(mtime_ns / 1e9, tz=timezone.utc) if mtime_ns else None
    )
    position = render_sidebar(audits, modified)
    if position is None or not audits:
        render_empty_state(error)
        return
    if notice:
        st.warning(notice)

    active = compute_stats(audits[position])
    frame = frame_for(mtime_ns, position)
    scope = f"{position}_{active['audit_id']}"
    page = st.session_state.get("page", PAGES[0])
    history = history_table(audits)

    if page == "Findings & remédiation":
        page_findings(active, frame, scope)
    elif page == "Ressources":
        page_resources(active, frame, scope)
    elif page == "Historique":
        page_history(audits, history, active)
    else:
        page_overview(active, frame, history)

    st.markdown(
        '<div class="cg-subtitle" style="text-align:center;margin-top:2rem">'
        "CloudGuard · données issues de rapports enregistrés (lecture seule, "
        "pas de temps réel)</div>",
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()