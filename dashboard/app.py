"""
app.py — ThreatLens Streamlit Dashboard

Reads alerts from SQLite (populated by run_pipeline.py) and displays
them in an interactive dashboard: summary metrics, filterable alert
table, and visualizations.
"""

import sys
import subprocess
from pathlib import Path
import pandas as pd
import streamlit as st

sys.path.append(str(Path(__file__).resolve().parent.parent / "src"))
from db import query_alerts, get_summary_stats, init_db

# ---------------- Page Config ----------------
st.set_page_config(
    page_title="ThreatLens",
    page_icon="🔎",
    layout="wide",
)

st.markdown("""
    <style>
    .block-container {padding-top: 2rem;}
    [data-testid="stMetricValue"] {font-size: 1.8rem;}
    </style>
""", unsafe_allow_html=True)

init_db()  # ensure DB exists even on fresh clone

# ---------------- Header ----------------
st.title("🔎 ThreatLens")
st.caption("SIEM-style log analysis & alerting dashboard — MITRE ATT&CK mapped detections")

# ---------------- Replay Attack Control ----------------
with st.sidebar:
    st.divider()
    st.subheader("Demo Controls")
    if st.button("🔁 Regenerate logs & replay attack"):
        with st.spinner("Generating new synthetic attack traffic..."):
            subprocess.run(["python", "src/generator.py"], cwd=Path(__file__).resolve().parent.parent)
            subprocess.run(["python", "run_pipeline.py"], cwd=Path(__file__).resolve().parent.parent)
        st.success("New attack data generated and processed! Refresh to see updates.")
        st.rerun()

# ---------------- Load Data ----------------
alerts_raw = query_alerts(limit=1000)

if not alerts_raw:
    st.warning(
        "No alerts found in the database. Run the pipeline first:\n\n"
        "```\npython src/generator.py\npython run_pipeline.py\n```"
    )
    st.stop()

df = pd.DataFrame(alerts_raw)
df["timestamp"] = pd.to_datetime(df["timestamp"])

# ---------------- Summary Metrics ----------------
stats = get_summary_stats()

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Alerts", stats["total_alerts"])
col2.metric("High Severity", stats["high_severity"])
col3.metric("Unique Source IPs", stats["unique_ips"])
col4.metric("Techniques Detected", df["technique_id"].nunique())

st.divider()

# ---------------- Sidebar Filters ----------------
st.sidebar.header("Filters")

severity_filter = st.sidebar.multiselect(
    "Severity",
    options=sorted(df["severity"].unique()),
    default=sorted(df["severity"].unique()),
)

technique_filter = st.sidebar.multiselect(
    "MITRE Technique",
    options=sorted(df["technique_id"].unique()),
    default=sorted(df["technique_id"].unique()),
)

ip_filter = st.sidebar.multiselect(
    "Source IP",
    options=sorted(df["src_ip"].dropna().unique()),
    default=sorted(df["src_ip"].dropna().unique()),
)

date_range = st.sidebar.date_input(
    "Date range",
    value=(df["timestamp"].min().date(), df["timestamp"].max().date()),
)

# Apply filters
filtered = df[
    df["severity"].isin(severity_filter)
    & df["technique_id"].isin(technique_filter)
    & df["src_ip"].isin(ip_filter)
]

if len(date_range) == 2:
    start_date, end_date = date_range
    filtered = filtered[
        (filtered["timestamp"].dt.date >= start_date)
        & (filtered["timestamp"].dt.date <= end_date)
    ]

st.sidebar.divider()
if st.sidebar.button("🔄 Re-run pipeline on current logs"):
    st.sidebar.info("Run `python run_pipeline.py` in your terminal, then refresh this page.")

# ---------------- Alert Table ----------------
st.subheader(f"Alerts ({len(filtered)})")

def severity_color(val):
    colors = {"High": "#ff4b4b", "Medium": "#ffa500", "Low": "#f0e130"}
    return f"background-color: {colors.get(val, 'white')}; color: black"

display_df = filtered[[
    "timestamp", "severity", "technique_id", "technique_name",
    "src_ip", "user", "description"
]].sort_values("timestamp", ascending=False)

styler = display_df.style
if hasattr(styler, "map"):
    styler = styler.map(severity_color, subset=["severity"])
else:
    styler = styler.applymap(severity_color, subset=["severity"])

st.dataframe(
    styler,
    use_container_width=True,
    height=350,
)

st.divider()

# ---------------- Visualizations ----------------
viz_col1, viz_col2 = st.columns(2)

with viz_col1:
    st.subheader("Alert Volume Over Time")
    if not filtered.empty:
        time_series = (
            filtered.set_index("timestamp")
            .resample("5min")
            .size()
            .reset_index(name="count")
        )
        st.line_chart(time_series.set_index("timestamp")["count"])
    else:
        st.info("No data for selected filters.")

with viz_col2:
    st.subheader("Alerts by MITRE Technique")
    if not filtered.empty:
        technique_counts = filtered["technique_name"].value_counts()
        st.bar_chart(technique_counts)
    else:
        st.info("No data for selected filters.")

viz_col3, viz_col4 = st.columns(2)

with viz_col3:
    st.subheader("Top Offending IPs")
    if not filtered.empty:
        ip_counts = filtered["src_ip"].value_counts().head(10)
        st.bar_chart(ip_counts)
    else:
        st.info("No data for selected filters.")

with viz_col4:
    st.subheader("Alerts by Severity")
    if not filtered.empty:
        severity_counts = filtered["severity"].value_counts()
        st.bar_chart(severity_counts)
    else:
        st.info("No data for selected filters.")

# ---------------- GeoIP Map ----------------
st.divider()
st.subheader("Attacker Locations")

sys.path.append(str(Path(__file__).resolve().parent.parent / "src"))
from geoip import enrich_ips

external_ips = filtered["src_ip"].dropna().unique().tolist()

if external_ips:
    with st.spinner("Resolving IP locations..."):
        geo_data = enrich_ips(external_ips)

    if geo_data:
        map_rows = []
        for ip, info in geo_data.items():
            count = filtered[filtered["src_ip"] == ip].shape[0]
            map_rows.append({
                "lat": info["lat"],
                "lon": info["lon"],
                "ip": ip,
                "city": info["city"],
                "country": info["country"],
                "alerts": count,
            })
        map_df = pd.DataFrame(map_rows)
        st.map(map_df, latitude="lat", longitude="lon", size="alerts")
        st.dataframe(map_df[["ip", "city", "country", "alerts"]], use_container_width=True)
    else:
        st.info("No external (public) IPs to map — all source IPs are private/internal.")
else:
    st.info("No data for selected filters.")

# ---------------- Footer ----------------
st.divider()
st.caption("ThreatLens — built as a portfolio project demonstrating SOC Tier-1 triage workflows.")
