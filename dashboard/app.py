"""
app.py — ThreatLens Streamlit SIEM Dashboard

Reads alerts from SQLite (populated by run_pipeline.py) and displays
them in an interactive dashboard: top threat insight summary, filterable & 
deduplicated alert table, analytical visualizations, and GeoIP attacker map.
"""

import sys
import subprocess
from pathlib import Path
import pandas as pd
import streamlit as st
import plotly.express as px

sys.path.append(str(Path(__file__).resolve().parent.parent / "src"))
from db import query_alerts, get_summary_stats, init_db
from geoip import enrich_ips

# ---------------- Page Config & Light Styling ----------------
st.set_page_config(
    page_title="ThreatLens SIEM Dashboard",
    page_icon="🔎",
    layout="wide",
)

st.markdown("""
    <style>
    .block-container {padding-top: 1.5rem; padding-bottom: 2rem;}
    [data-testid="stMetricValue"] {font-size: 1.9rem; font-weight: 700; color: #0f172a;}
    [data-testid="stMetricLabel"] {color: #475569; font-weight: 500;}
    .insight-box {
        background-color: #f0f4f9;
        color: #1e293b;
        border-left: 4px solid #ff4b4b;
        padding: 0.85rem 1.2rem;
        border-radius: 6px;
        margin-bottom: 1.2rem;
        font-size: 1.05rem;
        box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }
    .insight-box code {
        background-color: #e2e8f0;
        color: #0f766e;
        padding: 0.15rem 0.45rem;
        border-radius: 4px;
        font-weight: 600;
    }
    </style>
""", unsafe_allow_html=True)

init_db()  # Ensure database exists

# ---------------- Header ----------------
st.title("🔎 ThreatLens SIEM Dashboard")
st.caption("SIEM-style log analysis & alerting dashboard — MITRE ATT&CK mapped detections")

# ---------------- Replay Attack Control ----------------
with st.sidebar:
    st.divider()
    st.subheader("Demo Controls")
    if st.button("🔁 Regenerate logs & replay attack"):
        with st.spinner("Generating new synthetic attack traffic..."):
            subprocess.run(["python", "src/generator.py"], cwd=Path(__file__).resolve().parent.parent)
            subprocess.run(["python", "run_pipeline.py"], cwd=Path(__file__).resolve().parent.parent)
        st.success("New attack data generated and processed! Refreshing...")
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

# ---------------- Top Insight Summary Banner ----------------
st.divider()

if not filtered.empty:
    top_ip = filtered["src_ip"].value_counts().idxmax()
    top_ip_alert_count = filtered["src_ip"].value_counts().max()
    top_ip_pct = (top_ip_alert_count / len(filtered)) * 100
    
    top_ip_df = filtered[filtered["src_ip"] == top_ip]
    top_tech_name = top_ip_df["technique_name"].value_counts().idxmax()
    top_tech_id = top_ip_df[top_ip_df["technique_name"] == top_tech_name]["technique_id"].iloc[0]
    
    # Resolve location
    geo_res = enrich_ips([top_ip])
    if top_ip in geo_res:
        loc = geo_res[top_ip]
        location_str = f"{loc['city']}, {loc['country']}"
    elif top_ip.startswith(("192.168.", "10.", "172.16.", "127.")):
        location_str = "Internal / Private Network"
    else:
        location_str = "Unknown Location"
        
    st.markdown(
        f'<div class="insight-box">💡 <b>Top Threat Insight:</b> Primary threat vector is <b>{top_tech_name} ({top_tech_id})</b> from source IP <code><b>{top_ip}</b></code> ({location_str}) — <b>{top_ip_alert_count} alerts</b> ({top_ip_pct:.1f}% of filtered activity).</div>',
        unsafe_allow_html=True,
    )
else:
    st.markdown(
        '<div class="insight-box">💡 <b>Top Threat Insight:</b> No threat alerts match the currently selected filters.</div>',
        unsafe_allow_html=True,
    )

# ---------------- Alerts Table (Deduplicated & Interactive) ----------------
st.subheader(f"Alerts ({len(filtered)} total events)")

if not filtered.empty:
    # Deduplicate / aggregate near-identical alerts (same src_ip, technique_id, technique_name, severity, user)
    agg_rows = []
    grouped = filtered.groupby(["src_ip", "technique_id", "technique_name", "severity", "user"], dropna=False)
    
    for (src_ip, tech_id, tech_name, severity, user), group in grouped:
        group_sorted = group.sort_values("timestamp", ascending=False)
        occurrences = len(group_sorted)
        latest_time = group_sorted["timestamp"].iloc[0]
        earliest_time = group_sorted["timestamp"].iloc[-1]
        base_desc = group_sorted["description"].iloc[0]
        
        if occurrences > 1:
            if earliest_time.date() == latest_time.date():
                time_range_str = f"{earliest_time.strftime('%H:%M:%S')}–{latest_time.strftime('%H:%M:%S')}"
            else:
                time_range_str = f"{earliest_time.strftime('%m-%d %H:%M')} to {latest_time.strftime('%m-%d %H:%M')}"
            details_str = f"{base_desc} ({occurrences} occurrences, {time_range_str})"
        else:
            time_range_str = latest_time.strftime('%H:%M:%S')
            details_str = base_desc
            
        agg_rows.append({
            "Latest Timestamp": latest_time,
            "Severity": severity,
            "Technique ID": tech_id,
            "Technique Name": tech_name,
            "Source IP": src_ip,
            "User": user if pd.notna(user) else "-",
            "Occurrences": occurrences,
            "Time Range / Details": details_str,
        })
        
    display_df = pd.DataFrame(agg_rows).sort_values("Latest Timestamp", ascending=False)
    
    def severity_color(val):
        colors = {"High": "#ff4b4b", "Medium": "#ffa500", "Low": "#f0e130"}
        return f"background-color: {colors.get(val, 'white')}; color: black; font-weight: bold;"
        
    styler = display_df.style
    if hasattr(styler, "map"):
        styler = styler.map(severity_color, subset=["Severity"])
    else:
        styler = styler.applymap(severity_color, subset=["Severity"])
        
    st.dataframe(
        styler,
        use_container_width=True,
        height=320,
    )
else:
    st.info("No alert records available for the selected filters.")

st.divider()

# ---------------- Visualizations / Analytics ----------------
st.subheader("Analytics & Detection Trends")

viz_col1, viz_col2 = st.columns(2)

with viz_col1:
    st.markdown("##### Alert Volume Over Time")
    if not filtered.empty:
        # Choose dynamic resampling frequency based on time span
        time_span = (filtered["timestamp"].max() - filtered["timestamp"].min()).total_seconds()
        if time_span > 86400 * 2:
            freq = "1D"
        elif time_span > 3600 * 6:
            freq = "1h"
        else:
            freq = "5min"

        time_series = (
            filtered.set_index("timestamp")
            .resample(freq)
            .size()
            .reset_index(name="count")
            .sort_values("timestamp")
        )
        
        fig_time = px.line(
            time_series,
            x="timestamp",
            y="count",
            labels={"timestamp": "Time Window", "count": "Alert Count"},
            color_discrete_sequence=["#ff4b4b"],
        )
        fig_time.update_traces(mode="lines+markers", line=dict(width=2.5), marker=dict(size=7))
        
        max_y = time_series["count"].max()
        fig_time.update_xaxes(showgrid=True, gridcolor="#e2e8f0", title_text="Timestamp")
        fig_time.update_yaxes(
            showgrid=True,
            gridcolor="#e2e8f0",
            zeroline=True,
            dtick=1 if max_y <= 10 else None,
            rangemode="tozero",
            title_text="Alert Count",
        )
        fig_time.update_layout(
            margin=dict(l=20, r=20, t=25, b=20),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#1e293b"),
            height=310,
        )
        st.plotly_chart(fig_time, use_container_width=True)
    else:
        st.info("No data for selected filters.")

with viz_col2:
    st.markdown("##### Alerts by MITRE Technique")
    if not filtered.empty:
        tech_df = filtered["technique_name"].value_counts().reset_index()
        tech_df.columns = ["technique", "count"]
        
        fig_tech = px.bar(
            tech_df,
            x="count",
            y="technique",
            orientation="h",
            labels={"count": "Alert Count", "technique": "Technique"},
            color_discrete_sequence=["#636efa"],
            text="count",
        )
        fig_tech.update_traces(textposition="outside")
        fig_tech.update_xaxes(showgrid=True, gridcolor="#e2e8f0", title_text="Alert Count")
        fig_tech.update_yaxes(autorange="reversed", title_text="Technique")
        fig_tech.update_layout(
            margin=dict(l=20, r=20, t=25, b=20),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#1e293b"),
            height=310,
        )
        st.plotly_chart(fig_tech, use_container_width=True)
    else:
        st.info("No data for selected filters.")

viz_col3, viz_col4 = st.columns(2)

with viz_col3:
    st.markdown("##### Top Offending IPs")
    if not filtered.empty:
        ip_df = filtered["src_ip"].value_counts().head(10).reset_index()
        ip_df.columns = ["src_ip", "count"]
        
        fig_ip = px.bar(
            ip_df,
            x="count",
            y="src_ip",
            orientation="h",
            labels={"count": "Alert Count", "src_ip": "Source IP"},
            color_discrete_sequence=["#00cc96"],
            text="count",
        )
        fig_ip.update_traces(textposition="outside")
        fig_ip.update_xaxes(showgrid=True, gridcolor="#e2e8f0", title_text="Alert Count")
        fig_ip.update_yaxes(autorange="reversed", title_text="Source IP")
        fig_ip.update_layout(
            margin=dict(l=20, r=20, t=25, b=20),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#1e293b"),
            height=310,
        )
        st.plotly_chart(fig_ip, use_container_width=True)
    else:
        st.info("No data for selected filters.")

with viz_col4:
    st.markdown("##### Alerts by Severity")
    if not filtered.empty:
        sev_order = ["High", "Medium", "Low"]
        sev_counts = filtered["severity"].value_counts().reindex(sev_order, fill_value=0).reset_index()
        sev_counts.columns = ["severity", "count"]

        color_map = {
            "High": "#ff4b4b",
            "Medium": "#ffa500",
            "Low": "#f0e130"
        }

        fig_sev = px.bar(
            sev_counts,
            x="severity",
            y="count",
            color="severity",
            color_discrete_map=color_map,
            text="count",
            labels={"severity": "Severity Level", "count": "Alert Count"},
            category_orders={"severity": ["High", "Medium", "Low"]}
        )
        fig_sev.update_traces(textposition="outside")
        max_sev_y = sev_counts["count"].max()
        fig_sev.update_xaxes(title_text="Severity Level")
        fig_sev.update_yaxes(
            title_text="Alert Count",
            showgrid=True,
            gridcolor="#e2e8f0",
            dtick=1 if max_sev_y <= 10 else None,
            rangemode="tozero",
        )
        fig_sev.update_layout(
            showlegend=False,
            margin=dict(l=20, r=20, t=25, b=20),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#1e293b"),
            height=310,
        )
        st.plotly_chart(fig_sev, use_container_width=True)
    else:
        st.info("No data for selected filters.")

# ---------------- GeoIP Map View ----------------
st.divider()
st.subheader("Attacker Locations Map")

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
        
        # Plotly Scatter Geo Map matching Image 1 styling
        fig_map = px.scatter_geo(
            map_df,
            lat="lat",
            lon="lon",
            size="alerts",
            hover_name="ip",
            hover_data={"city": True, "country": True, "alerts": True, "lat": False, "lon": False},
            projection="natural earth",
            size_max=36,
            color_discrete_sequence=["#ff4b4b"],
        )
        fig_map.update_geos(
            showcountries=True, countrycolor="#475569",
            showcoastlines=True, coastlinecolor="#475569",
            showland=True, landcolor="#242832",
            showocean=True, oceancolor="#15181c",
            projection_type="natural earth"
        )
        fig_map.update_layout(
            margin=dict(l=0, r=0, t=10, b=0),
            height=430,
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#1e293b"),
        )
        st.plotly_chart(fig_map, use_container_width=True)
        st.dataframe(map_df[["ip", "city", "country", "alerts"]].rename(columns={"ip": "Source IP", "city": "City", "country": "Country", "alerts": "Alert Count"}), use_container_width=True)
    else:
        st.info("No external (public) IPs to map — all source IPs are private/internal.")
else:
    st.info("No data for selected filters.")

# ---------------- Footer ----------------
st.divider()
st.caption("ThreatLens — built as a portfolio project demonstrating SOC Tier-1 triage workflows.")
