import os
import sys
import json
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional
from collections import Counter
from fastapi import FastAPI, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

# Ensure src/ is on Python module search path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(ROOT_DIR / "src"))

from db import query_alerts, get_summary_stats, init_db, insert_alerts, clear_all_alerts
from generator import build_auth_log, build_access_log
from parser import parse_log_file
from detectors import run_all_detectors
from geoip import enrich_ips

app = FastAPI(title="ThreatLens SIEM Dashboard API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def ensure_data_populated():
    """Ensure database exists and is populated with initial SIEM telemetry."""
    try:
        init_db()
        stats = get_summary_stats()
        if stats["total_alerts"] == 0:
            run_synthetic_pipeline()
    except Exception as e:
        print(f"Data population warning: {e}")


def run_synthetic_pipeline():
    """Generate fresh synthetic logs, run detectors, and insert alerts."""
    import random
    clear_all_alerts()

    offset_minutes = random.randint(15, 180)
    base_time = datetime.now() - timedelta(minutes=offset_minutes)
    num_auth = random.randint(35, 65)
    num_access = random.randint(100, 200)

    auth_lines = build_auth_log(base_time, num_auth)
    access_lines = build_access_log(base_time, num_access)

    tmp_dir = Path("/tmp") if (os.environ.get("VERCEL") or not os.access(ROOT_DIR / "data", os.W_OK)) else (ROOT_DIR / "data")
    os.makedirs(tmp_dir, exist_ok=True)

    auth_log_path = tmp_dir / "sample_auth.log"
    access_log_path = tmp_dir / "sample_access.log"

    auth_log_path.write_text("\n".join(auth_lines) + "\n", encoding="utf-8")
    access_log_path.write_text("\n".join(access_lines) + "\n", encoding="utf-8")

    df_auth = parse_log_file(str(auth_log_path), log_type="auth")
    alerts = run_all_detectors(df_auth)
    insert_alerts(alerts)


@app.on_event("startup")
def startup_event():
    ensure_data_populated()


@app.get("/api/health")
@app.get("/health")
def health_check():
    return {"status": "ok", "app": "ThreatLens SIEM"}


@app.api_route("/api/pipeline/run", methods=["GET", "POST"])
@app.api_route("/pipeline/run", methods=["GET", "POST"])
@app.api_route("/api/index.py/api/pipeline/run", methods=["GET", "POST"])
@app.api_route("/api/index.py/pipeline/run", methods=["GET", "POST"])
def replay_attack_endpoint():
    """Replay attack demo control — generates fresh logs and populates DB."""
    try:
        run_synthetic_pipeline()
        return {"status": "success", "message": "Replayed attack traffic & regenerated alerts."}
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/api/stats")
@app.get("/stats")
@app.get("/api/index.py/api/stats")
@app.get("/api/index.py/stats")
def stats_endpoint():
    try:
        ensure_data_populated()
        return get_summary_stats()
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/api/alerts")
@app.get("/alerts")
@app.get("/api/index.py/api/alerts")
@app.get("/api/index.py/alerts")
def alerts_endpoint(
    severity: Optional[str] = Query(None),
    technique_id: Optional[str] = Query(None),
    src_ip: Optional[str] = Query(None),
    limit: int = Query(200)
):
    try:
        ensure_data_populated()
        alerts = query_alerts(severity=severity, technique_id=technique_id, src_ip=src_ip, limit=limit)
        return {"count": len(alerts), "alerts": alerts}
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.api_route("/", methods=["GET", "POST"], response_class=HTMLResponse)
@app.api_route("/api", methods=["GET", "POST"], response_class=HTMLResponse)
@app.api_route("/api/index", methods=["GET", "POST"], response_class=HTMLResponse)
@app.api_route("/api/index.py", methods=["GET", "POST"], response_class=HTMLResponse)
@app.api_route("/index.py", methods=["GET", "POST"], response_class=HTMLResponse)
def dashboard_ui(request: Request):
    path = str(request.url.path)
    if "pipeline" in path or "run" in path:
        run_synthetic_pipeline()
        return JSONResponse({"status": "success", "message": "Replayed attack traffic."})

    ensure_data_populated()
    stats = get_summary_stats()
    alerts = query_alerts(limit=500)

    # 1. Compute Top Threat Insight Banner data
    if alerts:
        ip_counts = Counter([a["src_ip"] for a in alerts if a.get("src_ip")])
        top_ip, top_ip_count = ip_counts.most_common(1)[0] if ip_counts else ("local", 0)
        top_ip_pct = (top_ip_count / len(alerts)) * 100 if alerts else 0
        
        top_ip_alerts = [a for a in alerts if a.get("src_ip") == top_ip]
        tech_counts = Counter([a["technique_name"] for a in top_ip_alerts])
        top_tech_name = tech_counts.most_common(1)[0][0] if tech_counts else "Brute Force"
        top_tech_id = next((a["technique_id"] for a in top_ip_alerts if a.get("technique_name") == top_tech_name), "T1110")
        
        geo_res = enrich_ips([top_ip])
        if top_ip in geo_res and geo_res[top_ip]:
            loc = geo_res[top_ip]
            location_str = f"{loc.get('city')}, {loc.get('country')}"
        elif str(top_ip).startswith(("192.168.", "10.", "172.16.", "127.")):
            location_str = "Internal / Private Network"
        else:
            location_str = "Unknown Location"
            
        insight_banner = f"💡 <b>Top Threat Insight:</b> Primary threat vector is <b>{top_tech_name} ({top_tech_id})</b> from source IP <code><b>{top_ip}</b></code> ({location_str}) — <b>{top_ip_count} alerts</b> ({top_ip_pct:.1f}% of filtered activity)."
    else:
        insight_banner = "💡 <b>Top Threat Insight:</b> No threat alerts available."

    # 2. Compute Chart Datasets
    # A. Time Series (Alert Volume Over Time)
    time_bins = Counter()
    for a in alerts:
        ts_raw = a.get("timestamp", "")
        try:
            dt = datetime.fromisoformat(str(ts_raw))
            time_key = dt.strftime("%b %d %H:%M")
        except Exception:
            time_key = str(ts_raw)[:16]
        time_bins[time_key] += 1

    time_labels = sorted(time_bins.keys())
    time_counts = [time_bins[k] for k in time_labels]

    # B. MITRE Technique breakdown
    tech_counts = Counter([a.get("technique_name", "Unknown") for a in alerts])
    tech_labels = [k for k, v in tech_counts.most_common(6)]
    tech_data = [v for k, v in tech_counts.most_common(6)]

    # C. Top Offending IPs
    ip_counts_all = Counter([a.get("src_ip", "local") for a in alerts])
    ip_labels = [k for k, v in ip_counts_all.most_common(8)]
    ip_data = [v for k, v in ip_counts_all.most_common(8)]

    # D. Severity breakdown
    sev_counts = Counter([a.get("severity", "Low") for a in alerts])
    sev_labels = ["High", "Medium", "Low"]
    sev_data = [sev_counts.get("High", 0), sev_counts.get("Medium", 0), sev_counts.get("Low", 0)]

    # 3. Compute GeoIP Map markers
    external_ips = [a["src_ip"] for a in alerts if a.get("src_ip") and not str(a["src_ip"]).startswith(("192.168.", "10.", "172.16.", "127.", "local"))]
    geo_data_dict = enrich_ips(external_ips)
    
    geo_markers = []
    geo_table_rows = []
    if geo_data_dict:
        for ip, info in geo_data_dict.items():
            if info:
                cnt = sum(1 for a in alerts if a.get("src_ip") == ip)
                geo_markers.append({
                    "ip": ip,
                    "lat": info["lat"],
                    "lon": info["lon"],
                    "city": info["city"],
                    "country": info["country"],
                    "count": cnt
                })
                geo_table_rows.append(f"""
                  <tr>
                    <td class="mono" style="color: var(--accent); font-weight: 600;">{ip}</td>
                    <td>{info['city']}</td>
                    <td>{info['country']}</td>
                    <td class="mono" style="font-weight: 700;">{cnt}</td>
                  </tr>
                """)

    # 4. Render Table rows
    unique_techs = len(set(a.get("technique_id") for a in alerts))
    rows_html = ""
    for a in alerts:
        sev = a.get("severity", "Low")
        rows_html += f"""
          <tr>
            <td class="mono">{a.get('timestamp') or '-'}</td>
            <td class="mono" style="color: var(--accent); font-weight: 600;">{a.get('src_ip') or 'local'}</td>
            <td class="mono" style="color: #cbd5e1;">{a.get('user') or '-'}</td>
            <td><span class="badge {sev}">{sev}</span></td>
            <td><span class="mitre-badge mono">{a.get('technique_id', '')} — {a.get('technique_name', '')}</span></td>
            <td>{a.get('description', '')}</td>
          </tr>
        """

    initial_alerts_json = json.dumps(alerts)
    geo_markers_json = json.dumps(geo_markers)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ThreatLens 🔎 — SIEM Security Dashboard</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
  <!-- Chart.js & Leaflet JS/CSS CDN -->
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
  <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
  <style>
    :root {{
      --bg: #0b0f19;
      --card-bg: #151c2c;
      --border: #26334d;
      --text: #f8fafc;
      --muted: #94a3b8;
      --accent: #38bdf8;
      --high: #ef4444;
      --medium: #f59e0b;
      --low: #10b981;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: 'Inter', sans-serif;
      background-color: var(--bg);
      color: var(--text);
      padding: 24px;
      line-height: 1.5;
    }}
    .container {{ max-width: 1350px; margin: 0 auto; }}
    header {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 24px;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--border);
    }}
    .logo-title {{ display: flex; align-items: center; gap: 12px; }}
    .logo-title h1 {{ font-size: 1.8rem; font-weight: 800; tracking: -0.02em; }}
    .subtitle {{ color: var(--muted); font-size: 0.9rem; margin-top: 4px; }}
    .header-actions {{ display: flex; align-items: center; gap: 12px; }}
    .badge-live {{
      background: rgba(16, 185, 129, 0.15);
      color: #34d399;
      border: 1px solid rgba(16, 185, 129, 0.3);
      padding: 4px 10px;
      border-radius: 9999px;
      font-size: 0.75rem;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 6px;
    }}
    .pulse {{
      width: 8px; height: 8px; background: #10b981; border-radius: 50%;
      box-shadow: 0 0 8px #10b981; animation: blink 1.5s infinite;
    }}
    @keyframes blink {{ 0%, 100% {{ opacity: 1; }} 50% {{ opacity: 0.3; }} }}

    .btn-replay {{
      background: #0284c7;
      color: #ffffff;
      border: none;
      padding: 8px 16px;
      border-radius: 8px;
      font-size: 0.85rem;
      font-weight: 700;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      transition: background 0.2s;
    }}
    .btn-replay:hover {{ background: #0369a1; }}
    
    .insight-box {{
      background-color: #1e293b;
      color: #f8fafc;
      border-left: 4px solid var(--high);
      padding: 1rem 1.25rem;
      border-radius: 8px;
      margin-bottom: 24px;
      font-size: 0.95rem;
      border: 1px solid var(--border);
      border-left-width: 4px;
      box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);
    }}
    .insight-box code {{
      background-color: #0f172a;
      color: var(--accent);
      padding: 0.15rem 0.45rem;
      border-radius: 4px;
      font-weight: 600;
      border: 1px solid var(--border);
    }}

    .stats-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 18px;
      margin-bottom: 28px;
    }}
    .stat-card {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 20px;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    }}
    .stat-label {{ color: var(--muted); font-size: 0.82rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }}
    .stat-value {{ font-size: 2.4rem; font-weight: 800; margin-top: 6px; }}
    .stat-card.total .stat-value {{ color: var(--text); }}
    .stat-card.high .stat-value {{ color: var(--high); }}
    .stat-card.ips .stat-value {{ color: var(--accent); }}
    .stat-card.techs .stat-value {{ color: #a78bfa; }}

    .section-title {{
      font-size: 1.25rem; font-weight: 700; margin-bottom: 16px; color: var(--text);
      display: flex; align-items: center; gap: 8px;
    }}

    .charts-grid {{
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 20px;
      margin-bottom: 32px;
    }}
    @media (max-width: 900px) {{ .charts-grid {{ grid-template-columns: 1fr; }} }}

    .chart-card {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 20px;
    }}
    .chart-card h3 {{ font-size: 0.95rem; font-weight: 600; color: var(--muted); margin-bottom: 14px; }}
    .chart-wrapper {{ position: relative; height: 260px; width: 100%; }}

    .map-container {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 20px;
      margin-bottom: 32px;
    }}
    #map {{ height: 380px; width: 100%; border-radius: 8px; background: #111827; }}

    .controls {{
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 18px;
    }}
    .filter-group {{ display: flex; gap: 8px; }}
    .btn {{
      background: var(--card-bg);
      color: var(--text);
      border: 1px solid var(--border);
      padding: 8px 16px;
      border-radius: 8px;
      font-size: 0.85rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s;
    }}
    .btn:hover, .btn.active {{
      background: #26334d;
      border-color: var(--accent);
      color: #fff;
    }}

    .table-container {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      overflow-x: auto;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
      margin-bottom: 32px;
    }}
    table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 0.9rem; }}
    th {{
      background: #0f172a;
      color: var(--muted);
      font-weight: 600;
      padding: 14px 16px;
      border-bottom: 1px solid var(--border);
      text-transform: uppercase;
      font-size: 0.75rem;
      letter-spacing: 0.05em;
    }}
    td {{ padding: 14px 16px; border-bottom: 1px solid #1e293b; }}
    tr:hover {{ background: #1e293b; }}
    .mono {{ font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; }}
    .badge {{
      display: inline-block;
      padding: 4px 10px;
      border-radius: 6px;
      font-weight: 700;
      font-size: 0.75rem;
      text-transform: uppercase;
    }}
    .badge.High {{ background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }}
    .badge.Medium {{ background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4); }}
    .badge.Low {{ background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }}
    .mitre-badge {{
      background: #0f172a;
      color: var(--accent);
      border: 1px solid #0284c7;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 0.8rem;
    }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="logo-title">
        <h1>ThreatLens 🔎</h1>
        <div class="badge-live"><div class="pulse"></div> SIEM Active</div>
      </div>
      <div class="header-actions">
        <button class="btn-replay" onclick="replayAttack()">🔁 Regenerate Logs & Replay Attack</button>
      </div>
    </header>

    <div class="insight-box">
      {insight_banner}
    </div>

    <div class="stats-grid">
      <div class="stat-card total">
        <div class="stat-label">Total Alerts</div>
        <div class="stat-value" id="stat-total">{stats.get('total_alerts', 0)}</div>
      </div>
      <div class="stat-card high">
        <div class="stat-label">High Severity</div>
        <div class="stat-value" id="stat-high">{stats.get('high_severity', 0)}</div>
      </div>
      <div class="stat-card ips">
        <div class="stat-label">Unique Source IPs</div>
        <div class="stat-value" id="stat-ips">{stats.get('unique_ips', 0)}</div>
      </div>
      <div class="stat-card techs">
        <div class="stat-label">Techniques Detected</div>
        <div class="stat-value" id="stat-techs">{unique_techs}</div>
      </div>
    </div>

    <!-- Analytics & Detection Trends Charts -->
    <div class="section-title">📊 Analytics & Detection Trends</div>
    <div class="charts-grid">
      <div class="chart-card">
        <h3>Alert Volume Over Time</h3>
        <div class="chart-wrapper"><canvas id="chartTime"></canvas></div>
      </div>
      <div class="chart-card">
        <h3>Alerts by MITRE Technique</h3>
        <div class="chart-wrapper"><canvas id="chartTech"></canvas></div>
      </div>
      <div class="chart-card">
        <h3>Top Offending IPs</h3>
        <div class="chart-wrapper"><canvas id="chartIP"></canvas></div>
      </div>
      <div class="chart-card">
        <h3>Alerts by Severity</h3>
        <div class="chart-wrapper"><canvas id="chartSev"></canvas></div>
      </div>
    </div>

    <!-- Attacker Locations Map -->
    <div class="section-title">🌍 Attacker Locations Map</div>
    <div class="map-container">
      <div id="map"></div>
      <div style="margin-top: 16px;" class="table-container">
        <table>
          <thead>
            <tr>
              <th>Source IP</th>
              <th>City</th>
              <th>Country</th>
              <th>Alert Count</th>
            </tr>
          </thead>
          <tbody>
            {''.join(geo_table_rows) if geo_table_rows else '<tr><td colspan="4" style="text-align: center; color: var(--muted);">No external attacker IPs to map.</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>

    <!-- Filterable Alerts Table -->
    <div class="section-title">📋 Security Alerts Telemetry</div>
    <div class="controls">
      <div class="filter-group">
        <button class="btn active" onclick="filterSeverity(null, this)">All Severities</button>
        <button class="btn" onclick="filterSeverity('High', this)">🔴 High</button>
        <button class="btn" onclick="filterSeverity('Medium', this)">🟡 Medium</button>
        <button class="btn" onclick="filterSeverity('Low', this)">🟢 Low</button>
      </div>
    </div>

    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Attacker IP</th>
            <th>Target User</th>
            <th>Severity</th>
            <th>MITRE Technique</th>
            <th>Alert Description</th>
          </tr>
        </thead>
        <tbody id="alerts-body">
          {rows_html if rows_html else '<tr><td colspan="6" style="text-align: center; color: var(--muted);">No security alerts found.</td></tr>'}
        </tbody>
      </table>
    </div>
  </div>

  <script>
    let currentSeverity = null;
    let allAlerts = {initial_alerts_json};
    let geoMarkers = {geo_markers_json};

    // 1. Time Series Chart
    new Chart(document.getElementById('chartTime'), {{
      type: 'line',
      data: {{
        labels: {json.dumps(time_labels)},
        datasets: [{{
          label: 'Alert Count',
          data: {json.dumps(time_counts)},
          borderColor: '#ef4444',
          backgroundColor: 'rgba(239, 68, 68, 0.15)',
          fill: true,
          tension: 0.35,
          borderWidth: 2,
          pointRadius: 4
        }}]
      }},
      options: {{
        responsive: true,
        maintainAspectRatio: false,
        plugins: {{ legend: {{ display: false }} }},
        scales: {{
          x: {{ grid: {{ color: '#1e293b' }}, ticks: {{ color: '#94a3b8' }} }},
          y: {{ grid: {{ color: '#1e293b' }}, ticks: {{ color: '#94a3b8', stepSize: 1 }}, beginAtZero: true }}
        }}
      }}
    }});

    // 2. MITRE Technique Chart (Vertical Bar Chart)
    new Chart(document.getElementById('chartTech'), {{
      type: 'bar',
      data: {{
        labels: {json.dumps(tech_labels)},
        datasets: [{{
          label: 'Alert Count',
          data: {json.dumps(tech_data)},
          backgroundColor: '#38bdf8',
          borderRadius: 6
        }}]
      }},
      options: {{
        responsive: true,
        maintainAspectRatio: false,
        plugins: {{ legend: {{ display: false }} }},
        scales: {{
          x: {{ grid: {{ color: '#1e293b' }}, ticks: {{ color: '#94a3b8', maxRotation: 45, minRotation: 0 }} }},
          y: {{ grid: {{ color: '#1e293b' }}, ticks: {{ color: '#94a3b8', stepSize: 1 }}, beginAtZero: true }}
        }}
      }}
    }});

    // 3. Top IPs Chart (Vertical Bar Chart)
    new Chart(document.getElementById('chartIP'), {{
      type: 'bar',
      data: {{
        labels: {json.dumps(ip_labels)},
        datasets: [{{
          label: 'Alert Count',
          data: {json.dumps(ip_data)},
          backgroundColor: '#a78bfa',
          borderRadius: 6
        }}]
      }},
      options: {{
        responsive: true,
        maintainAspectRatio: false,
        plugins: {{ legend: {{ display: false }} }},
        scales: {{
          x: {{ grid: {{ color: '#1e293b' }}, ticks: {{ color: '#94a3b8', maxRotation: 45, minRotation: 0 }} }},
          y: {{ grid: {{ color: '#1e293b' }}, ticks: {{ color: '#94a3b8', stepSize: 1 }}, beginAtZero: true }}
        }}
      }}
    }});

    // 4. Alerts by Severity Chart
    new Chart(document.getElementById('chartSev'), {{
      type: 'bar',
      data: {{
        labels: {json.dumps(sev_labels)},
        datasets: [{{
          label: 'Alert Count',
          data: {json.dumps(sev_data)},
          backgroundColor: ['#ef4444', '#f59e0b', '#10b981'],
          borderRadius: 6
        }}]
      }},
      options: {{
        responsive: true,
        maintainAspectRatio: false,
        plugins: {{ legend: {{ display: false }} }},
        scales: {{
          x: {{ grid: {{ color: '#1e293b' }}, ticks: {{ color: '#94a3b8' }} }},
          y: {{ grid: {{ color: '#1e293b' }}, ticks: {{ color: '#94a3b8', stepSize: 1 }}, beginAtZero: true }}
        }}
      }}
    }});

    // Leaflet Dark GeoIP Map Initialization
    const map = L.map('map').setView([30, 10], 2);
    L.tileLayer('https://{{s}}.basemaps.cartocdn.com/dark_all/{{z}}/{{x}}/{{y}}{{r}}.png', {{
      attribution: '&copy; OpenStreetMap &copy; CARTO',
      subdomains: 'abcd',
      maxZoom: 19
    }}).addTo(map);

    geoMarkers.forEach(m => {{
      const circle = L.circleMarker([m.lat, m.lon], {{
        color: '#ef4444',
        fillColor: '#ef4444',
        fillOpacity: 0.6,
        radius: Math.max(8, Math.min(24, m.count * 1.5))
      }}).addTo(map);

      circle.bindPopup(`
        <div style="color: #0f172a; font-family: sans-serif;">
          <b>Attacker IP:</b> ${{m.ip}}<br/>
          <b>Location:</b> ${{m.city}}, ${{m.country}}<br/>
          <b>Alerts:</b> ${{m.count}}
        </div>
      `);
    }});

    function renderTable(alertsList) {{
      const body = document.getElementById('alerts-body');
      if (!alertsList || alertsList.length === 0) {{
        body.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--muted);">No security alerts found.</td></tr>';
        return;
      }}

      body.innerHTML = alertsList.map(a => `
        <tr>
          <td class="mono">${{a.timestamp || '-'}}</td>
          <td class="mono" style="color: var(--accent); font-weight: 600;">${{a.src_ip || 'local'}}</td>
          <td class="mono" style="color: #cbd5e1;">${{a.user || '-'}}</td>
          <td><span class="badge ${{a.severity}}">${{a.severity}}</span></td>
          <td><span class="mitre-badge mono">${{a.technique_id}} — ${{a.technique_name}}</span></td>
          <td>${{a.description}}</td>
        </tr>
      `).join('');
    }}

    function filterSeverity(sev, btnElement) {{
      currentSeverity = sev;
      document.querySelectorAll('.filter-group .btn').forEach(b => b.classList.remove('active'));
      btnElement.classList.add('active');
      
      if (!sev) {{
        renderTable(allAlerts);
      }} else {{
        renderTable(allAlerts.filter(a => a.severity === sev));
      }}
    }}

    async function replayAttack() {{
      const btn = document.querySelector('.btn-replay');
      btn.innerText = '⌛ Generating & Replaying Attack...';
      try {{
        let res = await fetch('/api/pipeline/run', {{ method: 'POST' }});
        if (!res.ok) {{
          res = await fetch('/pipeline/run', {{ method: 'POST' }});
        }}
        if (!res.ok) {{
          res = await fetch('/api/pipeline/run', {{ method: 'GET' }});
        }}
        window.location.reload();
      }} catch (e) {{
        btn.innerText = '🔁 Regenerate Logs & Replay Attack';
        alert('Failed to trigger pipeline replay.');
      }}
    }}
  </script>
</body>
</html>"""
    return HTMLResponse(content=html_content)
