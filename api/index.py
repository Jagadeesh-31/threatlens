import os
import sys
import json
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional
# pyrefly: ignore [missing-import]
from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

# Ensure src/ is on Python module search path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(ROOT_DIR / "src"))

from db import query_alerts, get_summary_stats, init_db, insert_alerts
from generator import build_auth_log
from parser import parse_log_file
from detectors import run_all_detectors

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
            base_time = datetime.now() - timedelta(hours=2)
            auth_lines = build_auth_log(base_time, 50)
            tmp_dir = Path("/tmp") if (os.environ.get("VERCEL") or not os.access(ROOT_DIR / "data", os.W_OK)) else (ROOT_DIR / "data")
            os.makedirs(tmp_dir, exist_ok=True)
            tmp_log = tmp_dir / "sample_auth.log"
            tmp_log.write_text("\n".join(auth_lines) + "\n", encoding="utf-8")
            df = parse_log_file(str(tmp_log), log_type="auth")
            alerts = run_all_detectors(df)
            insert_alerts(alerts)
    except Exception as e:
        print(f"Data population warning: {e}")


@app.on_event("startup")
def startup_event():
    ensure_data_populated()


@app.get("/api/health")
@app.get("/health")
def health_check():
    return {"status": "ok", "app": "ThreatLens SIEM"}


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


@app.get("/", response_class=HTMLResponse)
@app.get("/api", response_class=HTMLResponse)
@app.get("/api/index", response_class=HTMLResponse)
@app.get("/api/index.py", response_class=HTMLResponse)
@app.get("/index.py", response_class=HTMLResponse)
def dashboard_ui():
    ensure_data_populated()
    stats = get_summary_stats()
    alerts = query_alerts(limit=300)

    # Render initial table rows server-side for zero latency
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

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ThreatLens 🔎 — SIEM Security Dashboard</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
  <style>
    :root {{
      --bg: #0f172a;
      --card-bg: #1e293b;
      --border: #334155;
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
    .container {{ max-width: 1300px; margin: 0 auto; }}
    header {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 28px;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--border);
    }}
    .logo-title {{ display: flex; align-items: center; gap: 12px; }}
    .logo-title h1 {{ font-size: 1.8rem; font-weight: 800; tracking: -0.02em; }}
    .subtitle {{ color: var(--muted); font-size: 0.9rem; margin-top: 4px; }}
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
    
    .stats-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
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
    .stat-label {{ color: var(--muted); font-size: 0.85rem; font-weight: 500; text-transform: uppercase; letter-spacing: 0.05em; }}
    .stat-value {{ font-size: 2.2rem; font-weight: 800; margin-top: 8px; }}
    .stat-card.high .stat-value {{ color: var(--high); }}
    .stat-card.total .stat-value {{ color: var(--accent); }}
    .stat-card.ips .stat-value {{ color: #a78bfa; }}

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
      background: #334155;
      border-color: var(--accent);
      color: #fff;
    }}

    .table-container {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      overflow-x: auto;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    }}
    table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 0.9rem; }}
    th {{
      background: #111827;
      color: var(--muted);
      font-weight: 600;
      padding: 14px 16px;
      border-bottom: 1px solid var(--border);
      text-transform: uppercase;
      font-size: 0.75rem;
      letter-spacing: 0.05em;
    }}
    td {{ padding: 14px 16px; border-bottom: 1px solid #26334d; }}
    tr:hover {{ background: #26334d; }}
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
      <div class="subtitle">MITRE ATT&CK Automated Log Parsing & Threat Detection Dashboard</div>
    </header>

    <div class="stats-grid">
      <div class="stat-card total">
        <div class="stat-label">Total Ingested Alerts</div>
        <div class="stat-value" id="stat-total">{stats.get('total_alerts', 0)}</div>
      </div>
      <div class="stat-card high">
        <div class="stat-label">High Severity Threats</div>
        <div class="stat-value" id="stat-high">{stats.get('high_severity', 0)}</div>
      </div>
      <div class="stat-card ips">
        <div class="stat-label">Unique Attacker IPs</div>
        <div class="stat-value" id="stat-ips">{stats.get('unique_ips', 0)}</div>
      </div>
    </div>

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

    async function refreshTelemetry() {{
      try {{
        let endpoint = '/api/stats';
        const res = await fetch(endpoint);
        if (res.ok) {{
          const data = await res.json();
          document.getElementById('stat-total').innerText = data.total_alerts || 0;
          document.getElementById('stat-high').innerText = data.high_severity || 0;
          document.getElementById('stat-ips').innerText = data.unique_ips || 0;
        }}
      }} catch (err) {{
        console.log('Background sync info:', err);
      }}
    }}

    setInterval(refreshTelemetry, 15000);
  </script>
</body>
</html>"""
    return HTMLResponse(content=html_content)
