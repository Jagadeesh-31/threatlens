import os
import sys
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

# Ensure src/ is on Python module search path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(ROOT_DIR / "src"))

from db import query_alerts, get_summary_stats, init_db, insert_alerts
from geoip import enrich_ips

app = FastAPI(title="ThreatLens SIEM Dashboard API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def startup_event():
    """Ensure DB table exists on serverless startup."""
    try:
        init_db()
    except Exception as e:
        print(f"Startup DB init warning: {e}")

@app.get("/api/health")
def health_check():
    return {"status": "ok", "app": "ThreatLens SIEM"}

@app.get("/api/stats")
def stats_endpoint():
    try:
        stats = get_summary_stats()
        return stats
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

@app.get("/api/alerts")
def alerts_endpoint(
    severity: Optional[str] = Query(None),
    technique_id: Optional[str] = Query(None),
    src_ip: Optional[str] = Query(None),
    limit: int = Query(200)
):
    try:
        alerts = query_alerts(severity=severity, technique_id=technique_id, src_ip=src_ip, limit=limit)
        return {"count": len(alerts), "alerts": alerts}
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

@app.get("/", response_class=HTMLResponse)
def dashboard_ui():
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ThreatLens 🔎 — SIEM Security Dashboard</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #0f172a;
      --card-bg: #1e293b;
      --border: #334155;
      --text: #f8fafc;
      --muted: #94a3b8;
      --accent: #38bdf8;
      --high: #ef4444;
      --medium: #f59e0b;
      --low: #10b981;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Inter', sans-serif;
      background-color: var(--bg);
      color: var(--text);
      padding: 24px;
      line-height: 1.5;
    }
    .container { max-width: 1300px; margin: 0 auto; }
    header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 28px;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--border);
    }
    .logo-title { display: flex; align-items: center; gap: 12px; }
    .logo-title h1 { font-size: 1.8rem; font-weight: 800; tracking: -0.02em; }
    .subtitle { color: var(--muted); font-size: 0.9rem; margin-top: 4px; }
    .badge-live {
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
    }
    .pulse {
      width: 8px; height: 8px; background: #10b981; border-radius: 50%;
      box-shadow: 0 0 8px #10b981; animation: blink 1.5s infinite;
    }
    @keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
    
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 18px;
      margin-bottom: 28px;
    }
    .stat-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 20px;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    }
    .stat-label { color: var(--muted); font-size: 0.85rem; font-weight: 500; text-transform: uppercase; letter-spacing: 0.05em; }
    .stat-value { font-size: 2.2rem; font-weight: 800; margin-top: 8px; }
    .stat-card.high .stat-value { color: var(--high); }
    .stat-card.total .stat-value { color: var(--accent); }
    .stat-card.ips .stat-value { color: #a78bfa; }

    .controls {
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 18px;
    }
    .filter-group { display: flex; gap: 8px; }
    .btn {
      background: var(--card-bg);
      color: var(--text);
      border: 1px solid var(--border);
      padding: 8px 16px;
      border-radius: 8px;
      font-size: 0.85rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s;
    }
    .btn:hover, .btn.active {
      background: #334155;
      border-color: var(--accent);
      color: #fff;
    }

    .table-container {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      overflow-x: auto;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    }
    table { width: 100%; border-collapse: collapse; text-align: left; font-size: 0.9rem; }
    th {
      background: #111827;
      color: var(--muted);
      font-weight: 600;
      padding: 14px 16px;
      border-bottom: 1px solid var(--border);
      text-transform: uppercase;
      font-size: 0.75rem;
      letter-spacing: 0.05em;
    }
    td { padding: 14px 16px; border-bottom: 1px solid #26334d; }
    tr:hover { background: #26334d; }
    .mono { font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; }
    .badge {
      display: inline-block;
      padding: 4px 10px;
      border-radius: 6px;
      font-weight: 700;
      font-size: 0.75rem;
      text-transform: uppercase;
    }
    .badge.High { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }
    .badge.Medium { background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4); }
    .badge.Low { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); }
    .mitre-badge {
      background: #0f172a;
      color: var(--accent);
      border: 1px solid #0284c7;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 0.8rem;
    }
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
        <div class="stat-value" id="stat-total">-</div>
      </div>
      <div class="stat-card high">
        <div class="stat-label">High Severity Threats</div>
        <div class="stat-value" id="stat-high">-</div>
      </div>
      <div class="stat-card ips">
        <div class="stat-label">Unique Attacker IPs</div>
        <div class="stat-value" id="stat-ips">-</div>
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
          <tr><td colspan="6" style="text-align: center; color: var(--muted);">Loading SIEM telemetry data...</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <script>
    let currentSeverity = null;

    async function fetchStats() {
      try {
        const res = await fetch('/api/stats');
        const data = await res.json();
        document.getElementById('stat-total').innerText = data.total_alerts || 0;
        document.getElementById('stat-high').innerText = data.high_severity || 0;
        document.getElementById('stat-ips').innerText = data.unique_ips || 0;
      } catch (err) {
        console.error('Stats fetch error:', err);
      }
    }

    async function fetchAlerts() {
      try {
        let url = '/api/alerts';
        if (currentSeverity) url += '?severity=' + currentSeverity;
        const res = await fetch(url);
        const data = await res.json();
        const body = document.getElementById('alerts-body');
        
        if (!data.alerts || data.alerts.length === 0) {
          body.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--muted);">No security alerts found.</td></tr>';
          return;
        }

        body.innerHTML = data.alerts.map(a => `
          <tr>
            <td class="mono">${a.timestamp || '-'}</td>
            <td class="mono" style="color: var(--accent); font-weight: 600;">${a.src_ip || 'local'}</td>
            <td class="mono" style="color: #cbd5e1;">${a.user || '-'}</td>
            <td><span class="badge ${a.severity}">${a.severity}</span></td>
            <td><span class="mitre-badge mono">${a.technique_id} — ${a.technique_name}</span></td>
            <td>${a.description}</td>
          </tr>
        `).join('');
      } catch (err) {
        console.error('Alerts fetch error:', err);
      }
    }

    function filterSeverity(sev, btnElement) {
      currentSeverity = sev;
      document.querySelectorAll('.filter-group .btn').forEach(b => b.classList.remove('active'));
      btnElement.classList.add('active');
      fetchAlerts();
    }

    fetchStats();
    fetchAlerts();
    setInterval(() => { fetchStats(); fetchAlerts(); }, 15000);
  </script>
</body>
</html>"""
    return HTMLResponse(content=html_content)
