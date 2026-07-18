# ThreatLens 🔍

ThreatLens is a lightweight, local Security Operations Center (SOC) Log Parser, Detection Engine, and Interactive Dashboard. It parses raw system logs (such as SSH auth logs and Web server access logs), detects malicious activities based on pre-defined heuristics mapped to the MITRE ATT&CK framework, stores alerts in a local SQLite database, and visualizes them on a rich Streamlit dashboard.

---

## 📂 Project Structure

```text
threatlens/
├── data/                  # Sample & synthetic raw logs
├── src/                   # Core Python detection pipeline
│   ├── parser.py          # Log regex parsing and structuring
│   ├── detectors.py       # Detection rule engine (MITRE ATT&CK mapping)
│   ├── generator.py       # Synthetic log generation script
│   └── db.py              # SQLite storage layer for alerts
├── dashboard/             # Front-end UI
│   └── app.py             # Streamlit visualization & alert manager
├── requirements.txt       # Project dependencies
└── README.md              # Project documentation (this file)
```

---

## 🛠️ Technology Stack

- **Core**: Python 3.10+
- **Log Processing**: `pandas`
- **Data Visualizations**: `plotly`
- **Interactive UI**: `streamlit`
- **Mock Log Generation**: `faker`
- **Storage Layer**: SQLite (`sqlite3` standard library)

---

## 📊 MITRE ATT&CK Detections Mapping

| Threat / Scenario | MITRE ATT&CK Technique | Severity | Detector Function |
|---|---|---|---|
| SSH Brute Force | Brute Force (T1110) | High | `detect_bruteforce` |
| Network Port Scan | Active Scanning (T1595) | Medium | `detect_portscan` |
| Privilege Escalation | Abuse of Privilege (T1548) | High | `detect_priv_escalation` |
| Off-hours Admin Logins | Valid Accounts (T1078) | Low | `detect_offhours_login` |

---

## 🚀 Getting Started

### 1. Set Up Virtual Environment

Open your terminal, navigate to the `threatlens` directory, and run:

**Windows:**
```powershell
python -m venv venv
.\venv\Scripts\activate
```

**Mac/Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Generate Sample Logs (Day 2 onwards)
```bash
python src/generator.py
```

### 4. Run Pipeline (Day 6 onwards)
```bash
python src/run_pipeline.py
```

### 5. Launch Dashboard (Day 8 onwards)
```bash
streamlit run dashboard/app.py
```

---

## 📅 Roadmap (2-Week Plan)

### Week 1: Foundation + Detection Engine
- **Day 1**: Setup, planning, dependencies, folder structure & README skeleton (Current).
- **Day 2**: Synthetic log generator (SSH & Web Server) simulating normal and malicious scenarios.
- **Day 3**: Log parser (regex-based parsing into structured Pandas DataFrames).
- **Day 4-5**: Detection Engine implementing standard detection heuristics.
- **Day 6**: Storage layer (SQLite integration) and full pipeline execution script.
- **Day 7**: Buffer, end-to-end integration, bug fixing, and repository polish.

### Week 2: Dashboard + Polish
- **Day 8-9**: Streamlit Dashboard (Core metrics, tables, and filtering).
- **Day 10**: Rich visual charts (Plotly time-series, bar chart, and donut).
- **Day 11**: Slack/Discord Alert Webhook notification integration.
- **Day 12**: Interactive "Replay Attack" trigger and styling refinement.
- **Day 13**: Final documentation and video demonstration recording.
- **Day 14**: Publishing, repository pinning, and project release.
