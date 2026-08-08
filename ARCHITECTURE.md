# ThreatLens — Architecture

This document covers ThreatLens's architecture from multiple angles, plus the full tech stack and why each piece was chosen.

---

## Tech Stack

| Layer | Technology | Why |
|---|---|---|
| Language | Python 3.10+ | Standard for security tooling, huge ecosystem |
| Data processing | pandas | Fast, expressive log parsing & time-window analysis |
| Detection logic | Custom rule engine (pure Python + pandas) | Full control over sliding-window logic; no black-box ML needed for interpretable SOC-style rules |
| Storage | SQLite | Zero-config, file-based, perfect for a portfolio-scale project; `UNIQUE` constraints handle dedup |
| Dashboard | Streamlit | Fastest path from Python script to interactive web UI; no separate frontend needed |
| Charts | Streamlit native charts (`st.line_chart`, `st.bar_chart`) / Plotly | Quick, clean visualizations with minimal code |
| Synthetic data | Faker + custom generators | Reproducible demo data; never blocked waiting on real attack traffic |
| GeoIP | ip-api.com (free tier) | No API key required, sufficient for demo-scale lookups |
| Alerting | Slack / Discord Incoming Webhooks | Simple HTTP POST, no SDK dependency, shows response-side thinking |
| Threat framework | MITRE ATT&CK | Industry-standard technique IDs (T1110, T1046, T1548, T1078) — the language real SOC teams use |

---

## 1. High-Level System Architecture
Major components and how they connect.

```mermaid
flowchart TB
    subgraph Input["Input — Python/Faker"]
        A[Linux Auth Logs]
        B[Web Access Logs]
    end

    subgraph Processing["Processing — Python + pandas"]
        C[Log Parser]
        D[Detection Engine]
    end

    subgraph Storage["Storage — SQLite"]
        E[(alerts table)]
    end

    subgraph Output["Output"]
        F[Streamlit Dashboard]
        G[Slack/Discord Webhook]
        H[GeoIP Map — ip-api.com]
    end

    A --> C
    B --> C
    C --> D
    D --> E
    D --> G
    E --> F
    E --> H
    H --> F
```

## 2. Data Flow Architecture
How raw data transforms at each stage.

```mermaid
flowchart LR
    A["Raw text (unstructured)<br/>Python file I/O"] --> B["Structured DataFrame<br/>pandas + regex"]
    B --> C["Alert objects<br/>Python rule engine"]
    C --> D["Persisted rows<br/>SQLite, deduplicated"]
    D --> E["Filtered views<br/>SQL queries"]
    E --> F["Visual output<br/>Streamlit tables/charts/map"]
```

## 3. Component / Module Architecture
Codebase structure and responsibilities.

```mermaid
flowchart TB
    subgraph src["src/ (Python)"]
        gen["generator.py<br/>Faker + random — synthetic logs"]
        par["parser.py<br/>re + pandas — log → DataFrame"]
        det["detectors.py<br/>pandas — rule-based detection"]
        db["db.py<br/>sqlite3 — persistence layer"]
        geo["geoip.py<br/>requests — IP → location"]
        alt["alerter.py<br/>requests — webhook notify"]
    end

    subgraph dashboard["dashboard/ (Streamlit)"]
        app["app.py<br/>Streamlit — UI + viz"]
    end

    pipeline["run_pipeline.py<br/>Orchestrator"]

    pipeline --> par
    pipeline --> det
    pipeline --> db
    pipeline --> alt
    gen -.->|produces input for| par
    app --> db
    app --> geo
```

## 4. Sequence Diagram — Full Run
Order of operations for one end-to-end execution.

```mermaid
flowchart TB
```

```mermaid
sequenceDiagram
    participant U as User
    participant Gen as generator.py
    participant Pipe as run_pipeline.py
    participant Par as parser.py
    participant Det as detectors.py
    participant DB as SQLite
    participant Alt as alerter.py
    participant Dash as Streamlit Dashboard

    U->>Gen: python src/generator.py
    Gen->>Gen: Write sample_auth.log / sample_access.log
    U->>Pipe: python run_pipeline.py
    Pipe->>Par: parse_log_file()
    Par-->>Pipe: structured DataFrame
    Pipe->>Det: run_all_detectors(df)
    Det-->>Pipe: list of alert dicts (MITRE-tagged)
    Pipe->>DB: insert_alerts()
    Pipe->>Alt: notify_high_severity()
    Alt-->>U: Slack/Discord message (if High severity)
    U->>Dash: streamlit run dashboard/app.py
    Dash->>DB: query_alerts()
    DB-->>Dash: alert rows
    Dash-->>U: table + charts + GeoIP map
```

## 5. Deployment / Runtime Architecture
What runs where, including external dependencies.

```mermaid
flowchart TB
    subgraph Local["Local Machine / Server — Python 3.10+"]
        A[Python Runtime]
        B[(SQLite file<br/>data/threatlens.db)]
        C["Streamlit Process<br/>localhost:8501"]
    end

    subgraph External["External HTTPS Services"]
        D["ip-api.com<br/>GeoIP REST API"]
        E["Slack/Discord<br/>Webhook endpoint"]
    end

    A -->|reads/writes| B
    A -->|serves| C
    A -->|GET requests| D
    A -->|POST requests| E
    F[Browser] -->|HTTP :8501| C
```

## 6. Detection Logic — Rules to MITRE ATT&CK Mapping

```mermaid
flowchart LR
    subgraph Rules["Detection Rules — pandas sliding window"]
        R1["≥5 failed logins<br/>same IP, 60s window"]
        R2["≥10 distinct ports<br/>same IP, 60s window"]
        R3["≥3 sudo failures<br/>same user"]
        R4["Login outside<br/>08:00–20:00"]
    end

    subgraph Techniques["MITRE ATT&CK Techniques"]
        T1["T1110 — Brute Force"]
        T2["T1046 — Network Service Discovery"]
        T3["T1548 — Abuse Elevation Control Mechanism"]
        T4["T1078 — Valid Accounts"]
    end

    R1 --> T1
    R2 --> T2
    R3 --> T3
    R4 --> T4
```

---

## Interview Quick-Reference

| If asked... | Point to |
|---|---|
| "Walk me through the architecture" | Diagram 1 |
| "How does data move through the system?" | Diagram 2 |
| "How is your code organized?" | Diagram 3 |
| "What happens when you run it?" | Diagram 4 |
| "How would this scale / deploy?" | Diagram 5 |
| "How does your detection logic work?" | Diagram 6 |
| "What's your tech stack and why?" | Tech Stack table |
