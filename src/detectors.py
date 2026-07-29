"""
detectors.py — Detection engine for ThreatLens.

Takes a parsed DataFrame (from parser.py) and runs rule-based
detections mapped to MITRE ATT&CK techniques. Each detector
returns a list of alert dicts ready to be stored in the database.
"""

import pandas as pd
from datetime import timedelta

# ---- Severity levels ----
SEVERITY_LOW = "Low"
SEVERITY_MEDIUM = "Medium"
SEVERITY_HIGH = "High"


def _make_alert(timestamp, src_ip, technique_id, technique_name, severity, description, user=None):
    """Helper to build a consistent alert dict."""
    return {
        "timestamp": timestamp,
        "src_ip": src_ip,
        "user": user,
        "technique_id": technique_id,
        "technique_name": technique_name,
        "severity": severity,
        "description": description,
    }


def detect_bruteforce(df: pd.DataFrame, threshold: int = 5, window_seconds: int = 60) -> list[dict]:
    """
    Detect brute-force login attempts: >= threshold failed logins
    from the same source IP within a rolling time window.

    Maps to MITRE ATT&CK T1110 - Brute Force.
    """
    alerts = []
    failed = df[df["event_type"] == "ssh_failed"].sort_values("timestamp")

    for ip, group in failed.groupby("src_ip"):
        group = group.sort_values("timestamp").reset_index(drop=True)
        timestamps = group["timestamp"].tolist()

        # sliding window check
        start_idx = 0
        for end_idx in range(len(timestamps)):
            # shrink window from the left if it's too wide
            while timestamps[end_idx] - timestamps[start_idx] > timedelta(seconds=window_seconds):
                start_idx += 1

            count_in_window = end_idx - start_idx + 1
            if count_in_window >= threshold:
                alerts.append(_make_alert(
                    timestamp=timestamps[end_idx],
                    src_ip=ip,
                    technique_id="T1110",
                    technique_name="Brute Force",
                    severity=SEVERITY_HIGH,
                    description=(
                        f"{count_in_window} failed SSH login attempts from {ip} "
                        f"within {window_seconds}s window"
                    ),
                    user=group.loc[end_idx, "user"] if "user" in group.columns else None,
                ))
                # avoid spamming duplicate alerts for every single event in the burst —
                # only alert once per burst, then reset the window
                start_idx = end_idx + 1

    return alerts


def detect_portscan(df: pd.DataFrame, threshold: int = 10, window_seconds: int = 60) -> list[dict]:
    """
    Detect port scanning: one source IP hitting >= threshold distinct
    destination ports within a time window.

    Maps to MITRE ATT&CK T1046 - Network Service Discovery.
    """
    alerts = []
    scans = df[df["event_type"] == "port_block"].sort_values("timestamp")

    for ip, group in scans.groupby("src_ip"):
        group = group.sort_values("timestamp").reset_index(drop=True)
        timestamps = group["timestamp"].tolist()
        ports = group["port"].tolist()

        start_idx = 0
        seen_ports = set()
        for end_idx in range(len(timestamps)):
            while timestamps[end_idx] - timestamps[start_idx] > timedelta(seconds=window_seconds):
                seen_ports.discard(ports[start_idx])
                start_idx += 1

            seen_ports.add(ports[end_idx])

            if len(seen_ports) >= threshold:
                alerts.append(_make_alert(
                    timestamp=timestamps[end_idx],
                    src_ip=ip,
                    technique_id="T1046",
                    technique_name="Network Service Discovery",
                    severity=SEVERITY_MEDIUM,
                    description=(
                        f"{len(seen_ports)} distinct ports probed from {ip} "
                        f"within {window_seconds}s window"
                    ),
                ))
                start_idx = end_idx + 1
                seen_ports = set()

    return alerts


def detect_priv_escalation(df: pd.DataFrame, threshold: int = 3) -> list[dict]:
    """
    Detect repeated sudo failures from the same user — indicator of
    privilege escalation attempts.

    Maps to MITRE ATT&CK T1548 - Abuse Elevation Control Mechanism.
    """
    alerts = []
    sudo_fails = df[df["event_type"] == "sudo_failed"]

    for user, group in sudo_fails.groupby("user"):
        if len(group) >= threshold:
            last_event = group.sort_values("timestamp").iloc[-1]
            alerts.append(_make_alert(
                timestamp=last_event["timestamp"],
                src_ip=last_event.get("src_ip", "local"),
                technique_id="T1548",
                technique_name="Abuse Elevation Control Mechanism",
                severity=SEVERITY_MEDIUM,
                description=f"{len(group)} failed sudo attempts by user '{user}'",
                user=user,
            ))

    return alerts


def detect_offhours_login(df: pd.DataFrame, start_hour: int = 8, end_hour: int = 20) -> list[dict]:
    """
    Detect successful logins outside normal working hours (default 08:00-20:00).

    Maps to MITRE ATT&CK T1078 - Valid Accounts.
    """
    alerts = []
    success = df[df["event_type"] == "ssh_success"].copy()
    if success.empty:
        return alerts
    success["hour"] = pd.to_datetime(success["timestamp"]).dt.hour

    offhours = success[(success["hour"] < start_hour) | (success["hour"] >= end_hour)]

    for _, row in offhours.iterrows():
        alerts.append(_make_alert(
            timestamp=row["timestamp"],
            src_ip=row["src_ip"],
            technique_id="T1078",
            technique_name="Valid Accounts",
            severity=SEVERITY_LOW,
            description=(
                f"Successful login by '{row.get('user', 'unknown')}' from {row['src_ip']} "
                f"outside normal hours ({pd.to_datetime(row['timestamp']).strftime('%H:%M')})"
            ),
            user=row.get("user"),
        ))

    return alerts


def run_all_detectors(df: pd.DataFrame) -> list[dict]:
    """Run every detection rule and return a combined, time-sorted alert list."""
    all_alerts = []
    all_alerts += detect_bruteforce(df)
    all_alerts += detect_portscan(df)
    all_alerts += detect_priv_escalation(df)
    all_alerts += detect_offhours_login(df)

    all_alerts.sort(key=lambda a: a["timestamp"])
    return all_alerts


if __name__ == "__main__":
    import sys
    sys.path.append("..")
    from parser import parse_log_file  # adjust import if running standalone

    df = parse_log_file("../data/sample_auth.log", log_type="auth")
    alerts = run_all_detectors(df)

    print(f"[+] {len(alerts)} alerts generated:\n")
    for a in alerts:
        print(f"[{a['severity']}] {a['technique_id']} {a['technique_name']} — {a['description']}")
