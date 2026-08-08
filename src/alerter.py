
"""
alerter.py — Webhook alerting for ThreatLens.

Sends a notification to Slack or Discord when a new High-severity
alert is detected. Configure via environment variable or the
WEBHOOK_URL constant below.
"""

import os
import requests

WEBHOOK_URL = os.environ.get("THREATLENS_WEBHOOK_URL", "")  # set your webhook URL here or via env var
WEBHOOK_TYPE = os.environ.get("THREATLENS_WEBHOOK_TYPE", "slack")  # "slack" or "discord"


def send_alert_notification(alert: dict) -> bool:
    """
    Send a single alert to the configured webhook.
    Returns True if sent successfully, False otherwise (fails silently —
    webhook issues shouldn't crash the pipeline).
    """
    if not WEBHOOK_URL:
        return False

    message = (
        f"🚨 *{alert['severity']} Severity Alert* — {alert['technique_id']} {alert['technique_name']}\n"
        f"Source IP: `{alert['src_ip']}`\n"
        f"{alert['description']}\n"
        f"Time: {alert['timestamp']}"
    )

    try:
        if WEBHOOK_TYPE == "discord":
            payload = {"content": message}
        else:  # slack
            payload = {"text": message}

        resp = requests.post(WEBHOOK_URL, json=payload, timeout=5)
        return resp.status_code in (200, 204)
    except requests.RequestException:
        return False


def notify_high_severity(alerts: list[dict]) -> int:
    """Send notifications for all High-severity alerts in the list. Returns count sent."""
    sent = 0
    for alert in alerts:
        if alert["severity"] == "High":
            if send_alert_notification(alert):
                sent += 1
    return sent


if __name__ == "__main__":
    test_alert = {
        "severity": "High",
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "src_ip": "203.0.113.45",
        "description": "Test alert from ThreatLens alerter.py",
        "timestamp": "2026-08-08 12:00:00",
    }
    result = send_alert_notification(test_alert)
    print(f"[+] Webhook test {'succeeded' if result else 'failed (check WEBHOOK_URL is set)'}")
