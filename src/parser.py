import re
import datetime
import pandas as pd

# Day 3 — Log Parser Module
# Parses raw syslog (SSH, Sudo, UFW) and web access logs into structured Pandas DataFrames.

SCHEMA_COLUMNS = ["timestamp", "src_ip", "event_type", "user", "port", "status", "raw_line"]

def parse_syslog_time(line: str, assumed_year: int = None) -> datetime.datetime:
    """
    Extracts and parses syslog timestamp format (e.g. 'Jul 20 14:32:01').
    Appends assumed_year since syslog timestamps omit the year.
    """
    if assumed_year is None:
        assumed_year = datetime.datetime.now().year
        
    match = re.match(r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})", line)
    if not match:
        return None
        
    ts_str = match.group(1)
    # Handle single or double spaces between month and day in syslog
    # e.g., "Jul  9 14:32:01" vs "Jul 20 14:32:01"
    ts_clean = " ".join(ts_str.split())
    dt = datetime.datetime.strptime(ts_clean, "%b %d %H:%M:%S")
    return dt.replace(year=assumed_year)

def parse_clf_time(time_str: str) -> datetime.datetime:
    """
    Parses Common Log Format timestamp (e.g. '20/Jul/2026:10:54:20 +0000').
    """
    try:
        # Strip timezone offset if present
        clean_str = time_str.split()[0]
        return datetime.datetime.strptime(clean_str, "%d/%b/%Y:%H:%M:%S")
    except (ValueError, IndexError):
        return None

def parse_auth_line(line: str, assumed_year: int = None) -> dict:
    """
    Parses SSH authentication log lines (Accepted password / Failed password).
    Returns a dict with schema fields or None if not matching.
    """
    dt = parse_syslog_time(line, assumed_year=assumed_year)
    if not dt:
        return None

    # Pattern for Accepted password
    acc_match = re.search(r"Accepted password for (\S+) from ([\d\.]+) port (\d+) ssh2", line)
    if acc_match:
        return {
            "timestamp": dt,
            "src_ip": acc_match.group(2),
            "event_type": "ssh_success",
            "user": acc_match.group(1),
            "port": int(acc_match.group(3)),
            "status": None,
            "raw_line": line.strip()
        }

    # Pattern for Failed password
    fail_match = re.search(r"Failed password for (\S+) from ([\d\.]+) port (\d+) ssh2", line)
    if fail_match:
        return {
            "timestamp": dt,
            "src_ip": fail_match.group(2),
            "event_type": "ssh_failed",
            "user": fail_match.group(1),
            "port": int(fail_match.group(3)),
            "status": None,
            "raw_line": line.strip()
        }

    return None

def parse_sudo_line(line: str, assumed_year: int = None) -> dict:
    """
    Parses sudo failure log lines (e.g. 'user : 3 incorrect password attempts').
    Returns a dict with schema fields or None if not matching.
    """
    dt = parse_syslog_time(line, assumed_year=assumed_year)
    if not dt:
        return None

    sudo_match = re.search(r"sudo:\s+(\S+)\s*:\s*\d+\s+incorrect password attempt", line)
    if sudo_match:
        return {
            "timestamp": dt,
            "src_ip": None,
            "event_type": "sudo_failed",
            "user": sudo_match.group(1),
            "port": None,
            "status": None,
            "raw_line": line.strip()
        }

    return None

def parse_ufw_line(line: str, assumed_year: int = None) -> dict:
    """
    Parses UFW block log lines (e.g. '[UFW BLOCK] ... SRC=... DPT=...').
    Returns a dict with schema fields or None if not matching.
    """
    dt = parse_syslog_time(line, assumed_year=assumed_year)
    if not dt:
        return None

    ufw_match = re.search(r"\[UFW BLOCK\].*SRC=([\d\.]+).*DPT=(\d+)", line)
    if ufw_match:
        return {
            "timestamp": dt,
            "src_ip": ufw_match.group(1),
            "event_type": "port_block",
            "user": None,
            "port": int(ufw_match.group(2)),
            "status": None,
            "raw_line": line.strip()
        }

    return None

def parse_access_line(line: str) -> dict:
    """
    Parses web server Common Log Format lines.
    Returns a dict with schema fields or None if not matching.
    """
    clf_regex = r'^([\d\.]+)\s+-\s+-\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^\s]+)\s+HTTP\/[0-9\.]+"\s+(\d+)\s+(\d+|-|\*)'
    match = re.match(clf_regex, line)
    if not match:
        return None

    ip = match.group(1)
    ts_str = match.group(2)
    status_code = int(match.group(5))
    dt = parse_clf_time(ts_str)

    if not dt:
        return None

    return {
        "timestamp": dt,
        "src_ip": ip,
        "event_type": "http_request",
        "user": None,
        "port": None,
        "status": status_code,
        "raw_line": line.strip()
    }

def parse_log_line(line: str, log_type: str = "auth", assumed_year: int = None) -> dict:
    """
    Routes a single log line to the appropriate parser function based on log_type or patterns.
    """
    line = line.strip()
    if not line:
        return None

    if log_type == "access":
        return parse_access_line(line)

    # Auth log type can contain SSH, Sudo, or UFW events
    parsed = parse_auth_line(line, assumed_year=assumed_year)
    if parsed:
        return parsed

    parsed = parse_sudo_line(line, assumed_year=assumed_year)
    if parsed:
        return parsed

    parsed = parse_ufw_line(line, assumed_year=assumed_year)
    if parsed:
        return parsed

    return None

def parse_log_file(filepath: str, log_type: str = "auth", assumed_year: int = None) -> pd.DataFrame:
    """
    Reads log file line by line, parses valid records into target schema,
    and returns a sorted Pandas DataFrame with datetime64[ns] timestamps.
    """
    parsed_rows = []
    unparsed_count = 0
    total_lines = 0

    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line_str = line.strip()
            if not line_str:
                continue
            total_lines += 1
            row = parse_log_line(line_str, log_type=log_type, assumed_year=assumed_year)
            if row:
                parsed_rows.append(row)
            else:
                unparsed_count += 1

    coverage = ((total_lines - unparsed_count) / total_lines * 100) if total_lines > 0 else 0.0
    print(f"[{log_type.upper()} LOG] Parsed {len(parsed_rows)}/{total_lines} lines ({coverage:.1f}% coverage, {unparsed_count} unparsed/ignored)")

    if not parsed_rows:
        return pd.DataFrame(columns=SCHEMA_COLUMNS)

    df = pd.DataFrame(parsed_rows)
    df = df[SCHEMA_COLUMNS]  # Ensure column order
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["port"] = df["port"].astype("Int64")
    df["status"] = df["status"].astype("Int64")
    df.sort_values(by="timestamp", inplace=True)
    df.reset_index(drop=True, inplace=True)

    return df

def save_parsed_csv(df: pd.DataFrame, output_path: str):
    """
    Saves parsed DataFrame to CSV file.
    """
    df.to_csv(output_path, index=False)
    print(f"[SUCCESS] Saved parsed DataFrame to: {output_path}")

if __name__ == "__main__":
    import os
    print("--- Testing Day 3 Log Parser ---")

    auth_log_path = "data/sample_auth.log"
    access_log_path = "data/sample_access.log"

    if os.path.exists(auth_log_path):
        auth_df = parse_log_file(auth_log_path, log_type="auth")
        print("\nAuth Log Sample Head:")
        print(auth_df.head(10))
        print("\nAuth Event Type Counts:")
        print(auth_df["event_type"].value_counts())
        save_parsed_csv(auth_df, "data/parsed_auth.csv")
    else:
        print(f"File not found: {auth_log_path}")

    if os.path.exists(access_log_path):
        access_df = parse_log_file(access_log_path, log_type="access")
        print("\nAccess Log Sample Head:")
        print(access_df.head(10))
        print("\nAccess Event Type Counts:")
        print(access_df["event_type"].value_counts())
        save_parsed_csv(access_df, "data/parsed_access.csv")
    else:
        print(f"File not found: {access_log_path}")
