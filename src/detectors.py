# detectors.py - SOC Detection Engine Heuristics
# Contains rule-based detectors mapped to MITRE ATT&CK techniques.

def detect_bruteforce(df):
    """
    Detects brute-force attack attempts from SSH logs.
    Technique: Brute Force (T1110)
    """
    pass

def detect_portscan(df):
    """
    Detects port scanning behavior from connection/access logs.
    Technique: Active Scanning (T1595)
    """
    pass

def detect_priv_escalation(df):
    """
    Detects privilege escalation attempts (e.g. repeated sudo failures).
    Technique: Abuse of Privilege (T1548)
    """
    pass

def detect_offhours_login(df):
    """
    Detects admin logins outside typical working hours.
    Technique: Valid Accounts (T1078)
    """
    pass
