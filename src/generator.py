import os
import random
import datetime
import argparse

try:
    from faker import Faker
    fake = Faker()
except ImportError:
    fake = None

# Day 2: Constants for Log Generation
NORMAL_IPS = [
    "192.168.1.50",
    "192.168.1.51",
    "192.168.1.102",
    "10.0.0.15",
    "10.0.0.16",
    "172.16.0.4",
    "172.16.0.5"
]

ATTACKER_IP = "198.51.100.42"
SERVER_IP = "192.168.1.150"

USERNAMES = [
    "alice",
    "bob",
    "charlie",
    "dev_user",
    "sysadmin",
    "john",
    "emily"
]

TARGET_USERNAME = "root"

def format_syslog_timestamp(dt: datetime.datetime) -> str:
    """
    Formats a datetime object to Syslog style format (e.g., Jul 20 14:32:01).
    Note: Syslog days are space-padded if single-digit (e.g., 'Jul  9').
    """
    return dt.strftime("%b %e %H:%M:%S")

def format_clf_timestamp(dt: datetime.datetime) -> str:
    """
    Formats a datetime object to Apache Common Log Format style (e.g., 20/Jul/2026:14:32:01 +0000).
    """
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")

def generate_normal_auth_traffic(start_time: datetime.datetime, count: int):
    """
    Generates normal SSH accepted/failed password logs.
    """
    logs = []
    current_time = start_time
    for _ in range(count):
        current_time += datetime.timedelta(seconds=random.randint(5, 60))
        ip = random.choice(NORMAL_IPS)
        user = random.choice(USERNAMES)
        port = random.randint(32768, 61000)
        pid = random.randint(1000, 30000)
        
        # 96% success rate for normal traffic
        if random.random() < 0.96:
            log_line = f"{format_syslog_timestamp(current_time)} server sshd[{pid}]: Accepted password for {user} from {ip} port {port} ssh2"
            logs.append((current_time, log_line))
        else:
            log_line = f"{format_syslog_timestamp(current_time)} server sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2"
            logs.append((current_time, log_line))
            # 50% chance of connection closed right after
            if random.random() < 0.5:
                current_time += datetime.timedelta(seconds=random.randint(1, 3))
                close_line = f"{format_syslog_timestamp(current_time)} server sshd[{pid}]: Connection closed by authenticating user {user} {ip} port {port} [preauth]"
                logs.append((current_time, close_line))
                
    return logs, current_time

def generate_bruteforce_attack(start_time: datetime.datetime):
    """
    Generates brute-force SSH password failures targeting 'root' from the attacker IP.
    """
    logs = []
    current_time = start_time
    ip = ATTACKER_IP
    user = TARGET_USERNAME
    
    # Rapid pace (1-4 seconds spacing) with ~15 attempts
    for _ in range(15):
        current_time += datetime.timedelta(seconds=random.randint(1, 4))
        port = random.randint(32768, 61000)
        pid = random.randint(1000, 30000)
        log_line = f"{format_syslog_timestamp(current_time)} server sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2"
        logs.append((current_time, log_line))
        
        # Connection closed log
        if random.random() < 0.8:
            current_time += datetime.timedelta(seconds=1)
            close_line = f"{format_syslog_timestamp(current_time)} server sshd[{pid}]: Connection closed by authenticating user {user} {ip} port {port} [preauth]"
            logs.append((current_time, close_line))
            
    return logs, current_time

def generate_sudo_failures(start_time: datetime.datetime):
    """
    Simulates a user repeatedly failing sudo authentication (T1548).
    """
    logs = []
    current_time = start_time
    user = random.choice(USERNAMES)
    
    # Simulates 3 incorrect password attempts for sudo
    for attempt in range(1, 4):
        current_time += datetime.timedelta(seconds=random.randint(2, 10))
        # PAM auth failure
        pam_line = f"{format_syslog_timestamp(current_time)} server sudo: pam_unix(sudo:auth): authentication failure; logname=uid=1000 euid=0 tty=/dev/pts/1 ruser={user} rhost= user={user}"
        logs.append((current_time, pam_line))
        
        # Sudo execution failure log
        current_time += datetime.timedelta(seconds=1)
        warn_line = f"{format_syslog_timestamp(current_time)} server sudo:   {user} : {attempt} incorrect password attempt{'s' if attempt > 1 else ''} ; TTY=pts/1 ; PWD=/home/{user} ; USER=root ; COMMAND=/usr/bin/apt-get update"
        logs.append((current_time, warn_line))
        
    return logs, current_time

def generate_port_scan(start_time: datetime.datetime):
    """
    Generates sequential UFW block log lines from the attacker IP hitting various ports rapidly.
    """
    logs = []
    current_time = start_time
    ip = ATTACKER_IP
    
    # Scan a range of 30 ports rapidly (100 to 500 milliseconds spacing)
    scanned_ports = list(range(20, 50))
    # We can keep them sequential or slightly shuffled to look realistic, let's keep sequential for clear detection later
    for port in scanned_ports:
        current_time += datetime.timedelta(milliseconds=random.randint(100, 500))
        mac = "00:11:22:33:44:55:66:77:88:99:aa:bb:08:00"
        log_line = f"{format_syslog_timestamp(current_time)} server kernel: [UFW BLOCK] IN=eth0 OUT= MAC={mac} SRC={ip} DST={SERVER_IP} LEN=40 TOS=0x00 PREC=0x00 TTL=64 ID={random.randint(10000, 60000)} PROTO=TCP SPT={random.randint(32768, 61000)} DPT={port} WINDOW=1024 RES=0x00 SYN URGP=0"
        logs.append((current_time, log_line))
        
    return logs, current_time

def generate_normal_access_traffic(start_time: datetime.datetime, count: int):
    """
    Generates normal HTTP web access logs in Common Log Format (CLF).
    """
    logs = []
    current_time = start_time
    paths = [
        "/", "/home", "/login", "/dashboard", "/settings", 
        "/profile", "/api/v1/status", "/static/css/main.css", 
        "/static/js/app.js", "/about", "/contact", "/search"
    ]
    
    # Standard fallback user agents
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
    ]
    
    for _ in range(count):
        current_time += datetime.timedelta(seconds=random.randint(2, 30))
        ip = random.choice(NORMAL_IPS)
        path = random.choice(paths)
        method = "GET" if path not in ["/login", "/search"] else random.choice(["GET", "POST"])
        
        # Assign HTTP status code
        rand = random.random()
        if rand < 0.85:
            status = 200
            size = random.randint(500, 5000)
        elif rand < 0.92:
            status = 302
            size = 0
        elif rand < 0.97:
            status = 404
            size = random.randint(100, 300)
        else:
            status = 500
            size = random.randint(100, 1000)
            
        ua = fake.user_agent() if (fake is not None) else random.choice(user_agents)
        log_line = f'{ip} - - [{format_clf_timestamp(current_time)}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'
        logs.append((current_time, log_line))
        
    return logs, current_time

def build_auth_log(start_time: datetime.datetime, num_normal: int) -> list:
    """
    Builds the complete auth log by chaining normal traffic and attack patterns.
    """
    all_logs = []
    current_time = start_time
    
    # 1. Normal traffic block 1
    block_logs, current_time = generate_normal_auth_traffic(current_time, num_normal)
    all_logs.extend(block_logs)
    
    # 2. Brute-force burst
    block_logs, current_time = generate_bruteforce_attack(current_time)
    all_logs.extend(block_logs)
    
    # 3. Normal traffic block 2
    block_logs, current_time = generate_normal_auth_traffic(current_time, num_normal)
    all_logs.extend(block_logs)
    
    # 4. Sudo failure injection
    block_logs, current_time = generate_sudo_failures(current_time)
    all_logs.extend(block_logs)
    
    # 5. Normal traffic block 3
    block_logs, current_time = generate_normal_auth_traffic(current_time, num_normal)
    all_logs.extend(block_logs)
    
    # 6. Port scan injection
    block_logs, current_time = generate_port_scan(current_time)
    all_logs.extend(block_logs)
    
    # 7. Normal traffic block 4
    block_logs, current_time = generate_normal_auth_traffic(current_time, num_normal)
    all_logs.extend(block_logs)
    
    # Keep list sorted by timestamp to ensure chronological consistency
    all_logs.sort(key=lambda x: x[0])
    return [line for _, line in all_logs]

def build_access_log(start_time: datetime.datetime, count: int) -> list:
    """
    Builds the web access log with normal traffic.
    """
    all_logs, _ = generate_normal_access_traffic(start_time, count)
    all_logs.sort(key=lambda x: x[0])
    return [line for _, line in all_logs]

def main():
    parser = argparse.ArgumentParser(description="Day 2: Synthetic Log Generator")
    parser.add_argument("--seed", "-s", type=int, default=42, help="Random seed for reproducibility")
    parser.add_argument("--auth-out", "-a", type=str, default="data/sample_auth.log", help="Output path for SSH/auth logs")
    parser.add_argument("--access-out", "-w", type=str, default="data/sample_access.log", help="Output path for web access logs")
    parser.add_argument("--num-normal-auth", type=int, default=50, help="Number of normal auth records per block")
    parser.add_argument("--num-normal-access", type=int, default=250, help="Number of normal web access records")
    args = parser.parse_args()
    
    # Set seed for reproducibility (Step 14)
    if args.seed is not None:
        random.seed(args.seed)
        
    # Set base time to 2 hours ago from now to make the logs look recent
    base_time = datetime.datetime.now() - datetime.timedelta(hours=2)
    
    print(f"Generating synthetic logs starting from: {base_time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Generate logs
    auth_lines = build_auth_log(base_time, args.num_normal_auth)
    access_lines = build_access_log(base_time, args.num_normal_access)
    
    # Ensure parent directories exist
    os.makedirs(os.path.dirname(os.path.abspath(args.auth_out)), exist_ok=True)
    os.makedirs(os.path.dirname(os.path.abspath(args.access_out)), exist_ok=True)
    
    # Write to files
    with open(args.auth_out, "w", encoding="utf-8") as f:
        f.write("\n".join(auth_lines) + "\n")
    print(f"[SUCCESS] Auth logs successfully written to: {args.auth_out} ({len(auth_lines)} lines)")
    
    with open(args.access_out, "w", encoding="utf-8") as f:
        f.write("\n".join(access_lines) + "\n")
    print(f"[SUCCESS] Web access logs successfully written to: {args.access_out} ({len(access_lines)} lines)")

if __name__ == "__main__":
    main()
