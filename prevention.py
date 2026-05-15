import requests
import subprocess
import logging
import json
import re
from datetime import datetime, timedelta
from collections import defaultdict

logging.basicConfig(
    filename='logs/prevention.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Track failed login attempts per IP
failed_attempts = defaultdict(list)
blocked_ips     = set()
suspicious_ips  = defaultdict(int)

# Known attack patterns in request logs
ATTACK_PATTERNS = [
    r'union.*select',
    r'<script>',
    r'../../../',
    r'etc/passwd',
    r'cmd=',
    r'exec\(',
    r'base64_decode',
    r'wget\s+http',
    r'curl\s+http',
    r'/bin/sh',
    r'DROP\s+TABLE',
    r'INSERT\s+INTO',
    r'1=1',
    r"'--",
]

# Dangerous ports that should never be open
DANGEROUS_PORTS = {
    21:    ('FTP',      'HIGH',     4, 4),
    23:    ('Telnet',   'CRITICAL', 5, 5),
    445:   ('SMB',      'CRITICAL', 5, 5),
    3389:  ('RDP',      'HIGH',     4, 4),
    3306:  ('MySQL',    'HIGH',     4, 4),
    27017: ('MongoDB',  'CRITICAL', 5, 4),
    6379:  ('Redis',    'HIGH',     4, 4),
    9200:  ('Elasticsearch', 'HIGH', 4, 4),
    5432:  ('PostgreSQL', 'MEDIUM', 3, 3),
}

# ── CVE Watcher ──────────────────────────────────────
def fetch_latest_cves(app, db, Risk, AuditLog):
    with app.app_context():
        logging.info("Fetching latest CVEs from NVD...")
        try:
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {
                'resultsPerPage': 10,
                'pubStartDate': (datetime.utcnow() - timedelta(days=1)).strftime('%Y-%m-%dT00:00:00.000'),
                'pubEndDate':   datetime.utcnow().strftime('%Y-%m-%dT23:59:59.000'),
                'cvssV3Severity': 'CRITICAL'
            }
            response = requests.get(url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                cves = data.get('vulnerabilities', [])
                for item in cves[:5]:
                    cve  = item.get('cve', {})
                    cveid = cve.get('id', 'Unknown')
                    descs = cve.get('descriptions', [{}])
                    desc  = descs[0].get('value', 'No description') if descs else 'No description'
                    existing = Risk.query.filter_by(name=f"CVE: {cveid}").first()
                    if not existing:
                        r = Risk(
                            name=f"CVE: {cveid}",
                            description=f"ZERO-DAY ALERT: {desc[:300]}. Source: National Vulnerability Database. Immediate review required.",
                            likelihood=5,
                            impact=5,
                            score=25,
                            level='CRITICAL',
                            owner='IT Security Team',
                            created_by='CVE-WATCHER'
                        )
                        db.session.add(r)
                        log = AuditLog(
                            user='CVE-WATCHER',
                            action=f"Critical CVE detected and risk created: {cveid}",
                            ip='system'
                        )
                        db.session.add(log)
                        db.session.commit()
                        logging.info(f"CVE risk created: {cveid}")
                        print(f"New critical CVE detected: {cveid}")
            else:
                logging.warning(f"NVD API returned status: {response.status_code}")
        except requests.exceptions.ConnectionError:
            logging.warning("No internet connection — CVE check skipped")
        except Exception as e:
            logging.error(f"CVE fetch error: {e}")

# ── Intrusion Detection ──────────────────────────────
def record_failed_login(ip, app=None, db=None, BlockedIP=None):
    now = datetime.utcnow()
    failed_attempts[ip].append(now)
    failed_attempts[ip] = [
        t for t in failed_attempts[ip]
        if now - t < timedelta(minutes=10)
    ]
    count = len(failed_attempts[ip])
    logging.info(f"Failed login from {ip} — count: {count}")
    if count >= 5:
        block_ip(ip)
        # Also save to database if available
        if app and db and BlockedIP:
            try:
                with app.app_context():
                    existing = BlockedIP.query.filter_by(ip=ip).first()
                    if not existing:
                        b = BlockedIP(ip=ip, reason=f"Auto-blocked after {count} failed logins", blocked_by="AUTO-SYSTEM")
                        db.session.add(b)
                        db.session.commit()
                        logging.warning(f"IP {ip} saved to database blocklist")
            except Exception as e:
                logging.error(f"DB block error: {e}")
        return True
    return False

def block_ip(ip):
    if ip in blocked_ips or ip == '127.0.0.1':
        return
    blocked_ips.add(ip)
    logging.warning(f"BLOCKING IP: {ip}")
    try:
        subprocess.run(
            ['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'],
            capture_output=True, timeout=5
        )
        logging.info(f"iptables rule added for {ip}")
    except Exception as e:
        logging.error(f"Could not block IP {ip}: {e}")

def unblock_ip(ip):
    if ip in blocked_ips:
        blocked_ips.discard(ip)
        try:
            subprocess.run(
                ['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'],
                capture_output=True, timeout=5
            )
            logging.info(f"IP unblocked: {ip}")
        except Exception as e:
            logging.error(f"Could not unblock IP {ip}: {e}")

def is_blocked(ip):
    return ip in blocked_ips

# ── Attack Pattern Detection ─────────────────────────
def scan_request_for_attacks(request_data, ip):
    request_lower = request_data.lower()
    for pattern in ATTACK_PATTERNS:
        if re.search(pattern, request_lower, re.IGNORECASE):
            suspicious_ips[ip] += 1
            logging.warning(f"Attack pattern detected from {ip}: {pattern}")
            if suspicious_ips[ip] >= 3:
                block_ip(ip)
                return 'BLOCKED', pattern
            return 'SUSPICIOUS', pattern
    return 'CLEAN', None

# ── Auto Port Scan and Risk Creation ─────────────────
def auto_port_scan_and_fix(app, db, Risk, AuditLog):
    with app.app_context():
        logging.info("Running automated port scan...")
        try:
            result = subprocess.run(
                ['nmap', '-F', '--open', '-oG', '-', '127.0.0.1'],
                capture_output=True, text=True, timeout=60
            )
            output = result.stdout
            found_ports = []
            for port, (service, level, likelihood, impact) in DANGEROUS_PORTS.items():
                if f"{port}/open" in output or f"{port}/tcp" in output:
                    found_ports.append(port)
                    existing = Risk.query.filter_by(
                        name=f"SCAN: Dangerous port {port} ({service}) is open"
                    ).first()
                    if not existing:
                        r = Risk(
                            name=f"SCAN: Dangerous port {port} ({service}) is open",
                            description=f"Automated scan detected port {port} ({service}) is open. This port is commonly exploited by attackers. Immediate review and closure recommended.",
                            likelihood=likelihood,
                            impact=impact,
                            score=likelihood * impact,
                            level=level,
                            owner='IT Team',
                            created_by='AUTO-SCANNER'
                        )
                        db.session.add(r)
                        log = AuditLog(
                            user='AUTO-SCANNER',
                            action=f"Dangerous port detected: {port} ({service}) — risk auto-created",
                            ip='system'
                        )
                        db.session.add(log)
            db.session.commit()
            if found_ports:
                logging.warning(f"Dangerous ports found: {found_ports}")
            else:
                logging.info("Port scan complete — no dangerous ports found")
        except Exception as e:
            logging.error(f"Port scan error: {e}")

# ── Security Health Check ─────────────────────────────
def full_security_health_check(app, db, models):
    with app.app_context():
        User     = models['User']
        Risk     = models['Risk']
        Training = models['Training']
        Policy   = models['Policy']
        AuditLog = models['AuditLog']

        issues   = []
        now      = datetime.utcnow()

        # Check for users with no recent login
        for u in User.query.all():
            age = now - u.created_at
            if age.days > 30 and u.role != 'admin':
                issues.append(f"Inactive user: {u.username}")

        # Check for untreated critical risks older than 48 hours
        for r in Risk.query.filter_by(level='CRITICAL').all():
            age = now - r.created_at
            if age.total_seconds() > 172800:  # 48 hours
                issues.append(f"Untreated critical risk: {r.name}")

        # Check for overdue training
        for t in Training.query.filter_by(status='Pending').all():
            if t.due_date:
                try:
                    due = datetime.strptime(t.due_date, '%Y-%m-%d')
                    if due < now:
                        issues.append(f"Overdue training: {t.employee} - {t.topic}")
                except:
                    pass

        # Check for old policies
        for p in Policy.query.all():
            age = now - p.uploaded_at
            if age.days > 365:
                issues.append(f"Policy needs review: {p.title}")

        # Log all issues found
        for issue in issues:
            log = AuditLog(
                user='HEALTH-CHECK',
                action=f"Security issue detected: {issue}",
                ip='system'
            )
            db.session.add(log)

        if issues:
            db.session.commit()
            logging.warning(f"Health check found {len(issues)} issues")
        else:
            logging.info("Health check passed — no issues found")

        return issues

def get_blocked_ips():
    return list(blocked_ips)

def get_suspicious_ips():
    return dict(suspicious_ips)

def auto_detect_system_risks(app, db, Risk, AuditLog):
    with app.app_context():
        checks = []
        try:
            result = subprocess.run(
                ["sudo", "ufw", "status"],
                capture_output=True, text=True, timeout=5
            )
            if "inactive" in result.stdout.lower():
                checks.append({
                    "name": "AUTO: Firewall is disabled",
                    "desc": "UFW firewall is not active. System exposed to network attacks.",
                    "likelihood": 4, "impact": 5,
                    "score": 20, "level": "CRITICAL",
                    "owner": "IT Team"
                })
        except:
            pass
        try:
            result = subprocess.run(
                ["apt", "list", "--upgradable"],
                capture_output=True, text=True, timeout=10
            )
            count = result.stdout.count("\n") - 1
            if count > 10:
                checks.append({
                    "name": f"AUTO: {count} system updates pending",
                    "desc": f"{count} packages need updating.",
                    "likelihood": 3, "impact": 4,
                    "score": 12, "level": "HIGH",
                    "owner": "IT Team"
                })
        except:
            pass
        try:
            result = subprocess.run(
                ["df", "-h", "/"],
                capture_output=True, text=True, timeout=5
            )
            lines = result.stdout.strip().split("\n")
            if len(lines) > 1:
                parts = lines[1].split()
                if len(parts) >= 5:
                    usage = int(parts[4].replace("%",""))
                    if usage > 80:
                        checks.append({
                            "name": f"AUTO: Disk usage critical — {usage}% full",
                            "desc": f"Disk is {usage}% full. Can cause failures.",
                            "likelihood": 3, "impact": 4,
                            "score": 12, "level": "HIGH",
                            "owner": "IT Team"
                        })
        except:
            pass
        for check in checks:
            existing = Risk.query.filter_by(name=check["name"]).first()
            if not existing:
                r = Risk(
                    name=check["name"],
                    description=check["desc"],
                    likelihood=check["likelihood"],
                    impact=check["impact"],
                    score=check["score"],
                    level=check["level"],
                    owner=check["owner"],
                    created_by="AUTO-DETECTOR"
                )
                db.session.add(r)
                log = AuditLog(
                    user="AUTO-DETECTOR",
                    action=f"Auto-detected risk: {check['name']}",
                    ip="system"
                )
                db.session.add(log)
        if checks:
            db.session.commit()
        return checks


def check_ssh_security(app, db, Risk, AuditLog):
    with app.app_context():
        risks_found = []
        try:
            with open("/etc/ssh/sshd_config", "r") as f:
                config = f.read()

            # Check root login enabled
            if "PermitRootLogin yes" in config:
                existing = Risk.query.filter_by(
                    name="AUTO: SSH root login is enabled"
                ).first()
                if not existing:
                    r = Risk(
                        name="AUTO: SSH root login is enabled",
                        description="SSH allows direct root login. Attackers can brute force root access directly. Disable with PermitRootLogin no.",
                        likelihood=4, impact=5,
                        score=20, level="CRITICAL",
                        owner="IT Team",
                        created_by="SSH-CHECKER"
                    )
                    db.session.add(r)
                    risks_found.append("SSH root login enabled")

            # Check password auth enabled
            if "PasswordAuthentication yes" in config:
                existing = Risk.query.filter_by(
                    name="AUTO: SSH password authentication enabled"
                ).first()
                if not existing:
                    r = Risk(
                        name="AUTO: SSH password authentication enabled",
                        description="SSH uses password authentication which is vulnerable to brute force. Use key-based authentication instead.",
                        likelihood=3, impact=4,
                        score=12, level="HIGH",
                        owner="IT Team",
                        created_by="SSH-CHECKER"
                    )
                    db.session.add(r)
                    risks_found.append("SSH password auth enabled")

            if risks_found:
                for risk in risks_found:
                    log = AuditLog(
                        user="SSH-CHECKER",
                        action=f"SSH security issue detected: {risk}",
                        ip="system"
                    )
                    db.session.add(log)
                db.session.commit()
                logging.info(f"SSH checker found: {risks_found}")

        except FileNotFoundError:
            logging.info("SSH config not found — skipping")
        except Exception as e:
            logging.error(f"SSH check error: {e}")

        return risks_found


def check_user_accounts(app, db, Risk, AuditLog):
    with app.app_context():
        risks_found = []
        try:
            result = subprocess.run(
                ["cat", "/etc/passwd"],
                capture_output=True, text=True, timeout=5
            )
            lines = result.stdout.strip().split("\n")
            shell_users = []
            for line in lines:
                parts = line.split(":")
                if len(parts) >= 7:
                    username = parts[0]
                    shell = parts[6]
                    uid = int(parts[2]) if parts[2].isdigit() else 0
                    if uid >= 1000 and shell not in ["/bin/false", "/usr/sbin/nologin", ""]:
                        shell_users.append(username)

            if len(shell_users) > 3:
                existing = Risk.query.filter_by(
                    name=f"AUTO: Multiple shell user accounts detected"
                ).first()
                if not existing:
                    r = Risk(
                        name="AUTO: Multiple shell user accounts detected",
                        description=f"Found {len(shell_users)} user accounts with shell access: {', '.join(shell_users[:5])}. Review and disable unused accounts.",
                        likelihood=3, impact=3,
                        score=9, level="MEDIUM",
                        owner="IT Team",
                        created_by="USER-CHECKER"
                    )
                    db.session.add(r)
                    log = AuditLog(
                        user="USER-CHECKER",
                        action=f"Multiple shell accounts detected: {shell_users}",
                        ip="system"
                    )
                    db.session.add(log)
                    db.session.commit()
                    risks_found.append(f"Multiple shell users: {shell_users}")

        except Exception as e:
            logging.error(f"User account check error: {e}")

        return risks_found


def check_running_services(app, db, Risk, AuditLog):
    with app.app_context():
        risks_found = []
        dangerous_services = {
            "telnet": "Telnet transmits data in plain text. Replace with SSH.",
            "ftp": "FTP transmits credentials in plain text. Use SFTP instead.",
            "rsh": "RSH is insecure remote shell. Replace with SSH.",
            "rlogin": "Rlogin is insecure. Replace with SSH.",
            "finger": "Finger service exposes user information to attackers.",
        }
        try:
            result = subprocess.run(
                ["systemctl", "list-units", "--type=service", "--state=running"],
                capture_output=True, text=True, timeout=10
            )
            output = result.stdout.lower()
            for service, description in dangerous_services.items():
                if service in output:
                    existing = Risk.query.filter_by(
                        name=f"AUTO: Dangerous service running — {service}"
                    ).first()
                    if not existing:
                        r = Risk(
                            name=f"AUTO: Dangerous service running — {service}",
                            description=description,
                            likelihood=4, impact=4,
                            score=16, level="HIGH",
                            owner="IT Team",
                            created_by="SERVICE-CHECKER"
                        )
                        db.session.add(r)
                        log = AuditLog(
                            user="SERVICE-CHECKER",
                            action=f"Dangerous service detected: {service}",
                            ip="system"
                        )
                        db.session.add(log)
                        risks_found.append(service)

            if risks_found:
                db.session.commit()

        except Exception as e:
            logging.error(f"Service check error: {e}")

        return risks_found


def check_failed_logins_system(app, db, Risk, AuditLog):
    with app.app_context():
        try:
            result = subprocess.run(
                ["grep", "Failed password", "/var/log/auth.log"],
                capture_output=True, text=True, timeout=5
            )
            count = result.stdout.count("Failed password")
            if count > 20:
                existing = Risk.query.filter_by(
                    name="AUTO: High number of failed system logins"
                ).first()
                if not existing:
                    r = Risk(
                        name="AUTO: High number of failed system logins",
                        description=f"Detected {count} failed login attempts in system auth log. Possible brute force attack in progress.",
                        likelihood=5, impact=4,
                        score=20, level="CRITICAL",
                        owner="Security Team",
                        created_by="LOGIN-CHECKER"
                    )
                    db.session.add(r)
                    log = AuditLog(
                        user="LOGIN-CHECKER",
                        action=f"Brute force detected: {count} failed logins in auth.log",
                        ip="system"
                    )
                    db.session.add(log)
                    db.session.commit()
                    logging.warning(f"Brute force detected: {count} failed logins")
        except Exception as e:
            logging.error(f"Login check error: {e}")


def check_breach_database(app, db, Risk, AuditLog, email_domain="sawairagohar3012@gmail.com"):
    with app.app_context():
        try:
            import hashlib
            email = f"admin@{email_domain}"
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
            headers = {
                "User-Agent": "ISMS-Platform",
                "hibp-api-key": "free-check"
            }
            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 200:
                breaches = response.json()
                breach_names = [b.get("Name","unknown") for b in breaches[:5]]
                existing = Risk.query.filter_by(
                    name=f"AUTO: Email domain found in data breach"
                ).first()
                if not existing:
                    r = Risk(
                        name="AUTO: Email domain found in data breach",
                        description=f"Company email found in {len(breaches)} known data breaches: {', '.join(breach_names)}. Passwords may be compromised. Force password reset immediately.",
                        likelihood=5, impact=5,
                        score=25, level="CRITICAL",
                        owner="Security Team",
                        created_by="BREACH-CHECKER"
                    )
                    db.session.add(r)
                    log = AuditLog(
                        user="BREACH-CHECKER",
                        action=f"Email found in {len(breaches)} breaches: {breach_names}",
                        ip="system"
                    )
                    db.session.add(log)
                    db.session.commit()
                    logging.warning(f"Breach detected: {breach_names}")
                    return breach_names

            elif response.status_code == 404:
                logging.info("No breaches found for this domain")

        except requests.exceptions.ConnectionError:
            logging.warning("No internet — breach check skipped")
        except Exception as e:
            logging.error(f"Breach check error: {e}")

        return []


# Track all IPs that attempted login recently — module level so it persists
_recent_ips = []

def detect_ip_rotation(ip, app=None, db=None, BlockedIP=None, AuditLog=None):
    now = datetime.utcnow()
    
    # Add this IP with timestamp
    _recent_ips.append({'ip': ip, 'time': now})
    
    # Keep only last 60 seconds
    _recent_ips_clean = [
        x for x in _recent_ips
        if (now - x['time']).total_seconds() < 60
    ]
    _recent_ips.clear()
    _recent_ips.extend(_recent_ips_clean)
    
    # Count unique IPs in last 60 seconds
    unique_ips = set(x['ip'] for x in _recent_ips)
    
    logging.info(f"Unique IPs in last 60s: {len(unique_ips)}")
    
    # If more than 5 different IPs attempted login in 60 seconds — IP rotation attack
    if len(unique_ips) >= 5:
        logging.warning(f"IP rotation attack detected! {len(unique_ips)} unique IPs in 60s")
        
        # Block all of them
        for suspicious_ip in unique_ips:
            if suspicious_ip == '127.0.0.1':
                continue
            block_ip(suspicious_ip)
            suspicious_ips[suspicious_ip] += 10  # mark as highly suspicious
            
            if app and db and BlockedIP:
                try:
                    with app.app_context():
                        existing = BlockedIP.query.filter_by(ip=suspicious_ip).first()
                        if not existing:
                            b = BlockedIP(
                                ip=suspicious_ip,
                                reason=f"IP rotation attack — {len(unique_ips)} IPs detected in 60 seconds",
                                blocked_by="ROTATION-DETECTOR"
                            )
                            db.session.add(b)
                            
                            if AuditLog:
                                log = AuditLog(
                                    user="ROTATION-DETECTOR",
                                    action=f"IP rotation attack blocked: {suspicious_ip} — part of {len(unique_ips)} rotating IPs",
                                    ip="system"
                                )
                                db.session.add(log)
                        db.session.commit()
                except Exception as e:
                    logging.error(f"Rotation block DB error: {e}")
        
        return True, list(unique_ips)
    
    return False, []


def check_policy_expiry(app, db, Policy, Risk, AuditLog):
    with app.app_context():
        from datetime import datetime, timedelta
        now     = datetime.utcnow()
        alerts  = []
        policies = Policy.query.filter(Policy.review_date != None).all()

        for p in policies:
            days_left = (p.review_date - now).days

            if days_left < 0:
                # Already expired
                existing = Risk.query.filter_by(
                    name=f"AUTO: Policy EXPIRED — {p.title}"
                ).first()
                if not existing:
                    r = Risk(
                        name=f"AUTO: Policy EXPIRED — {p.title}",
                        description=f"Policy document '{p.title}' expired {abs(days_left)} days ago. Must be reviewed and re-approved immediately. ISO 27001 Clause 7.5 requires current documented information.",
                        likelihood=4, impact=4,
                        score=16, level="HIGH",
                        owner=p.owner or "Compliance Team",
                        created_by="POLICY-CHECKER"
                    )
                    db.session.add(r)
                    log = AuditLog(
                        user="POLICY-CHECKER",
                        action=f"EXPIRED policy detected: {p.title} — {abs(days_left)} days overdue",
                        ip="system"
                    )
                    db.session.add(log)
                    alerts.append({"policy": p.title, "status": "EXPIRED", "days": abs(days_left)})

            elif days_left <= 30:
                existing = Risk.query.filter_by(
                    name=f"AUTO: Policy expiring in {days_left} days — {p.title}"
                ).first()
                if not existing:
                    r = Risk(
                        name=f"AUTO: Policy expiring in {days_left} days — {p.title}",
                        description=f"Policy '{p.title}' is due for review in {days_left} days. Schedule review and re-approval to maintain compliance.",
                        likelihood=3, impact=3,
                        score=9, level="MEDIUM",
                        owner=p.owner or "Compliance Team",
                        created_by="POLICY-CHECKER"
                    )
                    db.session.add(r)
                    log = AuditLog(
                        user="POLICY-CHECKER",
                        action=f"Policy expiry alert: {p.title} — {days_left} days remaining",
                        ip="system"
                    )
                    db.session.add(log)
                    alerts.append({"policy": p.title, "status": "EXPIRING_SOON", "days": days_left})

            elif days_left <= 60:
                alerts.append({"policy": p.title, "status": "EXPIRING_60", "days": days_left})

            elif days_left <= 90:
                alerts.append({"policy": p.title, "status": "EXPIRING_90", "days": days_left})

        if alerts:
            db.session.commit()
            logging.info(f"Policy expiry check: {len(alerts)} alerts")

        return alerts


def check_ssl_certificates(app, db, Risk, AuditLog):
    with app.app_context():
        import subprocess
        from datetime import datetime, timedelta
        risks_found = []

        targets = [
            ("127.0.0.1", 443),
            ("localhost", 443),
        ]

        for host, port in targets:
            try:
                result = subprocess.run(
                    ["openssl", "s_client", "-connect", f"{host}:{port}",
                     "-servername", host],
                    input=b"",
                    capture_output=True,
                    timeout=5
                )
                cert_info = subprocess.run(
                    ["openssl", "x509", "-noout", "-dates"],
                    input=result.stdout,
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                for line in cert_info.stdout.splitlines():
                    if "notAfter" in line:
                        date_str = line.split("=")[1].strip()
                        expiry = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
                        days_left = (expiry - datetime.utcnow()).days

                        if days_left <= 0:
                            name = f"AUTO: SSL certificate EXPIRED on {host}"
                            existing = Risk.query.filter_by(name=name).first()
                            if not existing:
                                r = Risk(
                                    name=name,
                                    description=f"SSL certificate on {host}:{port} has EXPIRED. Website shows Not Secure to all visitors. Renew immediately.",
                                    likelihood=5, impact=5,
                                    score=25, level="CRITICAL",
                                    owner="IT Team",
                                    created_by="SSL-CHECKER"
                                )
                                db.session.add(r)
                                log = AuditLog(
                                    user="SSL-CHECKER",
                                    action=f"CRITICAL: SSL cert expired on {host}:{port}",
                                    ip="system"
                                )
                                db.session.add(log)
                                risks_found.append(f"EXPIRED: {host}")

                        elif days_left <= 30:
                            name = f"AUTO: SSL certificate expiring in {days_left} days — {host}"
                            existing = Risk.query.filter_by(name=name).first()
                            if not existing:
                                r = Risk(
                                    name=name,
                                    description=f"SSL certificate on {host}:{port} expires in {days_left} days on {expiry.strftime('%d %b %Y')}. Renew before expiry to avoid security warnings.",
                                    likelihood=4, impact=4,
                                    score=16, level="HIGH",
                                    owner="IT Team",
                                    created_by="SSL-CHECKER"
                                )
                                db.session.add(r)
                                log = AuditLog(
                                    user="SSL-CHECKER",
                                    action=f"SSL cert expiring in {days_left} days: {host}:{port}",
                                    ip="system"
                                )
                                db.session.add(log)
                                risks_found.append(f"EXPIRING: {host} in {days_left} days")

                        elif days_left <= 90:
                            log = AuditLog(
                                user="SSL-CHECKER",
                                action=f"SSL cert notice: {host}:{port} expires in {days_left} days",
                                ip="system"
                            )
                            db.session.add(log)

            except subprocess.TimeoutExpired:
                logging.info(f"SSL check timeout: {host}:{port} — no SSL service running")
            except Exception as e:
                logging.info(f"SSL check skipped {host}:{port}: {e}")

        if risks_found:
            db.session.commit()
            logging.warning(f"SSL checker found: {risks_found}")
        
        return risks_found


def check_weak_passwords(app, db, Risk, AuditLog, User):
    with app.app_context():
        from werkzeug.security import check_password_hash
        import itertools

        risks_found = []
        weak_users  = []

        # Load top 1000 most common passwords from rockyou
        common_passwords = []
        try:
            with open("/usr/share/wordlists/rockyou.txt", "r",
                      encoding="latin-1", errors="ignore") as f:
                common_passwords = list(itertools.islice(f, 1000))
            common_passwords = [p.strip() for p in common_passwords]
            logging.info(f"Loaded {len(common_passwords)} passwords from rockyou.txt")
        except Exception as e:
            logging.error(f"Could not load rockyou.txt: {e}")
            return []

        # Also check these common patterns always
        always_check = [
            "password", "password123", "123456", "admin",
            "Admin@1234", "admin123", "letmein", "qwerty",
            "welcome", "monkey", "dragon", "master",
            "abc123", "pass123", "test123", "root",
            "toor", "kali", "linux", "security"
        ]
        all_passwords = list(set(common_passwords + always_check))

        users = User.query.all()
        for user in users:
            for pwd in all_passwords:
                try:
                    if check_password_hash(user.password_hash, pwd):
                        weak_users.append({
                            "username": user.username,
                            "password": pwd[:3] + "***"
                        })
                        logging.warning(
                            f"WEAK PASSWORD: {user.username} uses common password"
                        )
                        break
                except Exception:
                    continue

        if weak_users:
            usernames = [u["username"] for u in weak_users]
            name = f"AUTO: Weak passwords detected — {len(weak_users)} user(s)"
            existing = Risk.query.filter_by(name=name).first()
            if not existing:
                r = Risk(
                    name=name,
                    description=f"Password audit found {len(weak_users)} user(s) with weak or commonly known passwords: {', '.join(usernames)}. These passwords appear in the rockyou.txt breach database. Immediate password reset required.",
                    likelihood=5, impact=5,
                    score=25, level="CRITICAL",
                    owner="IT Security Team",
                    created_by="PASSWORD-AUDITOR"
                )
                db.session.add(r)
                log = AuditLog(
                    user="PASSWORD-AUDITOR",
                    action=f"CRITICAL: Weak passwords found for users: {', '.join(usernames)}",
                    ip="system"
                )
                db.session.add(log)
                db.session.commit()
                risks_found.append(f"Weak passwords: {usernames}")

        else:
            log = AuditLog(
                user="PASSWORD-AUDITOR",
                action="Password audit complete — no weak passwords detected",
                ip="system"
            )
            db.session.add(log)
            db.session.commit()
            logging.info("Password audit passed — no weak passwords found")

        return risks_found


def check_system_hardening(app, db, Risk, AuditLog):
    with app.app_context():
        import subprocess
        risks_found = []

        checks = [
            {
                "id": "world_writable",
                "name": "AUTO: World-writable files detected",
                "cmd": "find / -xdev -type f -perm -0002 -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | head -20",
                "desc": "World-writable files allow any user to modify them — attackers can inject malicious code.",
                "level": "HIGH", "score": 16, "l": 4, "i": 4
            },
            {
                "id": "suid_files",
                "name": "AUTO: Unexpected SUID binaries detected",
                "cmd": "find / -xdev -perm -4000 -type f -not -path '/proc/*' 2>/dev/null | grep -v -E '(sudo|su|passwd|ping|mount|umount|newgrp|chsh|chfn|gpasswd|pkexec|ssh-keysign|Xorg)' | head -20",
                "desc": "SUID binaries run with root privileges — unexpected ones may allow privilege escalation.",
                "level": "CRITICAL", "score": 20, "l": 5, "i": 4
            },
            {
                "id": "empty_passwords",
                "name": "AUTO: User accounts with empty passwords detected",
                "cmd": "awk -F: '($2 == \"\") {print $1}' /etc/shadow 2>/dev/null",
                "desc": "Accounts with empty passwords allow passwordless login — critical security failure.",
                "level": "CRITICAL", "score": 25, "l": 5, "i": 5
            },
            {
                "id": "root_cron",
                "name": "AUTO: Suspicious root cron jobs detected",
                "cmd": "crontab -l 2>/dev/null; cat /etc/cron.d/* 2>/dev/null | grep -v '^#' | grep -v '^$'",
                "desc": "Unexpected cron jobs running as root may indicate persistence by an attacker.",
                "level": "HIGH", "score": 16, "l": 4, "i": 4
            },
            {
                "id": "unowned_files",
                "name": "AUTO: Files with no owner detected",
                "cmd": "find / -xdev -nouser -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | head -10",
                "desc": "Unowned files may belong to deleted accounts and could be exploited.",
                "level": "MEDIUM", "score": 9, "l": 3, "i": 3
            },
            {
                "id": "listening_ports",
                "name": "AUTO: Unexpected services listening on all interfaces",
                "cmd": "ss -tlnp 2>/dev/null | grep '0.0.0.0' | grep -v -E '(22|80|443|5000)'",
                "desc": "Services exposed on all interfaces increase attack surface unnecessarily.",
                "level": "HIGH", "score": 12, "l": 3, "i": 4
            },
            {
                "id": "ssh_root",
                "name": "AUTO: SSH root login is enabled",
                "cmd": "grep -i 'PermitRootLogin yes' /etc/ssh/sshd_config 2>/dev/null",
                "desc": "Allowing root SSH login exposes the most privileged account to brute force attacks.",
                "level": "HIGH", "score": 16, "l": 4, "i": 4
            },
            {
                "id": "firewall_off",
                "name": "AUTO: Firewall is disabled",
                "cmd": "ufw status 2>/dev/null | grep -i inactive",
                "desc": "No active firewall means all ports are exposed to the network.",
                "level": "CRITICAL", "score": 20, "l": 4, "i": 5
            },
        ]

        for check in checks:
            try:
                result = subprocess.run(
                    check["cmd"], shell=True,
                    capture_output=True, text=True, timeout=30
                )
                output = result.stdout.strip()

                if output:
                    existing = Risk.query.filter_by(name=check["name"]).first()
                    if not existing:
                        r = Risk(
                            name=check["name"],
                            description=check["desc"] + f"\n\nDetected:\n{output[:500]}",
                            likelihood=check["l"], impact=check["i"],
                            score=check["score"], level=check["level"],
                            owner="IT Security Team",
                            created_by="HARDENING-CHECKER"
                        )
                        db.session.add(r)
                        log = AuditLog(
                            user="HARDENING-CHECKER",
                            action=f"{check['level']}: {check['name']}",
                            ip="system"
                        )
                        db.session.add(log)
                        risks_found.append(check["name"])

            except subprocess.TimeoutExpired:
                logging.warning(f"Hardening check timeout: {check['id']}")
            except Exception as e:
                logging.error(f"Hardening check error {check['id']}: {e}")

        if risks_found:
            db.session.commit()
            logging.warning(f"Hardening checker found {len(risks_found)} issues")

        return risks_found
