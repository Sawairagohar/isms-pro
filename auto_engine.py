from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime, timedelta
import subprocess
import logging
import os

os.makedirs('logs', exist_ok=True)
logging.basicConfig(filename='logs/automation.log', level=logging.INFO)

def run_auto_scan(app, db, Risk, AuditLog):
    with app.app_context():
        logging.info(f"Auto scan started at {datetime.now()}")
        dangerous_ports = {
            21:   "FTP — unencrypted file transfer",
            23:   "Telnet — unencrypted remote access",
            445:  "SMB — common ransomware target",
            3389: "RDP — remote desktop brute force target",
            3306: "MySQL — database exposed to network",
            27017:"MongoDB — database exposed to network",
        }
        try:
            result = subprocess.run(
                ['nmap', '-F', '--open', '127.0.0.1'],
                capture_output=True, text=True, timeout=60
            )
            output = result.stdout
            for port, description in dangerous_ports.items():
                if f"{port}/tcp" in output:
                    existing = Risk.query.filter_by(
                        name=f"AUTO: Open port {port} detected"
                    ).first()
                    if not existing:
                        r = Risk(
                            name=f"AUTO: Open port {port} detected",
                            description=f"{description}. Detected automatically by system scan.",
                            likelihood=4,
                            impact=4,
                            score=16,
                            level='HIGH',
                            owner='IT Team',
                            created_by='AUTO-SYSTEM'
                        )
                        db.session.add(r)
                        log = AuditLog(
                            user='AUTO-SYSTEM',
                            action=f"Auto-detected open port {port} — risk created",
                            ip='system'
                        )
                        db.session.add(log)
                        db.session.commit()
                        logging.info(f"Auto risk created for port {port}")
        except Exception as e:
            logging.error(f"Auto scan error: {e}")

def check_overdue_training(app, db, Training, AuditLog):
    with app.app_context():
        today = datetime.now().date()
        overdue = Training.query.filter_by(status='Pending').all()
        for t in overdue:
            if t.due_date:
                try:
                    due = datetime.strptime(t.due_date, '%Y-%m-%d').date()
                    if due < today:
                        log = AuditLog(
                            user='AUTO-SYSTEM',
                            action=f"Training overdue: {t.topic} for {t.employee}",
                            ip='system'
                        )
                        db.session.add(log)
                        db.session.commit()
                except Exception as e:
                    logging.error(f"Training check error: {e}")

def check_inactive_users(app, db, User, AuditLog):
    with app.app_context():
        cutoff = datetime.utcnow() - timedelta(days=30)
        users = User.query.all()
        for u in users:
            if u.created_at < cutoff and u.role != 'admin':
                log = AuditLog(
                    user='AUTO-SYSTEM',
                    action=f"Inactive user detected: {u.username}",
                    ip='system'
                )
                db.session.add(log)
                db.session.commit()

def check_old_policies(app, db, Policy, Risk, AuditLog):
    with app.app_context():
        cutoff = datetime.utcnow() - timedelta(days=365)
        old_policies = Policy.query.filter(
            Policy.uploaded_at < cutoff
        ).all()
        for p in old_policies:
            existing = Risk.query.filter_by(
                name=f"AUTO: Policy review overdue — {p.title}"
            ).first()
            if not existing:
                r = Risk(
                    name=f"AUTO: Policy review overdue — {p.title}",
                    description=f"Policy not reviewed in 12 months. ISO 27001 Clause 7.5 requires regular review.",
                    likelihood=3,
                    impact=3,
                    score=9,
                    level='MEDIUM',
                    owner='Compliance Team',
                    created_by='AUTO-SYSTEM'
                )
                db.session.add(r)
                log = AuditLog(
                    user='AUTO-SYSTEM',
                    action=f"Auto risk created: policy overdue — {p.title}",
                    ip='system'
                )
                db.session.add(log)
                db.session.commit()

def check_critical_risks(app, db, Risk, AuditLog):
    with app.app_context():
        critical = Risk.query.filter_by(level='CRITICAL').all()
        for r in critical:
            age = datetime.utcnow() - r.created_at
            if age.days >= 2:
                log = AuditLog(
                    user='AUTO-SYSTEM',
                    action=f"ESCALATION: Critical risk untreated {age.days} days — {r.name}",
                    ip='system'
                )
                db.session.add(log)
                db.session.commit()

def start_scheduler(app, db, models):
    User     = models['User']
    Risk     = models['Risk']
    Training = models['Training']
    Policy   = models['Policy']
    AuditLog = models['AuditLog']

    from prevention import auto_detect_system_risks, fetch_latest_cves

    scheduler = BackgroundScheduler()

    scheduler.add_job(
        func=run_auto_scan,
        args=[app, db, Risk, AuditLog],
        trigger='interval',
        minutes=2,
        id='auto_scan'
    )

    scheduler.add_job(
        func=auto_detect_system_risks,
        args=[app, db, Risk, AuditLog],
        trigger='interval',
        minutes=2,
        id='system_detector'
    )

    scheduler.add_job(
        func=fetch_latest_cves,
        args=[app, db, Risk, AuditLog],
        trigger='interval',
        hours=6,
        id='cve_watcher'
    )

    scheduler.add_job(
        func=check_overdue_training,
        args=[app, db, Training, AuditLog],
        trigger='cron',
        hour=8,
        minute=0,
        id='training_check'
    )

    scheduler.add_job(
        func=check_inactive_users,
        args=[app, db, User, AuditLog],
        trigger='cron',
        hour=0,
        minute=0,
        id='inactive_users'
    )

    scheduler.add_job(
        func=check_old_policies,
        args=[app, db, Policy, Risk, AuditLog],
        trigger='interval',
        weeks=1,
        id='policy_check'
    )

    scheduler.add_job(
        func=check_critical_risks,
        args=[app, db, Risk, AuditLog],
        trigger='interval',
        hours=12,
        id='critical_check'
    )


    from prevention import (check_ssh_security, check_user_accounts,
                            check_running_services, check_failed_logins_system,
                            check_breach_database)

    scheduler.add_job(
        func=check_ssh_security,
        args=[app, db, Risk, AuditLog],
        trigger="interval",
        minutes=5,
        id="ssh_checker"
    )
    scheduler.add_job(
        func=check_user_accounts,
        args=[app, db, Risk, AuditLog],
        trigger="interval",
        minutes=5,
        id="user_checker"
    )
    scheduler.add_job(
        func=check_running_services,
        args=[app, db, Risk, AuditLog],
        trigger="interval",
        minutes=5,
        id="service_checker"
    )
    scheduler.add_job(
        func=check_failed_logins_system,
        args=[app, db, Risk, AuditLog],
        trigger="interval",
        minutes=5,
        id="login_checker"
    )
    scheduler.add_job(
        func=check_breach_database,
        args=[app, db, Risk, AuditLog],
        trigger="interval",
        hours=12,
        id="breach_checker"
    )
    from prevention import check_policy_expiry
    scheduler.add_job(
        func=check_policy_expiry,
        args=[app, db, Policy, Risk, AuditLog],
        trigger="interval",
        hours=12,
        id="policy_expiry"
    )
    scheduler.add_job(
        func=check_policy_expiry,
        args=[app, db, Policy, AuditLog, lambda s,b: None],
        trigger="cron",
        hour=9,
        minute=0,
        id="expiry_checker"
    )
    from prevention import check_ssl_certificates, check_weak_passwords, check_system_hardening
    scheduler.add_job(
        func=check_system_hardening,
        args=[app, db, Risk, AuditLog],
        trigger="cron",
        hour=3,
        minute=0,
        id="hardening_checker"
    )
    from prevention import check_ssl_certificates, check_weak_passwords
    scheduler.add_job(
        func=check_weak_passwords,
        args=[app, db, Risk, AuditLog, User],
        trigger="cron",
        hour=2,
        minute=0,
        id="password_auditor"
    )
    from prevention import check_ssl_certificates
    scheduler.add_job(
        func=check_ssl_certificates,
        args=[app, db, Risk, AuditLog],
        trigger="interval",
        hours=12,
        id="ssl_checker"
    )
    from evidence_engine import run_auto_evidence
    from models import ControlEvidence
    scheduler.add_job(
        func=run_auto_evidence,
        args=[app, db, ControlEvidence, AuditLog, Risk, Policy, User],
        trigger="interval",
        hours=24,
        id="auto_evidence"
    )
    scheduler.start()
    logging.info("Automation scheduler started")
    print("Automation engine running — checks every 2 minutes")
    return scheduler

def check_policy_expiry(app, db, Policy, AuditLog, send_alert_email):
    with app.app_context():
        from datetime import datetime, timedelta
        now = datetime.utcnow()
        alerts = []

        policies = Policy.query.filter(Policy.review_date != None).all()
        for p in policies:
            days_left = (p.review_date - now).days

            if days_left <= 0:
                msg = f"OVERDUE: Policy '{p.title}' review was due {abs(days_left)} days ago"
                alerts.append(msg)
                log = AuditLog(
                    user="EXPIRY-CHECKER",
                    action=f"Policy review OVERDUE: {p.title} — {abs(days_left)} days overdue",
                    ip="system"
                )
                db.session.add(log)
                send_alert_email(
                    f"OVERDUE: Policy Review — {p.title}",
                    f"The policy '{p.title}' review date has passed by {abs(days_left)} days.\n\nPlease review and update this policy immediately.\n\nISO 27001 Clause 7.5 requires documented information to be reviewed regularly."
                )

            elif days_left <= 30:
                msg = f"URGENT: Policy '{p.title}' review due in {days_left} days"
                alerts.append(msg)
                log = AuditLog(
                    user="EXPIRY-CHECKER",
                    action=f"Policy review due in {days_left} days: {p.title}",
                    ip="system"
                )
                db.session.add(log)
                if days_left <= 7:
                    send_alert_email(
                        f"URGENT: Policy Review Due in {days_left} days — {p.title}",
                        f"The policy '{p.title}' review is due in {days_left} days.\n\nPlease review immediately to maintain ISO 27001 compliance."
                    )

            elif days_left <= 60:
                msg = f"WARNING: Policy '{p.title}' review due in {days_left} days"
                alerts.append(msg)
                log = AuditLog(
                    user="EXPIRY-CHECKER",
                    action=f"Policy review due in {days_left} days: {p.title}",
                    ip="system"
                )
                db.session.add(log)

            elif days_left <= 90:
                msg = f"NOTICE: Policy '{p.title}' review due in {days_left} days"
                alerts.append(msg)
                log = AuditLog(
                    user="EXPIRY-CHECKER",
                    action=f"Policy review notice: {p.title} due in {days_left} days",
                    ip="system"
                )
                db.session.add(log)

        if alerts:
            db.session.commit()
            logging.info(f"Policy expiry check: {len(alerts)} alerts generated")

        return alerts
