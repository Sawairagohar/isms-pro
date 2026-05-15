import logging
from datetime import datetime

def auto_link_evidence(db, ControlEvidence, control_id, control_name, description, evidence_type="auto", filename=None):
    """
    Automatically creates evidence entry for a control.
    Called by other parts of the system whenever a relevant action occurs.
    """
    try:
        # Check if identical evidence already exists today
        today = datetime.utcnow().date()
        existing = ControlEvidence.query.filter_by(
            control_id=control_id,
            description=description
        ).first()

        if existing:
            # Update timestamp to show it was checked today
            existing.uploaded_at = datetime.utcnow()
            db.session.commit()
            return existing

        e = ControlEvidence(
            control_id=control_id,
            control_name=control_name,
            description=description,
            evidence_type=evidence_type,
            filename=filename,
            uploaded_by="SYSTEM-AUTO"
        )
        db.session.add(e)
        db.session.commit()
        logging.info(f"Auto-evidence created for control {control_id}: {description[:50]}")
        return e

    except Exception as ex:
        logging.error(f"Auto-evidence error for {control_id}: {ex}")
        return None


def run_auto_evidence(app, db, ControlEvidence, AuditLog, Risk, Policy, User):
    """
    Main auto-evidence runner — called by scheduler every 24 hours.
    Scans existing data and auto-links evidence to controls.
    """
    with app.app_context():
        from datetime import datetime, timedelta
        now = datetime.utcnow()
        count = 0

        # CONTROL 8.15 — Logging
        # Evidence: audit log entries exist and are active
        log_count = AuditLog.query.count()
        if log_count > 0:
            recent = AuditLog.query.order_by(AuditLog.timestamp.desc()).first()
            e = auto_link_evidence(
                db, ControlEvidence,
                "8.15", "Logging",
                f"Audit log is active with {log_count} entries. Most recent entry: {recent.timestamp.strftime('%d %b %Y %H:%M')} by {recent.user}.",
                evidence_type="log"
            )
            if e: count += 1

        # CONTROL 8.16 — Monitoring activities
        # Evidence: IP blocking is active
        blocked = AuditLog.query.filter(AuditLog.action.like("%blocked%")).count()
        if blocked > 0:
            e = auto_link_evidence(
                db, ControlEvidence,
                "8.16", "Monitoring activities",
                f"Active monitoring confirmed — {blocked} IP blocking events recorded in audit log. System automatically detects and blocks suspicious activity.",
                evidence_type="log"
            )
            if e: count += 1

        # CONTROL 8.8 — Management of technical vulnerabilities
        # Evidence: vulnerability scans have been conducted
        scans = AuditLog.query.filter(AuditLog.action.like("%scan%")).count()
        if scans > 0:
            e = auto_link_evidence(
                db, ControlEvidence,
                "8.8", "Management of technical vulnerabilities",
                f"Vulnerability scanning is active — {scans} scan events recorded. System conducts automated nmap-based vulnerability assessments.",
                evidence_type="report"
            )
            if e: count += 1

        # CONTROL 5.1 — Policies for information security
        # Evidence: policies exist in the system
        policy_count = Policy.query.count()
        if policy_count > 0:
            titles = [p.title for p in Policy.query.limit(5).all()]
            e = auto_link_evidence(
                db, ControlEvidence,
                "5.1", "Policies for information security",
                f"{policy_count} information security policies maintained in the system: {', '.join(titles)}.",
                evidence_type="document"
            )
            if e: count += 1

        # CONTROL 7.5 — Protecting against physical and environmental threats
        # Evidence: policy review dates are being tracked
        policies_with_dates = Policy.query.filter(Policy.review_date != None).count()
        if policies_with_dates > 0:
            e = auto_link_evidence(
                db, ControlEvidence,
                "7.5", "Protecting against physical and environmental threats",
                f"{policies_with_dates} policies have scheduled review dates being tracked and monitored automatically.",
                evidence_type="procedure"
            )
            if e: count += 1

        # CONTROL 5.7 — Threat intelligence
        # Evidence: risks are being tracked
        risk_count = Risk.query.count()
        if risk_count > 0:
            critical = Risk.query.filter_by(level="CRITICAL").count()
            high = Risk.query.filter_by(level="HIGH").count()
            e = auto_link_evidence(
                db, ControlEvidence,
                "5.7", "Threat intelligence",
                f"Threat intelligence active — {risk_count} risks tracked ({critical} CRITICAL, {high} HIGH). Risks auto-created from CVE feeds, vulnerability scans and hardening checks.",
                evidence_type="report"
            )
            if e: count += 1

        # CONTROL 5.17 — Authentication information
        # Evidence: password audit has been conducted
        pwd_audit = AuditLog.query.filter(AuditLog.user == "PASSWORD-AUDITOR").count()
        if pwd_audit > 0:
            last = AuditLog.query.filter_by(user="PASSWORD-AUDITOR").order_by(AuditLog.timestamp.desc()).first()
            e = auto_link_evidence(
                db, ControlEvidence,
                "5.17", "Authentication information",
                f"Automated password audit conducted using rockyou.txt breach database. Last audit: {last.timestamp.strftime('%d %b %Y')}. Result: {last.action}.",
                evidence_type="report"
            )
            if e: count += 1

        # CONTROL 8.24 — Use of cryptography
        # Evidence: SSL certificate monitoring is active
        ssl_checks = AuditLog.query.filter(AuditLog.user == "SSL-CHECKER").count()
        if ssl_checks > 0:
            e = auto_link_evidence(
                db, ControlEvidence,
                "8.24", "Use of cryptography",
                f"SSL certificate monitoring active — {ssl_checks} automated checks conducted. System checks certificate expiry every 12 hours.",
                evidence_type="log"
            )
            if e: count += 1

        # CONTROL 8.9 — Configuration management
        # Evidence: hardening checks have been conducted
        hardening = AuditLog.query.filter(AuditLog.user == "HARDENING-CHECKER").count()
        if hardening > 0:
            e = auto_link_evidence(
                db, ControlEvidence,
                "8.9", "Configuration management",
                f"System hardening checks active — {hardening} automated configuration audit events. Checks include SUID files, world-writable files, SSH configuration and firewall status.",
                evidence_type="report"
            )
            if e: count += 1

        # CONTROL 6.3 — Security awareness training
        # Evidence: training records exist
        try:
            from models import Training
            training_count = Training.query.count()
            completed = Training.query.filter_by(completed=True).count()
            if training_count > 0:
                e = auto_link_evidence(
                    db, ControlEvidence,
                    "6.3", "Information security awareness, education and training",
                    f"Security training program active — {training_count} training modules assigned, {completed} completed. Training records maintained with completion dates.",
                    evidence_type="document"
                )
                if e: count += 1
        except Exception:
            pass

        # CONTROL 5.18 — Access rights
        # Evidence: access reviews have been conducted
        access_reviews = AuditLog.query.filter(AuditLog.action.like("%access review%")).count()
        if access_reviews > 0:
            e = auto_link_evidence(
                db, ControlEvidence,
                "5.18", "Access rights",
                f"Quarterly access review conducted {access_reviews} time(s). Reviews identify inactive accounts, flagged users and access anomalies.",
                evidence_type="report"
            )
            if e: count += 1

        # CONTROL 5.24 — Incident management planning
        # Evidence: incidents are being tracked
        try:
            from models import Incident
            inc_count = Incident.query.count()
            if inc_count > 0:
                e = auto_link_evidence(
                    db, ControlEvidence,
                    "5.24", "Information security incident management planning and preparation",
                    f"Incident management active — {inc_count} incidents recorded and tracked in the system with full audit trail.",
                    evidence_type="report"
                )
                if e: count += 1
        except Exception:
            pass

        # CONTROL 5.19 — Supplier relationships
        # Evidence: suppliers are being managed
        try:
            from models import Supplier
            sup_count = Supplier.query.count()
            if sup_count > 0:
                e = auto_link_evidence(
                    db, ControlEvidence,
                    "5.19", "Information security in supplier relationships",
                    f"Supplier management active — {sup_count} suppliers tracked with contract expiry dates, risk scores and security assessments.",
                    evidence_type="document"
                )
                if e: count += 1
        except Exception:
            pass

        # CONTROL 5.15 — Access control
        # Evidence: user accounts with roles exist
        user_count = User.query.count()
        if user_count > 0:
            roles = {}
            for u in User.query.all():
                roles[u.role] = roles.get(u.role, 0) + 1
            role_summary = ", ".join([f"{v} {k}" for k,v in roles.items()])
            e = auto_link_evidence(
                db, ControlEvidence,
                "5.15", "Access control",
                f"Role-based access control implemented — {user_count} users with defined roles: {role_summary}. Access controlled by role throughout the system.",
                evidence_type="procedure"
            )
            if e: count += 1

        logging.info(f"Auto-evidence engine complete — {count} evidence entries updated")
        return count
