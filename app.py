from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from config import Config
from models import db, User, Risk, Training, Policy, AuditLog, BlogPost, BlogComment, BlockedIP, KPILog, IncidentTicket, CorrectiveAction, SoAControl, ComplianceHistory
from auth import role_required, log_action
import os, datetime, subprocess
from flask import send_from_directory


import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import io, base64


import joblib
import numpy as np


from flask_mail import Mail, Message
from prevention import record_failed_login, scan_request_for_attacks, fetch_latest_cves, auto_port_scan_and_fix, full_security_health_check, get_blocked_ips, get_suspicious_ips, is_blocked




app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)


mail = Mail(app)

def send_alert_email(subject, body):
    try:
        msg = Message(subject,
                      sender=app.config['MAIL_USERNAME'],
                      recipients=[app.config['MAIL_USERNAME']])
        msg.body = body
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Email error: {e}")
        return False



login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@app.before_request
def check_blocked():
    ip = request.remote_addr
    if is_blocked(ip):
        return "Access denied — your IP has been blocked.", 403
    request_data = request.url + str(request.form)
    status, pattern = scan_request_for_attacks(request_data, ip)
    if status == 'BLOCKED':
        log_action(db, AuditLog, 'SYSTEM',
                   f"Attack blocked from {ip} — pattern: {pattern}", ip)
        return "Request blocked — attack pattern detected.", 403
    
    # Check database blocklist too
    from models import BlockedIP as BlockedIPModel
    db_blocked = BlockedIPModel.query.filter_by(ip=ip).first()
    if db_blocked:
        return f"Access denied — IP blocked: {db_blocked.reason}", 403

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ── Helper ──────────────────────────────────────────
def classify_risk(score):
    if score >= 20: return 'CRITICAL'
    if score >= 12: return 'HIGH'
    if score >= 6:  return 'MEDIUM'
    return 'LOW'

# ── Auth routes ─────────────────────────────────────
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.check_password(request.form['password']):
            login_user(user)
            log_action(db, AuditLog, user.username, 'Logged in',
                       request.remote_addr)
            return redirect(url_for('dashboard'))
        blocked = record_failed_login(request.remote_addr, app, db, BlockedIP)
        # Check for IP rotation attack
        from prevention import detect_ip_rotation
        rotation, ips = detect_ip_rotation(request.remote_addr, app, db, BlockedIP, AuditLog)
        if rotation:
            log_action(db, AuditLog, "SYSTEM", f"IP rotation attack detected and blocked — {len(ips)} IPs", request.remote_addr)
        if blocked:
            flash('Too many failed attempts. Your IP has been blocked.', 'danger')
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    log_action(db, AuditLog, current_user.username, 'Logged out',
               request.remote_addr)
    logout_user()
    return redirect(url_for('login'))

# ── Dashboard ────────────────────────────────────────
@app.route('/dashboard')
@login_required
def dashboard():
    from models import OnboardingChecklist, ControlEvidence, AuditPlan, AuditFinding

    # Risks
    total_risks    = Risk.query.count()
    critical_risks = Risk.query.filter_by(level="CRITICAL").count()
    high_risks     = Risk.query.filter_by(level="HIGH").count()
    auto_risks     = Risk.query.filter(Risk.created_by.in_(["CVE-FEED","HARDENING-CHECKER","INTERNAL-AUDIT","SSL-CHECKER"])).count()

    # Policies
    total_policies  = Policy.query.count()
    overdue_policies = Policy.query.filter(
        Policy.review_date != None,
        Policy.review_date < datetime.datetime.utcnow()
    ).count()

    # Training
    total_training   = Training.query.count()
    pending_training = Training.query.filter_by(status="Pending").count()
    completed_training = Training.query.filter_by(status='Completed').count()

    # Incidents
    try:
        from models import Incident
        total_incidents = Incident.query.count()
        open_incidents  = Incident.query.filter_by(status="open").count()
    except:
        total_incidents = 0
        open_incidents  = 0

    # Checklists
    total_checklists     = OnboardingChecklist.query.count()
    pending_checklists   = OnboardingChecklist.query.filter_by(completed=False).count()
    completed_checklists = OnboardingChecklist.query.filter_by(completed=True).count()

    # Evidence
    total_controls  = 93
    covered_controls = db.session.query(ControlEvidence.control_id).distinct().count()
    evidence_pct    = int((covered_controls / total_controls) * 100)

    # Internal Audits
    total_audits     = AuditPlan.query.count()
    completed_audits = AuditPlan.query.filter_by(status="completed").count()
    open_findings    = AuditFinding.query.filter_by(status="open").count()

    # Audit log
    recent_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(8).all()
    total_logs  = AuditLog.query.count()

    # Suppliers
    try:
        from models import Supplier
        total_suppliers = Supplier.query.count()
    except:
        total_suppliers = 0

    return render_template("dashboard.html",
        total_risks=total_risks,
        critical_risks=critical_risks,
        high_risks=high_risks,
        auto_risks=auto_risks,
        total_policies=total_policies,
        overdue_policies=overdue_policies,
        total_training=total_training,
        pending_training=pending_training,
        completed_training=completed_training,
        total_incidents=total_incidents,
        open_incidents=open_incidents,
        total_checklists=total_checklists,
        pending_checklists=pending_checklists,
        completed_checklists=completed_checklists,
        covered_controls=covered_controls,
        total_controls=total_controls,
        evidence_pct=evidence_pct,
        total_audits=total_audits,
        completed_audits=completed_audits,
        open_findings=open_findings,
        recent_logs=recent_logs,
        total_logs=total_logs,
        total_suppliers=total_suppliers
    )

# ── Risk Management ──────────────────────────────────
@app.route('/risk', methods=['GET', 'POST'])
@login_required
def risk():
    if request.method == 'POST':
        likelihood = int(request.form['likelihood'])
        impact     = int(request.form['impact'])
        score      = likelihood * impact
        r = Risk(
            name=request.form['name'],
            description=request.form.get('description',''),
            likelihood=likelihood,
            impact=impact,
            score=score,
            level=classify_risk(score),
            owner=request.form.get('owner',''),
            created_by=current_user.username)
        db.session.add(r)
        db.session.commit()
        log_action(db, AuditLog, current_user.username,
                   f"Added risk: {r.name} (score {score})", request.remote_addr)
        if r.level == 'CRITICAL':
            send_alert_email(
                subject='CRITICAL Risk Alert: ' + r.name,
                body='ISMS ALERT\n\nRisk: ' + r.name + '\nLevel: CRITICAL\nScore: ' + str(score) + '/25\nAdded by: ' + current_user.username
            )
        flash('Risk added — level: ' + r.level, 'success')
    risks = Risk.query.order_by(Risk.score.desc()).all()
    return render_template('risk.html', risks=risks)

# ── Training ─────────────────────────────────────────
@app.route('/training', methods=['GET', 'POST'])
@login_required
def training():
    if request.method == 'POST':
        t = Training(
            employee=request.form['employee'],
            topic=request.form['topic'],
            due_date=request.form.get('due_date',''),
            status='Pending')
        db.session.add(t)
        db.session.commit()
        log_action(db, AuditLog, current_user.username,
                   f"Added training for {t.employee}", request.remote_addr)
        flash('Training record added.', 'success')
    records = Training.query.order_by(Training.id.desc()).all()
    return render_template('training.html', records=records)

@app.route('/training/complete/<int:tid>')
@login_required
def complete_training(tid):
    t = Training.query.get_or_404(tid)
    t.status = 'Completed'
    t.completed_at = datetime.datetime.utcnow()
    db.session.commit()
    log_action(db, AuditLog, current_user.username,
               f"Marked training complete: {t.topic} for {t.employee}",
               request.remote_addr)
    flash('Marked as completed.', 'success')
    return redirect(url_for('training'))

# ── Policies ─────────────────────────────────────────
@app.route('/policies', methods=['GET', 'POST'])
@login_required
def policies():
    if request.method == 'POST':
        f = request.files.get('file')
        if f and f.filename:
            filename = f.filename
            f.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            review_date = None
            review_str  = request.form.get('review_date', '')
            if review_str:
                try:
                    review_date = datetime.datetime.strptime(review_str, '%Y-%m-%d')
                except:
                    pass
            p = Policy(
                title=request.form.get('title', filename),
                filename=filename,
                uploaded_by=current_user.username,
                owner=request.form.get('owner', ''),
                version=request.form.get('version', '1.0'),
                review_date=review_date)
            db.session.add(p)
            db.session.commit()
            log_action(db, AuditLog, current_user.username,
                       f"Uploaded policy: {filename}", request.remote_addr)
            flash('Policy uploaded.', 'success')
    docs = Policy.query.order_by(Policy.uploaded_at.desc()).all()
    return render_template('policies.html', docs=docs, now=datetime.datetime.utcnow())

# ── Audit Log ────────────────────────────────────────
@app.route('/auditlog')
@login_required
@role_required('admin', 'auditor')
def auditlog():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    return render_template('auditlog.html', logs=logs)

# ── Admin panel ──────────────────────────────────────
@app.route('/admin')
@login_required
@role_required('admin')
def admin_panel():
    users = User.query.all()
    return render_template('admin.html', users=users)


@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/scan', methods=['GET', 'POST'])
@login_required
def scan():
    result = None
    target = None
    scan_type = None
    if request.method == 'POST':
        target = request.form.get('target', '127.0.0.1')
        scan_type = request.form.get('scan_type', 'basic')

        if scan_type == 'basic':
            cmd = ['nmap', '-F', '--open', target]
        elif scan_type == 'os':
            cmd = ['nmap', '-O', '--open', target]
        elif scan_type == 'ports':
            cmd = ['nmap', '-p', '1-1000', target]
        elif scan_type == 'vuln':
            cmd = ['nmap', '--script', 'vuln', '-F', target]
        else:
            cmd = ['nmap', '-F', target]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            result = proc.stdout or proc.stderr
        except subprocess.TimeoutExpired:
            result = 'Scan timed out after 60 seconds.'
        except FileNotFoundError:
            result = 'nmap not found. Run: sudo apt install nmap'

        log_action(db, AuditLog, current_user.username,
                   f"Ran {scan_type} scan on {target}", request.remote_addr)

    return render_template('scan.html', result=result, target=target, scan_type=scan_type)




@app.route('/graphs')
@login_required
def graphs():
    # Risk level chart data
    levels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    colors = ['#16a34a', '#2563eb', '#d97706', '#dc2626']
    counts = [Risk.query.filter_by(level=l).count() for l in levels]

    # Bar chart — risk levels
    fig, ax = plt.subplots(figsize=(7, 3.5))
    fig.patch.set_facecolor('#1e293b')
    ax.set_facecolor('#0f172a')
    bars = ax.bar(levels, counts, color=colors, width=0.5)
    ax.set_title('Risks by Level', color='#94a3b8', fontsize=13, pad=12)
    ax.tick_params(colors='#94a3b8')
    ax.spines[:].set_color('#334155')
    for bar, count in zip(bars, counts):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1,
                str(count), ha='center', color='#f1f5f9', fontsize=11)
    plt.tight_layout()
    buf1 = io.BytesIO()
    plt.savefig(buf1, format='png', facecolor='#1e293b')
    buf1.seek(0)
    chart1 = base64.b64encode(buf1.read()).decode('utf-8')
    plt.close()

    # Training pie chart
    completed = Training.query.filter_by(status='Completed').count()
    pending   = Training.query.filter_by(status='Pending').count()
    fig2, ax2 = plt.subplots(figsize=(5, 3.5))
    fig2.patch.set_facecolor('#1e293b')
    ax2.set_facecolor('#1e293b')
    if completed + pending > 0:
        ax2.pie([completed, pending],
                labels=['Completed', 'Pending'],
                colors=['#16a34a', '#d97706'],
                autopct='%1.0f%%',
                textprops={'color': '#f1f5f9', 'fontsize': 11})
    ax2.set_title('Training Status', color='#94a3b8', fontsize=13, pad=12)
    plt.tight_layout()
    buf2 = io.BytesIO()
    plt.savefig(buf2, format='png', facecolor='#1e293b')
    buf2.seek(0)
    chart2 = base64.b64encode(buf2.read()).decode('utf-8')
    plt.close()

    # Risk score trend (all risks ordered by id)
    all_risks = Risk.query.order_by(Risk.id).all()
    risk_names  = [r.name[:15] for r in all_risks]
    risk_scores = [r.score for r in all_risks]

    fig3, ax3 = plt.subplots(figsize=(7, 3.5))
    fig3.patch.set_facecolor('#1e293b')
    ax3.set_facecolor('#0f172a')
    if risk_scores:
        ax3.plot(risk_names, risk_scores, color='#38bdf8',
                 marker='o', linewidth=2, markersize=6)
        ax3.fill_between(range(len(risk_scores)), risk_scores,
                         alpha=0.15, color='#38bdf8')
        ax3.set_xticks(range(len(risk_names)))
        ax3.set_xticklabels(risk_names, rotation=25, ha='right', fontsize=9)
    ax3.set_title('Risk Score Trend', color='#94a3b8', fontsize=13, pad=12)
    ax3.tick_params(colors='#94a3b8')
    ax3.spines[:].set_color('#334155')
    plt.tight_layout()
    buf3 = io.BytesIO()
    plt.savefig(buf3, format='png', facecolor='#1e293b')
    buf3.seek(0)
    chart3 = base64.b64encode(buf3.read()).decode('utf-8')
    plt.close()

    return render_template('graphs.html',
                           chart1=chart1, chart2=chart2, chart3=chart3,
                           total_risks=Risk.query.count(),
                           critical=Risk.query.filter_by(level='CRITICAL').count(),
                           completed=completed, pending=pending)







# Load AI model once at startup
try:
    ai_model = joblib.load('ai_model.pkl')
except:
    ai_model = None

@app.route('/ai', methods=['GET', 'POST'])
@login_required
def ai_risk():
    prediction   = None
    confidence   = None
    likelihood   = None
    impact       = None
    manual_score = None
    advice       = None

    if request.method == 'POST':
        likelihood   = int(request.form['likelihood'])
        impact       = int(request.form['impact'])
        manual_score = likelihood * impact

        if ai_model:
            pred_arr    = ai_model.predict([[likelihood, impact]])
            proba_arr   = ai_model.predict_proba([[likelihood, impact]])
            prediction  = pred_arr[0]
            confidence  = round(max(proba_arr[0]) * 100, 1)
        else:
            # Fallback if model not loaded
            if manual_score >= 20:   prediction = 'CRITICAL'
            elif manual_score >= 12: prediction = 'HIGH'
            elif manual_score >= 6:  prediction = 'MEDIUM'
            else:                    prediction = 'LOW'
            confidence = 100.0

        advice_map = {
            'CRITICAL': 'Immediate action required. Escalate to senior management. Implement emergency controls now.',
            'HIGH':     'Schedule treatment within 2 weeks. Assign risk owner and define mitigation plan.',
            'MEDIUM':   'Monitor closely. Plan treatment within 30 days. Review monthly.',
            'LOW':      'Accept or monitor. Review quarterly. No immediate action needed.'
        }
        advice = advice_map.get(prediction, '')

        log_action(db, AuditLog, current_user.username,
                   f"AI risk assessment: L={likelihood} I={impact} → {prediction} ({confidence}%)",
                   request.remote_addr)

    return render_template('ai.html',
                           prediction=prediction,
                           confidence=confidence,
                           likelihood=likelihood,
                           impact=impact,
                           manual_score=manual_score,
                           advice=advice)




@app.route('/security')
@login_required
@role_required('admin')
def security_center():
    # Merge in-memory blocks with database blocks
    mem_blocked = get_blocked_ips()
    db_blocked  = [b.ip for b in BlockedIP.query.all()]
    blocked     = list(set(mem_blocked + db_blocked))
    suspicious  = get_suspicious_ips()
    issues = full_security_health_check(app, db, {
        'User': User, 'Risk': Risk,
        'Training': Training, 'Policy': Policy,
        'AuditLog': AuditLog
    })
    recent_threats = Risk.query.filter(
        Risk.created_by.in_(['CVE-WATCHER', 'AUTO-SCANNER', 'AUTO-SYSTEM'])
    ).order_by(Risk.created_at.desc()).limit(10).all()
    return render_template('security.html',
                           blocked=blocked,
                           suspicious=suspicious,
                           issues=issues,
                           threats=recent_threats)







# ── Blog ─────────────────────────────────────────────
from datetime import datetime as dt

BLOG_POSTS = [
    {
        "id": 1,
        "title": "Understanding ISO 27001 Risk Assessment",
        "category": "ISO 27001",
        "date": "2026-04-01",
        "author": "ISMS Platform",
        "summary": "Risk assessment is the foundation of ISO 27001. Learn how to identify, analyze and evaluate information security risks effectively.",
        "content": """Risk assessment under ISO 27001 Clause 6.1.2 requires organizations to identify risks associated with the loss of confidentiality, integrity and availability of information.

The process involves four key steps:

1. IDENTIFY RISKS — What could go wrong? Who or what could cause harm? Common risks include data breaches, ransomware attacks, insider threats, and system failures.

2. ANALYZE RISKS — For each risk, assess the likelihood (1-5) and potential impact (1-5). Multiply these to get a risk score.

3. EVALUATE RISKS — Compare the risk score against your risk acceptance criteria. Scores above 15 typically require immediate treatment.

4. TREAT RISKS — Choose one of four treatment options: Mitigate (reduce the risk), Transfer (insurance), Accept (document it), or Avoid (stop the activity).

Our ISMS platform automates this entire process using AI-powered risk classification with a Random Forest machine learning model trained on real security scenarios.""",
        "tags": ["ISO 27001", "Risk Assessment", "Clause 6"]
    },
    {
        "id": 2,
        "title": "Top 10 Cybersecurity Threats in 2026",
        "category": "Threat Intelligence",
        "date": "2026-04-10",
        "author": "ISMS Platform",
        "summary": "The cybersecurity landscape is evolving rapidly. Here are the top 10 threats organizations face in 2026 and how to defend against them.",
        "content": """The threat landscape in 2026 is more complex than ever. Here are the top threats:

1. AI-POWERED PHISHING — Attackers now use AI to craft perfectly personalized phishing emails that are nearly impossible to detect manually.

2. RANSOMWARE-AS-A-SERVICE — Criminal groups sell ransomware kits to non-technical attackers, dramatically increasing attack frequency.

3. SUPPLY CHAIN ATTACKS — Attackers compromise software suppliers to infect thousands of organizations through trusted updates.

4. ZERO-DAY EXPLOITS — Vulnerabilities unknown to vendors are discovered and exploited before patches exist.

5. INSIDER THREATS — Malicious or negligent employees remain one of the most dangerous threat vectors.

6. CLOUD MISCONFIGURATIONS — Improperly configured cloud storage continues to expose sensitive data.

7. IOT VULNERABILITIES — Billions of poorly secured IoT devices create massive attack surfaces.

8. DEEPFAKE SOCIAL ENGINEERING — AI-generated audio and video used to impersonate executives.

9. API ATTACKS — Insecure APIs expose backend systems and data directly to attackers.

10. CREDENTIAL STUFFING — Automated attacks using breached credentials to access multiple services.""",
        "tags": ["Threats", "2026", "Cybersecurity"]
    },
    {
        "id": 3,
        "title": "How to Implement ISO 27001 Clause 7 — Support",
        "category": "ISO 27001",
        "date": "2026-04-15",
        "author": "ISMS Platform",
        "summary": "Clause 7 of ISO 27001 covers the support elements of your ISMS including competence, awareness, communication and documentation.",
        "content": """ISO 27001 Clause 7 is about ensuring your organization has the right resources and support structures for information security.

CLAUSE 7.1 — RESOURCES
Organizations must determine and provide the resources needed for the ISMS. This includes budget, people, technology and time.

CLAUSE 7.2 — COMPETENCE
Everyone performing security-related work must be competent. This means:
- Determining necessary competencies
- Providing training where needed
- Evaluating training effectiveness
- Maintaining records of training completed

Our platform automates this with the Training Tracker which assigns training, tracks completion and maintains evidence automatically.

CLAUSE 7.3 — AWARENESS
All employees must be aware of:
- The information security policy
- Their contribution to ISMS effectiveness
- The implications of not conforming

CLAUSE 7.4 — COMMUNICATION
Determine what to communicate, when, to whom and how regarding information security.

CLAUSE 7.5 — DOCUMENTED INFORMATION
Maintain required documentation including policies, procedures and records. Our Policy Manager automates document storage and version tracking.""",
        "tags": ["ISO 27001", "Clause 7", "Training", "Documentation"]
    },
    {
        "id": 4,
        "title": "Network Security Scanning with nmap",
        "category": "Security Tools",
        "date": "2026-04-20",
        "author": "ISMS Platform",
        "summary": "nmap is the industry standard network scanner used by security professionals worldwide. Learn how our platform integrates it for automated monitoring.",
        "content": """nmap (Network Mapper) is the most widely used network security scanner in the world. It is used by security teams, penetration testers and system administrators to discover hosts and services on a network.

HOW OUR PLATFORM USES NMAP

Our ISMS platform integrates nmap directly into the security dashboard. Every scan result is automatically:
- Displayed in the Security Scan interface
- Logged in the audit trail with timestamp and user
- Analyzed for dangerous open ports
- Converted into risk records if threats are found

SCAN TYPES AVAILABLE

Basic Scan — Scans the top 100 most common ports quickly. Good for daily monitoring.

Port Scan — Comprehensive scan of ports 1-1000. Takes longer but more thorough.

OS Detection — Identifies the operating system running on target hosts.

Vulnerability Scan — Uses nmap scripts to check for known CVEs and misconfigurations.

DANGEROUS PORTS TO WATCH

Port 21 (FTP) — Unencrypted file transfer
Port 23 (Telnet) — Unencrypted remote access  
Port 445 (SMB) — Common ransomware target
Port 3389 (RDP) — Brute force target
Port 3306 (MySQL) — Database exposure""",
        "tags": ["nmap", "Network Security", "Scanning", "Kali Linux"]
    },
    {
        "id": 5,
        "title": "What is a Zero-Day Vulnerability?",
        "category": "Threat Intelligence",
        "date": "2026-04-25",
        "author": "ISMS Platform",
        "summary": "Zero-day vulnerabilities are among the most dangerous threats in cybersecurity. Understand what they are and how our CVE watcher helps you stay informed.",
        "content": """A zero-day vulnerability is a security flaw in software that is unknown to the vendor and has no available patch. The term comes from the fact that developers have had zero days to fix it.

WHY ZERO-DAYS ARE DANGEROUS

When a vulnerability is discovered and kept secret by attackers, they can exploit it freely because:
- No patch exists yet
- Security tools cannot detect it
- Organizations have no way to defend against it

THE CVE SYSTEM

Every publicly known vulnerability is assigned a CVE (Common Vulnerabilities and Exposures) number by MITRE Corporation. The US government maintains the National Vulnerability Database (NVD) which scores each CVE on severity.

Scores range from 0-10:
- 9.0-10.0: CRITICAL
- 7.0-8.9: HIGH
- 4.0-6.9: MEDIUM
- 0.1-3.9: LOW

HOW OUR PLATFORM HELPS

Our CVE Watcher connects to the NVD API every 6 hours and automatically pulls the latest critical vulnerabilities. When a new zero-day is published anywhere in the world, our system creates a risk record automatically within 6 hours — giving your security team immediate awareness without any manual monitoring.""",
        "tags": ["Zero-Day", "CVE", "NVD", "Vulnerability"]
    }
]

@app.route("/blog")
@login_required
def blog():
    search   = request.args.get("q", "")
    category = request.args.get("category", "all")
    query    = BlogPost.query
    if search:
        query = query.filter(
            BlogPost.title.contains(search) |
            BlogPost.summary.contains(search)
        )
    if category != "all":
        query = query.filter_by(category=category)
    posts        = query.order_by(BlogPost.created_at.desc()).all()
    categories   = [r[0] for r in db.session.query(BlogPost.category).distinct().all()]
    total_posts  = BlogPost.query.count()
    auto_posts   = BlogPost.query.filter_by(is_auto=True).count()
    manual_posts = BlogPost.query.filter_by(is_auto=False).count()
    return render_template("blog.html",
                           posts=posts,
                           categories=categories,
                           selected=category,
                           search=search,
                           total_posts=total_posts,
                           auto_posts=auto_posts,
                           manual_posts=manual_posts)

@app.route("/blog/fetch")
@login_required
@role_required("admin")
def blog_fetch():
    count = fetch_security_news(app, db, BlogPost)
    flash(f"Fetched {count} new articles from cybersecurity feeds.", "success")
    return redirect(url_for("blog"))

@app.route("/blog/new", methods=["GET", "POST"])
@login_required
@role_required("admin")
def blog_new():
    if request.method == "POST":
        post = BlogPost(
            title=request.form["title"],
            slug=make_slug(request.form["title"]),
            category=request.form["category"],
            summary=request.form.get("summary", ""),
            content=request.form["content"],
            author=current_user.username,
            source_url=request.form.get("source_url", ""),
            tags=request.form.get("tags", ""),
            is_auto=False
        )
        db.session.add(post)
        db.session.commit()
        log_action(db, AuditLog, current_user.username,
                   f"Published blog post: {post.title}", request.remote_addr)
        flash("Post published successfully.", "success")
        return redirect(url_for("blog"))
    return render_template("blog_new.html")

@app.route("/blog/<int:post_id>")
@login_required
def blog_post(post_id):
    post = BlogPost.query.get_or_404(post_id)
    post.views += 1
    db.session.commit()
    comments = BlogComment.query.filter_by(post_id=post_id).order_by(BlogComment.created_at.desc()).all()
    return render_template("blog_post.html", post=post, comments=comments)

@app.route("/blog/<int:post_id>/comment", methods=["POST"])
@login_required
def blog_comment(post_id):
    comment = BlogComment(
        post_id=post_id,
        author=request.form.get("author", current_user.username),
        content=request.form["content"]
    )
    db.session.add(comment)
    db.session.commit()
    flash("Comment posted.", "success")
    return redirect(url_for("blog_post", post_id=post_id))



# ── IP Management ────────────────────────────────────
from models import BlockedIP

@app.route("/security/block/<ip>")
@login_required
@role_required("admin")
def block_ip_manual(ip):
    existing = BlockedIP.query.filter_by(ip=ip).first()
    if not existing:
        b = BlockedIP(ip=ip, reason="Manually blocked by admin",
                      blocked_by=current_user.username)
        db.session.add(b)
        db.session.commit()
        # Actually block with iptables
        try:
            subprocess.run(
                ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, timeout=5
            )
        except:
            pass
        log_action(db, AuditLog, current_user.username,
                   f"Manually blocked IP: {ip}", request.remote_addr)
        flash(f"IP {ip} has been blocked.", "success")
    return redirect(url_for("security_center"))

@app.route("/security/unblock/<ip>")
@login_required
@role_required("admin")
def unblock_ip_manual(ip):
    b = BlockedIP.query.filter_by(ip=ip).first()
    if b:
        db.session.delete(b)
        db.session.commit()
        try:
            subprocess.run(
                ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, timeout=5
            )
        except:
            pass
        log_action(db, AuditLog, current_user.username,
                   f"Unblocked IP: {ip}", request.remote_addr)
        flash(f"IP {ip} has been unblocked.", "success")
    return redirect(url_for("security_center"))



@app.route("/compliance")
@login_required
def compliance():
    models_dict = {
        "User": User, "Risk": Risk, "Training": Training,
        "Policy": Policy, "AuditLog": AuditLog,
        "IncidentTicket": IncidentTicket,
        "CorrectiveAction": CorrectiveAction,
        "SoAControl": SoAControl
    }
    from compliance_engine import (calculate_compliance, calculate_kpis,
                                   explain_compliance, get_compliance_history,
                                   time_to_compliance)
    compliance_data = calculate_compliance(app, db, models_dict)
    kpi_data        = calculate_kpis(app, db, models_dict)
    explanation     = explain_compliance(compliance_data)
    history         = get_compliance_history(app, db)
    ttc             = time_to_compliance(app, db, target=80)
    return render_template("compliance.html",
                           compliance=compliance_data,
                           kpis=kpi_data,
                           explanation=explanation,
                           history=history,
                           ttc=ttc)

@app.route("/whatif")
@login_required
def whatif():
    from compliance_engine import whatif_simulator, calculate_compliance
    models_dict = {
        "User": User, "Risk": Risk, "Training": Training,
        "Policy": Policy, "AuditLog": AuditLog,
        "IncidentTicket": IncidentTicket,
        "CorrectiveAction": CorrectiveAction,
        "SoAControl": SoAControl
    }
    fix_risks    = int(request.args.get("fix_risks", 0))
    fix_training = int(request.args.get("fix_training", 0))
    add_policies = int(request.args.get("add_policies", 0))
    run_scans    = int(request.args.get("run_scans", 0))
    current_data = calculate_compliance(app, db, models_dict)
    simulation   = whatif_simulator(app, db, models_dict,
                                    fix_risks, fix_training,
                                    add_policies, run_scans)
    return render_template("whatif.html",
                           current=current_data["overall"],
                           simulation=simulation)


@app.route("/goalplanner", methods=["GET", "POST"])
@login_required
def goal_planner():
    from compliance_engine import smart_goal_planner
    models_dict = {
        "User": User, "Risk": Risk, "Training": Training,
        "Policy": Policy, "AuditLog": AuditLog,
        "IncidentTicket": IncidentTicket,
        "CorrectiveAction": CorrectiveAction,
        "SoAControl": SoAControl
    }
    target = int(request.args.get("target", 80))
    plan   = smart_goal_planner(app, db, models_dict, target)
    return render_template("goalplanner.html", plan=plan, target=target)


@app.route("/auditreport")
@login_required
@role_required("admin", "auditor")
def audit_report():
    from report_generator import generate_audit_report
    from flask import send_file
    models_dict = {
        "User": User, "Risk": Risk, "Training": Training,
        "Policy": Policy, "AuditLog": AuditLog,
        "IncidentTicket": IncidentTicket,
        "CorrectiveAction": CorrectiveAction,
        "SoAControl": SoAControl
    }
    buffer = generate_audit_report(app, db, models_dict)
    filename = f"faseel-isms-audit-report-{datetime.datetime.utcnow().strftime('%Y%m%d-%H%M')}.pdf"
    log_action(db, AuditLog, current_user.username,
               "Downloaded ISO 27001 audit report PDF", request.remote_addr)
    return send_file(buffer, as_attachment=True,
                     download_name=filename,
                     mimetype="application/pdf")


@app.route("/integrity")
@login_required
def integrity():
    from compliance_engine import check_data_integrity
    models_dict = {
        "User": User, "Risk": Risk, "Training": Training,
        "Policy": Policy, "AuditLog": AuditLog,
        "IncidentTicket": IncidentTicket,
        "CorrectiveAction": CorrectiveAction,
        "SoAControl": SoAControl
    }
    result = check_data_integrity(app, db, models_dict)
    return render_template("integrity.html", result=result)


@app.route("/businessimpact")
@login_required
def business_impact():
    from compliance_engine import business_impact_mode
    models_dict = {
        "User": User, "Risk": Risk, "Training": Training,
        "Policy": Policy, "AuditLog": AuditLog,
        "IncidentTicket": IncidentTicket,
        "CorrectiveAction": CorrectiveAction,
        "SoAControl": SoAControl
    }
    impact = business_impact_mode(app, db, models_dict)
    return render_template("businessimpact.html", impact=impact)


@app.route("/drilldown/<clause>")
@login_required
def drilldown(clause):
    data = {}
    if clause == "clause6":
        data["title"]    = "Clause 6 — Risk Management"
        data["critical"] = Risk.query.filter_by(level="CRITICAL").all()
        data["high"]     = Risk.query.filter_by(level="HIGH").all()
        data["medium"]   = Risk.query.filter_by(level="MEDIUM").all()
        data["low"]      = Risk.query.filter_by(level="LOW").all()
        data["auto"]     = Risk.query.filter(
            Risk.created_by.in_(["AUTO-SYSTEM","AUTO-DETECTOR",
                                  "AUTO-SCANNER","CVE-WATCHER"])
        ).order_by(Risk.created_at.desc()).all()
    elif clause == "clause7":
        data["title"]     = "Clause 7 — Support"
        data["training"]  = Training.query.order_by(Training.id.desc()).all()
        data["policies"]  = Policy.query.order_by(Policy.uploaded_at.desc()).all()
        data["completed"] = Training.query.filter_by(status="Completed").count()
        data["pending"]   = Training.query.filter_by(status="Pending").count()
    elif clause == "clause8":
        data["title"]     = "Clause 8 — Operations"
        data["incidents"] = IncidentTicket.query.order_by(
            IncidentTicket.detected_at.desc()
        ).all()
        data["scans"] = AuditLog.query.filter(
            AuditLog.action.contains("scan")
        ).order_by(AuditLog.timestamp.desc()).limit(20).all()
    elif clause == "clause9":
        data["title"] = "Clause 9 — Performance Evaluation"
        data["logs"]  = AuditLog.query.order_by(
            AuditLog.timestamp.desc()
        ).limit(30).all()
        data["auto_actions"] = AuditLog.query.filter(
            AuditLog.user.in_(["AUTO-SYSTEM","AUTO-DETECTOR",
                                "AUTO-SCANNER","CVE-WATCHER"])
        ).order_by(AuditLog.timestamp.desc()).limit(20).all()
    elif clause == "clause10":
        data["title"]   = "Clause 10 — Improvement"
        data["actions"] = CorrectiveAction.query.order_by(
            CorrectiveAction.created_at.desc()
        ).all()
    return render_template("drilldown.html", clause=clause, data=data)


@app.route("/trends")
@login_required
def trends():
    from compliance_engine import get_compliance_history, calculate_compliance
    import json
    models_dict = {
        "User": User, "Risk": Risk, "Training": Training,
        "Policy": Policy, "AuditLog": AuditLog,
        "IncidentTicket": IncidentTicket,
        "CorrectiveAction": CorrectiveAction,
        "SoAControl": SoAControl
    }
    # Calculate current to add to history
    calculate_compliance(app, db, models_dict)
    history = get_compliance_history(app, db)
    return render_template("trends.html",
                           history=json.dumps(history),
                           history_raw=history)


@app.route("/soa", methods=["GET", "POST"])
@login_required
def soa():
    if request.method == "POST":
        control_id    = request.form.get("control_id")
        applicable    = request.form.get("applicable") == "true"
        implemented   = request.form.get("implemented") == "true"
        justification = request.form.get("justification", "")
        evidence      = request.form.get("evidence", "")
        control = SoAControl.query.filter_by(control_id=control_id).first()
        if control:
            control.applicable    = applicable
            control.implemented   = implemented
            control.justification = justification
            control.evidence      = evidence
            control.updated_at    = datetime.datetime.utcnow()
            db.session.commit()
            log_action(db, AuditLog, current_user.username,
                       f"Updated SoA control {control_id}: implemented={implemented}",
                       request.remote_addr)
            flash(f"Control {control_id} updated.", "success")
        return redirect(url_for("soa"))

    theme_filter = request.args.get("theme", "all")
    status_filter = request.args.get("status", "all")

    query = SoAControl.query
    if theme_filter != "all":
        query = query.filter_by(theme=theme_filter)
    if status_filter == "implemented":
        query = query.filter_by(implemented=True, applicable=True)
    elif status_filter == "gap":
        query = query.filter_by(implemented=False, applicable=True)
    elif status_filter == "na":
        query = query.filter_by(applicable=False)

    controls = query.order_by(SoAControl.control_id).all()

    total       = SoAControl.query.count()
    applicable  = SoAControl.query.filter_by(applicable=True).count()
    implemented = SoAControl.query.filter_by(applicable=True, implemented=True).count()
    gaps        = applicable - implemented
    coverage    = round((implemented / applicable * 100), 1) if applicable > 0 else 0

    return render_template("soa.html",
                           controls=controls,
                           total=total,
                           applicable=applicable,
                           implemented=implemented,
                           gaps=gaps,
                           coverage=coverage,
                           theme_filter=theme_filter,
                           status_filter=status_filter)


# ── Asset Inventory ───────────────────────────────────
from models import Asset

@app.route("/assets", methods=["GET", "POST"])
@login_required
def assets():
    if request.method == "POST":
        asset = Asset(
            name=request.form["name"],
            asset_type=request.form["asset_type"],
            description=request.form.get("description", ""),
            owner=request.form.get("owner", ""),
            location=request.form.get("location", ""),
            classification=request.form.get("classification", "Internal"),
            criticality=request.form.get("criticality", "Medium"),
            ip_address=request.form.get("ip_address", ""),
            status="Active"
        )
        db.session.add(asset)
        db.session.commit()
        log_action(db, AuditLog, current_user.username,
                   f"Asset registered: {asset.name} ({asset.asset_type})",
                   request.remote_addr)
        flash(f"Asset registered: {asset.name}", "success")
        return redirect(url_for("assets"))

    type_filter = request.args.get("type", "all")
    crit_filter = request.args.get("criticality", "all")

    query = Asset.query
    if type_filter != "all":
        query = query.filter_by(asset_type=type_filter)
    if crit_filter != "all":
        query = query.filter_by(criticality=crit_filter)

    all_assets = query.order_by(Asset.criticality.desc()).all()

    total      = Asset.query.count()
    critical   = Asset.query.filter_by(criticality="Critical").count()
    high       = Asset.query.filter_by(criticality="High").count()
    active     = Asset.query.filter_by(status="Active").count()

    return render_template("assets.html",
                           assets=all_assets,
                           total=total,
                           critical=critical,
                           high=high,
                           active=active,
                           type_filter=type_filter,
                           crit_filter=crit_filter)

@app.route("/assets/retire/<int:asset_id>")
@login_required
@role_required("admin")
def retire_asset(asset_id):
    asset = Asset.query.get_or_404(asset_id)
    asset.status = "Retired"
    db.session.commit()
    log_action(db, AuditLog, current_user.username,
               f"Asset retired: {asset.name}", request.remote_addr)
    flash(f"Asset {asset.name} marked as retired.", "success")
    return redirect(url_for("assets"))


# ── Supplier Risk Tracker ─────────────────────────────
from models import Supplier

@app.route("/suppliers", methods=["GET", "POST"])
@login_required
def suppliers():
    if request.method == "POST":
        # Calculate risk score automatically
        risk_score = 0
        if request.form.get("data_access") == "on":
            risk_score += 30
        if request.form.get("iso_certified") != "on":
            risk_score += 20
        if request.form.get("nda_signed") != "on":
            risk_score += 25
        service_type = request.form.get("service_type", "")
        if service_type in ["Cloud", "IT", "Security"]:
            risk_score += 25

        if risk_score >= 60:
            risk_level = "HIGH"
        elif risk_score >= 35:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        contract_expiry = None
        expiry_str = request.form.get("contract_expiry", "")
        if expiry_str:
            try:
                contract_expiry = datetime.datetime.strptime(expiry_str, "%Y-%m-%d")
            except:
                pass

        supplier = Supplier(
            name=request.form["name"],
            service_type=service_type,
            contact_name=request.form.get("contact_name", ""),
            contact_email=request.form.get("contact_email", ""),
            risk_score=risk_score,
            risk_level=risk_level,
            iso_certified=request.form.get("iso_certified") == "on",
            nda_signed=request.form.get("nda_signed") == "on",
            data_access=request.form.get("data_access") == "on",
            contract_expiry=contract_expiry,
            last_assessed=datetime.datetime.utcnow(),
            notes=request.form.get("notes", ""),
            status="Active"
        )
        db.session.add(supplier)

        # Auto-create risk if supplier is HIGH
        if risk_level == "HIGH":
            r = Risk(
                name=f"AUTO: High-risk supplier — {request.form['name']}",
                description=f"Supplier {request.form['name']} has been assessed as HIGH risk (score: {risk_score}/100). Review contract and security controls immediately.",
                likelihood=4, impact=4,
                score=16, level="HIGH",
                owner="Procurement Team",
                created_by="SUPPLIER-CHECKER"
            )
            db.session.add(r)

        db.session.commit()
        log_action(db, AuditLog, current_user.username,
                   f"Supplier registered: {supplier.name} — risk: {risk_level}",
                   request.remote_addr)
        flash(f"Supplier added — Risk Level: {risk_level}", "success")
        return redirect(url_for("suppliers"))

    all_suppliers = Supplier.query.order_by(Supplier.risk_score.desc()).all()
    total    = Supplier.query.count()
    high     = Supplier.query.filter_by(risk_level="HIGH").count()
    medium   = Supplier.query.filter_by(risk_level="MEDIUM").count()
    low      = Supplier.query.filter_by(risk_level="LOW").count()

    now = datetime.datetime.utcnow()
    return render_template("suppliers.html", now=now,
                           suppliers=all_suppliers,
                           total=total, high=high,
                           medium=medium, low=low)


@app.route("/gapanalysis")
@login_required
def gap_analysis():
    from compliance_engine import generate_gap_analysis
    models_dict = {
        "User": User, "Risk": Risk, "Training": Training,
        "Policy": Policy, "AuditLog": AuditLog,
        "IncidentTicket": IncidentTicket,
        "CorrectiveAction": CorrectiveAction,
        "SoAControl": SoAControl
    }
    result = generate_gap_analysis(app, db, models_dict)
    return render_template("gapanalysis.html", result=result)


@app.route("/pdca")
@login_required
def pdca():
    from compliance_engine import calculate_compliance
    models_dict = {
        "User": User, "Risk": Risk, "Training": Training,
        "Policy": Policy, "AuditLog": AuditLog,
        "IncidentTicket": IncidentTicket,
        "CorrectiveAction": CorrectiveAction,
        "SoAControl": SoAControl
    }
    compliance_data = calculate_compliance(app, db, models_dict)

    # PLAN phase data
    plan_items = [
        {"task": "Define ISMS scope document",        "done": Policy.query.count() > 0,        "url": "/policies",   "clause": "4.3"},
        {"task": "Complete risk assessment",           "done": Risk.query.count() >= 5,          "url": "/risk",       "clause": "6.1.2"},
        {"task": "Create risk treatment plan",         "done": Risk.query.filter_by(level="CRITICAL").count() == 0, "url": "/risk", "clause": "6.1.3"},
        {"task": "Define security objectives",         "done": Policy.query.count() >= 3,        "url": "/policies",   "clause": "6.2"},
        {"task": "Complete Statement of Applicability","done": SoAControl.query.filter_by(implemented=True).count() > 10, "url": "/soa", "clause": "6.1.3"},
    ]

    # DO phase data
    do_items = [
        {"task": "Implement security controls",        "done": SoAControl.query.filter_by(implemented=True).count() > 5, "url": "/soa",      "clause": "8.1"},
        {"task": "Run security awareness training",    "done": Training.query.filter_by(status="Completed").count() > 0, "url": "/training", "clause": "7.2"},
        {"task": "Upload policy documents",            "done": Policy.query.count() >= 3,        "url": "/policies",   "clause": "7.5"},
        {"task": "Register information assets",        "done": True,                             "url": "/assets",     "clause": "5.9"},
        {"task": "Set up incident management",         "done": IncidentTicket.query.count() > 0, "url": "/incidents",  "clause": "5.24"},
    ]

    # CHECK phase data
    check_items = [
        {"task": "Run vulnerability scans",            "done": AuditLog.query.filter(AuditLog.action.contains("scan")).count() > 0, "url": "/scan",      "clause": "9.1"},
        {"task": "Review audit logs",                  "done": AuditLog.query.count() > 20,      "url": "/auditlog",   "clause": "9.1"},
        {"task": "Monitor compliance score",           "done": True,                             "url": "/compliance", "clause": "9.1"},
        {"task": "Conduct gap analysis",               "done": True,                             "url": "/gapanalysis","clause": "9.2"},
        {"task": "Check KPI metrics",                  "done": True,                             "url": "/compliance", "clause": "9.1"},
    ]

    # ACT phase data
    act_items = [
        {"task": "Create corrective actions for gaps", "done": CorrectiveAction.query.count() > 0, "url": "/actions",    "clause": "10.1"},
        {"task": "Close resolved corrective actions",  "done": CorrectiveAction.query.filter_by(status="Closed").count() > 0, "url": "/actions", "clause": "10.1"},
        {"task": "Update risk register",               "done": Risk.query.count() > 0,           "url": "/risk",       "clause": "10.2"},
        {"task": "Review and update policies",         "done": Policy.query.count() > 0,         "url": "/policies",   "clause": "10.2"},
        {"task": "Improve compliance score",           "done": compliance_data["overall"] >= 60, "url": "/compliance", "clause": "10.2"},
    ]

    def phase_score(items):
        done = sum(1 for i in items if i["done"])
        return round(done / len(items) * 100)

    plan_score  = phase_score(plan_items)
    do_score    = phase_score(do_items)
    check_score = phase_score(check_items)
    act_score   = phase_score(act_items)
    overall     = round((plan_score + do_score + check_score + act_score) / 4)

    # Determine current phase
    if plan_score < 60:
        current_phase = "PLAN"
    elif do_score < 60:
        current_phase = "DO"
    elif check_score < 60:
        current_phase = "CHECK"
    else:
        current_phase = "ACT"

    return render_template("pdca.html",
                           plan_items=plan_items,
                           do_items=do_items,
                           check_items=check_items,
                           act_items=act_items,
                           plan_score=plan_score,
                           do_score=do_score,
                           check_score=check_score,
                           act_score=act_score,
                           overall=overall,
                           current_phase=current_phase,
                           compliance=compliance_data)


@app.route("/managementreview")
@login_required
@role_required("admin")
def management_review():
    from compliance_engine import calculate_compliance, calculate_kpis
    from flask import send_file
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    import io

    models_dict = {
        "User": User, "Risk": Risk, "Training": Training,
        "Policy": Policy, "AuditLog": AuditLog,
        "IncidentTicket": IncidentTicket,
        "CorrectiveAction": CorrectiveAction,
        "SoAControl": SoAControl
    }

    compliance_data = calculate_compliance(app, db, models_dict)
    kpi_data        = calculate_kpis(app, db, models_dict)

    BLUE      = colors.HexColor("#1F66D6")
    DARK      = colors.HexColor("#0f172a")
    GRAY      = colors.HexColor("#64748b")
    GREEN     = colors.HexColor("#16a34a")
    RED       = colors.HexColor("#dc2626")
    AMBER     = colors.HexColor("#d97706")
    WHITE     = colors.white
    LIGHTGRAY = colors.HexColor("#334155")
    CARD      = colors.HexColor("#1e293b")

    buffer = io.BytesIO()
    doc    = SimpleDocTemplate(buffer, pagesize=A4,
                               rightMargin=2.5*cm, leftMargin=2.5*cm,
                               topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    story  = []

    title_style = ParagraphStyle("T", parent=styles["Title"],
                                 fontSize=20, textColor=BLUE,
                                 spaceAfter=6, alignment=TA_CENTER)
    sub_style   = ParagraphStyle("S", parent=styles["Normal"],
                                 fontSize=11, textColor=GRAY,
                                 alignment=TA_CENTER, spaceAfter=4)
    h1_style    = ParagraphStyle("H1", parent=styles["Heading1"],
                                 fontSize=13, textColor=BLUE,
                                 spaceBefore=14, spaceAfter=8)
    normal      = ParagraphStyle("N", parent=styles["Normal"],
                                 fontSize=10, textColor=colors.HexColor("#334155"),
                                 spaceAfter=6, leading=16)
    bold_style  = ParagraphStyle("B", parent=styles["Normal"],
                                 fontSize=10, textColor=colors.HexColor("#1e293b"),
                                 fontName="Helvetica-Bold", spaceAfter=4)

    # Cover
    story.append(Spacer(1, 1*cm))
    story.append(Paragraph("FASEEL INFOSEC", title_style))
    story.append(Paragraph("ISO 27001 ISMS Management Review", sub_style))
    story.append(Paragraph(f"Review Date: {datetime.datetime.utcnow().strftime('%d %B %Y')}", sub_style))
    story.append(Paragraph("Clause 9.3 — Management Review", sub_style))
    story.append(Spacer(1, 0.5*cm))
    story.append(HRFlowable(width="100%", thickness=2, color=BLUE))
    story.append(Spacer(1, 0.5*cm))

    # 1. Purpose
    story.append(Paragraph("1. Purpose and Scope", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=LIGHTGRAY))
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph(
        "This Management Review has been conducted in accordance with ISO/IEC 27001:2022 Clause 9.3. "
        "The purpose is to ensure the continuing suitability, adequacy, and effectiveness of the "
        "Information Security Management System (ISMS). This review covers all ISMS controls, "
        "risk posture, KPI performance, and improvement actions.",
        normal))

    # 2. Compliance Score
    story.append(Paragraph("2. ISMS Compliance Status", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=LIGHTGRAY))
    story.append(Spacer(1, 0.3*cm))

    overall = compliance_data["overall"]
    status  = "GOOD" if overall >= 80 else ("MODERATE" if overall >= 60 else "REQUIRES IMPROVEMENT")
    story.append(Paragraph(f"Overall Compliance Score: {overall}% — {status}", bold_style))

    clause_data = [["ISO 27001 Clause", "Score", "Target", "Status"]]
    for key, clause in compliance_data["clauses"].items():
        s = clause["score"]
        t = clause["target"]
        st = "PASS" if s >= t else ("WARN" if s >= t*0.7 else "FAIL")
        clause_data.append([clause["name"], f"{s}%", f"{t}%", st])

    clause_table = Table(clause_data, colWidths=[9*cm, 2.5*cm, 2.5*cm, 2.5*cm])
    clause_table.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (-1,0), BLUE),
        ("TEXTCOLOR",   (0,0), (-1,0), WHITE),
        ("FONTNAME",    (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",    (0,0), (-1,-1), 9),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.HexColor("#f8fafc"), WHITE]),
        ("GRID",        (0,0), (-1,-1), 0.5, LIGHTGRAY),
        ("PADDING",     (0,0), (-1,-1), 8),
        ("ALIGN",       (1,0), (-1,-1), "CENTER"),
    ]))
    story.append(clause_table)
    story.append(Spacer(1, 0.5*cm))

    # 3. KPI Review
    story.append(Paragraph("3. KPI Performance Review", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=LIGHTGRAY))
    story.append(Spacer(1, 0.3*cm))

    kpi_data_table = [["KPI Metric", "Value", "Target", "Clause", "Result"]]
    for kpi in kpi_data["kpis"]:
        kpi_data_table.append([
            kpi["name"],
            f"{kpi['value']}{kpi['unit']}",
            f"{kpi['target']}{kpi['unit']}",
            kpi["clause"],
            kpi["status"]
        ])

    kpi_table = Table(kpi_data_table, colWidths=[5.5*cm, 2*cm, 2*cm, 3*cm, 2*cm])
    kpi_table.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (-1,0), BLUE),
        ("TEXTCOLOR",   (0,0), (-1,0), WHITE),
        ("FONTNAME",    (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",    (0,0), (-1,-1), 9),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.HexColor("#f8fafc"), WHITE]),
        ("GRID",        (0,0), (-1,-1), 0.5, LIGHTGRAY),
        ("PADDING",     (0,0), (-1,-1), 7),
        ("ALIGN",       (1,0), (-1,-1), "CENTER"),
    ]))
    story.append(kpi_table)
    story.append(Spacer(1, 0.5*cm))

    # 4. Risk Summary
    story.append(Paragraph("4. Risk Posture Summary", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=LIGHTGRAY))
    story.append(Spacer(1, 0.3*cm))

    total_r    = Risk.query.count()
    critical_r = Risk.query.filter_by(level="CRITICAL").count()
    high_r     = Risk.query.filter_by(level="HIGH").count()
    auto_r     = Risk.query.filter(Risk.created_by.in_(
        ["AUTO-SYSTEM","AUTO-DETECTOR","AUTO-SCANNER","CVE-WATCHER"]
    )).count()

    risk_summary = [
        ["Metric", "Value"],
        ["Total risks in register", str(total_r)],
        ["Critical risks", str(critical_r)],
        ["High risks", str(high_r)],
        ["Auto-detected risks", str(auto_r)],
        ["Training completion", f"{Training.query.filter_by(status='Completed').count()}/{Training.query.count()}"],
        ["Policies documented", str(Policy.query.count())],
        ["Audit log entries", str(AuditLog.query.count())],
    ]
    risk_table = Table(risk_summary, colWidths=[10*cm, 6*cm])
    risk_table.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (-1,0), BLUE),
        ("TEXTCOLOR",   (0,0), (-1,0), WHITE),
        ("FONTNAME",    (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",    (0,0), (-1,-1), 10),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.HexColor("#f8fafc"), WHITE]),
        ("GRID",        (0,0), (-1,-1), 0.5, LIGHTGRAY),
        ("PADDING",     (0,0), (-1,-1), 8),
    ]))
    story.append(risk_table)
    story.append(Spacer(1, 0.5*cm))

    # 5. Decisions and Actions
    story.append(Paragraph("5. Management Decisions and Actions", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=LIGHTGRAY))
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph(
        "The following decisions were made during this management review:", normal))

    decisions = [
        ["#", "Decision / Action", "Owner", "Target Date"],
        ["1", "Continue ISMS operation with quarterly reviews", "CISO", "Ongoing"],
        ["2", "Address all critical risks within 30 days", "IT Manager", "30 days"],
        ["3", "Increase policy documentation to minimum 5 documents", "Compliance", "60 days"],
        ["4", "Achieve 95% training completion rate", "HR Manager", "90 days"],
        ["5", "Complete Statement of Applicability", "CISO", "60 days"],
    ]
    dec_table = Table(decisions, colWidths=[1*cm, 9*cm, 3*cm, 3*cm])
    dec_table.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (-1,0), BLUE),
        ("TEXTCOLOR",   (0,0), (-1,0), WHITE),
        ("FONTNAME",    (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",    (0,0), (-1,-1), 9),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.HexColor("#f8fafc"), WHITE]),
        ("GRID",        (0,0), (-1,-1), 0.5, LIGHTGRAY),
        ("PADDING",     (0,0), (-1,-1), 7),
    ]))
    story.append(dec_table)
    story.append(Spacer(1, 0.5*cm))

    # 6. Conclusion
    story.append(Paragraph("6. Conclusion and Sign-Off", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=LIGHTGRAY))
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph(
        f"The ISMS Management Review has been completed on {datetime.datetime.utcnow().strftime('%d %B %Y')}. "
        f"The current compliance score of {overall}% reflects the organization's security posture. "
        "Management is committed to continual improvement of the ISMS in accordance with ISO/IEC 27001:2022.",
        normal))
    story.append(Spacer(1, 1*cm))

    sign_data = [
        ["Role", "Name", "Signature", "Date"],
        ["Chief Executive Officer", "", "_______________", datetime.datetime.utcnow().strftime("%d/%m/%Y")],
        ["CISO / ISMS Manager",    "", "_______________", datetime.datetime.utcnow().strftime("%d/%m/%Y")],
        ["Internal Auditor",       "", "_______________", datetime.datetime.utcnow().strftime("%d/%m/%Y")],
    ]
    sign_table = Table(sign_data, colWidths=[5*cm, 4*cm, 4*cm, 3*cm])
    sign_table.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (-1,0), BLUE),
        ("TEXTCOLOR",   (0,0), (-1,0), WHITE),
        ("FONTNAME",    (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",    (0,0), (-1,-1), 9),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.HexColor("#f8fafc"), WHITE]),
        ("GRID",        (0,0), (-1,-1), 0.5, LIGHTGRAY),
        ("PADDING",     (0,0), (-1,-1), 10),
        ("ROWHEIGHT",   (1,1), (-1,-1), 30),
    ]))
    story.append(sign_table)
    story.append(Spacer(1, 0.5*cm))
    story.append(HRFlowable(width="100%", thickness=1, color=BLUE))
    story.append(Paragraph(
        f"Generated by Faseel Infosec ISMS Platform — {datetime.datetime.utcnow().strftime('%d %B %Y')} — CONFIDENTIAL",
        ParagraphStyle("footer", parent=styles["Normal"], fontSize=8,
                       textColor=GRAY, alignment=TA_CENTER)
    ))

    doc.build(story)
    buffer.seek(0)

    filename = f"faseel-management-review-{datetime.datetime.utcnow().strftime('%Y%m%d')}.pdf"
    log_action(db, AuditLog, current_user.username,
               "Downloaded ISO 27001 Management Review PDF", request.remote_addr)
    return send_file(buffer, as_attachment=True,
                     download_name=filename,
                     mimetype="application/pdf")


@app.route("/incidents", methods=["GET", "POST"])
@login_required
def incidents():
    if request.method == "POST":
        inc = IncidentTicket(
            title=request.form["title"],
            description=request.form.get("description", ""),
            severity=request.form["severity"],
            assigned_to=request.form.get("assigned_to", ""),
            created_by=current_user.username,
            annex_controls=request.form.get("annex_controls", "")
        )
        db.session.add(inc)
        db.session.commit()
        log_action(db, AuditLog, current_user.username,
                   f"Incident raised: {inc.title} — {inc.severity}",
                   request.remote_addr)
        flash(f"Incident raised — ID: {inc.id}", "success")
    all_incidents = IncidentTicket.query.order_by(
        IncidentTicket.detected_at.desc()
    ).all()
    return render_template("incidents.html", incidents=all_incidents)

@app.route("/incidents/close/<int:inc_id>")
@login_required
@role_required("admin", "auditor")
def close_incident(inc_id):
    inc = IncidentTicket.query.get_or_404(inc_id)
    inc.status = "Closed"
    inc.resolved_at = datetime.datetime.utcnow()
    db.session.commit()
    log_action(db, AuditLog, current_user.username,
               f"Incident closed: {inc.title}", request.remote_addr)
    flash("Incident closed.", "success")
    return redirect(url_for("incidents"))

@app.route("/actions", methods=["GET", "POST"])
@login_required
def corrective_actions():
    if request.method == "POST":
        action = CorrectiveAction(
            title=request.form["title"],
            description=request.form.get("description", ""),
            raised_by=current_user.username,
            assigned_to=request.form.get("assigned_to", ""),
            due_date=request.form.get("due_date", ""),
            root_cause=request.form.get("root_cause", "")
        )
        db.session.add(action)
        db.session.commit()
        log_action(db, AuditLog, current_user.username,
                   f"Corrective action raised: {action.title}",
                   request.remote_addr)
        flash("Corrective action created.", "success")
    actions = CorrectiveAction.query.order_by(
        CorrectiveAction.created_at.desc()
    ).all()
    return render_template("actions.html", actions=actions)

@app.route("/actions/close/<int:action_id>")
@login_required
@role_required("admin")
def close_action(action_id):
    action = CorrectiveAction.query.get_or_404(action_id)
    action.status = "Closed"
    action.closed_at = datetime.datetime.utcnow()
    db.session.commit()
    log_action(db, AuditLog, current_user.username,
               f"Corrective action closed: {action.title}",
               request.remote_addr)
    flash("Action closed.", "success")
    return redirect(url_for("corrective_actions"))


@app.route("/policyexpiry")
@login_required
def policy_expiry():
    from datetime import datetime, timedelta
    now      = datetime.utcnow()
    policies = Policy.query.all()

    overdue  = []
    urgent   = []
    warning  = []
    notice   = []
    ok       = []

    for p in policies:
        if p.review_date:
            days_left = (p.review_date - now).days
            if days_left <= 0:
                overdue.append({"policy": p, "days": abs(days_left), "label": "OVERDUE"})
            elif days_left <= 30:
                urgent.append({"policy": p, "days": days_left, "label": "URGENT"})
            elif days_left <= 60:
                warning.append({"policy": p, "days": days_left, "label": "WARNING"})
            elif days_left <= 90:
                notice.append({"policy": p, "days": days_left, "label": "NOTICE"})
            else:
                ok.append({"policy": p, "days": days_left, "label": "OK"})
        else:
            overdue.append({"policy": p, "days": None, "label": "NO DATE SET"})

    return render_template("policyexpiry.html",
                           overdue=overdue,
                           urgent=urgent,
                           warning=warning,
                           notice=notice,
                           ok=ok,
                           total=len(policies))

@app.route("/policy/acknowledge/<int:policy_id>")
@login_required
def acknowledge_policy(policy_id):
    p = Policy.query.get_or_404(policy_id)
    p.acknowledged += 1
    db.session.commit()
    log_action(db, AuditLog, current_user.username,
               f"Acknowledged policy: {p.title}", request.remote_addr)
    flash(f"You have acknowledged: {p.title}", "success")
    return redirect(url_for("policy_expiry"))

@app.route("/policy/setreview/<int:policy_id>", methods=["POST"])
@login_required
@role_required("admin")
def set_review_date(policy_id):
    p = Policy.query.get_or_404(policy_id)
    date_str = request.form.get("review_date")
    if date_str:
        p.review_date = datetime.datetime.strptime(date_str, "%Y-%m-%d")
        db.session.commit()
        log_action(db, AuditLog, current_user.username,
                   f"Set review date for policy: {p.title} — {date_str}",
                   request.remote_addr)
        flash(f"Review date set for {p.title}", "success")
    return redirect(url_for("policy_expiry"))


@app.route("/accessreview")
@login_required
@role_required("admin")
def access_review():
    from datetime import datetime, timedelta
    now   = datetime.utcnow()
    users = User.query.all()

    active    = []
    inactive  = []
    flagged   = []

    for u in users:
        last_login = AuditLog.query.filter_by(
            user=u.username, action="Logged in"
        ).order_by(AuditLog.timestamp.desc()).first()

        days_since = None
        if last_login:
            days_since = (now - last_login.timestamp).days

        entry = {
            "user":       u,
            "last_login": last_login.timestamp if last_login else None,
            "days_since": days_since
        }

        if days_since is None:
            flagged.append({**entry, "reason": "Never logged in"})
        elif days_since > 90:
            flagged.append({**entry, "reason": f"No login for {days_since} days"})
        elif days_since > 30:
            inactive.append(entry)
        else:
            active.append(entry)

    log_action(db, AuditLog, current_user.username,
               "Conducted quarterly access review", request.remote_addr)

    return render_template("accessreview.html",
                           active=active,
                           inactive=inactive,
                           flagged=flagged,
                           review_date=now.strftime("%d %B %Y"))

@app.route("/accessreview/disable/<int:user_id>")
@login_required
@role_required("admin")
def disable_user(user_id):
    u = User.query.get_or_404(user_id)
    if u.username == "admin":
        flash("Cannot disable the admin account.", "danger")
        return redirect(url_for("access_review"))
    u.role = "disabled"
    db.session.commit()

    # AUTO-GENERATE OFFBOARDING CHECKLIST
    import json
    from models import OnboardingChecklist
    items = [
        "User account disabled immediately",
        "All system access revoked",
        "Email account disabled and forwarded to manager",
        "VPN access revoked",
        "Physical access card returned and deactivated",
        "Laptop/device returned and wiped",
        "Company data removed from personal devices",
        "Handover document completed",
        "Exit interview security briefing conducted",
        "Payroll and HR systems updated"
    ]
    items_data = [{"item": i, "done": False} for i in items]
    c = OnboardingChecklist(
        username=u.username,
        checklist_type="offboarding",
        created_by="SYSTEM",
        items=json.dumps(items_data)
    )
    db.session.add(c)
    db.session.commit()

    log_action(db, AuditLog, current_user.username,
               f"Disabled user account: {u.username} — offboarding checklist auto-generated",
               request.remote_addr)
    flash(f"Account disabled: {u.username} — offboarding checklist auto-generated.", "success")
    return redirect(url_for("access_review"))


ONBOARDING_ITEMS = [
    "NDA and confidentiality agreement signed",
    "Security awareness training assigned",
    "User account created with minimum required access only",
    "Email account created and 2FA enabled",
    "Company security policies provided and acknowledged",
    "Physical access card issued if required",
    "Laptop/device issued and encrypted",
    "VPN access configured if required",
    "Added to relevant communication channels only",
    "Line manager briefed on new starter access requirements"
]

OFFBOARDING_ITEMS = [
    "User account disabled immediately",
    "All system access revoked",
    "Email account disabled and forwarded to manager",
    "VPN access revoked",
    "Physical access card returned and deactivated",
    "Laptop/device returned and wiped",
    "Company data removed from personal devices",
    "Handover document completed",
    "Exit interview security briefing conducted",
    "Payroll and HR systems updated"
]

@app.route("/checklists")
@login_required
def checklists():
    from models import OnboardingChecklist
    all_lists = OnboardingChecklist.query.order_by(
        OnboardingChecklist.created_at.desc()
    ).all()
    return render_template("checklists.html", checklists=all_lists)

@app.route("/checklists/new/<checklist_type>/<username>")
@login_required
@role_required("admin")
def new_checklist(checklist_type, username):
    import json
    from models import OnboardingChecklist
    items = ONBOARDING_ITEMS if checklist_type == "onboarding" else OFFBOARDING_ITEMS
    items_data = [{"item": i, "done": False} for i in items]
    c = OnboardingChecklist(
        username=username,
        checklist_type=checklist_type,
        created_by=current_user.username,
        items=json.dumps(items_data)
    )
    db.session.add(c)
    db.session.commit()
    log_action(db, AuditLog, current_user.username,
               f"Created {checklist_type} checklist for {username}",
               request.remote_addr)
    flash(f"{checklist_type.title()} checklist created for {username}", "success")
    return redirect(url_for("checklist_detail", checklist_id=c.id))

@app.route("/checklists/<int:checklist_id>", methods=["GET", "POST"])
@login_required
def checklist_detail(checklist_id):
    import json
    from models import OnboardingChecklist
    c = OnboardingChecklist.query.get_or_404(checklist_id)
    items = json.loads(c.items) if c.items else []

    if request.method == "POST":
        checked = request.form.getlist("items")
        for item in items:
            item["done"] = item["item"] in checked
        c.items = json.dumps(items)
        c.notes = request.form.get("notes", "")
        c.completed = all(i["done"] for i in items)
        db.session.commit()
        log_action(db, AuditLog, current_user.username,
                   f"Updated {c.checklist_type} checklist for {c.username}",
                   request.remote_addr)
        flash("Checklist updated", "success")
        return redirect(url_for("checklist_detail", checklist_id=c.id))

    return render_template("checklist_detail.html", checklist=c, items=items)

@app.route("/checklists/create", methods=["GET", "POST"])
@login_required
@role_required("admin")
def create_checklist():
    if request.method == "POST":
        username = request.form.get("username")
        checklist_type = request.form.get("checklist_type")
        return redirect(url_for("new_checklist",
                                checklist_type=checklist_type,
                                username=username))
    users = User.query.all()
    return render_template("create_checklist.html", users=users)


@app.route("/admin/createuser", methods=["GET", "POST"])
@login_required
@role_required("admin")
def create_user():
    import json
    from models import OnboardingChecklist
    if request.method == "POST":
        username = request.form.get("username")
        email    = request.form.get("email")
        role     = request.form.get("role")
        password = request.form.get("password")

        if User.query.filter_by(username=username).first():
            flash("Username already exists.", "danger")
            return redirect(url_for("create_user"))

        u = User(username=username, email=email, role=role)
        u.set_password(password)
        db.session.add(u)
        db.session.commit()

        # AUTO-GENERATE ONBOARDING CHECKLIST
        items = [
            "NDA and confidentiality agreement signed",
            "Security awareness training assigned",
            "User account created with minimum required access only",
            "Email account created and 2FA enabled",
            "Company security policies provided and acknowledged",
            "Physical access card issued if required",
            "Laptop/device issued and encrypted",
            "VPN access configured if required",
            "Added to relevant communication channels only",
            "Line manager briefed on new starter access requirements"
        ]
        items_data = [{"item": i, "done": False} for i in items]
        c = OnboardingChecklist(
            username=username,
            checklist_type="onboarding",
            created_by="SYSTEM",
            items=json.dumps(items_data)
        )
        db.session.add(c)
        db.session.commit()

        log_action(db, AuditLog, current_user.username,
                   f"Created user: {username} ({role}) — onboarding checklist auto-generated",
                   request.remote_addr)
        flash(f"User {username} created and onboarding checklist auto-generated.", "success")
        return redirect(url_for("checklists"))

    return render_template("create_user.html")


@app.route("/evidence", methods=["GET", "POST"])
@login_required
def evidence():
    from models import ControlEvidence
    import json

    CONTROLS = [
        ("5.1", "Policies for information security"),
        ("5.2", "Information security roles and responsibilities"),
        ("5.3", "Segregation of duties"),
        ("5.4", "Management responsibilities"),
        ("5.5", "Contact with authorities"),
        ("5.6", "Contact with special interest groups"),
        ("5.7", "Threat intelligence"),
        ("5.8", "Information security in project management"),
        ("5.9", "Inventory of information and other associated assets"),
        ("5.10", "Acceptable use of information and other associated assets"),
        ("5.11", "Return of assets"),
        ("5.12", "Classification of information"),
        ("5.13", "Labelling of information"),
        ("5.14", "Information transfer"),
        ("5.15", "Access control"),
        ("5.16", "Identity management"),
        ("5.17", "Authentication information"),
        ("5.18", "Access rights"),
        ("5.19", "Information security in supplier relationships"),
        ("5.20", "Addressing information security within supplier agreements"),
        ("5.21", "Managing information security in the ICT supply chain"),
        ("5.22", "Monitoring, review and change management of supplier services"),
        ("5.23", "Information security for use of cloud services"),
        ("5.24", "Information security incident management planning and preparation"),
        ("5.25", "Assessment and decision on information security events"),
        ("5.26", "Response to information security incidents"),
        ("5.27", "Learning from information security incidents"),
        ("5.28", "Collection of evidence"),
        ("5.29", "Information security during disruption"),
        ("5.30", "ICT readiness for business continuity"),
        ("5.31", "Legal, statutory, regulatory and contractual requirements"),
        ("5.32", "Intellectual property rights"),
        ("5.33", "Protection of records"),
        ("5.34", "Privacy and protection of PII"),
        ("5.35", "Independent review of information security"),
        ("5.36", "Compliance with policies, rules and standards for information security"),
        ("5.37", "Documented operating procedures"),
        ("6.1", "Screening"),
        ("6.2", "Terms and conditions of employment"),
        ("6.3", "Information security awareness, education and training"),
        ("6.4", "Disciplinary process"),
        ("6.5", "Responsibilities after termination or change of employment"),
        ("6.6", "Confidentiality or non-disclosure agreements"),
        ("6.7", "Remote working"),
        ("6.8", "Information security event reporting"),
        ("7.1", "Physical security perimeters"),
        ("7.2", "Physical entry"),
        ("7.3", "Securing offices, rooms and facilities"),
        ("7.4", "Physical security monitoring"),
        ("7.5", "Protecting against physical and environmental threats"),
        ("7.6", "Working in secure areas"),
        ("7.7", "Clear desk and clear screen"),
        ("7.8", "Equipment siting and protection"),
        ("7.9", "Security of assets off-premises"),
        ("7.10", "Storage media"),
        ("7.11", "Supporting utilities"),
        ("7.12", "Cabling security"),
        ("7.13", "Equipment maintenance"),
        ("7.14", "Secure disposal or re-use of equipment"),
        ("8.1", "User endpoint devices"),
        ("8.2", "Privileged access rights"),
        ("8.3", "Information access restriction"),
        ("8.4", "Access to source code"),
        ("8.5", "Secure authentication"),
        ("8.6", "Capacity management"),
        ("8.7", "Protection against malware"),
        ("8.8", "Management of technical vulnerabilities"),
        ("8.9", "Configuration management"),
        ("8.10", "Information deletion"),
        ("8.11", "Data masking"),
        ("8.12", "Data leakage prevention"),
        ("8.13", "Information backup"),
        ("8.14", "Redundancy of information processing facilities"),
        ("8.15", "Logging"),
        ("8.16", "Monitoring activities"),
        ("8.17", "Clock synchronization"),
        ("8.18", "Use of privileged utility programs"),
        ("8.19", "Installation of software on operational systems"),
        ("8.20", "Networks security"),
        ("8.21", "Security of network services"),
        ("8.22", "Segregation of networks"),
        ("8.23", "Web filtering"),
        ("8.24", "Use of cryptography"),
        ("8.25", "Secure development life cycle"),
        ("8.26", "Application security requirements"),
        ("8.27", "Secure system architecture and engineering principles"),
        ("8.28", "Secure coding"),
        ("8.29", "Security testing in development and acceptance"),
        ("8.30", "Outsourced development"),
        ("8.31", "Separation of development, test and production environments"),
        ("8.32", "Change management"),
        ("8.33", "Test information"),
        ("8.34", "Protection of information systems during audit testing"),
    ]

    if request.method == "POST":
        control_id   = request.form.get("control_id")
        control_name = dict(CONTROLS).get(control_id, "")
        description  = request.form.get("description")
        evidence_type = request.form.get("evidence_type")
        filename     = None

        if "file" in request.files:
            file = request.files["file"]
            if file and file.filename:
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

        from models import ControlEvidence
        e = ControlEvidence(
            control_id=control_id,
            control_name=control_name,
            filename=filename,
            description=description,
            uploaded_by=current_user.username,
            evidence_type=evidence_type
        )
        db.session.add(e)
        db.session.commit()
        log_action(db, AuditLog, current_user.username,
                   f"Evidence uploaded for control {control_id}: {control_name}",
                   request.remote_addr)
        flash(f"Evidence uploaded for control {control_id}", "success")
        return redirect(url_for("evidence"))

    from models import ControlEvidence
    all_evidence = ControlEvidence.query.order_by(
        ControlEvidence.uploaded_at.desc()
    ).all()

    evidence_map = {}
    for e in all_evidence:
        if e.control_id not in evidence_map:
            evidence_map[e.control_id] = []
        evidence_map[e.control_id].append(e)

    covered   = len(evidence_map)
    total     = len(CONTROLS)
    uncovered = total - covered

    return render_template("evidence.html",
                           controls=CONTROLS,
                           evidence_map=evidence_map,
                           all_evidence=all_evidence,
                           covered=covered,
                           total=total,
                           uncovered=uncovered)


@app.route("/internalaudit", methods=["GET", "POST"])
@login_required
def internal_audit():
    from models import AuditPlan, AuditFinding

    CLAUSES = [
        "4.1 - Understanding the organization",
        "4.2 - Needs and expectations of interested parties",
        "4.3 - Scope of the ISMS",
        "5.1 - Leadership and commitment",
        "5.2 - Information security policy",
        "5.3 - Roles and responsibilities",
        "6.1 - Actions to address risks and opportunities",
        "6.2 - Information security objectives",
        "7.1 - Resources",
        "7.2 - Competence",
        "7.3 - Awareness",
        "7.4 - Communication",
        "7.5 - Documented information",
        "8.1 - Operational planning and control",
        "8.2 - Information security risk assessment",
        "8.3 - Information security risk treatment",
        "9.1 - Monitoring measurement analysis and evaluation",
        "9.2 - Internal audit",
        "9.3 - Management review",
        "10.1 - Continual improvement",
        "10.2 - Nonconformity and corrective action",
    ]

    if request.method == "POST":
        title      = request.form.get("title")
        audit_date = request.form.get("audit_date")
        auditor    = request.form.get("auditor")
        scope      = request.form.get("scope")

        plan = AuditPlan(
            title=title,
            audit_date=datetime.datetime.strptime(audit_date, "%Y-%m-%d") if audit_date else None,
            auditor=auditor,
            scope=scope,
            created_by=current_user.username,
            status="planned"
        )
        db.session.add(plan)
        db.session.commit()
        log_action(db, AuditLog, current_user.username,
                   f"Created internal audit plan: {title}",
                   request.remote_addr)
        flash(f"Audit plan created: {title}", "success")
        return redirect(url_for("audit_detail", plan_id=plan.id))

    plans = AuditPlan.query.order_by(AuditPlan.created_at.desc()).all()
    return render_template("internalaudit.html", plans=plans)


@app.route("/internalaudit/<int:plan_id>", methods=["GET", "POST"])
@login_required
def audit_detail(plan_id):
    from models import AuditPlan, AuditFinding

    CLAUSES = [
        "4.1 - Understanding the organization",
        "4.2 - Needs and expectations of interested parties",
        "4.3 - Scope of the ISMS",
        "5.1 - Leadership and commitment",
        "5.2 - Information security policy",
        "5.3 - Roles and responsibilities",
        "6.1 - Actions to address risks and opportunities",
        "6.2 - Information security objectives",
        "7.1 - Resources",
        "7.2 - Competence",
        "7.3 - Awareness",
        "7.4 - Communication",
        "7.5 - Documented information",
        "8.1 - Operational planning and control",
        "8.2 - Information security risk assessment",
        "8.3 - Information security risk treatment",
        "9.1 - Monitoring measurement analysis and evaluation",
        "9.2 - Internal audit",
        "9.3 - Management review",
        "10.1 - Continual improvement",
        "10.2 - Nonconformity and corrective action",
    ]

    plan = AuditPlan.query.get_or_404(plan_id)

    if request.method == "POST":
        action = request.form.get("action")

        if action == "add_finding":
            finding = AuditFinding(
                plan_id=plan_id,
                clause=request.form.get("clause"),
                finding=request.form.get("finding"),
                severity=request.form.get("severity"),
                root_cause=request.form.get("root_cause"),
                action=request.form.get("action_required"),
                due_date=datetime.datetime.strptime(
                    request.form.get("due_date"), "%Y-%m-%d"
                ) if request.form.get("due_date") else None,
                status="open"
            )
            db.session.add(finding)

            # AUTO CREATE RISK IF CRITICAL OR HIGH
            if finding.severity in ["critical", "high"]:
                r = Risk(
                    name=f"AUDIT: {finding.clause} — {finding.finding[:80]}",
                    description="Finding from internal audit: " + str(finding.finding or "") + "\nRoot cause: " + str(finding.root_cause or "") + "\nRequired action: " + str(finding.action or ""),
                    level=finding.severity.upper(),
                    owner=plan.auditor,
                    created_by="INTERNAL-AUDIT"
                )
                db.session.add(r)

            # AUTO CREATE EVIDENCE FOR CLAUSE 9.2
            from models import ControlEvidence
            from evidence_engine import auto_link_evidence
            auto_link_evidence(
                db, ControlEvidence,
                "9.2", "Internal audit",
                f"Internal audit conducted: {plan.title} — {len(plan.findings)+1} finding(s) recorded.",
                evidence_type="report"
            )

            db.session.commit()
            log_action(db, AuditLog, current_user.username,
                       f"Added audit finding for {finding.clause} in plan: {plan.title}",
                       request.remote_addr)
            flash("Finding added", "success")

        elif action == "complete":
            plan.status = "completed"
            db.session.commit()
            flash("Audit marked as complete", "success")

        elif action == "close_finding":
            fid = request.form.get("finding_id")
            f = AuditFinding.query.get(fid)
            if f:
                f.status = "closed"
                db.session.commit()
                flash("Finding closed", "success")

        return redirect(url_for("audit_detail", plan_id=plan_id))

    open_findings   = [f for f in plan.findings if f.status == "open"]
    closed_findings = [f for f in plan.findings if f.status == "closed"]
    return render_template("audit_detail.html",
                           plan=plan,
                           clauses=CLAUSES,
                           open_findings=open_findings,
                           closed_findings=closed_findings)


@app.route("/internalaudit/<int:plan_id>/report")
@login_required
def audit_report_pdf(plan_id):
    from models import AuditPlan
    plan = AuditPlan.query.get_or_404(plan_id)
    open_f   = [f for f in plan.findings if f.status == "open"]
    closed_f = [f for f in plan.findings if f.status == "closed"]
    return render_template("audit_report.html",
                           plan=plan,
                           open_findings=open_f,
                           closed_findings=closed_f,
                           now=datetime.datetime.utcnow())


@app.route("/chatbot", methods=["GET", "POST"])
@login_required
def chatbot():
    from models import Policy
    policies = Policy.query.all()
    policy_context = ""
    for p in policies:
        policy_context += f"Policy: {p.title} (version {p.version}, owner: {p.owner or 'Not assigned'}, review date: {p.review_date.strftime('%d %b %Y') if p.review_date else 'Not set'})\n"
    return render_template("chatbot.html", policy_context=policy_context)


@app.route("/risk/export/pdf")
@login_required
def risk_export_pdf():
    from weasyprint import HTML
    from models import Risk
    risks = Risk.query.order_by(Risk.score.desc()).all()
    html = render_template("risk_pdf.html", risks=risks, now=datetime.datetime.utcnow())
    pdf = HTML(string=html).write_pdf()
    from flask import Response
    return Response(pdf, mimetype="application/pdf",
        headers={"Content-Disposition": "attachment;filename=risk_register.pdf"})

@app.route("/internalaudit/<int:plan_id>/export/pdf")
@login_required
def audit_export_pdf(plan_id):
    from weasyprint import HTML
    from models import AuditPlan, AuditFinding
    plan = AuditPlan.query.get_or_404(plan_id)
    open_findings   = AuditFinding.query.filter_by(plan_id=plan_id, status="open").all()
    closed_findings = AuditFinding.query.filter_by(plan_id=plan_id, status="closed").all()
    html = render_template("audit_report.html", plan=plan,
        open_findings=open_findings, closed_findings=closed_findings,
        now=datetime.datetime.utcnow())
    pdf = HTML(string=html).write_pdf()
    from flask import Response
    return Response(pdf, mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment;filename=audit_{plan_id}.pdf"})

# Auto-create database on startup
with app.app_context():
    db.create_all()
    # Create default admin if not exists
    from models import User
    try:
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', role='admin', email='admin@isms.local')
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
    except Exception:
        db.session.rollback()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Create default admin if none exists
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin',
                         email='sawairagohar3012@gmail.com',
                         role='admin')
            admin.set_password('Admin@1234')
            db.session.add(admin)
            db.session.commit()
            print('Default admin created — username: admin / password: Admin@1234')
        models = {
            'User': User,
            'Risk': Risk,
            'Training': Training,
            'Policy': Policy,
            'AuditLog': AuditLog
        }
        from auto_engine import start_scheduler
        start_scheduler(app, db, models)
    app.run(debug=True)
