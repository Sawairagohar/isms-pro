from datetime import datetime, timedelta
import logging
import os

os.makedirs('logs', exist_ok=True)
logging.basicConfig(filename='logs/compliance.log', level=logging.INFO)

def calculate_compliance(app, db, models):
    with app.app_context():
        Risk             = models['Risk']
        Training         = models['Training']
        Policy           = models['Policy']
        AuditLog         = models['AuditLog']
        IncidentTicket   = models['IncidentTicket']
        CorrectiveAction = models['CorrectiveAction']
        SoAControl       = models['SoAControl']

        # Clause 6 — Risk Management
        total_risks    = Risk.query.count()
        critical_risks = Risk.query.filter_by(level='CRITICAL').count()
        high_risks     = Risk.query.filter_by(level='HIGH').count()
        auto_risks     = Risk.query.filter(
            Risk.created_by.in_(['AUTO-SYSTEM','AUTO-DETECTOR',
                                  'AUTO-SCANNER','CVE-WATCHER'])
        ).count()
        if total_risks == 0:
            clause6_score = 30
        else:
            untreated     = critical_risks + high_risks
            treated       = max(0, total_risks - untreated)
            clause6_score = round((treated / total_risks) * 100, 1)

        # Clause 7 — Support
        total_training     = Training.query.count()
        completed_training = Training.query.filter_by(status='Completed').count()
        total_policies     = Policy.query.count()
        training_rate      = round((completed_training / total_training * 100), 1) if total_training > 0 else 0
        policy_score       = min(100, total_policies * 20)
        clause7_score      = round((training_rate + policy_score) / 2, 1)

        # Clause 8 — Operations
        recent_scans = AuditLog.query.filter(
            AuditLog.action.contains('scan'),
            AuditLog.timestamp > datetime.utcnow() - timedelta(days=30)
        ).count()
        open_incidents  = IncidentTicket.query.filter_by(status='Open').count()
        total_incidents = IncidentTicket.query.count()
        scan_score      = min(100, recent_scans * 10)
        incident_score  = 100 if total_incidents == 0 else max(0, 100 - (open_incidents * 20))
        clause8_score   = round((scan_score + incident_score) / 2, 1)

        # Clause 9 — Performance
        total_logs      = AuditLog.query.count()
        log_score       = min(100, total_logs * 2)
        soa_total       = SoAControl.query.count()
        soa_implemented = SoAControl.query.filter_by(implemented=True).count()
        soa_score       = round((soa_implemented / soa_total * 100), 1) if soa_total > 0 else 50
        clause9_score   = round((log_score + soa_score) / 2, 1)

        # Clause 10 — Improvement
        open_actions   = CorrectiveAction.query.filter_by(status='Open').count()
        closed_actions = CorrectiveAction.query.filter_by(status='Closed').count()
        total_actions  = CorrectiveAction.query.count()
        clause10_score = 70 if total_actions == 0 else round((closed_actions / total_actions * 100), 1)

        # Overall
        all_scores    = [clause6_score, clause7_score, clause8_score,
                         clause9_score, clause10_score]
        overall_score = round(sum(all_scores) / len(all_scores), 1)

        # Save to history
        try:
            from models import ComplianceHistory
            history = ComplianceHistory(
                overall=overall_score,
                clause6=clause6_score,
                clause7=clause7_score,
                clause8=clause8_score,
                clause9=clause9_score,
                clause10=clause10_score
            )
            db.session.add(history)
            db.session.commit()
        except Exception as e:
            logging.error(f"History save error: {e}")

        return {
            'overall': overall_score,
            'clauses': {
                'clause6':  {'name': 'Clause 6 — Risk Management',       'score': clause6_score,  'target': 80, 'details': {'Total risks': total_risks, 'Critical': critical_risks, 'High': high_risks, 'Auto-detected': auto_risks}},
                'clause7':  {'name': 'Clause 7 — Support',               'score': clause7_score,  'target': 90, 'details': {'Training rate': f"{training_rate}%", 'Completed': f"{completed_training}/{total_training}", 'Policies': total_policies}},
                'clause8':  {'name': 'Clause 8 — Operations',            'score': clause8_score,  'target': 85, 'details': {'Scans 30 days': recent_scans, 'Open incidents': open_incidents}},
                'clause9':  {'name': 'Clause 9 — Performance Evaluation','score': clause9_score,  'target': 85, 'details': {'Audit logs': total_logs, 'SoA coverage': f"{soa_implemented}/{soa_total}"}},
                'clause10': {'name': 'Clause 10 — Improvement',          'score': clause10_score, 'target': 80, 'details': {'Open actions': open_actions, 'Closed': closed_actions}},
            },
            'calculated_at': datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')
        }


def explain_compliance(compliance_data):
    overall = compliance_data['overall']
    clauses = compliance_data['clauses']
    reasons = []
    fixes   = []

    c6 = clauses['clause6']['details']
    if c6['Critical'] > 0:
        reasons.append(f"{c6['Critical']} critical risks are untreated")
        fixes.append({'priority': 1, 'action': 'Treat critical risks immediately', 'impact': '+10-15%', 'clause': 'Clause 6', 'url': '/risk'})

    if c6['High'] > 0:
        reasons.append(f"{c6['High']} high risks need treatment plans")
        fixes.append({'priority': 2, 'action': 'Create treatment plans for HIGH risks', 'impact': '+5-10%', 'clause': 'Clause 6', 'url': '/risk'})

    c7 = clauses['clause7']['details']
    comp_str = str(c7['Completed'])
    if '/' in comp_str:
        done, total = int(comp_str.split('/')[0]), int(comp_str.split('/')[1])
        pending = total - done
        if pending > 0:
            reasons.append(f"{pending} employees have not completed training")
            fixes.append({'priority': 3, 'action': f'Complete training for {pending} employees', 'impact': '+5-8%', 'clause': 'Clause 7', 'url': '/training'})

    if c7['Policies'] < 3:
        reasons.append("Less than 3 policy documents uploaded")
        fixes.append({'priority': 4, 'action': 'Upload core security policies', 'impact': '+5%', 'clause': 'Clause 7.5', 'url': '/policies'})

    c8 = clauses['clause8']['details']
    if c8['Scans 30 days'] == 0:
        reasons.append("No security scans run in the last 30 days")
        fixes.append({'priority': 5, 'action': 'Run a security scan now', 'impact': '+5%', 'clause': 'Clause 9.1', 'url': '/scan'})

    if c8['Open incidents'] > 0:
        reasons.append(f"{c8['Open incidents']} incidents are unresolved")
        fixes.append({'priority': 6, 'action': 'Resolve open security incidents', 'impact': '+3-5%', 'clause': 'Clause 8', 'url': '/incidents'})

    if overall >= 80:
        summary = f"Your compliance is strong at {overall}%. Focus on maintaining controls and closing remaining gaps."
    elif overall >= 60:
        summary = f"Your compliance is at {overall}% — moderate but needs improvement before an audit."
    else:
        summary = f"Your compliance is at {overall}% — critical gaps exist that would cause audit failure. Act now."

    return {
        'summary': summary,
        'reasons': reasons,
        'fixes':   sorted(fixes, key=lambda x: x['priority'])[:5]
    }


def whatif_simulator(app, db, models, fix_risks=0, fix_training=0, add_policies=0, run_scans=0):
    with app.app_context():
        Risk     = models['Risk']
        Training = models['Training']
        Policy   = models['Policy']
        AuditLog = models['AuditLog']

        total_risks    = Risk.query.count()
        critical_risks = Risk.query.filter_by(level='CRITICAL').count()
        high_risks     = Risk.query.filter_by(level='HIGH').count()
        total_training     = Training.query.count()
        completed_training = Training.query.filter_by(status='Completed').count()
        total_policies     = Policy.query.count()
        recent_scans = AuditLog.query.filter(
            AuditLog.action.contains('scan'),
            AuditLog.timestamp > datetime.utcnow() - timedelta(days=30)
        ).count()

        sim_critical = max(0, critical_risks - fix_risks)
        sim_high     = max(0, high_risks - fix_risks)
        sim_training = min(total_training, completed_training + fix_training)
        sim_policies = total_policies + add_policies
        sim_scans    = recent_scans + run_scans

        untreated  = sim_critical + sim_high
        treated    = max(0, total_risks - untreated)
        c6_sim     = round((treated / total_risks * 100), 1) if total_risks > 0 else 30
        t_rate     = round((sim_training / total_training * 100), 1) if total_training > 0 else 0
        p_score    = min(100, sim_policies * 20)
        c7_sim     = round((t_rate + p_score) / 2, 1)
        scan_score = min(100, sim_scans * 10)
        c8_sim     = round((scan_score + 80) / 2, 1)
        simulated  = round((c6_sim + c7_sim + c8_sim + 70 + 70) / 5, 1)

        # Explain what changed
        changes = []
        if fix_risks > 0:
            changes.append(f"Treating {fix_risks} risks improves Clause 6 from {c6_sim - 10:.1f}% toward {c6_sim:.1f}%")
        if fix_training > 0:
            changes.append(f"Completing {fix_training} trainings improves Clause 7 score")
        if add_policies > 0:
            changes.append(f"Adding {add_policies} policies strengthens documentation score")
        if run_scans > 0:
            changes.append(f"Running {run_scans} scans improves operational compliance")
        if not changes:
            changes.append("No fixes applied — score reflects current state with ongoing risk weight")

        return {
            'simulated':    simulated,
            'c6_sim':       c6_sim,
            'c7_sim':       c7_sim,
            'c8_sim':       c8_sim,
            'fix_risks':    fix_risks,
            'fix_training': fix_training,
            'add_policies': add_policies,
            'run_scans':    run_scans,
            'changes':      changes
        }


def get_compliance_history(app, db):
    with app.app_context():
        from models import ComplianceHistory
        records = ComplianceHistory.query.order_by(
            ComplianceHistory.recorded_at.desc()
        ).limit(30).all()
        return [{
            'date':    r.recorded_at.strftime('%d %b'),
            'overall': r.overall,
            'clause6': r.clause6,
            'clause7': r.clause7,
            'clause8': r.clause8,
        } for r in reversed(records)]


def calculate_kpis(app, db, models):
    with app.app_context():
        Risk           = models['Risk']
        Training       = models['Training']
        AuditLog       = models['AuditLog']
        Policy         = models['Policy']
        IncidentTicket = models['IncidentTicket']

        kpis = []

        total_t     = Training.query.count()
        completed_t = Training.query.filter_by(status='Completed').count()
        rate        = round((completed_t / total_t * 100), 1) if total_t > 0 else 0
        kpis.append({'name': 'Training Completion Rate', 'value': rate,      'unit': '%', 'target': 95, 'status': 'PASS' if rate >= 95 else 'WARN' if rate >= 70 else 'FAIL', 'clause': 'Clause 7.2', 'icon': '🎓'})

        critical = Risk.query.filter_by(level='CRITICAL').count()
        kpis.append({'name': 'Open Critical Risks',      'value': critical,  'unit': '',  'target': 0,  'status': 'PASS' if critical == 0 else 'FAIL', 'clause': 'Clause 6.1', 'icon': '🔴'})

        policies = Policy.query.count()
        kpis.append({'name': 'Policies Documented',      'value': policies,  'unit': '',  'target': 5,  'status': 'PASS' if policies >= 5 else 'WARN' if policies >= 2 else 'FAIL', 'clause': 'Clause 7.5', 'icon': '📁'})

        scans = AuditLog.query.filter(AuditLog.action.contains('scan'), AuditLog.timestamp > datetime.utcnow() - timedelta(days=30)).count()
        kpis.append({'name': 'Security Scans (30 days)', 'value': scans,     'unit': '',  'target': 4,  'status': 'PASS' if scans >= 4 else 'WARN' if scans >= 1 else 'FAIL', 'clause': 'Clause 9.1', 'icon': '🔍'})

        open_inc = IncidentTicket.query.filter_by(status='Open').count()
        kpis.append({'name': 'Open Incidents',           'value': open_inc,  'unit': '',  'target': 0,  'status': 'PASS' if open_inc == 0 else 'WARN' if open_inc <= 2 else 'FAIL', 'clause': 'Clause 8', 'icon': '🚨'})

        auto_risks = Risk.query.filter(Risk.created_by.in_(['AUTO-SYSTEM','AUTO-DETECTOR','AUTO-SCANNER','CVE-WATCHER'])).count()
        kpis.append({'name': 'Auto-Detected Risks',      'value': auto_risks,'unit': '',  'target': 1,  'status': 'PASS' if auto_risks >= 1 else 'FAIL', 'clause': 'Clause 6.1.2', 'icon': '🤖'})

        logs = AuditLog.query.count()
        kpis.append({'name': 'Audit Log Entries',        'value': logs,      'unit': '',  'target': 10, 'status': 'PASS' if logs >= 10 else 'WARN', 'clause': 'Clause 9.1', 'icon': '📋'})

        high = Risk.query.filter_by(level='HIGH').count()
        kpis.append({'name': 'Open High Risks',          'value': high,      'unit': '',  'target': 0,  'status': 'PASS' if high == 0 else 'WARN' if high <= 3 else 'FAIL', 'clause': 'Clause 6.1', 'icon': '🟠'})

        pass_count = len([k for k in kpis if k['status'] == 'PASS'])
        fail_count = len([k for k in kpis if k['status'] == 'FAIL'])
        warn_count = len([k for k in kpis if k['status'] == 'WARN'])

        return {'kpis': kpis, 'pass': pass_count, 'fail': fail_count, 'warn': warn_count, 'total': len(kpis)}


def time_to_compliance(app, db, target=80):
    with app.app_context():
        from models import ComplianceHistory
        records = ComplianceHistory.query.order_by(
            ComplianceHistory.recorded_at.asc()
        ).all()

        if len(records) < 2:
            return {
                'days': None,
                'message': 'Not enough history yet. Check back after the system runs for a while.',
                'current': records[-1].overall if records else 0,
                'target': target,
                'daily_rate': 0
            }

        # Calculate average daily improvement
        first = records[0]
        last  = records[-1]
        days_elapsed = max(1, (last.recorded_at - first.recorded_at).total_seconds() / 86400)
        total_improvement = last.overall - first.overall
        daily_rate = total_improvement / days_elapsed

        current = last.overall

        if current >= target:
            return {
                'days': 0,
                'message': f'You have already reached the {target}% target.',
                'current': current,
                'target': target,
                'daily_rate': round(daily_rate, 2)
            }

        if daily_rate <= 0:
            return {
                'days': None,
                'message': 'Your compliance is not improving. Address the priority actions to start progressing.',
                'current': current,
                'target': target,
                'daily_rate': round(daily_rate, 2)
            }

        days_needed = round((target - current) / daily_rate)

        return {
            'days': days_needed,
            'message': f'At your current rate, you will reach {target}% compliance in approximately {days_needed} days.',
            'current': current,
            'target': target,
            'daily_rate': round(daily_rate, 2)
        }


def time_to_compliance(app, db, target=80):
    with app.app_context():
        from models import ComplianceHistory
        records = ComplianceHistory.query.order_by(
            ComplianceHistory.recorded_at.asc()
        ).all()

        if len(records) < 2:
            return {
                'days': None,
                'message': 'Not enough history yet. Check back after the system runs for a while.',
                'current': records[-1].overall if records else 0,
                'target': target,
                'daily_rate': 0
            }

        # Calculate average daily improvement
        first = records[0]
        last  = records[-1]
        days_elapsed = max(1, (last.recorded_at - first.recorded_at).total_seconds() / 86400)
        total_improvement = last.overall - first.overall
        daily_rate = total_improvement / days_elapsed

        current = last.overall

        if current >= target:
            return {
                'days': 0,
                'message': f'You have already reached the {target}% target.',
                'current': current,
                'target': target,
                'daily_rate': round(daily_rate, 2)
            }

        if daily_rate <= 0:
            return {
                'days': None,
                'message': 'Your compliance is not improving. Address the priority actions to start progressing.',
                'current': current,
                'target': target,
                'daily_rate': round(daily_rate, 2)
            }

        days_needed = round((target - current) / daily_rate)

        return {
            'days': days_needed,
            'message': f'At your current rate, you will reach {target}% compliance in approximately {days_needed} days.',
            'current': current,
            'target': target,
            'daily_rate': round(daily_rate, 2)
        }


def smart_goal_planner(app, db, models, target_score):
    with app.app_context():
        Risk     = models['Risk']
        Training = models['Training']
        Policy   = models['Policy']
        AuditLog = models['AuditLog']

        current_critical = Risk.query.filter_by(level='CRITICAL').count()
        current_high     = Risk.query.filter_by(level='HIGH').count()
        total_risks      = Risk.query.count()
        total_training   = Training.query.count()
        completed        = Training.query.filter_by(status='Completed').count()
        pending          = total_training - completed
        current_policies = Policy.query.count()
        current_scans    = AuditLog.query.filter(
            AuditLog.action.contains('scan')
        ).count()

        plan   = []
        impact = 0

        if current_critical > 0:
            plan.append({
                'step':   len(plan) + 1,
                'action': f'Treat {current_critical} critical risks',
                'impact': 15,
                'url':    '/risk',
                'effort': 'High',
                'clause': 'Clause 6.1.2'
            })
            impact += 15

        if current_high > 0:
            plan.append({
                'step':   len(plan) + 1,
                'action': f'Create treatment plans for {current_high} HIGH risks',
                'impact': 10,
                'url':    '/risk',
                'effort': 'Medium',
                'clause': 'Clause 6.1.2'
            })
            impact += 10

        if pending > 0:
            plan.append({
                'step':   len(plan) + 1,
                'action': f'Complete security training for {pending} employees',
                'impact': 8,
                'url':    '/training',
                'effort': 'Low',
                'clause': 'Clause 7.2'
            })
            impact += 8

        if current_policies < 5:
            needed = 5 - current_policies
            plan.append({
                'step':   len(plan) + 1,
                'action': f'Upload {needed} more policy documents',
                'impact': 5,
                'url':    '/policies',
                'effort': 'Low',
                'clause': 'Clause 7.5'
            })
            impact += 5

        if current_scans < 4:
            plan.append({
                'step':   len(plan) + 1,
                'action': 'Run 4 security scans this month',
                'impact': 5,
                'url':    '/scan',
                'effort': 'Low',
                'clause': 'Clause 9.1'
            })
            impact += 5

        plan.append({
            'step':   len(plan) + 1,
            'action': 'Raise and resolve at least one incident ticket',
            'impact': 3,
            'url':    '/incidents',
            'effort': 'Low',
            'clause': 'Clause 8'
        })
        impact += 3

        plan.append({
            'step':   len(plan) + 1,
            'action': 'Create corrective actions for identified gaps',
            'impact': 3,
            'url':    '/actions',
            'effort': 'Low',
            'clause': 'Clause 10'
        })
        impact += 3

        from models import ComplianceHistory
        latest = ComplianceHistory.query.order_by(
            ComplianceHistory.recorded_at.desc()
        ).first()
        current_score = latest.overall if latest else 45.0

        projected = min(100, round(current_score + impact, 1))
        gap       = max(0, target_score - current_score)
        achievable = projected >= target_score

        return {
            'target':      target_score,
            'current':     current_score,
            'projected':   projected,
            'gap':         round(gap, 1),
            'achievable':  achievable,
            'total_impact': impact,
            'plan':        plan
        }


def check_data_integrity(app, db, models):
    with app.app_context():
        Risk     = models['Risk']
        Training = models['Training']
        Policy   = models['Policy']
        AuditLog = models['AuditLog']
        User     = models['User']

        issues    = []
        warnings  = []
        score     = 100

        # Check 1 — Any risks at all?
        total_risks = Risk.query.count()
        if total_risks == 0:
            issues.append("No risks recorded — risk register is empty")
            score -= 25
        elif total_risks < 3:
            warnings.append(f"Only {total_risks} risks recorded — register may be incomplete")
            score -= 10

        # Check 2 — Risks without owners
        no_owner = Risk.query.filter(
            (Risk.owner == None) | (Risk.owner == "")
        ).count()
        if no_owner > 0:
            warnings.append(f"{no_owner} risks have no assigned owner")
            score -= 5

        # Check 3 — Training records
        total_training = Training.query.count()
        if total_training == 0:
            issues.append("No training records — Clause 7.2 evidence is missing")
            score -= 20

        # Check 4 — Policies
        total_policies = Policy.query.count()
        if total_policies == 0:
            issues.append("No policy documents uploaded — Clause 7.5 evidence is missing")
            score -= 20
        elif total_policies < 3:
            warnings.append(f"Only {total_policies} policies uploaded — at least 5 recommended")
            score -= 10

        # Check 5 — Recent scans
        from datetime import datetime, timedelta
        recent_scans = AuditLog.query.filter(
            AuditLog.action.contains('scan'),
            AuditLog.timestamp > datetime.utcnow() - timedelta(days=30)
        ).count()
        if recent_scans == 0:
            issues.append("No security scans in last 30 days — monitoring evidence missing")
            score -= 15
        elif recent_scans < 2:
            warnings.append("Less than 2 scans in last 30 days — increase scanning frequency")
            score -= 5

        # Check 6 — Audit log activity
        total_logs = AuditLog.query.count()
        if total_logs < 10:
            warnings.append("Very few audit log entries — system may not be actively used")
            score -= 5

        # Check 7 — Users registered
        total_users = User.query.count()
        if total_users < 2:
            warnings.append("Only 1 user registered — consider adding employee and auditor accounts")
            score -= 5

        # Check 8 — Auto detection working
        auto_risks = Risk.query.filter(
            Risk.created_by.in_(["AUTO-SYSTEM","AUTO-DETECTOR",
                                  "AUTO-SCANNER","CVE-WATCHER"])
        ).count()
        if auto_risks == 0:
            warnings.append("No auto-detected risks — automation engine may not be running")
            score -= 5

        score = max(0, score)

        if score >= 80:
            trust_level = "HIGH"
            trust_msg   = "Data quality is high. Compliance score is reliable."
        elif score >= 60:
            trust_level = "MEDIUM"
            trust_msg   = "Data quality is moderate. Some gaps exist that may affect score accuracy."
        else:
            trust_level = "LOW"
            trust_msg   = "Data quality is low. Compliance score may be misleading. Address issues below."

        return {
            "score":       score,
            "trust_level": trust_level,
            "trust_msg":   trust_msg,
            "issues":      issues,
            "warnings":    warnings,
            "total_checks": 8,
            "passed":      8 - len(issues) - len(warnings)
        }


def business_impact_mode(app, db, models):
    with app.app_context():
        Risk           = models['Risk']
        Training       = models['Training']
        Policy         = models['Policy']
        IncidentTicket = models['IncidentTicket']

        critical_risks = Risk.query.filter_by(level='CRITICAL').count()
        high_risks     = Risk.query.filter_by(level='HIGH').count()
        total_training = Training.query.count()
        completed      = Training.query.filter_by(status='Completed').count()
        pending        = total_training - completed
        policies       = Policy.query.count()
        open_incidents = IncidentTicket.query.filter_by(status='Open').count()

        impacts = []

        if critical_risks > 0:
            impacts.append({
                'icon':     '💸',
                'title':    'Financial Risk',
                'technical': f'{critical_risks} critical unmitigated risks',
                'business':  f'Unmitigated critical risks could result in data breach costs averaging £3.5M per incident. Your organization has {critical_risks} unaddressed critical risks.',
                'severity':  'CRITICAL',
                'action':    'Treat critical risks immediately',
                'url':       '/risk'
            })

        if high_risks > 0:
            impacts.append({
                'icon':     '⚖️',
                'title':    'Legal & Regulatory Risk',
                'technical': f'{high_risks} HIGH risks unmitigated',
                'business':  f'GDPR fines can reach €20M or 4% of global turnover. {high_risks} unmitigated HIGH risks increase regulatory exposure significantly.',
                'severity':  'HIGH',
                'action':    'Create risk treatment plans',
                'url':       '/risk'
            })

        if pending > 0:
            impacts.append({
                'icon':     '👥',
                'title':    'Human Error Risk',
                'technical': f'{pending} employees without security training',
                'business':  f'95% of cybersecurity breaches involve human error. {pending} untrained employees represent a significant insider threat and phishing vulnerability.',
                'severity':  'HIGH',
                'action':    'Complete employee security training',
                'url':       '/training'
            })

        if policies < 3:
            impacts.append({
                'icon':     '📋',
                'title':    'Compliance & Audit Risk',
                'technical': f'Only {policies} policy documents uploaded',
                'business':  'Without documented security policies, your organization cannot demonstrate compliance to clients, auditors, or regulators. This blocks enterprise contracts and certifications.',
                'severity':  'MEDIUM',
                'action':    'Upload core security policies',
                'url':       '/policies'
            })

        if open_incidents > 0:
            impacts.append({
                'icon':     '🚨',
                'title':    'Operational Risk',
                'technical': f'{open_incidents} open security incidents',
                'business':  f'{open_incidents} unresolved security incidents could escalate into major breaches. Every hour of delay increases potential damage and regulatory reporting obligations.',
                'severity':  'HIGH',
                'action':    'Resolve open incidents immediately',
                'url':       '/incidents'
            })

        impacts.append({
            'icon':     '🏆',
            'title':    'Business Opportunity',
            'technical': 'ISO 27001 certification gap',
            'business':  'ISO 27001 certified organizations win 40% more enterprise contracts. Certification opens government tenders, financial sector clients, and international markets.',
            'severity':  'OPPORTUNITY',
            'action':    'Work toward ISO 27001 certification',
            'url':       '/compliance'
        })

        overall_risk = 'CRITICAL' if critical_risks > 3 else ('HIGH' if critical_risks > 0 or high_risks > 3 else 'MEDIUM')

        return {
            'impacts':      impacts,
            'overall_risk': overall_risk,
            'critical_count': critical_risks,
            'high_count':     high_risks,
            'pending_training': pending,
            'open_incidents':   open_incidents
        }


def generate_gap_analysis(app, db, models):
    with app.app_context():
        Risk             = models['Risk']
        Training         = models['Training']
        Policy           = models['Policy']
        AuditLog         = models['AuditLog']
        User             = models['User']
        IncidentTicket   = models['IncidentTicket']
        CorrectiveAction = models['CorrectiveAction']
        SoAControl       = models['SoAControl']

        gaps = []
        strengths = []

        # Check Clause 4 — Context
        gaps.append({
            "clause":   "4.1",
            "name":     "Understanding the organization",
            "status":   "GAP",
            "finding":  "No formal context of organization document uploaded",
            "action":   "Upload organizational context document to Policy Manager",
            "priority": "MEDIUM",
            "url":      "/policies"
        })

        # Check Clause 5 — Leadership
        admins = User.query.filter_by(role="admin").count()
        if admins >= 1:
            strengths.append({
                "clause":  "5.3",
                "name":    "Organizational roles and responsibilities",
                "finding": f"{admins} admin user(s) defined with clear roles"
            })
        else:
            gaps.append({
                "clause":   "5.3",
                "name":     "Organizational roles and responsibilities",
                "status":   "GAP",
                "finding":  "No admin roles defined",
                "action":   "Create admin, auditor and employee user accounts",
                "priority": "HIGH",
                "url":      "/admin"
            })

        # Check Clause 6 — Risk Assessment
        total_risks = Risk.query.count()
        if total_risks >= 5:
            strengths.append({
                "clause":  "6.1.2",
                "name":    "Risk assessment",
                "finding": f"{total_risks} risks identified and scored in risk register"
            })
        else:
            gaps.append({
                "clause":   "6.1.2",
                "name":     "Risk assessment",
                "status":   "GAP",
                "finding":  f"Only {total_risks} risks in register — insufficient for audit",
                "action":   "Identify and document at least 10 information security risks",
                "priority": "CRITICAL",
                "url":      "/risk"
            })

        critical_risks = Risk.query.filter_by(level="CRITICAL").count()
        if critical_risks > 0:
            gaps.append({
                "clause":   "6.1.3",
                "name":     "Risk treatment",
                "status":   "GAP",
                "finding":  f"{critical_risks} critical risks have no treatment plan",
                "action":   "Create treatment plans for all critical risks",
                "priority": "CRITICAL",
                "url":      "/risk"
            })
        else:
            strengths.append({
                "clause":  "6.1.3",
                "name":    "Risk treatment",
                "finding": "No untreated critical risks — good posture"
            })

        # Check Clause 7 — Support
        policies = Policy.query.count()
        if policies >= 5:
            strengths.append({
                "clause":  "7.5",
                "name":    "Documented information",
                "finding": f"{policies} policy documents maintained"
            })
        elif policies > 0:
            gaps.append({
                "clause":   "7.5",
                "name":     "Documented information",
                "status":   "PARTIAL",
                "finding":  f"Only {policies} policies — need at least 5 core policies",
                "action":   "Upload: IS Policy, Access Control, Incident Response, BCP, Acceptable Use",
                "priority": "HIGH",
                "url":      "/policies"
            })
        else:
            gaps.append({
                "clause":   "7.5",
                "name":     "Documented information",
                "status":   "GAP",
                "finding":  "No policy documents uploaded",
                "action":   "Upload all required ISO 27001 policy documents",
                "priority": "CRITICAL",
                "url":      "/policies"
            })

        training_total     = Training.query.count()
        training_completed = Training.query.filter_by(status="Completed").count()
        if training_total > 0:
            rate = round(training_completed / training_total * 100)
            if rate >= 80:
                strengths.append({
                    "clause":  "7.2",
                    "name":    "Competence and awareness",
                    "finding": f"{rate}% training completion rate"
                })
            else:
                gaps.append({
                    "clause":   "7.2",
                    "name":     "Competence and awareness",
                    "status":   "PARTIAL",
                    "finding":  f"Training completion only {rate}% — below 80% threshold",
                    "action":   "Complete security awareness training for all employees",
                    "priority": "HIGH",
                    "url":      "/training"
                })
        else:
            gaps.append({
                "clause":   "7.2",
                "name":     "Competence and awareness",
                "status":   "GAP",
                "finding":  "No training records — cannot prove employee awareness",
                "action":   "Assign and complete security awareness training",
                "priority": "HIGH",
                "url":      "/training"
            })

        # Check Clause 8 — Operations
        from datetime import datetime, timedelta
        recent_scans = AuditLog.query.filter(
            AuditLog.action.contains("scan"),
            AuditLog.timestamp > datetime.utcnow() - timedelta(days=30)
        ).count()
        if recent_scans >= 2:
            strengths.append({
                "clause":  "8.8",
                "name":    "Management of technical vulnerabilities",
                "finding": f"{recent_scans} vulnerability scans run in last 30 days"
            })
        else:
            gaps.append({
                "clause":   "8.8",
                "name":     "Management of technical vulnerabilities",
                "status":   "GAP",
                "finding":  "Insufficient vulnerability scanning evidence",
                "action":   "Run security scans at least weekly",
                "priority": "HIGH",
                "url":      "/scan"
            })

        incidents = IncidentTicket.query.count()
        if incidents > 0:
            strengths.append({
                "clause":  "5.24",
                "name":    "Incident management",
                "finding": f"{incidents} incidents recorded with formal tracking"
            })
        else:
            gaps.append({
                "clause":   "5.24",
                "name":     "Incident management",
                "status":   "GAP",
                "finding":  "No incident management records",
                "action":   "Set up incident response process and log all security events",
                "priority": "MEDIUM",
                "url":      "/incidents"
            })

        # Check Clause 9 — Performance
        logs = AuditLog.query.count()
        if logs >= 50:
            strengths.append({
                "clause":  "8.15",
                "name":    "Logging and monitoring",
                "finding": f"{logs} audit log entries — strong monitoring evidence"
            })
        else:
            gaps.append({
                "clause":   "8.15",
                "name":     "Logging and monitoring",
                "status":   "PARTIAL",
                "finding":  f"Only {logs} log entries — needs more activity",
                "action":   "Ensure all security events are logged consistently",
                "priority": "MEDIUM",
                "url":      "/auditlog"
            })

        # Check SoA
        soa_total       = SoAControl.query.count()
        soa_implemented = SoAControl.query.filter_by(implemented=True).count()
        if soa_total > 0:
            coverage = round(soa_implemented / soa_total * 100)
            if coverage >= 50:
                strengths.append({
                    "clause":  "6.1.3",
                    "name":    "Statement of Applicability",
                    "finding": f"SoA {coverage}% complete — {soa_implemented}/{soa_total} controls"
                })
            else:
                gaps.append({
                    "clause":   "6.1.3",
                    "name":     "Statement of Applicability",
                    "status":   "PARTIAL",
                    "finding":  f"SoA only {coverage}% complete",
                    "action":   "Mark implemented controls in the SoA register",
                    "priority": "HIGH",
                    "url":      "/soa"
                })

        # Check Clause 10 — Improvement
        actions = CorrectiveAction.query.count()
        if actions > 0:
            strengths.append({
                "clause":  "10.1",
                "name":    "Continual improvement",
                "finding": f"{actions} corrective actions tracked"
            })
        else:
            gaps.append({
                "clause":   "10.1",
                "name":     "Continual improvement",
                "status":   "GAP",
                "finding":  "No corrective actions recorded",
                "action":   "Create corrective actions for identified gaps",
                "priority": "MEDIUM",
                "url":      "/actions"
            })

        critical_gaps = len([g for g in gaps if g.get("priority") == "CRITICAL"])
        high_gaps     = len([g for g in gaps if g.get("priority") == "HIGH"])
        medium_gaps   = len([g for g in gaps if g.get("priority") == "MEDIUM"])

        if critical_gaps == 0 and high_gaps == 0:
            readiness = "READY"
            readiness_msg = "No critical or high gaps. Organization may be ready for ISO 27001 audit."
        elif critical_gaps == 0:
            readiness = "NEARLY"
            readiness_msg = f"No critical gaps but {high_gaps} high priority gaps need addressing before audit."
        else:
            readiness = "NOT_READY"
            readiness_msg = f"{critical_gaps} critical gaps must be resolved before considering ISO 27001 audit."

        return {
            "gaps":         gaps,
            "strengths":    strengths,
            "critical_gaps": critical_gaps,
            "high_gaps":    high_gaps,
            "medium_gaps":  medium_gaps,
            "total_gaps":   len(gaps),
            "total_strengths": len(strengths),
            "readiness":    readiness,
            "readiness_msg": readiness_msg,
            "generated_at": datetime.utcnow().strftime("%d %B %Y %H:%M UTC")
        }


def generate_gap_analysis(app, db, models):
    with app.app_context():
        Risk             = models['Risk']
        Training         = models['Training']
        Policy           = models['Policy']
        AuditLog         = models['AuditLog']
        User             = models['User']
        IncidentTicket   = models['IncidentTicket']
        CorrectiveAction = models['CorrectiveAction']
        SoAControl       = models['SoAControl']

        gaps = []
        strengths = []

        # Check Clause 4 — Context
        gaps.append({
            "clause":   "4.1",
            "name":     "Understanding the organization",
            "status":   "GAP",
            "finding":  "No formal context of organization document uploaded",
            "action":   "Upload organizational context document to Policy Manager",
            "priority": "MEDIUM",
            "url":      "/policies"
        })

        # Check Clause 5 — Leadership
        admins = User.query.filter_by(role="admin").count()
        if admins >= 1:
            strengths.append({
                "clause":  "5.3",
                "name":    "Organizational roles and responsibilities",
                "finding": f"{admins} admin user(s) defined with clear roles"
            })
        else:
            gaps.append({
                "clause":   "5.3",
                "name":     "Organizational roles and responsibilities",
                "status":   "GAP",
                "finding":  "No admin roles defined",
                "action":   "Create admin, auditor and employee user accounts",
                "priority": "HIGH",
                "url":      "/admin"
            })

        # Check Clause 6 — Risk Assessment
        total_risks = Risk.query.count()
        if total_risks >= 5:
            strengths.append({
                "clause":  "6.1.2",
                "name":    "Risk assessment",
                "finding": f"{total_risks} risks identified and scored in risk register"
            })
        else:
            gaps.append({
                "clause":   "6.1.2",
                "name":     "Risk assessment",
                "status":   "GAP",
                "finding":  f"Only {total_risks} risks in register — insufficient for audit",
                "action":   "Identify and document at least 10 information security risks",
                "priority": "CRITICAL",
                "url":      "/risk"
            })

        critical_risks = Risk.query.filter_by(level="CRITICAL").count()
        if critical_risks > 0:
            gaps.append({
                "clause":   "6.1.3",
                "name":     "Risk treatment",
                "status":   "GAP",
                "finding":  f"{critical_risks} critical risks have no treatment plan",
                "action":   "Create treatment plans for all critical risks",
                "priority": "CRITICAL",
                "url":      "/risk"
            })
        else:
            strengths.append({
                "clause":  "6.1.3",
                "name":    "Risk treatment",
                "finding": "No untreated critical risks — good posture"
            })

        # Check Clause 7 — Support
        policies = Policy.query.count()
        if policies >= 5:
            strengths.append({
                "clause":  "7.5",
                "name":    "Documented information",
                "finding": f"{policies} policy documents maintained"
            })
        elif policies > 0:
            gaps.append({
                "clause":   "7.5",
                "name":     "Documented information",
                "status":   "PARTIAL",
                "finding":  f"Only {policies} policies — need at least 5 core policies",
                "action":   "Upload: IS Policy, Access Control, Incident Response, BCP, Acceptable Use",
                "priority": "HIGH",
                "url":      "/policies"
            })
        else:
            gaps.append({
                "clause":   "7.5",
                "name":     "Documented information",
                "status":   "GAP",
                "finding":  "No policy documents uploaded",
                "action":   "Upload all required ISO 27001 policy documents",
                "priority": "CRITICAL",
                "url":      "/policies"
            })

        training_total     = Training.query.count()
        training_completed = Training.query.filter_by(status="Completed").count()
        if training_total > 0:
            rate = round(training_completed / training_total * 100)
            if rate >= 80:
                strengths.append({
                    "clause":  "7.2",
                    "name":    "Competence and awareness",
                    "finding": f"{rate}% training completion rate"
                })
            else:
                gaps.append({
                    "clause":   "7.2",
                    "name":     "Competence and awareness",
                    "status":   "PARTIAL",
                    "finding":  f"Training completion only {rate}% — below 80% threshold",
                    "action":   "Complete security awareness training for all employees",
                    "priority": "HIGH",
                    "url":      "/training"
                })
        else:
            gaps.append({
                "clause":   "7.2",
                "name":     "Competence and awareness",
                "status":   "GAP",
                "finding":  "No training records — cannot prove employee awareness",
                "action":   "Assign and complete security awareness training",
                "priority": "HIGH",
                "url":      "/training"
            })

        # Check Clause 8 — Operations
        from datetime import datetime, timedelta
        recent_scans = AuditLog.query.filter(
            AuditLog.action.contains("scan"),
            AuditLog.timestamp > datetime.utcnow() - timedelta(days=30)
        ).count()
        if recent_scans >= 2:
            strengths.append({
                "clause":  "8.8",
                "name":    "Management of technical vulnerabilities",
                "finding": f"{recent_scans} vulnerability scans run in last 30 days"
            })
        else:
            gaps.append({
                "clause":   "8.8",
                "name":     "Management of technical vulnerabilities",
                "status":   "GAP",
                "finding":  "Insufficient vulnerability scanning evidence",
                "action":   "Run security scans at least weekly",
                "priority": "HIGH",
                "url":      "/scan"
            })

        incidents = IncidentTicket.query.count()
        if incidents > 0:
            strengths.append({
                "clause":  "5.24",
                "name":    "Incident management",
                "finding": f"{incidents} incidents recorded with formal tracking"
            })
        else:
            gaps.append({
                "clause":   "5.24",
                "name":     "Incident management",
                "status":   "GAP",
                "finding":  "No incident management records",
                "action":   "Set up incident response process and log all security events",
                "priority": "MEDIUM",
                "url":      "/incidents"
            })

        # Check Clause 9 — Performance
        logs = AuditLog.query.count()
        if logs >= 50:
            strengths.append({
                "clause":  "8.15",
                "name":    "Logging and monitoring",
                "finding": f"{logs} audit log entries — strong monitoring evidence"
            })
        else:
            gaps.append({
                "clause":   "8.15",
                "name":     "Logging and monitoring",
                "status":   "PARTIAL",
                "finding":  f"Only {logs} log entries — needs more activity",
                "action":   "Ensure all security events are logged consistently",
                "priority": "MEDIUM",
                "url":      "/auditlog"
            })

        # Check SoA
        soa_total       = SoAControl.query.count()
        soa_implemented = SoAControl.query.filter_by(implemented=True).count()
        if soa_total > 0:
            coverage = round(soa_implemented / soa_total * 100)
            if coverage >= 50:
                strengths.append({
                    "clause":  "6.1.3",
                    "name":    "Statement of Applicability",
                    "finding": f"SoA {coverage}% complete — {soa_implemented}/{soa_total} controls"
                })
            else:
                gaps.append({
                    "clause":   "6.1.3",
                    "name":     "Statement of Applicability",
                    "status":   "PARTIAL",
                    "finding":  f"SoA only {coverage}% complete",
                    "action":   "Mark implemented controls in the SoA register",
                    "priority": "HIGH",
                    "url":      "/soa"
                })

        # Check Clause 10 — Improvement
        actions = CorrectiveAction.query.count()
        if actions > 0:
            strengths.append({
                "clause":  "10.1",
                "name":    "Continual improvement",
                "finding": f"{actions} corrective actions tracked"
            })
        else:
            gaps.append({
                "clause":   "10.1",
                "name":     "Continual improvement",
                "status":   "GAP",
                "finding":  "No corrective actions recorded",
                "action":   "Create corrective actions for identified gaps",
                "priority": "MEDIUM",
                "url":      "/actions"
            })

        critical_gaps = len([g for g in gaps if g.get("priority") == "CRITICAL"])
        high_gaps     = len([g for g in gaps if g.get("priority") == "HIGH"])
        medium_gaps   = len([g for g in gaps if g.get("priority") == "MEDIUM"])

        if critical_gaps == 0 and high_gaps == 0:
            readiness = "READY"
            readiness_msg = "No critical or high gaps. Organization may be ready for ISO 27001 audit."
        elif critical_gaps == 0:
            readiness = "NEARLY"
            readiness_msg = f"No critical gaps but {high_gaps} high priority gaps need addressing before audit."
        else:
            readiness = "NOT_READY"
            readiness_msg = f"{critical_gaps} critical gaps must be resolved before considering ISO 27001 audit."

        return {
            "gaps":         gaps,
            "strengths":    strengths,
            "critical_gaps": critical_gaps,
            "high_gaps":    high_gaps,
            "medium_gaps":  medium_gaps,
            "total_gaps":   len(gaps),
            "total_strengths": len(strengths),
            "readiness":    readiness,
            "readiness_msg": readiness_msg,
            "generated_at": datetime.utcnow().strftime("%d %B %Y %H:%M UTC")
        }
