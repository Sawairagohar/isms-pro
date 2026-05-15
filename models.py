from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(100), unique=True, nullable=False)
    email         = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role          = db.Column(db.String(20), default='employee')  # admin / employee / auditor
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Risk(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    name        = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    likelihood  = db.Column(db.Integer, nullable=False)
    impact      = db.Column(db.Integer, nullable=False)
    score       = db.Column(db.Integer)
    level       = db.Column(db.String(20))   # LOW / MEDIUM / HIGH / CRITICAL
    owner       = db.Column(db.String(100))
    created_by  = db.Column(db.String(100))
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)

class Training(db.Model):
    id           = db.Column(db.Integer, primary_key=True)
    employee     = db.Column(db.String(100), nullable=False)
    topic        = db.Column(db.String(200), nullable=False)
    status       = db.Column(db.String(20), default='Pending')  # Pending / Completed
    due_date     = db.Column(db.String(50))
    completed_at = db.Column(db.DateTime)

class Policy(db.Model):
    id           = db.Column(db.Integer, primary_key=True)
    title        = db.Column(db.String(200), nullable=False)
    filename     = db.Column(db.String(200), nullable=False)
    uploaded_by  = db.Column(db.String(100))
    uploaded_at  = db.Column(db.DateTime, default=datetime.utcnow)
    review_date  = db.Column(db.DateTime)
    version      = db.Column(db.String(20), default='1.0')
    owner        = db.Column(db.String(100))
    acknowledged = db.Column(db.Integer, default=0)

class AuditLog(db.Model):
    id        = db.Column(db.Integer, primary_key=True)
    user      = db.Column(db.String(100))
    action    = db.Column(db.String(300))
    ip        = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class BlogPost(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    title      = db.Column(db.String(300), nullable=False)
    slug       = db.Column(db.String(300), unique=True)
    category   = db.Column(db.String(100))
    summary    = db.Column(db.Text)
    content    = db.Column(db.Text)
    author     = db.Column(db.String(100), default='Faseel Infosec')
    source_url = db.Column(db.String(500))
    image_url  = db.Column(db.String(500))
    is_auto    = db.Column(db.Boolean, default=False)
    views      = db.Column(db.Integer, default=0)
    tags       = db.Column(db.String(300))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

class BlogComment(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    post_id    = db.Column(db.Integer, db.ForeignKey("blog_post.id"))
    author     = db.Column(db.String(100))
    content    = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class BlockedIP(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    ip         = db.Column(db.String(50), unique=True)
    reason     = db.Column(db.String(300))
    blocked_at = db.Column(db.DateTime, default=datetime.utcnow)
    blocked_by = db.Column(db.String(100), default="AUTO-SYSTEM")

class ComplianceHistory(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    overall    = db.Column(db.Float)
    clause6    = db.Column(db.Float)
    clause7    = db.Column(db.Float)
    clause8    = db.Column(db.Float)
    clause9    = db.Column(db.Float)
    clause10   = db.Column(db.Float)
    recorded_at = db.Column(db.DateTime, default=datetime.utcnow)

class KPILog(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    metric     = db.Column(db.String(200))
    value      = db.Column(db.Float)
    target     = db.Column(db.Float)
    status     = db.Column(db.String(20))
    recorded_at = db.Column(db.DateTime, default=datetime.utcnow)

class IncidentTicket(db.Model):
    id             = db.Column(db.Integer, primary_key=True)
    title          = db.Column(db.String(300))
    description    = db.Column(db.Text)
    severity       = db.Column(db.String(20))
    status         = db.Column(db.String(20), default="Open")
    assigned_to    = db.Column(db.String(100))
    created_by     = db.Column(db.String(100))
    detected_at    = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at    = db.Column(db.DateTime)
    root_cause     = db.Column(db.Text)
    annex_controls = db.Column(db.String(300))

class CorrectiveAction(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    title       = db.Column(db.String(300))
    description = db.Column(db.Text)
    raised_by   = db.Column(db.String(100))
    assigned_to = db.Column(db.String(100))
    due_date    = db.Column(db.String(50))
    status      = db.Column(db.String(20), default="Open")
    root_cause  = db.Column(db.Text)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    closed_at   = db.Column(db.DateTime)

class SoAControl(db.Model):
    id            = db.Column(db.Integer, primary_key=True)
    control_id    = db.Column(db.String(20))
    control_name  = db.Column(db.String(300))
    theme         = db.Column(db.String(50))
    applicable    = db.Column(db.Boolean, default=True)
    implemented   = db.Column(db.Boolean, default=False)
    justification = db.Column(db.Text)
    evidence      = db.Column(db.Text)
    updated_at    = db.Column(db.DateTime, default=datetime.utcnow)

class Asset(db.Model):
    id           = db.Column(db.Integer, primary_key=True)
    name         = db.Column(db.String(200), nullable=False)
    asset_type   = db.Column(db.String(50))
    description  = db.Column(db.Text)
    owner        = db.Column(db.String(100))
    location     = db.Column(db.String(200))
    classification = db.Column(db.String(20), default='Internal')
    criticality  = db.Column(db.String(20), default='Medium')
    status       = db.Column(db.String(20), default='Active')
    ip_address   = db.Column(db.String(50))
    linked_risks = db.Column(db.Integer, default=0)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)
    last_reviewed = db.Column(db.DateTime)

class Supplier(db.Model):
    id              = db.Column(db.Integer, primary_key=True)
    name            = db.Column(db.String(200), nullable=False)
    service_type    = db.Column(db.String(100))
    contact_name    = db.Column(db.String(100))
    contact_email   = db.Column(db.String(150))
    risk_level      = db.Column(db.String(20), default="Medium")
    risk_score      = db.Column(db.Integer, default=0)
    iso_certified   = db.Column(db.Boolean, default=False)
    contract_expiry = db.Column(db.DateTime)
    last_assessed   = db.Column(db.DateTime)
    nda_signed      = db.Column(db.Boolean, default=False)
    data_access     = db.Column(db.Boolean, default=False)
    notes           = db.Column(db.Text)
    status          = db.Column(db.String(20), default="Active")
    created_at      = db.Column(db.DateTime, default=datetime.utcnow)



class OnboardingChecklist(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    username    = db.Column(db.String(100), nullable=False)
    checklist_type = db.Column(db.String(20))  # onboarding / offboarding
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    created_by  = db.Column(db.String(100))
    items       = db.Column(db.Text, default="")  # JSON string
    completed   = db.Column(db.Boolean, default=False)
    notes       = db.Column(db.Text, default="")


class ControlEvidence(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    control_id  = db.Column(db.String(20), nullable=False)
    control_name = db.Column(db.String(200))
    filename    = db.Column(db.String(200))
    description = db.Column(db.Text)
    uploaded_by = db.Column(db.String(100))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    evidence_type = db.Column(db.String(50))


class AuditPlan(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    title       = db.Column(db.String(200), nullable=False)
    audit_date  = db.Column(db.DateTime)
    auditor     = db.Column(db.String(100))
    scope       = db.Column(db.Text)
    status      = db.Column(db.String(20), default="planned")
    created_by  = db.Column(db.String(100))
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    findings    = db.relationship("AuditFinding", backref="plan", lazy=True)

class AuditFinding(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    plan_id     = db.Column(db.Integer, db.ForeignKey("audit_plan.id"), nullable=False)
    clause      = db.Column(db.String(20))
    finding     = db.Column(db.Text)
    severity    = db.Column(db.String(20))
    status      = db.Column(db.String(20), default="open")
    root_cause  = db.Column(db.Text)
    action      = db.Column(db.Text)
    due_date    = db.Column(db.DateTime)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
