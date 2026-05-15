from app import app, db
from models import SoAControl

CONTROLS = [
    # Theme 5 — Organizational (37 controls)
    ("5.1",  "Policies for information security",           "Organizational"),
    ("5.2",  "Information security roles and responsibilities", "Organizational"),
    ("5.3",  "Segregation of duties",                       "Organizational"),
    ("5.4",  "Management responsibilities",                 "Organizational"),
    ("5.5",  "Contact with authorities",                    "Organizational"),
    ("5.6",  "Contact with special interest groups",        "Organizational"),
    ("5.7",  "Threat intelligence",                         "Organizational"),
    ("5.8",  "Information security in project management",  "Organizational"),
    ("5.9",  "Inventory of information and assets",         "Organizational"),
    ("5.10", "Acceptable use of information and assets",    "Organizational"),
    ("5.11", "Return of assets",                            "Organizational"),
    ("5.12", "Classification of information",               "Organizational"),
    ("5.13", "Labelling of information",                    "Organizational"),
    ("5.14", "Information transfer",                        "Organizational"),
    ("5.15", "Access control",                              "Organizational"),
    ("5.16", "Identity management",                         "Organizational"),
    ("5.17", "Authentication information",                  "Organizational"),
    ("5.18", "Access rights",                               "Organizational"),
    ("5.19", "Information security in supplier relationships", "Organizational"),
    ("5.20", "Addressing security within supplier agreements", "Organizational"),
    ("5.21", "Managing security in the ICT supply chain",   "Organizational"),
    ("5.22", "Monitoring and review of supplier services",  "Organizational"),
    ("5.23", "Information security for use of cloud services", "Organizational"),
    ("5.24", "Information security incident management planning", "Organizational"),
    ("5.25", "Assessment and decision on information security events", "Organizational"),
    ("5.26", "Response to information security incidents",  "Organizational"),
    ("5.27", "Learning from information security incidents", "Organizational"),
    ("5.28", "Collection of evidence",                      "Organizational"),
    ("5.29", "Information security during disruption",      "Organizational"),
    ("5.30", "ICT readiness for business continuity",       "Organizational"),
    ("5.31", "Legal statutory regulatory and contractual requirements", "Organizational"),
    ("5.32", "Intellectual property rights",                "Organizational"),
    ("5.33", "Protection of records",                       "Organizational"),
    ("5.34", "Privacy and protection of personal information", "Organizational"),
    ("5.35", "Independent review of information security",  "Organizational"),
    ("5.36", "Compliance with policies rules and standards", "Organizational"),
    ("5.37", "Documented operating procedures",             "Organizational"),
    # Theme 6 — People (8 controls)
    ("6.1",  "Screening",                                   "People"),
    ("6.2",  "Terms and conditions of employment",          "People"),
    ("6.3",  "Information security awareness education and training", "People"),
    ("6.4",  "Disciplinary process",                        "People"),
    ("6.5",  "Responsibilities after termination or change of employment", "People"),
    ("6.6",  "Confidentiality or non-disclosure agreements", "People"),
    ("6.7",  "Remote working",                              "People"),
    ("6.8",  "Information security event reporting",        "People"),
    # Theme 7 — Physical (14 controls)
    ("7.1",  "Physical security perimeters",                "Physical"),
    ("7.2",  "Physical entry",                              "Physical"),
    ("7.3",  "Securing offices rooms and facilities",       "Physical"),
    ("7.4",  "Physical security monitoring",                "Physical"),
    ("7.5",  "Protecting against physical and environmental threats", "Physical"),
    ("7.6",  "Working in secure areas",                     "Physical"),
    ("7.7",  "Clear desk and clear screen",                 "Physical"),
    ("7.8",  "Equipment siting and protection",             "Physical"),
    ("7.9",  "Security of assets off-premises",             "Physical"),
    ("7.10", "Storage media",                               "Physical"),
    ("7.11", "Supporting utilities",                        "Physical"),
    ("7.12", "Cabling security",                            "Physical"),
    ("7.13", "Equipment maintenance",                       "Physical"),
    ("7.14", "Secure disposal or re-use of equipment",      "Physical"),
    # Theme 8 — Technological (34 controls)
    ("8.1",  "User endpoint devices",                       "Technological"),
    ("8.2",  "Privileged access rights",                    "Technological"),
    ("8.3",  "Information access restriction",              "Technological"),
    ("8.4",  "Access to source code",                       "Technological"),
    ("8.5",  "Secure authentication",                       "Technological"),
    ("8.6",  "Capacity management",                         "Technological"),
    ("8.7",  "Protection against malware",                  "Technological"),
    ("8.8",  "Management of technical vulnerabilities",     "Technological"),
    ("8.9",  "Configuration management",                    "Technological"),
    ("8.10", "Information deletion",                        "Technological"),
    ("8.11", "Data masking",                                "Technological"),
    ("8.12", "Data leakage prevention",                     "Technological"),
    ("8.13", "Information backup",                          "Technological"),
    ("8.14", "Redundancy of information processing facilities", "Technological"),
    ("8.15", "Logging",                                     "Technological"),
    ("8.16", "Monitoring activities",                       "Technological"),
    ("8.17", "Clock synchronization",                       "Technological"),
    ("8.18", "Use of privileged utility programs",          "Technological"),
    ("8.19", "Installation of software on operational systems", "Technological"),
    ("8.20", "Network security",                            "Technological"),
    ("8.21", "Security of network services",                "Technological"),
    ("8.22", "Segregation of networks",                     "Technological"),
    ("8.23", "Web filtering",                               "Technological"),
    ("8.24", "Use of cryptography",                         "Technological"),
    ("8.25", "Secure development lifecycle",                "Technological"),
    ("8.26", "Application security requirements",           "Technological"),
    ("8.27", "Secure system architecture and engineering principles", "Technological"),
    ("8.28", "Secure coding",                               "Technological"),
    ("8.29", "Security testing in development and acceptance", "Technological"),
    ("8.30", "Outsourced development",                      "Technological"),
    ("8.31", "Separation of development test and production environments", "Technological"),
    ("8.32", "Change management",                           "Technological"),
    ("8.33", "Test information",                            "Technological"),
    ("8.34", "Protection of information systems during audit testing", "Technological"),
]

with app.app_context():
    existing = SoAControl.query.count()
    if existing >= 93:
        print(f"Already have {existing} controls — skipping")
    else:
        added = 0
        for control_id, control_name, theme in CONTROLS:
            exists = SoAControl.query.filter_by(control_id=control_id).first()
            if not exists:
                c = SoAControl(
                    control_id=control_id,
                    control_name=control_name,
                    theme=theme,
                    applicable=True,
                    implemented=False,
                    justification="",
                    evidence=""
                )
                db.session.add(c)
                added += 1
        db.session.commit()
        print(f"Done — added {added} controls. Total: {SoAControl.query.count()}")
