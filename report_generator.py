from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from datetime import datetime
import io

# Faseel brand colors
BLUE      = colors.HexColor('#1F66D6')
DARK      = colors.HexColor('#0f172a')
CARD      = colors.HexColor('#1e293b')
GRAY      = colors.HexColor('#64748b')
GREEN     = colors.HexColor('#16a34a')
RED       = colors.HexColor('#dc2626')
AMBER     = colors.HexColor('#d97706')
WHITE     = colors.white
LIGHTGRAY = colors.HexColor('#334155')

def generate_audit_report(app, db, models):
    with app.app_context():
        Risk             = models['Risk']
        Training         = models['Training']
        Policy           = models['Policy']
        AuditLog         = models['AuditLog']
        User             = models['User']
        IncidentTicket   = models['IncidentTicket']
        CorrectiveAction = models['CorrectiveAction']
        SoAControl       = models['SoAControl']

        from compliance_engine import calculate_compliance, calculate_kpis
        models_dict      = models
        compliance_data  = calculate_compliance(app, db, models_dict)
        kpi_data         = calculate_kpis(app, db, models_dict)

        buffer = io.BytesIO()
        doc    = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=2*cm,
            leftMargin=2*cm,
            topMargin=2*cm,
            bottomMargin=2*cm
        )

        styles = getSampleStyleSheet()
        story  = []

        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Title'],
            fontSize=24,
            textColor=BLUE,
            spaceAfter=6,
            alignment=TA_CENTER
        )
        subtitle_style = ParagraphStyle(
            'Subtitle',
            parent=styles['Normal'],
            fontSize=11,
            textColor=GRAY,
            alignment=TA_CENTER,
            spaceAfter=4
        )
        heading_style = ParagraphStyle(
            'Heading',
            parent=styles['Heading1'],
            fontSize=14,
            textColor=BLUE,
            spaceBefore=16,
            spaceAfter=8,
            borderPad=4
        )
        subheading_style = ParagraphStyle(
            'SubHeading',
            parent=styles['Heading2'],
            fontSize=11,
            textColor=WHITE,
            spaceBefore=10,
            spaceAfter=6
        )
        normal_style = ParagraphStyle(
            'CustomNormal',
            parent=styles['Normal'],
            fontSize=9,
            textColor=colors.HexColor('#cbd5e1'),
            spaceAfter=4
        )
        small_style = ParagraphStyle(
            'Small',
            parent=styles['Normal'],
            fontSize=8,
            textColor=GRAY
        )

        # ── COVER PAGE ───────────────────────────────────
        story.append(Spacer(1, 2*cm))
        story.append(Paragraph("FASEEL INFOSEC", title_style))
        story.append(Paragraph("ISO 27001 ISMS Audit Report", subtitle_style))
        story.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%d %B %Y — %H:%M UTC')}", subtitle_style))
        story.append(Spacer(1, 0.5*cm))
        story.append(HRFlowable(width="100%", thickness=2, color=BLUE))
        story.append(Spacer(1, 0.5*cm))

        # Overall score box
        overall = compliance_data['overall']
        score_color = GREEN if overall >= 80 else (AMBER if overall >= 60 else RED)
        score_data = [[
            Paragraph("OVERALL COMPLIANCE SCORE", ParagraphStyle('sc', parent=styles['Normal'], fontSize=10, textColor=GRAY, alignment=TA_CENTER)),
            Paragraph(f"{overall}%", ParagraphStyle('sv', parent=styles['Normal'], fontSize=32, textColor=score_color, alignment=TA_CENTER, fontName='Helvetica-Bold')),
            Paragraph("CONFIDENTIAL — INTERNAL USE", ParagraphStyle('conf', parent=styles['Normal'], fontSize=8, textColor=GRAY, alignment=TA_CENTER))
        ]]
        score_table = Table(score_data, colWidths=[5*cm, 6*cm, 6*cm])
        score_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), CARD),
            ('ROUNDEDCORNERS', [8]),
            ('PADDING', (0,0), (-1,-1), 16),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        story.append(score_table)
        story.append(Spacer(1, 0.8*cm))

        # ── SECTION 1: EXECUTIVE SUMMARY ─────────────────
        story.append(Paragraph("1. Executive Summary", heading_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=LIGHTGRAY))
        story.append(Spacer(1, 0.3*cm))

        if overall >= 80:
            summary = f"The organization demonstrates strong ISO 27001 compliance at {overall}%. Current controls are largely effective. Continue monitoring and address remaining gaps."
        elif overall >= 60:
            summary = f"The organization is at {overall}% compliance — a moderate posture that requires focused improvement before a formal ISO 27001 audit. Priority actions are documented in Section 4."
        else:
            summary = f"The organization is at {overall}% compliance — below acceptable thresholds. Critical gaps exist that would result in major nonconformities in a certification audit. Immediate action is required."

        story.append(Paragraph(summary, normal_style))
        story.append(Spacer(1, 0.3*cm))

        # Clause scores table
        clause_header = [['ISO 27001 Clause', 'Score', 'Target', 'Status']]
        clause_rows   = []
        for key, clause in compliance_data['clauses'].items():
            score  = clause['score']
            target = clause['target']
            status = 'PASS' if score >= target else ('WARN' if score >= target * 0.7 else 'FAIL')
            clause_rows.append([
                clause['name'],
                f"{score}%",
                f"{target}%",
                status
            ])

        clause_table = Table(clause_header + clause_rows, colWidths=[9*cm, 2.5*cm, 2.5*cm, 3*cm])
        clause_table.setStyle(TableStyle([
            ('BACKGROUND',  (0,0), (-1,0),  BLUE),
            ('TEXTCOLOR',   (0,0), (-1,0),  WHITE),
            ('FONTNAME',    (0,0), (-1,0),  'Helvetica-Bold'),
            ('FONTSIZE',    (0,0), (-1,-1), 9),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [CARD, colors.HexColor('#0f172a')]),
            ('TEXTCOLOR',   (0,1), (-1,-1), colors.HexColor('#cbd5e1')),
            ('GRID',        (0,0), (-1,-1), 0.5, LIGHTGRAY),
            ('PADDING',     (0,0), (-1,-1), 8),
            ('ALIGN',       (1,0), (-1,-1), 'CENTER'),
        ]))
        story.append(clause_table)
        story.append(Spacer(1, 0.5*cm))

        # ── SECTION 2: KPI SUMMARY ───────────────────────
        story.append(Paragraph("2. KPI Summary — Clause 9.1", heading_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=LIGHTGRAY))
        story.append(Spacer(1, 0.3*cm))

        kpi_header = [['KPI Metric', 'Current Value', 'Target', 'ISO Clause', 'Status']]
        kpi_rows   = []
        for kpi in kpi_data['kpis']:
            kpi_rows.append([
                kpi['name'],
                f"{kpi['value']}{kpi['unit']}",
                f"{kpi['target']}{kpi['unit']}",
                kpi['clause'],
                kpi['status']
            ])

        kpi_table = Table(kpi_header + kpi_rows, colWidths=[5.5*cm, 2.5*cm, 2*cm, 3*cm, 2*cm])
        kpi_table.setStyle(TableStyle([
            ('BACKGROUND',     (0,0), (-1,0),  BLUE),
            ('TEXTCOLOR',      (0,0), (-1,0),  WHITE),
            ('FONTNAME',       (0,0), (-1,0),  'Helvetica-Bold'),
            ('FONTSIZE',       (0,0), (-1,-1), 8),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [CARD, colors.HexColor('#0f172a')]),
            ('TEXTCOLOR',      (0,1), (-1,-1), colors.HexColor('#cbd5e1')),
            ('GRID',           (0,0), (-1,-1), 0.5, LIGHTGRAY),
            ('PADDING',        (0,0), (-1,-1), 7),
            ('ALIGN',          (1,0), (-1,-1), 'CENTER'),
        ]))
        story.append(kpi_table)
        story.append(Spacer(1, 0.5*cm))

        # ── SECTION 3: RISK REGISTER ─────────────────────
        story.append(Paragraph("3. Risk Register — Clause 6.1.2", heading_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=LIGHTGRAY))
        story.append(Spacer(1, 0.3*cm))

        risks = Risk.query.order_by(Risk.score.desc()).limit(20).all()
        if risks:
            risk_header = [['Risk Name', 'Owner', 'L', 'I', 'Score', 'Level', 'Source']]
            risk_rows   = []
            for r in risks:
                risk_rows.append([
                    r.name[:45] + ('...' if len(r.name) > 45 else ''),
                    r.owner or '—',
                    str(r.likelihood),
                    str(r.impact),
                    str(r.score),
                    r.level,
                    r.created_by or '—'
                ])
            risk_table = Table(risk_header + risk_rows,
                               colWidths=[5.5*cm, 2.5*cm, 0.8*cm, 0.8*cm, 1.2*cm, 2*cm, 3*cm])
            risk_table.setStyle(TableStyle([
                ('BACKGROUND',     (0,0), (-1,0),  BLUE),
                ('TEXTCOLOR',      (0,0), (-1,0),  WHITE),
                ('FONTNAME',       (0,0), (-1,0),  'Helvetica-Bold'),
                ('FONTSIZE',       (0,0), (-1,-1), 7),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [CARD, colors.HexColor('#0f172a')]),
                ('TEXTCOLOR',      (0,1), (-1,-1), colors.HexColor('#cbd5e1')),
                ('GRID',           (0,0), (-1,-1), 0.5, LIGHTGRAY),
                ('PADDING',        (0,0), (-1,-1), 6),
                ('ALIGN',          (2,0), (-1,-1), 'CENTER'),
            ]))
            story.append(risk_table)
        else:
            story.append(Paragraph("No risks recorded.", normal_style))
        story.append(Spacer(1, 0.5*cm))

        # ── SECTION 4: TRAINING RECORDS ──────────────────
        story.append(Paragraph("4. Training Records — Clause 7.2", heading_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=LIGHTGRAY))
        story.append(Spacer(1, 0.3*cm))

        training = Training.query.all()
        if training:
            tr_header = [['Employee', 'Topic', 'Due Date', 'Status']]
            tr_rows   = []
            for t in training:
                tr_rows.append([
                    t.employee,
                    t.topic[:40],
                    t.due_date or '—',
                    t.status
                ])
            tr_table = Table(tr_header + tr_rows, colWidths=[4*cm, 7*cm, 3*cm, 3*cm])
            tr_table.setStyle(TableStyle([
                ('BACKGROUND',     (0,0), (-1,0),  BLUE),
                ('TEXTCOLOR',      (0,0), (-1,0),  WHITE),
                ('FONTNAME',       (0,0), (-1,0),  'Helvetica-Bold'),
                ('FONTSIZE',       (0,0), (-1,-1), 8),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [CARD, colors.HexColor('#0f172a')]),
                ('TEXTCOLOR',      (0,1), (-1,-1), colors.HexColor('#cbd5e1')),
                ('GRID',           (0,0), (-1,-1), 0.5, LIGHTGRAY),
                ('PADDING',        (0,0), (-1,-1), 7),
            ]))
            story.append(tr_table)
        else:
            story.append(Paragraph("No training records.", normal_style))
        story.append(Spacer(1, 0.5*cm))

        # ── SECTION 5: POLICY DOCUMENTS ──────────────────
        story.append(Paragraph("5. Policy Documents — Clause 7.5", heading_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=LIGHTGRAY))
        story.append(Spacer(1, 0.3*cm))

        policies = Policy.query.all()
        if policies:
            pol_header = [['Document Title', 'Filename', 'Uploaded By', 'Date']]
            pol_rows   = []
            for p in policies:
                pol_rows.append([
                    p.title[:40],
                    p.filename[:30],
                    p.uploaded_by,
                    p.uploaded_at.strftime('%d %b %Y')
                ])
            pol_table = Table(pol_header + pol_rows, colWidths=[5*cm, 4*cm, 3*cm, 3*cm])
            pol_table.setStyle(TableStyle([
                ('BACKGROUND',     (0,0), (-1,0),  BLUE),
                ('TEXTCOLOR',      (0,0), (-1,0),  WHITE),
                ('FONTNAME',       (0,0), (-1,0),  'Helvetica-Bold'),
                ('FONTSIZE',       (0,0), (-1,-1), 8),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [CARD, colors.HexColor('#0f172a')]),
                ('TEXTCOLOR',      (0,1), (-1,-1), colors.HexColor('#cbd5e1')),
                ('GRID',           (0,0), (-1,-1), 0.5, LIGHTGRAY),
                ('PADDING',        (0,0), (-1,-1), 7),
            ]))
            story.append(pol_table)
        else:
            story.append(Paragraph("No policy documents uploaded.", normal_style))
        story.append(Spacer(1, 0.5*cm))

        # ── SECTION 6: AUDIT LOG ─────────────────────────
        story.append(Paragraph("6. Audit Trail — Clause 9.1", heading_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=LIGHTGRAY))
        story.append(Spacer(1, 0.3*cm))

        logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(25).all()
        if logs:
            log_header = [['User', 'Action', 'IP', 'Timestamp']]
            log_rows   = []
            for log in logs:
                log_rows.append([
                    log.user,
                    log.action[:55] + ('...' if len(log.action) > 55 else ''),
                    log.ip,
                    log.timestamp.strftime('%d %b %Y %H:%M')
                ])
            log_table = Table(log_header + log_rows,
                              colWidths=[2.5*cm, 8*cm, 2.5*cm, 4*cm])
            log_table.setStyle(TableStyle([
                ('BACKGROUND',     (0,0), (-1,0),  BLUE),
                ('TEXTCOLOR',      (0,0), (-1,0),  WHITE),
                ('FONTNAME',       (0,0), (-1,0),  'Helvetica-Bold'),
                ('FONTSIZE',       (0,0), (-1,-1), 7),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [CARD, colors.HexColor('#0f172a')]),
                ('TEXTCOLOR',      (0,1), (-1,-1), colors.HexColor('#cbd5e1')),
                ('GRID',           (0,0), (-1,-1), 0.5, LIGHTGRAY),
                ('PADDING',        (0,0), (-1,-1), 5),
            ]))
            story.append(log_table)
        story.append(Spacer(1, 0.5*cm))

        # ── FOOTER ───────────────────────────────────────
        story.append(HRFlowable(width="100%", thickness=1, color=BLUE))
        story.append(Spacer(1, 0.2*cm))
        story.append(Paragraph(
            f"Generated by Faseel Infosec ISMS Platform — {datetime.utcnow().strftime('%d %B %Y')} — CONFIDENTIAL",
            ParagraphStyle('footer', parent=styles['Normal'], fontSize=8,
                           textColor=GRAY, alignment=TA_CENTER)
        ))

        doc.build(story)
        buffer.seek(0)
        return buffer
