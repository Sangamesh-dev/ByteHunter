"""
ByteHunter PDF Report Generator.
Uses reportlab to create professional dark-themed security reports.
"""
import io
import os
from datetime import datetime, timezone
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.units import inch

# Theme Colors
BG_COLOR = colors.HexColor("#0a0a0c")
SURFACE_COLOR = colors.HexColor("#121216")
BORDER_COLOR = colors.HexColor("#1f1f24")
TEXT_COLOR = colors.black
MUTED_COLOR = colors.HexColor("#444444")
GREEN = colors.green
RED = colors.HexColor("#ff4444")
AMBER = colors.HexColor("#ffaa00")

def generate_pdf_report(result: dict) -> bytes:
    """Generates a professional PDF report from analysis results."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=50,
        leftMargin=50,
        topMargin=50,
        bottomMargin=50
    )

    styles = getSampleStyleSheet()
    
    # Custom Styles
    styles.add(ParagraphStyle(
        name='BHTitle',
        fontName='Helvetica-Bold',
        fontSize=24,
        textColor=GREEN,
        spaceAfter=12
    ))
    styles.add(ParagraphStyle(
        name='BHHeader',
        fontName='Helvetica-Bold',
        fontSize=18,
        textColor=TEXT_COLOR,
        spaceBefore=20,
        spaceAfter=10
    ))
    styles.add(ParagraphStyle(
        name='BHSubHeader',
        fontName='Helvetica-Bold',
        fontSize=14,
        textColor=TEXT_COLOR,
        spaceBefore=12,
        spaceAfter=6
    ))
    styles.add(ParagraphStyle(
        name='BHBody',
        fontName='Helvetica',
        fontSize=10,
        textColor=TEXT_COLOR,
        leading=14
    ))
    styles.add(ParagraphStyle(
        name='BHMuted',
        fontName='Helvetica',
        fontSize=9,
        textColor=MUTED_COLOR
    ))

    elements = []

    # 1. Header
    elements.append(Paragraph("BYTEHUNTER", styles['BHTitle']))
    elements.append(Paragraph(f"Analysis Report — {result.get('filename', 'N/A')}", styles['BHBody']))
    elements.append(Paragraph(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}", styles['BHMuted']))
    elements.append(Spacer(1, 12))

    # 2. Executive Summary
    elements.append(Paragraph("Executive Summary", styles['BHHeader']))
    
    risk_lvl = result.get('risk_level', 'LOW')
    verdict = result.get('verdict', 'SAFE')
    
    if risk_lvl == 'HIGH':
        summary_text = "<b>CRITICAL:</b> This file contains strong indicators of malicious behavior. It is highly recommended that you DO NOT open or execute this file. It has been flagged as MALICIOUS by our AI payload analysis."
        status_color = RED
    elif risk_lvl == 'MEDIUM':
        summary_text = "<b>WARNING:</b> This file shows suspicious characteristics. Proceed with caution. Heuristic analysis suggests potential obfuscation or unusual structure often found in unwanted software."
        status_color = AMBER
    else:
        summary_text = "<b>SAFE:</b> No malicious indicators were detected during analysis. The file structure and behavior profile appear consistent with legitimate software."
        status_color = GREEN

    elements.append(Paragraph(summary_text, styles['BHBody']))
    elements.append(Spacer(1, 12))

    # 3. File Information
    elements.append(Paragraph("File Information", styles['BHHeader']))
    # Format file size for professionalism
    file_size_raw = result.get("file_size")
    if isinstance(file_size_raw, (int, float)) and file_size_raw > 0:
        file_size_str = f"{file_size_raw / (1024*1024):.2f} MB"
    else:
        file_size_str = str(file_size_raw or "N/A")

    meta_data = [
        [Paragraph("Attribute", styles['BHBody']), Paragraph("Value", styles['BHBody'])],
        [Paragraph("Filename", styles['BHBody']), Paragraph(str(result.get("filename") or "N/A"), styles['BHBody'])],
        [Paragraph("File Type", styles['BHBody']), Paragraph(str(result.get("file_type") or "application/octet-stream"), styles['BHBody'])],
        [Paragraph("File Size", styles['BHBody']), Paragraph(file_size_str, styles['BHBody'])],
        [Paragraph("MD5", styles['BHBody']), Paragraph(str(result.get("md5") or "N/A"), styles['BHBody'])],
        [Paragraph("SHA256", styles['BHBody']), Paragraph(str(result.get("sha256") or "N/A"), styles['BHBody'])],
    ]
    meta_table = Table(meta_data, colWidths=[150, 300])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.black),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.green),
        ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 12))

    # 4. Risk Interpretation
    elements.append(Paragraph("Risk Interpretation", styles['BHHeader']))
    interpretation = """
    Even though a file may be classified as SAFE, minor indicators such as entropy or structural anomalies may exist.
    These are not always sufficient to classify the file as malicious on their own. ByteHunter uses an ensemble 
    of AI models to weighted these indicators against known benign patterns.
    """
    elements.append(Paragraph(interpretation, styles['BHBody']))
    elements.append(Spacer(1, 12))

    # 5. Key Risk Factors
    elements.append(Paragraph("Key Risk Factors", styles['BHHeader']))
    explanations = result.get("explanations", [])
    if explanations:
        for exp in explanations:
            text = f"<b>{exp['category']}</b>: {exp['reason']}"
            elements.append(Paragraph(text, styles['BHBody']))
            elements.append(Spacer(1, 6))
    else:
        elements.append(Paragraph(result.get("explanation_summary", "No significant risk factors identified."), styles['BHBody']))
    elements.append(Spacer(1, 12))

    # 6. Behavior Indicators
    elements.append(Paragraph("Behavior Indicators", styles['BHHeader']))
    behaviors = result.get("simulated_behaviors", [])
    if behaviors:
        for b in behaviors:
            text = f"• {b['name']} (Severity: {b['severity']})"
            elements.append(Paragraph(text, styles['BHBody']))
            elements.append(Spacer(1, 4))
    else:
        elements.append(Paragraph("No high-risk behavioral patterns detected from static analysis.", styles['BHBody']))
    elements.append(Spacer(1, 12))

    # 7. Recommendation
    elements.append(Paragraph("Recommendation", styles['BHHeader']))
    if risk_lvl == "HIGH":
        recommendation = "<b>CRITICAL ACTION:</b> Do not execute this file. Quarantine or delete it immediately. It contains verified malicious payloads."
    elif risk_lvl == "MEDIUM":
        recommendation = "<b>CAUTION:</b> Run only in a strictly isolated sandboxed environment. File shows evasive characteristics."
    else:
        recommendation = "<b>PROCEED:</b> File is likely safe to execute under normal monitoring. If unsure, verify with additional threat intelligence sources."
    
    elements.append(Paragraph(recommendation, styles['BHBody']))

    # Build PDF
    doc.build(elements)
    
    pdf_content = buffer.getvalue()
    buffer.close()
    return pdf_content
