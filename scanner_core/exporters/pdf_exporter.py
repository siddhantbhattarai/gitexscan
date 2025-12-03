"""PDF export functionality for scan reports."""

from typing import Union
from pathlib import Path
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image, HRFlowable
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

from ..severity import ScanReport, Severity


class PDFExporter:
    """Export scan reports to PDF format."""
    
    def __init__(self, page_size=A4):
        """
        Initialize the PDF exporter.
        
        Args:
            page_size: Page size (A4 or letter)
        """
        self.page_size = page_size
        self.styles = getSampleStyleSheet()
        self._setup_styles()
    
    def _setup_styles(self):
        """Setup custom paragraph styles."""
        self.styles.add(ParagraphStyle(
            name='Title2',
            parent=self.styles['Title'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.HexColor('#1e293b')
        ))
        
        self.styles.add(ParagraphStyle(
            name='Heading2Custom',
            parent=self.styles['Heading2'],
            fontSize=14,
            spaceAfter=12,
            spaceBefore=20,
            textColor=colors.HexColor('#334155')
        ))
        
        self.styles.add(ParagraphStyle(
            name='Finding',
            parent=self.styles['Normal'],
            fontSize=10,
            spaceAfter=6,
        ))
        
        self.styles.add(ParagraphStyle(
            name='URL',
            parent=self.styles['Normal'],
            fontSize=9,
            textColor=colors.HexColor('#2563eb'),
            spaceAfter=4,
        ))
        
        self.styles.add(ParagraphStyle(
            name='Evidence',
            parent=self.styles['Normal'],
            fontSize=8,
            textColor=colors.HexColor('#64748b'),
            leftIndent=20,
            spaceAfter=4,
            fontName='Courier',
        ))
    
    def _severity_color(self, severity: Severity) -> colors.Color:
        """Get color for severity level."""
        color_map = {
            Severity.CRITICAL: colors.HexColor('#dc2626'),
            Severity.HIGH: colors.HexColor('#ea580c'),
            Severity.MEDIUM: colors.HexColor('#ca8a04'),
            Severity.LOW: colors.HexColor('#2563eb'),
            Severity.INFO: colors.HexColor('#6b7280'),
        }
        return color_map.get(severity, colors.HexColor('#6b7280'))
    
    def export(self, report: ScanReport, output_path: Union[str, Path]) -> str:
        """
        Export report to PDF file.
        
        Args:
            report: ScanReport to export
            output_path: Path to save the PDF file
            
        Returns:
            Path to the exported file
        """
        output_path = Path(output_path)
        
        # Ensure .pdf extension
        if output_path.suffix.lower() != '.pdf':
            output_path = output_path.with_suffix('.pdf')
        
        # Create parent directories if needed
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Create document
        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=self.page_size,
            rightMargin=0.75*inch,
            leftMargin=0.75*inch,
            topMargin=0.75*inch,
            bottomMargin=0.75*inch
        )
        
        # Build content
        story = []
        
        # Title
        story.append(Paragraph("GitExScan Security Report", self.styles['Title2']))
        story.append(Paragraph(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            self.styles['Normal']
        ))
        story.append(Spacer(1, 20))
        
        # Summary
        story.append(Paragraph("Executive Summary", self.styles['Heading2Custom']))
        
        summary_data = [
            ['Metric', 'Value'],
            ['Total Targets Scanned', str(report.total_targets)],
            ['Vulnerable Targets', str(report.vulnerable_targets)],
            ['Secure Targets', str(report.secure_targets)],
            ['Errors', str(report.error_targets)],
            ['Total Findings', str(report.total_findings)],
        ]
        
        summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8fafc')),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('TOPPADDING', (0, 1), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 8),
        ]))
        
        story.append(summary_table)
        story.append(Spacer(1, 20))
        
        # Severity breakdown
        severity_counts = {s: 0 for s in Severity}
        for result in report.results:
            for finding in result.findings:
                severity_counts[finding.severity] += 1
        
        story.append(Paragraph("Findings by Severity", self.styles['Heading2Custom']))
        
        severity_data = [['Severity', 'Count']]
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            severity_data.append([sev.value.upper(), str(severity_counts[sev])])
        
        severity_table = Table(severity_data, colWidths=[2*inch, 1.5*inch])
        severity_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            # Color code severity rows
            ('TEXTCOLOR', (0, 1), (0, 1), self._severity_color(Severity.CRITICAL)),
            ('TEXTCOLOR', (0, 2), (0, 2), self._severity_color(Severity.HIGH)),
            ('TEXTCOLOR', (0, 3), (0, 3), self._severity_color(Severity.MEDIUM)),
            ('TEXTCOLOR', (0, 4), (0, 4), self._severity_color(Severity.LOW)),
            ('TEXTCOLOR', (0, 5), (0, 5), self._severity_color(Severity.INFO)),
        ]))
        
        story.append(severity_table)
        story.append(Spacer(1, 20))
        
        # Results table
        story.append(Paragraph("Scan Results", self.styles['Heading2Custom']))
        
        results_data = [['Target', 'Status', 'Findings']]
        for result in report.results:
            # Truncate long URLs
            target = result.target
            if len(target) > 50:
                target = target[:47] + '...'
            
            results_data.append([
                target,
                result.status.upper(),
                str(len(result.findings))
            ])
        
        results_table = Table(results_data, colWidths=[4*inch, 1.2*inch, 0.8*inch])
        results_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
        ]))
        
        story.append(results_table)
        
        # Detailed findings
        if report.total_findings > 0:
            story.append(PageBreak())
            story.append(Paragraph("Detailed Findings", self.styles['Heading2Custom']))
            
            for result in report.results:
                if not result.findings:
                    continue
                
                story.append(Spacer(1, 10))
                story.append(Paragraph(f"<b>Target:</b> {result.target}", self.styles['Finding']))
                story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e2e8f0')))
                
                for finding in result.findings:
                    sev_color = self._severity_color(finding.severity)
                    
                    story.append(Spacer(1, 8))
                    story.append(Paragraph(
                        f"<font color='{sev_color.hexval()}'>[{finding.severity.value.upper()}]</font> "
                        f"<b>{finding.title}</b>",
                        self.styles['Finding']
                    ))
                    
                    story.append(Paragraph(finding.url, self.styles['URL']))
                    story.append(Paragraph(finding.description, self.styles['Finding']))
                    
                    if finding.evidence:
                        evidence_text = finding.evidence[:200]
                        if len(finding.evidence) > 200:
                            evidence_text += "..."
                        story.append(Paragraph(f"Evidence: {evidence_text}", self.styles['Evidence']))
                    
                    if finding.remediation:
                        story.append(Paragraph(
                            f"<b>Remediation:</b> {finding.remediation}",
                            self.styles['Finding']
                        ))
        
        # Build PDF
        doc.build(story)
        
        return str(output_path)


def export_pdf(report: ScanReport, output_path: Union[str, Path]) -> str:
    """
    Convenience function to export report to PDF.
    
    Args:
        report: ScanReport to export
        output_path: Path to save the PDF file
        
    Returns:
        Path to the exported file
    """
    exporter = PDFExporter()
    return exporter.export(report, output_path)
