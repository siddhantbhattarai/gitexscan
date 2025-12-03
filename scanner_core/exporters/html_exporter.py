"""HTML export functionality for scan reports."""

from typing import Union
from pathlib import Path
from datetime import datetime

from ..severity import ScanReport, Severity


class HTMLExporter:
    """Export scan reports to HTML format."""
    
    def __init__(self):
        """Initialize the HTML exporter."""
        pass
    
    def export(self, report: ScanReport, output_path: Union[str, Path]) -> str:
        """
        Export report to HTML file.
        
        Args:
            report: ScanReport to export
            output_path: Path to save the HTML file
            
        Returns:
            Path to the exported file
        """
        output_path = Path(output_path)
        
        # Ensure .html extension
        if output_path.suffix.lower() != '.html':
            output_path = output_path.with_suffix('.html')
        
        # Create parent directories if needed
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        html_content = self._generate_html(report)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return str(output_path)
    
    def _severity_color(self, severity: Severity) -> str:
        """Get color for severity level."""
        colors = {
            Severity.CRITICAL: "#dc2626",
            Severity.HIGH: "#ea580c",
            Severity.MEDIUM: "#ca8a04",
            Severity.LOW: "#2563eb",
            Severity.INFO: "#6b7280",
        }
        return colors.get(severity, "#6b7280")
    
    def _severity_bg(self, severity: Severity) -> str:
        """Get background color for severity level."""
        colors = {
            Severity.CRITICAL: "#fef2f2",
            Severity.HIGH: "#fff7ed",
            Severity.MEDIUM: "#fefce8",
            Severity.LOW: "#eff6ff",
            Severity.INFO: "#f9fafb",
        }
        return colors.get(severity, "#f9fafb")
    
    def _generate_html(self, report: ScanReport) -> str:
        """Generate HTML content for the report."""
        
        # Count severities
        severity_counts = {s: 0 for s in Severity}
        for result in report.results:
            for finding in result.findings:
                severity_counts[finding.severity] += 1
        
        # Generate findings HTML
        findings_html = ""
        for result in report.results:
            if result.findings:
                for finding in result.findings:
                    findings_html += f"""
                    <div class="finding" style="border-left: 4px solid {self._severity_color(finding.severity)}; background: {self._severity_bg(finding.severity)};">
                        <div class="finding-header">
                            <span class="severity-badge" style="background: {self._severity_color(finding.severity)};">{finding.severity.value.upper()}</span>
                            <span class="finding-title">{self._escape(finding.title)}</span>
                        </div>
                        <div class="finding-url">{self._escape(finding.url)}</div>
                        <div class="finding-desc">{self._escape(finding.description)}</div>
                        {f'<div class="finding-evidence"><strong>Evidence:</strong> <code>{self._escape(finding.evidence[:300] if finding.evidence else "")}</code></div>' if finding.evidence else ''}
                        {f'<div class="finding-remediation"><strong>Remediation:</strong> {self._escape(finding.remediation)}</div>' if finding.remediation else ''}
                    </div>
                    """
        
        # Generate results table
        results_rows = ""
        for result in report.results:
            status_class = "status-vulnerable" if result.is_vulnerable else ("status-error" if result.status == "error" else "status-secure")
            results_rows += f"""
            <tr>
                <td><a href="{self._escape(result.target)}" target="_blank">{self._escape(result.target)}</a></td>
                <td><span class="{status_class}">{result.status}</span></td>
                <td>{result.highest_severity.value.upper() if result.highest_severity else '-'}</td>
                <td>{len(result.findings)}</td>
                <td>{result.scan_duration:.2f}s</td>
            </tr>
            """
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GitExScan Security Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: #0f172a;
            color: #e2e8f0;
            line-height: 1.6;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 2rem; }}
        
        header {{
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            border-bottom: 1px solid #334155;
            padding: 2rem 0;
            margin-bottom: 2rem;
        }}
        h1 {{ 
            font-size: 2rem;
            font-weight: 700;
            background: linear-gradient(90deg, #60a5fa, #a78bfa);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
        }}
        .subtitle {{ color: #94a3b8; font-size: 0.9rem; }}
        
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .stat-card {{
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 12px;
            padding: 1.5rem;
            text-align: center;
        }}
        .stat-value {{ font-size: 2.5rem; font-weight: 700; }}
        .stat-label {{ color: #94a3b8; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; }}
        .stat-vulnerable {{ color: #f87171; }}
        .stat-secure {{ color: #4ade80; }}
        .stat-error {{ color: #fbbf24; }}
        .stat-findings {{ color: #60a5fa; }}
        
        .severity-summary {{
            display: flex;
            gap: 1rem;
            margin-bottom: 2rem;
            flex-wrap: wrap;
        }}
        .severity-item {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.5rem 1rem;
            background: #1e293b;
            border-radius: 8px;
            border: 1px solid #334155;
        }}
        .severity-dot {{
            width: 12px;
            height: 12px;
            border-radius: 50%;
        }}
        
        section {{ margin-bottom: 2rem; }}
        h2 {{ 
            font-size: 1.25rem;
            color: #f1f5f9;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid #334155;
        }}
        
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid #334155; }}
        th {{ background: #1e293b; color: #94a3b8; font-weight: 600; font-size: 0.8rem; text-transform: uppercase; }}
        tr:hover {{ background: #1e293b; }}
        td a {{ color: #60a5fa; text-decoration: none; }}
        td a:hover {{ text-decoration: underline; }}
        
        .status-vulnerable {{ color: #f87171; font-weight: 600; }}
        .status-secure {{ color: #4ade80; }}
        .status-error {{ color: #fbbf24; }}
        
        .finding {{
            background: #1e293b;
            border-radius: 8px;
            padding: 1rem;
            margin-bottom: 1rem;
        }}
        .finding-header {{ display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.5rem; }}
        .severity-badge {{
            color: white;
            font-size: 0.7rem;
            font-weight: 700;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            text-transform: uppercase;
        }}
        .finding-title {{ font-weight: 600; color: #f1f5f9; }}
        .finding-url {{ font-size: 0.85rem; color: #60a5fa; margin-bottom: 0.5rem; word-break: break-all; }}
        .finding-desc {{ color: #cbd5e1; margin-bottom: 0.5rem; }}
        .finding-evidence {{ 
            font-size: 0.85rem;
            color: #94a3b8;
            margin-bottom: 0.5rem;
        }}
        .finding-evidence code {{
            background: #0f172a;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.8rem;
            word-break: break-all;
        }}
        .finding-remediation {{
            font-size: 0.85rem;
            color: #a5b4fc;
            padding: 0.5rem;
            background: rgba(99, 102, 241, 0.1);
            border-radius: 4px;
            border-left: 3px solid #6366f1;
        }}
        
        footer {{
            text-align: center;
            padding: 2rem;
            color: #64748b;
            font-size: 0.85rem;
            border-top: 1px solid #334155;
        }}
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>🔍 GitExScan Security Report</h1>
            <p class="subtitle">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </header>
    
    <main class="container">
        <div class="summary">
            <div class="stat-card">
                <div class="stat-value">{report.total_targets}</div>
                <div class="stat-label">Total Targets</div>
            </div>
            <div class="stat-card">
                <div class="stat-value stat-vulnerable">{report.vulnerable_targets}</div>
                <div class="stat-label">Vulnerable</div>
            </div>
            <div class="stat-card">
                <div class="stat-value stat-secure">{report.secure_targets}</div>
                <div class="stat-label">Secure</div>
            </div>
            <div class="stat-card">
                <div class="stat-value stat-error">{report.error_targets}</div>
                <div class="stat-label">Errors</div>
            </div>
            <div class="stat-card">
                <div class="stat-value stat-findings">{report.total_findings}</div>
                <div class="stat-label">Total Findings</div>
            </div>
        </div>
        
        <div class="severity-summary">
            <div class="severity-item">
                <div class="severity-dot" style="background: {self._severity_color(Severity.CRITICAL)};"></div>
                <span>Critical: {severity_counts[Severity.CRITICAL]}</span>
            </div>
            <div class="severity-item">
                <div class="severity-dot" style="background: {self._severity_color(Severity.HIGH)};"></div>
                <span>High: {severity_counts[Severity.HIGH]}</span>
            </div>
            <div class="severity-item">
                <div class="severity-dot" style="background: {self._severity_color(Severity.MEDIUM)};"></div>
                <span>Medium: {severity_counts[Severity.MEDIUM]}</span>
            </div>
            <div class="severity-item">
                <div class="severity-dot" style="background: {self._severity_color(Severity.LOW)};"></div>
                <span>Low: {severity_counts[Severity.LOW]}</span>
            </div>
            <div class="severity-item">
                <div class="severity-dot" style="background: {self._severity_color(Severity.INFO)};"></div>
                <span>Info: {severity_counts[Severity.INFO]}</span>
            </div>
        </div>
        
        <section>
            <h2>📋 Scan Results</h2>
            <table>
                <thead>
                    <tr>
                        <th>Target</th>
                        <th>Status</th>
                        <th>Severity</th>
                        <th>Findings</th>
                        <th>Duration</th>
                    </tr>
                </thead>
                <tbody>
                    {results_rows}
                </tbody>
            </table>
        </section>
        
        <section>
            <h2>🚨 Findings Detail</h2>
            {findings_html if findings_html else '<p style="color: #94a3b8;">No vulnerabilities found.</p>'}
        </section>
    </main>
    
    <footer>
        <p>Generated by GitExScan - Git Exposure Scanner</p>
    </footer>
</body>
</html>"""
        
        return html
    
    def _escape(self, text: str) -> str:
        """Escape HTML special characters."""
        if not text:
            return ""
        return (
            text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&#39;")
        )


def export_html(report: ScanReport, output_path: Union[str, Path]) -> str:
    """
    Convenience function to export report to HTML.
    
    Args:
        report: ScanReport to export
        output_path: Path to save the HTML file
        
    Returns:
        Path to the exported file
    """
    exporter = HTMLExporter()
    return exporter.export(report, output_path)
