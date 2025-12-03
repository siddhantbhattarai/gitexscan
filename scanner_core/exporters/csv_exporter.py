"""CSV export functionality for scan reports."""

import csv
from typing import Union, List, Dict
from pathlib import Path

from ..severity import ScanReport, ScanResult, Finding


class CSVExporter:
    """Export scan reports to CSV format."""
    
    def __init__(self):
        """Initialize the CSV exporter."""
        pass
    
    def export(self, report: ScanReport, output_path: Union[str, Path]) -> str:
        """
        Export report to CSV file.
        
        Args:
            report: ScanReport to export
            output_path: Path to save the CSV file
            
        Returns:
            Path to the exported file
        """
        output_path = Path(output_path)
        
        # Ensure .csv extension
        if output_path.suffix.lower() != '.csv':
            output_path = output_path.with_suffix('.csv')
        
        # Create parent directories if needed
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Flatten findings for CSV
        rows = self._flatten_report(report)
        
        if not rows:
            # Write empty file with headers only
            rows = [{}]
        
        # Get all possible headers
        headers = [
            'target',
            'status',
            'is_vulnerable',
            'highest_severity',
            'finding_url',
            'finding_type',
            'finding_severity',
            'finding_title',
            'finding_description',
            'finding_evidence',
            'finding_remediation',
            'scan_duration',
            'timestamp'
        ]
        
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=headers, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(rows)
        
        return str(output_path)
    
    def _flatten_report(self, report: ScanReport) -> List[Dict]:
        """Flatten report into rows for CSV."""
        rows = []
        
        for result in report.results:
            if result.findings:
                # One row per finding
                for finding in result.findings:
                    rows.append({
                        'target': result.target,
                        'status': result.status,
                        'is_vulnerable': 'Yes' if result.is_vulnerable else 'No',
                        'highest_severity': result.highest_severity.value if result.highest_severity else '',
                        'finding_url': finding.url,
                        'finding_type': finding.finding_type,
                        'finding_severity': finding.severity.value,
                        'finding_title': finding.title,
                        'finding_description': finding.description,
                        'finding_evidence': (finding.evidence or '')[:200],  # Truncate evidence
                        'finding_remediation': finding.remediation or '',
                        'scan_duration': f"{result.scan_duration:.2f}s",
                        'timestamp': result.timestamp,
                    })
            else:
                # One row for targets with no findings
                rows.append({
                    'target': result.target,
                    'status': result.status,
                    'is_vulnerable': 'No',
                    'highest_severity': '',
                    'finding_url': '',
                    'finding_type': '',
                    'finding_severity': '',
                    'finding_title': '',
                    'finding_description': result.error_message or '',
                    'finding_evidence': '',
                    'finding_remediation': '',
                    'scan_duration': f"{result.scan_duration:.2f}s",
                    'timestamp': result.timestamp,
                })
        
        return rows
    
    def export_summary(self, report: ScanReport, output_path: Union[str, Path]) -> str:
        """
        Export summary CSV (one row per target).
        
        Args:
            report: ScanReport to export
            output_path: Path to save the CSV file
            
        Returns:
            Path to the exported file
        """
        output_path = Path(output_path)
        
        if output_path.suffix.lower() != '.csv':
            output_path = output_path.with_suffix('.csv')
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        headers = [
            'target',
            'status',
            'is_vulnerable',
            'highest_severity',
            'findings_count',
            'scan_duration',
            'error_message',
            'timestamp'
        ]
        
        rows = []
        for result in report.results:
            rows.append({
                'target': result.target,
                'status': result.status,
                'is_vulnerable': 'Yes' if result.is_vulnerable else 'No',
                'highest_severity': result.highest_severity.value if result.highest_severity else '',
                'findings_count': len(result.findings),
                'scan_duration': f"{result.scan_duration:.2f}s",
                'error_message': result.error_message or '',
                'timestamp': result.timestamp,
            })
        
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            writer.writerows(rows)
        
        return str(output_path)


def export_csv(report: ScanReport, output_path: Union[str, Path]) -> str:
    """
    Convenience function to export report to CSV.
    
    Args:
        report: ScanReport to export
        output_path: Path to save the CSV file
        
    Returns:
        Path to the exported file
    """
    exporter = CSVExporter()
    return exporter.export(report, output_path)
