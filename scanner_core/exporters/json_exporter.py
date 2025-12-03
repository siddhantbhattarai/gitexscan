"""JSON export functionality for scan reports."""

import json
from typing import Union
from pathlib import Path

from ..severity import ScanReport


class JSONExporter:
    """Export scan reports to JSON format."""
    
    def __init__(self, pretty: bool = True):
        """
        Initialize the JSON exporter.
        
        Args:
            pretty: Whether to format JSON with indentation
        """
        self.pretty = pretty
    
    def export(self, report: ScanReport, output_path: Union[str, Path]) -> str:
        """
        Export report to JSON file.
        
        Args:
            report: ScanReport to export
            output_path: Path to save the JSON file
            
        Returns:
            Path to the exported file
        """
        output_path = Path(output_path)
        
        # Ensure .json extension
        if output_path.suffix.lower() != '.json':
            output_path = output_path.with_suffix('.json')
        
        # Create parent directories if needed
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Convert report to dict
        data = report.to_dict()
        
        # Write JSON
        with open(output_path, 'w', encoding='utf-8') as f:
            if self.pretty:
                json.dump(data, f, indent=2, ensure_ascii=False)
            else:
                json.dump(data, f, ensure_ascii=False)
        
        return str(output_path)
    
    def to_string(self, report: ScanReport) -> str:
        """
        Convert report to JSON string.
        
        Args:
            report: ScanReport to convert
            
        Returns:
            JSON string
        """
        data = report.to_dict()
        
        if self.pretty:
            return json.dumps(data, indent=2, ensure_ascii=False)
        else:
            return json.dumps(data, ensure_ascii=False)


def export_json(report: ScanReport, output_path: Union[str, Path]) -> str:
    """
    Convenience function to export report to JSON.
    
    Args:
        report: ScanReport to export
        output_path: Path to save the JSON file
        
    Returns:
        Path to the exported file
    """
    exporter = JSONExporter()
    return exporter.export(report, output_path)
