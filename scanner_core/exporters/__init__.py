"""Export modules for scan reports."""

from .json_exporter import export_json, JSONExporter
from .csv_exporter import export_csv, CSVExporter
from .html_exporter import export_html, HTMLExporter
from .pdf_exporter import export_pdf, PDFExporter


def export_report(report, output_path: str, format: str = "json") -> str:
    """
    Export a scan report to the specified format.
    
    Args:
        report: ScanReport object
        output_path: Path to save the report
        format: Output format (json, csv, html, pdf)
        
    Returns:
        Path to the exported file
    """
    exporters = {
        "json": export_json,
        "csv": export_csv,
        "html": export_html,
        "pdf": export_pdf,
    }
    
    if format not in exporters:
        raise ValueError(f"Unknown format: {format}. Supported: {list(exporters.keys())}")
    
    return exporters[format](report, output_path)


__all__ = [
    "export_json",
    "export_csv", 
    "export_html",
    "export_pdf",
    "export_report",
    "JSONExporter",
    "CSVExporter",
    "HTMLExporter",
    "PDFExporter",
]

