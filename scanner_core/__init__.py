"""GitExScan - Git Exposure Scanner Core Module."""

from .severity import Severity, Finding, ScanResult, ScanReport
from .scanner import GitExposureScanner, scan_url, scan_urls
from .secret_scanner import scan_content_for_secrets
from .repo_reconstructor import GitRepoReconstructor, reconstruct_repo
from .utils import normalize_url, parse_urls_from_file
from .exporters import export_report, export_json, export_csv, export_html, export_pdf

__version__ = "0.1.0"
__all__ = [
    # Core classes
    "GitExposureScanner",
    "GitRepoReconstructor",
    
    # Data classes
    "Severity",
    "Finding", 
    "ScanResult",
    "ScanReport",
    
    # Functions
    "scan_url",
    "scan_urls",
    "scan_content_for_secrets",
    "reconstruct_repo",
    "normalize_url",
    "parse_urls_from_file",
    
    # Exporters
    "export_report",
    "export_json",
    "export_csv",
    "export_html",
    "export_pdf",
]

