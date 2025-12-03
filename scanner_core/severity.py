"""Severity levels for security findings."""

from enum import Enum
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime


class Severity(Enum):
    """Severity levels for vulnerabilities."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def score(self) -> int:
        """Return numeric score for sorting."""
        scores = {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "info": 1
        }
        return scores[self.value]


@dataclass
class Finding:
    """Represents a security finding."""
    url: str
    finding_type: str
    severity: Severity
    title: str
    description: str
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            "url": self.url,
            "finding_type": self.finding_type,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "timestamp": self.timestamp
        }


@dataclass
class ScanResult:
    """Represents the result of scanning a single target."""
    target: str
    status: str  # "vulnerable", "secure", "error", "timeout"
    findings: List[Finding] = field(default_factory=list)
    scan_duration: float = 0.0
    error_message: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    @property
    def is_vulnerable(self) -> bool:
        """Check if target has any vulnerabilities."""
        return len(self.findings) > 0

    @property
    def highest_severity(self) -> Optional[Severity]:
        """Get the highest severity finding."""
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: f.severity.score).severity

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "target": self.target,
            "status": self.status,
            "is_vulnerable": self.is_vulnerable,
            "highest_severity": self.highest_severity.value if self.highest_severity else None,
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "scan_duration": self.scan_duration,
            "error_message": self.error_message,
            "timestamp": self.timestamp
        }


@dataclass
class ScanReport:
    """Represents a complete scan report."""
    results: List[ScanResult] = field(default_factory=list)
    total_targets: int = 0
    vulnerable_targets: int = 0
    secure_targets: int = 0
    error_targets: int = 0
    total_findings: int = 0
    scan_start: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    scan_end: Optional[str] = None

    def add_result(self, result: ScanResult):
        """Add a scan result to the report."""
        self.results.append(result)
        self.total_targets += 1
        self.total_findings += len(result.findings)
        
        if result.status == "error" or result.status == "timeout":
            self.error_targets += 1
        elif result.is_vulnerable:
            self.vulnerable_targets += 1
        else:
            self.secure_targets += 1

    def finalize(self):
        """Mark scan as complete."""
        self.scan_end = datetime.utcnow().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary."""
        return {
            "summary": {
                "total_targets": self.total_targets,
                "vulnerable_targets": self.vulnerable_targets,
                "secure_targets": self.secure_targets,
                "error_targets": self.error_targets,
                "total_findings": self.total_findings,
                "scan_start": self.scan_start,
                "scan_end": self.scan_end
            },
            "results": [r.to_dict() for r in self.results]
        }
