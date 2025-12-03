"""Main Git exposure scanner."""

import time
import concurrent.futures
from typing import List, Optional, Callable
from urllib.parse import urljoin

import requests

from .severity import Severity, Finding, ScanResult, ScanReport
from .sensitive_files import (
    ALL_SENSITIVE_FILES, GIT_FILES, SensitiveFile,
    get_critical_files
)
from .utils import (
    create_session, normalize_url, build_url, check_url_exists,
    safe_request, truncate_content, RateLimiter, is_html_response
)
from .secret_scanner import scan_content_for_secrets


class GitExposureScanner:
    """Scanner for detecting exposed Git repositories and sensitive files."""
    
    def __init__(
        self,
        timeout: int = 10,
        max_workers: int = 10,
        rate_limit: float = 2.0,
        verbose: bool = False,
        check_secrets: bool = True,
        quick_scan: bool = False,
        callback: Optional[Callable[[str, str], None]] = None
    ):
        """
        Initialize the scanner.
        
        Args:
            timeout: Request timeout in seconds
            max_workers: Maximum concurrent workers
            rate_limit: Requests per second limit
            verbose: Enable verbose output
            check_secrets: Enable secret scanning in responses
            quick_scan: Only check critical files
            callback: Progress callback function(target, status)
        """
        self.timeout = timeout
        self.max_workers = max_workers
        self.rate_limiter = RateLimiter(rate_limit)
        self.verbose = verbose
        self.check_secrets = check_secrets
        self.quick_scan = quick_scan
        self.callback = callback
        self.session = create_session()
    
    def _log(self, message: str):
        """Log message if verbose mode is enabled."""
        if self.verbose:
            print(f"[*] {message}")
    
    def _notify(self, target: str, status: str):
        """Notify progress via callback."""
        if self.callback:
            self.callback(target, status)
    
    def _check_sensitive_file(
        self,
        base_url: str,
        sensitive_file: SensitiveFile
    ) -> Optional[Finding]:
        """Check if a sensitive file is exposed."""
        url = build_url(base_url, sensitive_file.path)
        
        self.rate_limiter.wait()
        exists, response, error = check_url_exists(url, self.session, self.timeout)
        
        if not exists or response is None:
            return None
        
        # For 403 responses, we can't verify content
        if response.status_code == 403:
            return Finding(
                url=url,
                finding_type=sensitive_file.category,
                severity=Severity.MEDIUM,  # Downgrade since we can't verify
                title=f"{sensitive_file.name} (Access Denied)",
                description=f"{sensitive_file.description} - Access forbidden but file may exist",
                evidence="HTTP 403 Forbidden",
                remediation="Remove the file from the web server or ensure proper access controls"
            )
        
        # Check content indicators if specified
        content = ""
        try:
            content = response.text[:10000]  # Limit content size
        except Exception:
            try:
                content = response.content[:10000].decode('utf-8', errors='ignore')
            except Exception:
                pass
        
        # If we got HTML back, this might be a custom 404 page
        if is_html_response(response) and sensitive_file.category != "ide":
            # Check if it's likely a custom error page
            lower_content = content.lower()
            if any(indicator in lower_content for indicator in 
                   ['not found', '404', 'error', 'page not found', 'does not exist']):
                return None
        
        # Verify with content indicators if available
        if sensitive_file.indicators:
            found_indicator = False
            for indicator in sensitive_file.indicators:
                if indicator in content:
                    found_indicator = True
                    break
            
            if not found_indicator:
                # Binary files might not have readable indicators
                if sensitive_file.category not in ['database', 'backup', 'ide']:
                    return None
        
        # Create finding
        evidence = truncate_content(content, 200) if content else "File accessible"
        
        return Finding(
            url=url,
            finding_type=sensitive_file.category,
            severity=sensitive_file.severity,
            title=f"{sensitive_file.name} Exposed",
            description=sensitive_file.description,
            evidence=evidence,
            remediation=self._get_remediation(sensitive_file.category)
        )
    
    def _get_remediation(self, category: str) -> str:
        """Get remediation advice based on category."""
        remediations = {
            "git": "Add '.git' to your web server's deny rules. For Apache: 'RedirectMatch 404 /\\.git'. For Nginx: 'location ~ /\\.git { deny all; }'",
            "config": "Move configuration files outside the web root or deny access via web server configuration",
            "wordpress": "Ensure wp-config.php is not accessible. Remove any backup files from the server",
            "database": "Never store database dumps in web-accessible locations. Delete the file immediately",
            "backup": "Remove backup files from web-accessible locations",
            "credentials": "Remove credential files from the web server. Rotate any exposed credentials immediately",
            "vcs": "Remove version control directories from production or deny access via web server",
            "ide": "Remove IDE configuration files from production deployments"
        }
        return remediations.get(category, "Remove or restrict access to this file")
    
    def _check_git_exposure(self, base_url: str) -> List[Finding]:
        """Check for Git repository exposure."""
        findings = []
        
        for git_file in GIT_FILES:
            finding = self._check_sensitive_file(base_url, git_file)
            if finding:
                findings.append(finding)
                self._log(f"Found: {git_file.path} at {base_url}")
        
        return findings
    
    def _check_all_sensitive_files(self, base_url: str) -> List[Finding]:
        """Check all sensitive files."""
        findings = []
        
        files_to_check = get_critical_files() if self.quick_scan else ALL_SENSITIVE_FILES
        
        for sensitive_file in files_to_check:
            finding = self._check_sensitive_file(base_url, sensitive_file)
            if finding:
                findings.append(finding)
                self._log(f"Found: {sensitive_file.path} at {base_url}")
        
        return findings
    
    def scan_target(self, target: str) -> ScanResult:
        """
        Scan a single target for vulnerabilities.
        
        Args:
            target: URL to scan
            
        Returns:
            ScanResult with findings
        """
        target = normalize_url(target)
        start_time = time.time()
        
        self._log(f"Scanning: {target}")
        self._notify(target, "scanning")
        
        try:
            # First, check if target is reachable
            response, error = safe_request(target, self.session, self.timeout)
            
            if error:
                self._notify(target, "error")
                return ScanResult(
                    target=target,
                    status="error",
                    error_message=error,
                    scan_duration=time.time() - start_time
                )
            
            findings = []
            
            # Check for sensitive files
            findings.extend(self._check_all_sensitive_files(target))
            
            # Check for secrets in main page if enabled
            if self.check_secrets and response:
                try:
                    secret_findings = scan_content_for_secrets(
                        response.text[:50000],
                        target
                    )
                    findings.extend(secret_findings)
                except Exception:
                    pass
            
            scan_duration = time.time() - start_time
            
            status = "vulnerable" if findings else "secure"
            self._notify(target, status)
            
            return ScanResult(
                target=target,
                status=status,
                findings=findings,
                scan_duration=scan_duration
            )
            
        except Exception as e:
            self._notify(target, "error")
            return ScanResult(
                target=target,
                status="error",
                error_message=str(e),
                scan_duration=time.time() - start_time
            )
    
    def scan_targets(self, targets: List[str]) -> ScanReport:
        """
        Scan multiple targets concurrently.
        
        Args:
            targets: List of URLs to scan
            
        Returns:
            ScanReport with all results
        """
        report = ScanReport()
        
        self._log(f"Starting scan of {len(targets)} targets")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_target = {
                executor.submit(self.scan_target, target): target
                for target in targets
            }
            
            for future in concurrent.futures.as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    result = future.result()
                    report.add_result(result)
                except Exception as e:
                    report.add_result(ScanResult(
                        target=target,
                        status="error",
                        error_message=str(e)
                    ))
        
        report.finalize()
        self._log(f"Scan complete. Vulnerable: {report.vulnerable_targets}/{report.total_targets}")
        
        return report


def scan_url(url: str, verbose: bool = False) -> ScanResult:
    """Convenience function to scan a single URL."""
    scanner = GitExposureScanner(verbose=verbose)
    return scanner.scan_target(url)


def scan_urls(urls: List[str], verbose: bool = False) -> ScanReport:
    """Convenience function to scan multiple URLs."""
    scanner = GitExposureScanner(verbose=verbose)
    return scanner.scan_targets(urls)
