"""Scanner for detecting exposed secrets and API keys."""

import re
from typing import List, Dict, Pattern
from dataclasses import dataclass

from .severity import Severity, Finding


@dataclass
class SecretPattern:
    """Definition of a secret pattern to detect."""
    name: str
    pattern: Pattern
    severity: Severity
    description: str


# Compiled regex patterns for secret detection
SECRET_PATTERNS: List[SecretPattern] = [
    # AWS
    SecretPattern(
        name="AWS Access Key ID",
        pattern=re.compile(r'AKIA[0-9A-Z]{16}'),
        severity=Severity.CRITICAL,
        description="AWS Access Key ID found - immediate credential rotation required"
    ),
    SecretPattern(
        name="AWS Secret Access Key",
        pattern=re.compile(r'(?i)aws_secret_access_key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?'),
        severity=Severity.CRITICAL,
        description="AWS Secret Access Key found - immediate credential rotation required"
    ),
    
    # Google
    SecretPattern(
        name="Google API Key",
        pattern=re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
        severity=Severity.HIGH,
        description="Google API Key exposed"
    ),
    SecretPattern(
        name="Google OAuth",
        pattern=re.compile(r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com'),
        severity=Severity.HIGH,
        description="Google OAuth Client ID exposed"
    ),
    
    # GitHub
    SecretPattern(
        name="GitHub Token",
        pattern=re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,}'),
        severity=Severity.CRITICAL,
        description="GitHub personal access token exposed"
    ),
    SecretPattern(
        name="GitHub OAuth",
        pattern=re.compile(r'(?i)github[_\-\.]?(?:oauth[_\-\.]?)?(?:token|secret|key)\s*[=:]\s*["\']?([a-f0-9]{40})["\']?'),
        severity=Severity.CRITICAL,
        description="GitHub OAuth token exposed"
    ),
    
    # Stripe
    SecretPattern(
        name="Stripe Secret Key",
        pattern=re.compile(r'sk_live_[0-9a-zA-Z]{24,}'),
        severity=Severity.CRITICAL,
        description="Stripe live secret key exposed - immediate rotation required"
    ),
    SecretPattern(
        name="Stripe Publishable Key",
        pattern=re.compile(r'pk_live_[0-9a-zA-Z]{24,}'),
        severity=Severity.MEDIUM,
        description="Stripe live publishable key exposed"
    ),
    
    # Slack
    SecretPattern(
        name="Slack Token",
        pattern=re.compile(r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*'),
        severity=Severity.HIGH,
        description="Slack token exposed"
    ),
    SecretPattern(
        name="Slack Webhook",
        pattern=re.compile(r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24}'),
        severity=Severity.MEDIUM,
        description="Slack webhook URL exposed"
    ),
    
    # Private Keys
    SecretPattern(
        name="RSA Private Key",
        pattern=re.compile(r'-----BEGIN RSA PRIVATE KEY-----'),
        severity=Severity.CRITICAL,
        description="RSA private key exposed"
    ),
    SecretPattern(
        name="OpenSSH Private Key",
        pattern=re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----'),
        severity=Severity.CRITICAL,
        description="OpenSSH private key exposed"
    ),
    SecretPattern(
        name="PGP Private Key",
        pattern=re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----'),
        severity=Severity.CRITICAL,
        description="PGP private key exposed"
    ),
    SecretPattern(
        name="EC Private Key",
        pattern=re.compile(r'-----BEGIN EC PRIVATE KEY-----'),
        severity=Severity.CRITICAL,
        description="EC private key exposed"
    ),
    
    # Database connection strings
    SecretPattern(
        name="MySQL Connection String",
        pattern=re.compile(r'mysql://[^:]+:[^@]+@[^/]+/[^\s"\']+'),
        severity=Severity.CRITICAL,
        description="MySQL connection string with credentials exposed"
    ),
    SecretPattern(
        name="PostgreSQL Connection String",
        pattern=re.compile(r'postgres(?:ql)?://[^:]+:[^@]+@[^/]+/[^\s"\']+'),
        severity=Severity.CRITICAL,
        description="PostgreSQL connection string with credentials exposed"
    ),
    SecretPattern(
        name="MongoDB Connection String",
        pattern=re.compile(r'mongodb(?:\+srv)?://[^:]+:[^@]+@[^\s"\']+'),
        severity=Severity.CRITICAL,
        description="MongoDB connection string with credentials exposed"
    ),
    SecretPattern(
        name="Redis Connection String",
        pattern=re.compile(r'redis://[^:]*:[^@]+@[^\s"\']+'),
        severity=Severity.HIGH,
        description="Redis connection string with credentials exposed"
    ),
    
    # Twilio
    SecretPattern(
        name="Twilio Account SID",
        pattern=re.compile(r'AC[a-z0-9]{32}'),
        severity=Severity.HIGH,
        description="Twilio Account SID exposed"
    ),
    SecretPattern(
        name="Twilio Auth Token",
        pattern=re.compile(r'(?i)twilio[_\-\.]?auth[_\-\.]?token\s*[=:]\s*["\']?([a-f0-9]{32})["\']?'),
        severity=Severity.CRITICAL,
        description="Twilio Auth Token exposed"
    ),
    
    # SendGrid
    SecretPattern(
        name="SendGrid API Key",
        pattern=re.compile(r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}'),
        severity=Severity.HIGH,
        description="SendGrid API Key exposed"
    ),
    
    # Mailgun
    SecretPattern(
        name="Mailgun API Key",
        pattern=re.compile(r'key-[0-9a-zA-Z]{32}'),
        severity=Severity.HIGH,
        description="Mailgun API Key exposed"
    ),
    
    # Square
    SecretPattern(
        name="Square Access Token",
        pattern=re.compile(r'sq0atp-[0-9A-Za-z\-_]{22}'),
        severity=Severity.HIGH,
        description="Square access token exposed"
    ),
    SecretPattern(
        name="Square OAuth Secret",
        pattern=re.compile(r'sq0csp-[0-9A-Za-z\-_]{43}'),
        severity=Severity.HIGH,
        description="Square OAuth secret exposed"
    ),
    
    # PayPal
    SecretPattern(
        name="PayPal Braintree Access Token",
        pattern=re.compile(r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}'),
        severity=Severity.CRITICAL,
        description="PayPal Braintree access token exposed"
    ),
    
    # Heroku
    SecretPattern(
        name="Heroku API Key",
        pattern=re.compile(r'(?i)heroku[_\-\.]?api[_\-\.]?key\s*[=:]\s*["\']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\']?'),
        severity=Severity.HIGH,
        description="Heroku API Key exposed"
    ),
    
    # Firebase
    SecretPattern(
        name="Firebase Database URL",
        pattern=re.compile(r'https://[a-z0-9-]+\.firebaseio\.com'),
        severity=Severity.MEDIUM,
        description="Firebase database URL exposed"
    ),
    
    # Generic patterns
    SecretPattern(
        name="Generic API Key",
        pattern=re.compile(r'(?i)(?:api[_\-\.]?key|apikey)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?'),
        severity=Severity.MEDIUM,
        description="Potential API key exposed"
    ),
    SecretPattern(
        name="Generic Secret",
        pattern=re.compile(r'(?i)(?:secret|password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\']{8,})["\']?'),
        severity=Severity.MEDIUM,
        description="Potential secret/password exposed"
    ),
    SecretPattern(
        name="Bearer Token",
        pattern=re.compile(r'(?i)bearer\s+[a-zA-Z0-9_\-\.=]+'),
        severity=Severity.HIGH,
        description="Bearer token exposed"
    ),
    SecretPattern(
        name="Basic Auth",
        pattern=re.compile(r'(?i)basic\s+[a-zA-Z0-9+/=]{20,}'),
        severity=Severity.HIGH,
        description="Basic authentication credentials exposed"
    ),
    SecretPattern(
        name="JWT Token",
        pattern=re.compile(r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'),
        severity=Severity.HIGH,
        description="JWT token exposed"
    ),
]


def scan_content_for_secrets(content: str, source_url: str) -> List[Finding]:
    """
    Scan content for exposed secrets.
    
    Args:
        content: Text content to scan
        source_url: URL where the content was found
        
    Returns:
        List of findings for detected secrets
    """
    findings = []
    seen_patterns = set()  # Avoid duplicate findings
    
    for secret_pattern in SECRET_PATTERNS:
        matches = secret_pattern.pattern.findall(content)
        
        for match in matches:
            # Create a unique key for this finding
            if isinstance(match, tuple):
                match = match[0] if match else ""
            
            finding_key = f"{secret_pattern.name}:{match[:20]}"
            
            if finding_key in seen_patterns:
                continue
            seen_patterns.add(finding_key)
            
            # Mask the secret for evidence
            if len(match) > 10:
                masked = match[:4] + "*" * (len(match) - 8) + match[-4:]
            else:
                masked = match[:2] + "*" * (len(match) - 2)
            
            findings.append(Finding(
                url=source_url,
                finding_type="secret",
                severity=secret_pattern.severity,
                title=f"{secret_pattern.name} Detected",
                description=secret_pattern.description,
                evidence=f"Pattern matched: {masked}",
                remediation="Rotate this credential immediately and remove it from the exposed location"
            ))
    
    return findings


def scan_file_for_secrets(filepath: str) -> List[Finding]:
    """
    Scan a file for exposed secrets.
    
    Args:
        filepath: Path to the file to scan
        
    Returns:
        List of findings for detected secrets
    """
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        return scan_content_for_secrets(content, f"file://{filepath}")
    except Exception as e:
        return []
