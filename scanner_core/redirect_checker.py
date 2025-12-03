"""Redirect checking and following module."""

from typing import List, Optional, Tuple
from urllib.parse import urlparse, urljoin
from dataclasses import dataclass

import requests

from .utils import create_session, normalize_url, DEFAULT_TIMEOUT


@dataclass
class RedirectInfo:
    """Information about a redirect chain."""
    original_url: str
    final_url: str
    redirect_count: int
    redirect_chain: List[str]
    is_same_domain: bool
    crosses_protocol: bool


def follow_redirects(
    url: str,
    max_redirects: int = 10,
    timeout: int = DEFAULT_TIMEOUT
) -> RedirectInfo:
    """
    Follow redirects and return information about the chain.
    
    Args:
        url: URL to check
        max_redirects: Maximum redirects to follow
        timeout: Request timeout
        
    Returns:
        RedirectInfo with redirect chain details
    """
    session = create_session()
    original_url = normalize_url(url)
    redirect_chain = [original_url]
    current_url = original_url
    
    original_parsed = urlparse(original_url)
    original_domain = original_parsed.netloc.lower()
    original_scheme = original_parsed.scheme
    
    crosses_protocol = False
    
    for i in range(max_redirects):
        try:
            response = session.get(
                current_url,
                allow_redirects=False,
                timeout=timeout,
                verify=False
            )
            
            # Check for redirect status codes
            if response.status_code in [301, 302, 303, 307, 308]:
                location = response.headers.get('Location', '')
                
                if not location:
                    break
                
                # Handle relative redirects
                if not location.startswith(('http://', 'https://')):
                    location = urljoin(current_url, location)
                
                location = normalize_url(location)
                redirect_chain.append(location)
                
                # Check protocol change
                location_parsed = urlparse(location)
                if location_parsed.scheme != original_scheme:
                    crosses_protocol = True
                
                current_url = location
            else:
                # No redirect
                break
                
        except requests.RequestException:
            break
    
    final_url = redirect_chain[-1]
    final_parsed = urlparse(final_url)
    final_domain = final_parsed.netloc.lower()
    
    is_same_domain = (
        original_domain == final_domain or
        final_domain.endswith('.' + original_domain) or
        original_domain.endswith('.' + final_domain)
    )
    
    return RedirectInfo(
        original_url=original_url,
        final_url=final_url,
        redirect_count=len(redirect_chain) - 1,
        redirect_chain=redirect_chain,
        is_same_domain=is_same_domain,
        crosses_protocol=crosses_protocol
    )


def check_redirect_to_login(
    url: str,
    timeout: int = DEFAULT_TIMEOUT
) -> Tuple[bool, str]:
    """
    Check if a URL redirects to a login page.
    
    Args:
        url: URL to check
        timeout: Request timeout
        
    Returns:
        Tuple of (redirects_to_login, final_url)
    """
    redirect_info = follow_redirects(url, timeout=timeout)
    
    login_indicators = [
        '/login',
        '/signin',
        '/sign-in',
        '/auth',
        '/authenticate',
        '/sso',
        '/cas/login',
        '/oauth',
        '/saml',
        'login.php',
        'login.aspx',
        'signin.aspx',
    ]
    
    final_lower = redirect_info.final_url.lower()
    
    for indicator in login_indicators:
        if indicator in final_lower:
            return True, redirect_info.final_url
    
    return False, redirect_info.final_url


def get_effective_url(url: str, timeout: int = DEFAULT_TIMEOUT) -> str:
    """
    Get the effective URL after following all redirects.
    
    Args:
        url: URL to resolve
        timeout: Request timeout
        
    Returns:
        Final URL after redirects
    """
    redirect_info = follow_redirects(url, timeout=timeout)
    return redirect_info.final_url


def analyze_redirect_security(url: str, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """
    Analyze redirect chain for security implications.
    
    Args:
        url: URL to analyze
        timeout: Request timeout
        
    Returns:
        Dict with security analysis
    """
    redirect_info = follow_redirects(url, timeout=timeout)
    
    issues = []
    
    # Check for HTTP to HTTPS downgrade
    for i, redir_url in enumerate(redirect_info.redirect_chain[:-1]):
        parsed = urlparse(redir_url)
        next_parsed = urlparse(redirect_info.redirect_chain[i + 1])
        
        if parsed.scheme == 'https' and next_parsed.scheme == 'http':
            issues.append({
                "type": "https_downgrade",
                "message": f"HTTPS to HTTP downgrade: {redir_url} -> {redirect_info.redirect_chain[i + 1]}",
                "severity": "high"
            })
    
    # Check for open redirect potential
    if not redirect_info.is_same_domain:
        issues.append({
            "type": "cross_domain_redirect",
            "message": f"Redirects to different domain: {redirect_info.final_url}",
            "severity": "medium"
        })
    
    # Check for excessive redirects
    if redirect_info.redirect_count > 5:
        issues.append({
            "type": "excessive_redirects",
            "message": f"Excessive redirect chain ({redirect_info.redirect_count} redirects)",
            "severity": "low"
        })
    
    return {
        "redirect_info": {
            "original_url": redirect_info.original_url,
            "final_url": redirect_info.final_url,
            "redirect_count": redirect_info.redirect_count,
            "redirect_chain": redirect_info.redirect_chain,
            "is_same_domain": redirect_info.is_same_domain,
            "crosses_protocol": redirect_info.crosses_protocol,
        },
        "issues": issues,
        "has_issues": len(issues) > 0
    }
