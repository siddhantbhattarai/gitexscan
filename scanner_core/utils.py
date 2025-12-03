"""Utility functions for the scanner."""

import re
import time
import warnings
from urllib.parse import urlparse, urljoin
from typing import Optional, Tuple, Dict, Any
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore', message='Unverified HTTPS request')


# Default timeout for requests
DEFAULT_TIMEOUT = 10

# Default user agent
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

# Headers to use for requests
DEFAULT_HEADERS = {
    "User-Agent": DEFAULT_USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
}


def create_session(
    retries: int = 3,
    backoff_factor: float = 0.3,
    status_forcelist: Tuple[int, ...] = (500, 502, 503, 504)
) -> requests.Session:
    """Create a requests session with retry logic."""
    session = requests.Session()
    
    retry_strategy = Retry(
        total=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )
    
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update(DEFAULT_HEADERS)
    
    return session


def normalize_url(url: str) -> str:
    """Normalize a URL to ensure it has a scheme."""
    url = url.strip()
    
    if not url:
        return ""
    
    # Add scheme if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # Parse and reconstruct to normalize
    parsed = urlparse(url)
    
    # Ensure path ends without trailing slash for consistency
    path = parsed.path.rstrip('/') if parsed.path != '/' else ''
    
    # Reconstruct URL
    normalized = f"{parsed.scheme}://{parsed.netloc}{path}"
    
    return normalized


def build_url(base_url: str, path: str) -> str:
    """Build a full URL from base URL and path."""
    base_url = normalize_url(base_url)
    
    # Ensure base_url ends with /
    if not base_url.endswith('/'):
        base_url += '/'
    
    # Remove leading slash from path
    path = path.lstrip('/')
    
    return urljoin(base_url, path)


def safe_request(
    url: str,
    session: Optional[requests.Session] = None,
    timeout: int = DEFAULT_TIMEOUT,
    method: str = "GET",
    allow_redirects: bool = True,
    **kwargs
) -> Tuple[Optional[requests.Response], Optional[str]]:
    """
    Make a safe HTTP request with error handling.
    
    Returns:
        Tuple of (response, error_message)
    """
    if session is None:
        session = create_session()
    
    try:
        response = session.request(
            method=method,
            url=url,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=True,  # Verify SSL
            **kwargs
        )
        return response, None
    except requests.exceptions.SSLError as e:
        # Try without SSL verification
        try:
            response = session.request(
                method=method,
                url=url,
                timeout=timeout,
                allow_redirects=allow_redirects,
                verify=False,
                **kwargs
            )
            return response, None
        except Exception as e2:
            return None, f"SSL Error: {str(e)}"
    except requests.exceptions.Timeout:
        return None, "Request timed out"
    except requests.exceptions.ConnectionError as e:
        return None, f"Connection error: {str(e)}"
    except requests.exceptions.TooManyRedirects:
        return None, "Too many redirects"
    except requests.exceptions.RequestException as e:
        return None, f"Request error: {str(e)}"


def check_url_exists(
    url: str,
    session: Optional[requests.Session] = None,
    timeout: int = DEFAULT_TIMEOUT
) -> Tuple[bool, Optional[requests.Response], Optional[str]]:
    """
    Check if a URL exists and returns content.
    
    Returns:
        Tuple of (exists, response, error_message)
    """
    response, error = safe_request(url, session, timeout)
    
    if error:
        return False, None, error
    
    if response is None:
        return False, None, "No response received"
    
    # Check for success status codes
    if response.status_code == 200:
        return True, response, None
    elif response.status_code == 403:
        # Forbidden might still indicate the file exists
        return True, response, "Access forbidden (file may exist)"
    elif response.status_code == 404:
        return False, response, None
    else:
        return False, response, f"HTTP {response.status_code}"


def extract_domain(url: str) -> str:
    """Extract domain from URL."""
    parsed = urlparse(normalize_url(url))
    return parsed.netloc


def is_valid_url(url: str) -> bool:
    """Check if a string is a valid URL."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def get_content_type(response: requests.Response) -> str:
    """Extract content type from response headers."""
    content_type = response.headers.get('Content-Type', '')
    return content_type.split(';')[0].strip().lower()


def is_html_response(response: requests.Response) -> bool:
    """Check if response is HTML."""
    content_type = get_content_type(response)
    return 'text/html' in content_type


def is_binary_response(response: requests.Response) -> bool:
    """Check if response is binary content."""
    content_type = get_content_type(response)
    binary_types = [
        'application/octet-stream',
        'application/zip',
        'application/gzip',
        'application/x-tar',
        'image/',
        'audio/',
        'video/',
    ]
    return any(bt in content_type for bt in binary_types)


def truncate_content(content: str, max_length: int = 500) -> str:
    """Truncate content for display purposes."""
    if len(content) <= max_length:
        return content
    return content[:max_length] + "... [truncated]"


def sanitize_filename(filename: str) -> str:
    """Sanitize a filename to remove dangerous characters."""
    # Remove or replace dangerous characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    filename = re.sub(r'\.\.+', '.', filename)
    return filename.strip('. ')


def rate_limit(delay: float = 0.5):
    """Simple rate limiting by sleeping."""
    time.sleep(delay)


class RateLimiter:
    """Rate limiter for controlling request frequency."""
    
    def __init__(self, requests_per_second: float = 2.0):
        self.min_interval = 1.0 / requests_per_second
        self.last_request_time = 0.0
    
    def wait(self):
        """Wait if necessary to respect rate limit."""
        current_time = time.time()
        elapsed = current_time - self.last_request_time
        
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        
        self.last_request_time = time.time()


def parse_urls_from_file(filepath: str) -> list:
    """Parse URLs from a file, one per line."""
    urls = []
    
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            # Skip empty lines and comments
            if line and not line.startswith('#'):
                urls.append(normalize_url(line))
    
    return urls
