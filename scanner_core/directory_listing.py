"""Directory listing detection module."""

import re
from typing import Optional, List, Tuple
from dataclasses import dataclass

from .utils import safe_request, create_session, build_url, DEFAULT_TIMEOUT


@dataclass
class DirectoryListingResult:
    """Result of directory listing check."""
    url: str
    has_listing: bool
    server_type: Optional[str]
    files_found: List[str]
    directories_found: List[str]


# Patterns for detecting directory listing
LISTING_PATTERNS = {
    "apache": [
        r'<title>Index of /',
        r'<h1>Index of /',
        r'Apache/[\d.]+ Server at',
        r'<address>Apache/[\d.]+',
    ],
    "nginx": [
        r'<title>Index of /',
        r'<h1>Index of /',
        r'nginx/[\d.]+',
        r'<hr><center>nginx',
    ],
    "iis": [
        r'<title>.*- /',
        r'\[To Parent Directory\]',
        r'Microsoft-IIS/[\d.]+',
    ],
    "lighttpd": [
        r'<title>Index of /',
        r'lighttpd/[\d.]+',
    ],
    "python": [
        r'Directory listing for /',
        r'SimpleHTTP',
    ],
    "generic": [
        r'Parent Directory',
        r'\.\./',
        r'<a href="[^"]+/">',
        r'Directory Listing',
    ],
}

# Patterns to extract file/directory names
FILE_EXTRACTION_PATTERNS = [
    r'<a href="([^"]+)"[^>]*>[^<]+</a>',
    r'href="([^"/?][^"]*)"',
]


def check_directory_listing(
    url: str,
    timeout: int = DEFAULT_TIMEOUT
) -> DirectoryListingResult:
    """
    Check if a URL has directory listing enabled.
    
    Args:
        url: URL to check
        timeout: Request timeout
        
    Returns:
        DirectoryListingResult with findings
    """
    session = create_session()
    response, error = safe_request(url, session, timeout)
    
    if error or response is None:
        return DirectoryListingResult(
            url=url,
            has_listing=False,
            server_type=None,
            files_found=[],
            directories_found=[]
        )
    
    if response.status_code != 200:
        return DirectoryListingResult(
            url=url,
            has_listing=False,
            server_type=None,
            files_found=[],
            directories_found=[]
        )
    
    content = response.text
    server_type = None
    has_listing = False
    
    # Check each server type pattern
    for stype, patterns in LISTING_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                has_listing = True
                if stype != "generic":
                    server_type = stype
                break
        if has_listing and server_type:
            break
    
    if not has_listing:
        return DirectoryListingResult(
            url=url,
            has_listing=False,
            server_type=None,
            files_found=[],
            directories_found=[]
        )
    
    # Extract files and directories
    files = []
    directories = []
    
    for pattern in FILE_EXTRACTION_PATTERNS:
        matches = re.findall(pattern, content)
        for match in matches:
            # Skip parent directory and same directory links
            if match in ['../', './', '../', '.', '..']:
                continue
            # Skip absolute URLs
            if match.startswith(('http://', 'https://', '//')):
                continue
            # Skip query strings and anchors
            if '?' in match or '#' in match:
                continue
            
            if match.endswith('/'):
                directories.append(match.rstrip('/'))
            else:
                files.append(match)
    
    # Deduplicate
    files = list(set(files))
    directories = list(set(directories))
    
    return DirectoryListingResult(
        url=url,
        has_listing=True,
        server_type=server_type,
        files_found=sorted(files),
        directories_found=sorted(directories)
    )


def check_git_directory_listing(base_url: str, timeout: int = DEFAULT_TIMEOUT) -> Tuple[bool, List[str]]:
    """
    Check if .git directory has listing enabled.
    
    Args:
        base_url: Base URL of the website
        timeout: Request timeout
        
    Returns:
        Tuple of (has_listing, files_found)
    """
    git_url = build_url(base_url, ".git/")
    result = check_directory_listing(git_url, timeout)
    
    if result.has_listing:
        return True, result.files_found + result.directories_found
    
    return False, []


def find_interesting_files(listing_result: DirectoryListingResult) -> List[str]:
    """
    Find interesting files in a directory listing.
    
    Args:
        listing_result: Result from directory listing check
        
    Returns:
        List of interesting file paths
    """
    interesting_patterns = [
        r'\.sql$',
        r'\.bak$',
        r'\.backup$',
        r'\.old$',
        r'\.orig$',
        r'\.save$',
        r'\.swp$',
        r'\.zip$',
        r'\.tar',
        r'\.gz$',
        r'\.7z$',
        r'\.rar$',
        r'config',
        r'\.env',
        r'\.git',
        r'\.htpasswd',
        r'password',
        r'secret',
        r'key',
        r'credential',
        r'dump',
        r'database',
        r'\.pem$',
        r'\.key$',
        r'id_rsa',
        r'id_dsa',
    ]
    
    interesting = []
    
    all_items = listing_result.files_found + listing_result.directories_found
    
    for item in all_items:
        for pattern in interesting_patterns:
            if re.search(pattern, item, re.IGNORECASE):
                interesting.append(item)
                break
    
    return interesting


def recursive_listing_scan(
    base_url: str,
    max_depth: int = 3,
    timeout: int = DEFAULT_TIMEOUT
) -> List[DirectoryListingResult]:
    """
    Recursively scan for directory listings.
    
    Args:
        base_url: Base URL to start from
        max_depth: Maximum recursion depth
        timeout: Request timeout
        
    Returns:
        List of all directory listing results
    """
    results = []
    visited = set()
    
    def scan_recursive(url: str, depth: int):
        if depth > max_depth or url in visited:
            return
        
        visited.add(url)
        result = check_directory_listing(url, timeout)
        
        if result.has_listing:
            results.append(result)
            
            # Scan subdirectories
            for directory in result.directories_found[:20]:  # Limit to avoid infinite loops
                subdir_url = build_url(url, directory + '/')
                scan_recursive(subdir_url, depth + 1)
    
    scan_recursive(base_url, 0)
    return results
