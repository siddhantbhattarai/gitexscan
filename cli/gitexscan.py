#!/usr/bin/env python3
"""GitExScan - Git Exposure Scanner CLI tool."""

import sys
import os
from pathlib import Path

import click

from scanner_core import (
    GitExposureScanner,
    GitRepoReconstructor,
    parse_urls_from_file,
    normalize_url,
    export_report,
)
from scanner_core.waf_detection import detect_waf


def print_banner():
    """Print the tool banner."""
    banner = r"""
   ╔════════════════════════════════════════════════════════════╗
   ║                                                            ║
   ║    ██████╗ ██╗████████╗███████╗██╗  ██╗███████╗ ██████╗    ║
   ║   ██╔════╝ ██║╚══██╔══╝██╔════╝╚██╗██╔╝██╔════╝██╔════╝    ║
   ║   ██║  ███╗██║   ██║   █████╗   ╚███╔╝ ███████╗██║         ║
   ║   ██║   ██║██║   ██║   ██╔══╝   ██╔██╗ ╚════██║██║         ║
   ║   ╚██████╔╝██║   ██║   ███████╗██╔╝ ██╗███████║╚██████╗    ║
   ║    ╚═════╝ ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝    ║
   ║                                                            ║
   ║        Git Exposure Scanner - Security Auditing Tool       ║
   ║                         v0.1.0                             ║
   ║               Author: Siddhant Bhattarai                   ║
   ╚════════════════════════════════════════════════════════════╝
    """
    click.echo(click.style(banner, fg='cyan'))


@click.group()
@click.version_option(version="0.1.0", prog_name="gitexscan")
def main():
    """GitExScan - Security tool for detecting exposed Git repositories and sensitive files."""
    pass


@main.command()
@click.argument("target", required=False)
@click.option("--input", "-i", "input_file", type=click.Path(exists=True),
              help="Input file containing URLs to scan (one per line)")
@click.option("--output", "-o", "output_path", default=None,
              help="Output file path for the report")
@click.option("--format", "-f", "output_format", default="json",
              type=click.Choice(["json", "csv", "html", "pdf"]),
              help="Output format (default: json)")
@click.option("--workers", "-w", default=10, type=int,
              help="Number of concurrent workers (default: 10)")
@click.option("--timeout", "-t", default=10, type=int,
              help="Request timeout in seconds (default: 10)")
@click.option("--rate-limit", "-r", default=5.0, type=float,
              help="Max requests per second (default: 5)")
@click.option("--quick", "-q", is_flag=True,
              help="Quick scan - only check critical files")
@click.option("--no-secrets", is_flag=True,
              help="Disable secret scanning in responses")
@click.option("--verbose", "-v", is_flag=True,
              help="Enable verbose output")
def scan(target, input_file, output_path, output_format, workers, timeout, 
         rate_limit, quick, no_secrets, verbose):
    """
    Scan target(s) for exposed Git repositories and sensitive files.
    
    Examples:
    
        gitexscan scan https://example.com
        
        gitexscan scan --input domains.txt --output report.html --format html
        
        gitexscan scan https://example.com -v --quick
    """
    if not target and not input_file:
        raise click.UsageError("Please provide either a TARGET URL or --input file")
    
    print_banner()
    
    # Gather targets
    targets = []
    if input_file:
        click.echo(f"[*] Loading targets from: {input_file}")
        targets = parse_urls_from_file(input_file)
        click.echo(f"[*] Loaded {len(targets)} targets")
    elif target:
        targets = [normalize_url(target)]
    
    if not targets:
        click.echo(click.style("[!] No valid targets found", fg='red'))
        sys.exit(1)
    
    # Progress callback
    def progress_callback(url, status):
        if status == "scanning":
            click.echo(f"[*] Scanning: {url}")
        elif status == "vulnerable":
            click.echo(click.style(f"[!] VULNERABLE: {url}", fg='red', bold=True))
        elif status == "secure":
            click.echo(click.style(f"[✓] Secure: {url}", fg='green'))
        elif status == "error":
            click.echo(click.style(f"[x] Error: {url}", fg='yellow'))
    
    # Create scanner
    scanner = GitExposureScanner(
        timeout=timeout,
        max_workers=workers,
        rate_limit=rate_limit,
        verbose=verbose,
        check_secrets=not no_secrets,
        quick_scan=quick,
        callback=progress_callback if not verbose else None
    )
    
    click.echo(f"\n[*] Starting scan of {len(targets)} target(s)...")
    click.echo(f"[*] Workers: {workers}, Timeout: {timeout}s, Rate limit: {rate_limit}/s\n")
    
    # Run scan
    report = scanner.scan_targets(targets)
    
    # Print summary
    click.echo("\n" + "="*60)
    click.echo(click.style("SCAN COMPLETE", fg='cyan', bold=True))
    click.echo("="*60)
    click.echo(f"  Total targets:    {report.total_targets}")
    click.echo(click.style(f"  Vulnerable:       {report.vulnerable_targets}", fg='red' if report.vulnerable_targets > 0 else 'green'))
    click.echo(click.style(f"  Secure:           {report.secure_targets}", fg='green'))
    click.echo(f"  Errors:           {report.error_targets}")
    click.echo(f"  Total findings:   {report.total_findings}")
    click.echo("="*60 + "\n")
    
    # Export report
    if output_path:
        click.echo(f"[*] Exporting report to: {output_path}")
        exported_path = export_report(report, output_path, output_format)
        click.echo(click.style(f"[✓] Report saved: {exported_path}", fg='green'))
    else:
        # Default output
        default_output = f"gitexscan_report.{output_format}"
        click.echo(f"[*] Exporting report to: {default_output}")
        exported_path = export_report(report, default_output, output_format)
        click.echo(click.style(f"[✓] Report saved: {exported_path}", fg='green'))
    
    # Exit with appropriate code
    if report.vulnerable_targets > 0:
        sys.exit(1)
    sys.exit(0)


@main.command()
@click.argument("url", required=True)
@click.option("--output", "-o", "output_dir", default="./reconstructed",
              help="Output directory for reconstructed repo")
@click.option("--verbose", "-v", is_flag=True,
              help="Enable verbose output")
def reconstruct(url, output_dir, verbose):
    """
    Attempt to reconstruct a Git repository from an exposed .git directory.
    
    Examples:
    
        gitexscan reconstruct https://vulnerable-site.com
        
        gitexscan reconstruct https://example.com -o ./output -v
    """
    print_banner()
    
    url = normalize_url(url)
    click.echo(f"[*] Target: {url}")
    click.echo(f"[*] Output directory: {output_dir}")
    
    # Create output directory with domain name
    from urllib.parse import urlparse
    domain = urlparse(url).netloc.replace(':', '_')
    full_output_dir = Path(output_dir) / domain
    
    click.echo(f"\n[*] Starting repository reconstruction...")
    
    reconstructor = GitRepoReconstructor(
        base_url=url,
        output_dir=str(full_output_dir),
        verbose=verbose
    )
    
    success, stats = reconstructor.reconstruct()
    
    click.echo("\n" + "="*60)
    if success:
        click.echo(click.style("RECONSTRUCTION COMPLETE", fg='green', bold=True))
        click.echo("="*60)
        click.echo(f"  Objects downloaded:  {stats['objects_downloaded']}")
        click.echo(f"  Objects failed:      {stats['objects_failed']}")
        click.echo(f"  Refs found:          {len(stats['refs_found'])}")
        click.echo(f"  Output directory:    {stats['output_dir']}")
        click.echo("="*60)
        click.echo(f"\n[*] Try: cd {stats['output_dir']} && git status")
    else:
        click.echo(click.style("RECONSTRUCTION FAILED", fg='red', bold=True))
        click.echo("="*60)
        click.echo("[!] Could not download any git objects")
        click.echo("[!] The .git directory may not be fully exposed")


@main.command()
@click.argument("url", required=True)
def waf(url):
    """
    Check if a website is protected by a Web Application Firewall.
    
    Examples:
    
        gitexscan waf https://example.com
    """
    print_banner()
    
    url = normalize_url(url)
    click.echo(f"[*] Checking WAF for: {url}\n")
    
    waf_info = detect_waf(url)
    
    if waf_info.detected:
        click.echo(click.style(f"[!] WAF Detected: {waf_info.name}", fg='yellow', bold=True))
        click.echo(f"    Confidence: {waf_info.confidence}")
        click.echo(f"    Indicators:")
        for indicator in waf_info.indicators:
            click.echo(f"      - {indicator}")
    else:
        click.echo(click.style("[✓] No WAF detected", fg='green'))


@main.command(name="list-checks")
def list_checks():
    """List all sensitive files that will be checked during a scan."""
    print_banner()
    
    from scanner_core.sensitive_files import ALL_SENSITIVE_FILES
    
    click.echo("Files checked during scan:\n")
    
    categories = {}
    for sf in ALL_SENSITIVE_FILES:
        if sf.category not in categories:
            categories[sf.category] = []
        categories[sf.category].append(sf)
    
    for category, files in sorted(categories.items()):
        click.echo(click.style(f"\n[{category.upper()}]", fg='cyan', bold=True))
        for sf in files:
            sev_color = {
                'critical': 'red',
                'high': 'yellow', 
                'medium': 'blue',
                'low': 'white',
                'info': 'white'
            }.get(sf.severity.value, 'white')
            
            click.echo(f"  {sf.path}")
            click.echo(click.style(f"    [{sf.severity.value.upper()}] {sf.name}", fg=sev_color))


if __name__ == "__main__":
    main()
