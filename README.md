# GitExScan

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8+-blue.svg" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="MIT License">
  <img src="https://img.shields.io/badge/version-0.1.0-orange.svg" alt="Version 0.1.0">
</p>

**GitExScan** is a powerful security auditing tool designed to detect exposed `.git` repositories and sensitive configuration files on websites. It helps security researchers and penetration testers identify critical misconfigurations that could lead to source code compromise or credential leakage.

## 🎯 Features

- **Git Exposure Detection** - Checks for exposed `.git/HEAD`, `.git/config`, `.git/index` files
- **Sensitive File Scanner** - Detects 70+ sensitive files including:
  - Environment files (`.env`, `.env.local`, `.env.production`)
  - WordPress configs (`wp-config.php`, backups)
  - Database dumps (`.sql` files)
  - Credential files (`.htpasswd`, SSH keys, AWS credentials)
  - Version control files (`.svn`, `.hg`, `CVS`)
- **Secret Detection** - Scans for exposed API keys (AWS, GitHub, Stripe, etc.)
- **Git Repository Reconstruction** - Downloads and reconstructs exposed Git repos
- **WAF Detection** - Identifies Web Application Firewalls (Cloudflare, AWS WAF, etc.)
- **Multiple Export Formats** - JSON, CSV, HTML, PDF reports
- **Concurrent Scanning** - Fast multi-threaded scanning with rate limiting

## 📦 Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/siddhantbhattarai/gitexscan.git
cd gitexscan

# Create virtual environment
python3 -m venv env
source env/bin/activate  # Linux/Mac
# or: env\Scripts\activate  # Windows

# Install the package
pip install .
```

### Dependencies

- Python 3.8+
- click
- requests
- reportlab (for PDF export)

## 🚀 Usage

### Basic Scan

```bash
# Scan a single URL
gitexscan scan https://example.com

# Scan multiple domains from a file
gitexscan scan --input domains.txt

# Quick scan (critical files only)
gitexscan scan --input domains.txt --quick
```

### Export Reports

```bash
# Export as HTML report
gitexscan scan --input domains.txt --output report.html --format html

# Export as JSON
gitexscan scan https://example.com --output results.json --format json

# Export as CSV
gitexscan scan --input domains.txt --output results.csv --format csv

# Export as PDF
gitexscan scan --input domains.txt --output report.pdf --format pdf
```

### Advanced Options

```bash
# Custom workers and timeout
gitexscan scan --input domains.txt --workers 20 --timeout 15

# Adjust rate limiting
gitexscan scan --input domains.txt --rate-limit 10

# Verbose output
gitexscan scan https://example.com --verbose

# Disable secret scanning
gitexscan scan --input domains.txt --no-secrets
```

### Git Repository Reconstruction

If a `.git` directory is exposed, you can attempt to reconstruct the repository:

```bash
# Reconstruct exposed git repo
gitexscan reconstruct https://vulnerable-site.com

# Specify output directory
gitexscan reconstruct https://vulnerable-site.com --output ./repos --verbose
```

### WAF Detection

Check if a target is protected by a Web Application Firewall:

```bash
gitexscan waf https://example.com
```

### List All Checks

View all sensitive files that will be checked:

```bash
gitexscan list-checks
```

## 📋 Input File Format

Create a text file with one URL per line:

```
https://example1.com
https://example2.com
https://subdomain.example3.com
```

## 📊 Output Examples

### Terminal Output

```
   ╔════════════════════════════════════════════════════════════╗
   ║    ██████╗ ██╗████████╗███████╗██╗  ██╗███████╗ ██████╗    ║
   ║   ██╔════╝ ██║╚══██╔══╝██╔════╝╚██╗██╔╝██╔════╝██╔════╝    ║
   ║   ██║  ███╗██║   ██║   █████╗   ╚███╔╝ ███████╗██║         ║
   ║   ██║   ██║██║   ██║   ██╔══╝   ██╔██╗ ╚════██║██║         ║
   ║   ╚██████╔╝██║   ██║   ███████╗██╔╝ ██╗███████║╚██████╗    ║
   ║    ╚═════╝ ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝    ║
   ║        Git Exposure Scanner - Security Auditing Tool       ║
   ╚════════════════════════════════════════════════════════════╝

[*] Starting scan of 10 target(s)...
[*] Scanning: https://example.com
[!] VULNERABLE: https://example.com
[✓] Secure: https://example2.com

============================================================
SCAN COMPLETE
============================================================
  Total targets:    10
  Vulnerable:       3
  Secure:           6
  Errors:           1
  Total findings:   15
============================================================
```

## 🔍 What It Detects

| Category | Files | Severity |
|----------|-------|----------|
| Git | `.git/HEAD`, `.git/config`, `.git/index` | Critical |
| Environment | `.env`, `.env.local`, `.env.production` | Critical |
| WordPress | `wp-config.php`, `wp-config.php.bak` | Critical |
| Database | `database.sql`, `dump.sql`, `backup.sql` | Critical |
| Credentials | `.htpasswd`, `id_rsa`, AWS credentials | Critical |
| Backups | `backup.zip`, `site.zip`, `*.tar.gz` | High |
| VCS | `.svn/entries`, `.hg/hgrc` | High |

## 🛡️ Responsible Disclosure

This tool is intended for:
- Security researchers conducting authorized penetration tests
- System administrators auditing their own infrastructure
- Bug bounty hunters with proper authorization

**Always obtain proper authorization before scanning any target.**

## 📁 Project Structure

```
gitexscan/
├── cli/
│   ├── __init__.py
│   └── gitexscan.py          # CLI interface
├── scanner_core/
│   ├── __init__.py
│   ├── scanner.py            # Main scanner logic
│   ├── sensitive_files.py    # Sensitive file definitions
│   ├── secret_scanner.py     # API key detection
│   ├── repo_reconstructor.py # Git repo reconstruction
│   ├── waf_detection.py      # WAF detection
│   ├── severity.py           # Severity levels & data classes
│   ├── utils.py              # HTTP utilities
│   └── exporters/
│       ├── json_exporter.py
│       ├── csv_exporter.py
│       ├── html_exporter.py
│       └── pdf_exporter.py
├── pyproject.toml
└── README.md
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is provided for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this tool. Always ensure you have proper authorization before scanning any target.

## 🙏 Acknowledgments

- Inspired by various Git exposure tools in the security community
- Thanks to all contributors and security researchers

---

<p align="center">
  Made with ❤️ by <b>Siddhant Bhattarai</b> for the security community
</p>

