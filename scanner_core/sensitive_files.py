"""Sensitive files and patterns to check for exposure."""

from dataclasses import dataclass
from typing import List, Optional
from .severity import Severity


@dataclass
class SensitiveFile:
    """Definition of a sensitive file to check."""
    path: str
    name: str
    severity: Severity
    description: str
    category: str
    indicators: Optional[List[str]] = None  # Content indicators to verify


# Git-related files
GIT_FILES = [
    SensitiveFile(
        path=".git/HEAD",
        name="Git HEAD",
        severity=Severity.CRITICAL,
        description="Git HEAD file exposed - repository structure accessible",
        category="git",
        indicators=["ref: refs/"]
    ),
    SensitiveFile(
        path=".git/config",
        name="Git Config",
        severity=Severity.CRITICAL,
        description="Git configuration exposed - may contain remote URLs and credentials",
        category="git",
        indicators=["[core]", "[remote", "repositoryformatversion"]
    ),
    SensitiveFile(
        path=".git/index",
        name="Git Index",
        severity=Severity.CRITICAL,
        description="Git index file exposed - contains file tree structure",
        category="git",
        indicators=["DIRC"]  # Git index magic bytes
    ),
    SensitiveFile(
        path=".git/packed-refs",
        name="Git Packed Refs",
        severity=Severity.HIGH,
        description="Git packed references exposed",
        category="git",
        indicators=["# pack-refs"]
    ),
    SensitiveFile(
        path=".git/objects/info/packs",
        name="Git Pack Info",
        severity=Severity.HIGH,
        description="Git pack information exposed",
        category="git",
        indicators=["P pack-"]
    ),
    SensitiveFile(
        path=".git/description",
        name="Git Description",
        severity=Severity.MEDIUM,
        description="Git repository description exposed",
        category="git",
        indicators=["Unnamed repository"]
    ),
    SensitiveFile(
        path=".git/info/exclude",
        name="Git Exclude",
        severity=Severity.MEDIUM,
        description="Git exclude file exposed",
        category="git",
        indicators=["# git ls-files"]
    ),
    SensitiveFile(
        path=".git/logs/HEAD",
        name="Git Logs HEAD",
        severity=Severity.HIGH,
        description="Git commit logs exposed - contains commit history",
        category="git",
        indicators=["commit:", "0000000000"]
    ),
    SensitiveFile(
        path=".git/COMMIT_EDITMSG",
        name="Git Commit Message",
        severity=Severity.MEDIUM,
        description="Last commit message exposed",
        category="git",
        indicators=None
    ),
]

# Environment and configuration files
ENV_CONFIG_FILES = [
    SensitiveFile(
        path=".env",
        name="Environment File",
        severity=Severity.CRITICAL,
        description="Environment file exposed - likely contains secrets and API keys",
        category="config",
        indicators=["=", "API", "KEY", "SECRET", "PASSWORD", "DATABASE"]
    ),
    SensitiveFile(
        path=".env.local",
        name="Local Environment File",
        severity=Severity.CRITICAL,
        description="Local environment file exposed",
        category="config",
        indicators=["="]
    ),
    SensitiveFile(
        path=".env.production",
        name="Production Environment File",
        severity=Severity.CRITICAL,
        description="Production environment file exposed - contains production secrets",
        category="config",
        indicators=["="]
    ),
    SensitiveFile(
        path=".env.backup",
        name="Environment Backup",
        severity=Severity.CRITICAL,
        description="Environment backup file exposed",
        category="config",
        indicators=["="]
    ),
    SensitiveFile(
        path="config.php",
        name="PHP Config",
        severity=Severity.HIGH,
        description="PHP configuration file exposed",
        category="config",
        indicators=["<?php", "DB_", "database"]
    ),
    SensitiveFile(
        path="configuration.php",
        name="Joomla Config",
        severity=Severity.CRITICAL,
        description="Joomla configuration file exposed",
        category="config",
        indicators=["JConfig", "$host", "$user", "$password"]
    ),
    SensitiveFile(
        path="config.yml",
        name="YAML Config",
        severity=Severity.HIGH,
        description="YAML configuration file exposed",
        category="config",
        indicators=["database:", "password:", "secret:"]
    ),
    SensitiveFile(
        path="config.yaml",
        name="YAML Config",
        severity=Severity.HIGH,
        description="YAML configuration file exposed",
        category="config",
        indicators=["database:", "password:", "secret:"]
    ),
    SensitiveFile(
        path="settings.py",
        name="Django Settings",
        severity=Severity.HIGH,
        description="Django settings file exposed",
        category="config",
        indicators=["SECRET_KEY", "DATABASES", "Django"]
    ),
]

# WordPress-specific files
WORDPRESS_FILES = [
    SensitiveFile(
        path="wp-config.php",
        name="WordPress Config",
        severity=Severity.CRITICAL,
        description="WordPress configuration file exposed - contains database credentials",
        category="wordpress",
        indicators=["DB_NAME", "DB_USER", "DB_PASSWORD", "DB_HOST"]
    ),
    SensitiveFile(
        path="wp-config.php.bak",
        name="WordPress Config Backup",
        severity=Severity.CRITICAL,
        description="WordPress configuration backup exposed",
        category="wordpress",
        indicators=["DB_NAME", "DB_USER", "DB_PASSWORD"]
    ),
    SensitiveFile(
        path="wp-config.php.old",
        name="WordPress Config Old",
        severity=Severity.CRITICAL,
        description="Old WordPress configuration file exposed",
        category="wordpress",
        indicators=["DB_NAME", "DB_USER"]
    ),
    SensitiveFile(
        path="wp-config.php.save",
        name="WordPress Config Save",
        severity=Severity.CRITICAL,
        description="WordPress configuration save file exposed",
        category="wordpress",
        indicators=["DB_NAME", "DB_USER"]
    ),
    SensitiveFile(
        path="wp-config.php.swp",
        name="WordPress Config Swap",
        severity=Severity.CRITICAL,
        description="WordPress vim swap file exposed",
        category="wordpress",
        indicators=None
    ),
    SensitiveFile(
        path="wp-config.php~",
        name="WordPress Config Backup",
        severity=Severity.CRITICAL,
        description="WordPress configuration backup (tilde) exposed",
        category="wordpress",
        indicators=["DB_NAME"]
    ),
    SensitiveFile(
        path="wp-config.txt",
        name="WordPress Config Text",
        severity=Severity.CRITICAL,
        description="WordPress configuration as text file exposed",
        category="wordpress",
        indicators=["DB_NAME"]
    ),
]

# Database files
DATABASE_FILES = [
    SensitiveFile(
        path="database.sql",
        name="SQL Dump",
        severity=Severity.CRITICAL,
        description="SQL database dump exposed",
        category="database",
        indicators=["INSERT INTO", "CREATE TABLE", "mysqldump"]
    ),
    SensitiveFile(
        path="dump.sql",
        name="SQL Dump",
        severity=Severity.CRITICAL,
        description="SQL dump file exposed",
        category="database",
        indicators=["INSERT INTO", "CREATE TABLE"]
    ),
    SensitiveFile(
        path="backup.sql",
        name="SQL Backup",
        severity=Severity.CRITICAL,
        description="SQL backup file exposed",
        category="database",
        indicators=["INSERT INTO", "CREATE TABLE"]
    ),
    SensitiveFile(
        path="db.sql",
        name="Database SQL",
        severity=Severity.CRITICAL,
        description="Database SQL file exposed",
        category="database",
        indicators=["INSERT INTO", "CREATE TABLE"]
    ),
    SensitiveFile(
        path="data.sql",
        name="Data SQL",
        severity=Severity.CRITICAL,
        description="Data SQL file exposed",
        category="database",
        indicators=["INSERT INTO", "CREATE TABLE"]
    ),
    SensitiveFile(
        path="mysql.sql",
        name="MySQL Dump",
        severity=Severity.CRITICAL,
        description="MySQL dump file exposed",
        category="database",
        indicators=["INSERT INTO", "CREATE TABLE"]
    ),
    SensitiveFile(
        path="db.sqlite",
        name="SQLite Database",
        severity=Severity.CRITICAL,
        description="SQLite database file exposed",
        category="database",
        indicators=["SQLite format"]
    ),
    SensitiveFile(
        path="database.sqlite",
        name="SQLite Database",
        severity=Severity.CRITICAL,
        description="SQLite database file exposed",
        category="database",
        indicators=["SQLite format"]
    ),
    SensitiveFile(
        path="database.sqlite3",
        name="SQLite3 Database",
        severity=Severity.CRITICAL,
        description="SQLite3 database file exposed",
        category="database",
        indicators=["SQLite format"]
    ),
]

# Backup files
BACKUP_FILES = [
    SensitiveFile(
        path="backup.zip",
        name="Backup Archive",
        severity=Severity.HIGH,
        description="Backup archive exposed",
        category="backup",
        indicators=["PK"]  # ZIP magic bytes
    ),
    SensitiveFile(
        path="backup.tar.gz",
        name="Backup Archive",
        severity=Severity.HIGH,
        description="Backup tar archive exposed",
        category="backup",
        indicators=None
    ),
    SensitiveFile(
        path="site.zip",
        name="Site Archive",
        severity=Severity.HIGH,
        description="Site archive exposed",
        category="backup",
        indicators=["PK"]
    ),
    SensitiveFile(
        path="www.zip",
        name="WWW Archive",
        severity=Severity.HIGH,
        description="WWW directory archive exposed",
        category="backup",
        indicators=["PK"]
    ),
    SensitiveFile(
        path="public_html.zip",
        name="Public HTML Archive",
        severity=Severity.HIGH,
        description="Public HTML archive exposed",
        category="backup",
        indicators=["PK"]
    ),
]

# Key and credential files
CREDENTIAL_FILES = [
    SensitiveFile(
        path=".htpasswd",
        name="Apache Password File",
        severity=Severity.CRITICAL,
        description="Apache password file exposed",
        category="credentials",
        indicators=[":$", ":{SHA}"]
    ),
    SensitiveFile(
        path=".htaccess",
        name="Apache Config",
        severity=Severity.MEDIUM,
        description="Apache htaccess configuration exposed",
        category="config",
        indicators=["RewriteEngine", "AuthType", "Deny from"]
    ),
    SensitiveFile(
        path="id_rsa",
        name="SSH Private Key",
        severity=Severity.CRITICAL,
        description="SSH private key exposed",
        category="credentials",
        indicators=["-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----"]
    ),
    SensitiveFile(
        path=".ssh/id_rsa",
        name="SSH Private Key",
        severity=Severity.CRITICAL,
        description="SSH private key exposed",
        category="credentials",
        indicators=["-----BEGIN RSA PRIVATE KEY-----"]
    ),
    SensitiveFile(
        path="id_dsa",
        name="DSA Private Key",
        severity=Severity.CRITICAL,
        description="DSA private key exposed",
        category="credentials",
        indicators=["-----BEGIN DSA PRIVATE KEY-----"]
    ),
    SensitiveFile(
        path=".npmrc",
        name="NPM Config",
        severity=Severity.HIGH,
        description="NPM configuration exposed - may contain auth tokens",
        category="credentials",
        indicators=["//registry", "_authToken", "_auth"]
    ),
    SensitiveFile(
        path=".dockercfg",
        name="Docker Config",
        severity=Severity.HIGH,
        description="Docker configuration exposed",
        category="credentials",
        indicators=["auth", "email"]
    ),
    SensitiveFile(
        path="credentials.json",
        name="Credentials JSON",
        severity=Severity.CRITICAL,
        description="Credentials JSON file exposed",
        category="credentials",
        indicators=["client_id", "client_secret", "private_key"]
    ),
    SensitiveFile(
        path="secrets.json",
        name="Secrets JSON",
        severity=Severity.CRITICAL,
        description="Secrets JSON file exposed",
        category="credentials",
        indicators=["key", "secret", "password"]
    ),
    SensitiveFile(
        path="aws_credentials",
        name="AWS Credentials",
        severity=Severity.CRITICAL,
        description="AWS credentials file exposed",
        category="credentials",
        indicators=["aws_access_key_id", "aws_secret_access_key"]
    ),
    SensitiveFile(
        path=".aws/credentials",
        name="AWS Credentials",
        severity=Severity.CRITICAL,
        description="AWS credentials file exposed",
        category="credentials",
        indicators=["aws_access_key_id", "aws_secret_access_key"]
    ),
]

# Version control files (non-git)
VCS_FILES = [
    SensitiveFile(
        path=".svn/entries",
        name="SVN Entries",
        severity=Severity.HIGH,
        description="SVN entries file exposed",
        category="vcs",
        indicators=["svn", "dir"]
    ),
    SensitiveFile(
        path=".svn/wc.db",
        name="SVN Database",
        severity=Severity.HIGH,
        description="SVN working copy database exposed",
        category="vcs",
        indicators=["SQLite format"]
    ),
    SensitiveFile(
        path=".hg/hgrc",
        name="Mercurial Config",
        severity=Severity.HIGH,
        description="Mercurial configuration exposed",
        category="vcs",
        indicators=["[paths]", "default ="]
    ),
    SensitiveFile(
        path=".bzr/branch/branch.conf",
        name="Bazaar Config",
        severity=Severity.HIGH,
        description="Bazaar branch configuration exposed",
        category="vcs",
        indicators=["parent_location"]
    ),
    SensitiveFile(
        path="CVS/Root",
        name="CVS Root",
        severity=Severity.MEDIUM,
        description="CVS root file exposed",
        category="vcs",
        indicators=[":pserver:", ":ext:"]
    ),
]

# IDE and editor files
IDE_FILES = [
    SensitiveFile(
        path=".idea/workspace.xml",
        name="IntelliJ Workspace",
        severity=Severity.LOW,
        description="IntelliJ IDEA workspace file exposed",
        category="ide",
        indicators=["<?xml", "<project"]
    ),
    SensitiveFile(
        path=".vscode/settings.json",
        name="VSCode Settings",
        severity=Severity.LOW,
        description="VSCode settings exposed",
        category="ide",
        indicators=["{", "}"]
    ),
    SensitiveFile(
        path=".DS_Store",
        name="macOS Metadata",
        severity=Severity.LOW,
        description="macOS directory metadata exposed",
        category="ide",
        indicators=["Bud1"]
    ),
    SensitiveFile(
        path="Thumbs.db",
        name="Windows Thumbnails",
        severity=Severity.LOW,
        description="Windows thumbnail database exposed",
        category="ide",
        indicators=None
    ),
]

# Combine all sensitive files
ALL_SENSITIVE_FILES = (
    GIT_FILES +
    ENV_CONFIG_FILES +
    WORDPRESS_FILES +
    DATABASE_FILES +
    BACKUP_FILES +
    CREDENTIAL_FILES +
    VCS_FILES +
    IDE_FILES
)


def get_files_by_category(category: str) -> List[SensitiveFile]:
    """Get sensitive files by category."""
    return [f for f in ALL_SENSITIVE_FILES if f.category == category]


def get_files_by_severity(severity: Severity) -> List[SensitiveFile]:
    """Get sensitive files by severity level."""
    return [f for f in ALL_SENSITIVE_FILES if f.severity == severity]


def get_critical_files() -> List[SensitiveFile]:
    """Get only critical severity files for quick scanning."""
    return get_files_by_severity(Severity.CRITICAL)
