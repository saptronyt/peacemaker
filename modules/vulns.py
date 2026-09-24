"""Service detection from banners + vulnerability mapping (built-in DB + online lookup)."""

import json
import re
import urllib.parse
import urllib.request

SERVICE_PATTERNS = [
    (r"OpenSSH[_-](\d+(?:\.\d+)+)", "ssh", "OpenSSH"),
    (r"SSH-2\.0-(Dropbear[^\s]*)", "ssh", "Dropbear"),
    (r"vsFTPd[_\s](\d+(?:\.\d+)+)", "ftp", "vsftpd"),
    (r"ProFTPD[_\s](\d+(?:\.\d+)+)", "ftp", "ProFTPD"),
    (r"220[- ](.*) FileZilla", "ftp", "FileZilla Server"),
    (r"Apache[^\d]*/(\d+(?:\.\d+)+)", "http", "Apache httpd"),
    (r"nginx[^\d]*/(\d+(?:\.\d+)+)", "http", "nginx"),
    (r"Microsoft-IIS[^\d]*/(\d+(?:\.\d+)+)", "http", "Microsoft IIS"),
    (r"Exim[^\d]*(\d+(?:\.\d+)+)", "smtp", "Exim"),
    (r"Postfix[^\d]*(\d+(?:\.\d+)+)", "smtp", "Postfix"),
    (r"Sendmail[^\d]*(\d+(?:\.\d+)+)", "smtp", "Sendmail"),
    (r"MySQL", "mysql", "MySQL"),
    (r"MariaDB", "mysql", "MariaDB"),
    (r"PostgreSQL[^\d]*(\d+(?:\.\d+)+)", "postgresql", "PostgreSQL"),
    (r"redis[^\d]*version[=\s']*(\d+(?:\.\d+)+)", "redis", "Redis"),
    (r"Samba[^\d]*(\d+(?:\.\d+)+)", "smb", "Samba"),
    (r"Banner.*FreeFloat", "ftp", "FreeFloat FTP"),
]

# Built-in vulnerability knowledge base: (service, product, version) -> issues.
# version "None" or "*" matches any; "x.y" matches that version (or lower).
VULN_DB = [
    {
        "product": "OpenSSH", "version": None, "min": None,
        "cves": ["CVE-2018-15473 (user enumeration)", "CVE-2023-38408 (remote code exec < 9.3p1)"],
        "note": "Consider disabling password auth, use key-based auth.",
    },
    {
        "product": "vsftpd", "version": "2.3.4", "min": None,
        "cves": ["CVE-2011-2523 (backdoor, remote shell)"],
        "note": "Immediately vulnerable - update or isolate.",
    },
    {
        "product": "Apache httpd", "version": "2.4.49", "min": None,
        "cves": ["CVE-2021-41773 (path traversal / RCE)"],
        "note": "Upgrade to >= 2.4.50.",
    },
    {
        "product": "nginx", "version": None, "min": None,
        "cves": ["CVE-2021-23017 (resolver off-by-one, < 1.20.0)"],
        "note": "Keep nginx updated; review server_tokens off.",
    },
    {
        "product": "Microsoft IIS", "version": None, "min": None,
        "cves": ["CVE-2021-31166 (remote code exec, < 10.0)", "CVE-2017-7269 (WebDAV buffer overflow)"],
        "note": "Patch IIS; restrict WebDAV if unused.",
    },
    {
        "product": "Exim", "version": None, "min": None,
        "cves": ["CVE-2019-10149 (remote code execution)"],
        "note": "Upgrade Exim immediately.",
    },
    {
        "product": "Samba", "version": None, "min": None,
        "cves": ["CVE-2017-7494 (remote code exec)", "CVE-2020-1472 (Zerologon, SMB)"],
        "note": "Apply Samba updates; restrict SMB exposure.",
    },
    {
        "product": "Redis", "version": "3.2", "min": None,
        "cves": ["CVE-2021-32761 (RCE)", "CVE-2022-0543 (Lua sandbox escape)"],
        "note": "Bind to localhost; require auth.",
    },
    {
        "product": "MySQL", "version": None, "min": None,
        "cves": ["CVE-2012-2122 (auth bypass)"],
        "note": "Use strong passwords; restrict remote access.",
    },
    {
        "product": "PostgreSQL", "version": None, "min": None,
        "cves": ["CVE-2018-1058 (search_path privilege escalation)"],
        "note": "Review roles and search_path.",
    },
]


def parse_banner(port, banner):
    """Return (product, version) detected from a banner string."""
    if not banner:
        return None, None
    text = banner.replace("\r", " ").replace("\n", " ")
    for pattern, _svc, product in SERVICE_PATTERNS:
        m = re.search(pattern, text)
        if m:
            return product, (m.group(1) if m.lastindex else None)
    if text.upper().startswith("HTTP") or "Server:" in text:
        server = re.search(r"Server:\s*([^\s]+)", text)
        if server:
            name, _, ver = server.group(1).partition("/")
            return name, ver or None
        return "Generic HTTP server", None
    return None, None


def map_vulnerabilities(product, version):
    """Match a detected product/version against the built-in vulnerability DB."""
    matches = []
    if not product:
        return matches
    for entry in VULN_DB:
        if entry["product"].lower() != product.lower():
            continue
        if entry["version"] and entry["version"] != "*":
            if not version or version != entry["version"]:
                if not (entry["min"] and version):
                    continue
                try:
                    if tuple(map(int, version.split("."))) >= tuple(map(int, entry["min"].split("."))):
                        continue
                except ValueError:
                    continue
        matches.append(entry)
    return matches


def lookup_cve_online(product, version):
    """Optional online CVE lookup via the CIRCL API. Returns [] if offline."""
    try:
        query = urllib.parse.quote(f"{product} {version or ''}".strip())
        url = f"https://cve.circl.lu/api/search/{query}"
        with urllib.request.urlopen(url, timeout=8) as resp:
            data = json.loads(resp.read().decode())
        cves = data.get("results", [])[:5]
        return [(c.get("id", ""), c.get("summary", "")[:120]) for c in cves]
    except Exception:
        return []
