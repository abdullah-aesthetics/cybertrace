"""
IOC (Indicator of Compromise) Extractor
Automatically extracts IPs, domains, hashes, URLs, emails
from any pasted text — logs, emails, threat reports, etc.
"""
import re
from datetime import datetime

# ── Regex patterns ────────────────────────────────────────────────────────────
PATTERNS = {
    "ipv4": re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    ),
    "domain": re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
        r'+(?:com|net|org|io|xyz|ru|cn|tk|ml|ga|cf|cc|su|pw|top|info|biz|co|uk|de|fr|jp|br)\b',
        re.IGNORECASE
    ),
    "md5":    re.compile(r'\b[a-fA-F0-9]{32}\b'),
    "sha1":   re.compile(r'\b[a-fA-F0-9]{40}\b'),
    "sha256": re.compile(r'\b[a-fA-F0-9]{64}\b'),
    "url": re.compile(
        r'https?://[^\s\'"<>]+', re.IGNORECASE
    ),
    "email": re.compile(
        r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'
    ),
    "cve": re.compile(
        r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE
    ),
    "registry_key": re.compile(
        r'HKEY_[A-Z_]+\\[^\s\'"]+', re.IGNORECASE
    ),
    "file_path": re.compile(
        r'(?:[A-Za-z]:\\|/(?:etc|var|tmp|home|usr|bin|root|proc)/)[^\s\'"<>]*'
    ),
}

# Private/localhost IPs to exclude
EXCLUDED_IPS = {
    "127.0.0.1", "0.0.0.0", "255.255.255.255",
    "192.168.", "10.", "172.16.", "172.17.", "172.18.",
    "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
    "172.29.", "172.30.", "172.31.",
}

# Common false-positive domains to skip
EXCLUDED_DOMAINS = {
    "example.com", "localhost", "google.com", "microsoft.com",
    "windows.com", "apple.com", "github.com", "stackoverflow.com",
}


def extract_iocs(text):
    """
    Extract all IOCs from raw text.
    Returns structured dict with deduplicated indicators.
    """
    if not text:
        return {"error": "No text provided"}

    results = {
        "timestamp":   datetime.now().isoformat(),
        "input_length": len(text),
        "iocs": {
            "ips":          [],
            "domains":      [],
            "urls":         [],
            "md5":          [],
            "sha1":         [],
            "sha256":       [],
            "emails":       [],
            "cves":         [],
            "registry_keys":[],
            "file_paths":   [],
        },
        "total_found": 0,
        "summary":     []
    }

    # Extract IPs
    for ip in set(PATTERNS["ipv4"].findall(text)):
        if not any(ip.startswith(excl) or ip == excl for excl in EXCLUDED_IPS):
            results["iocs"]["ips"].append(ip)

    # Extract domains (exclude those already in URLs and excluded list)
    urls_found = set(PATTERNS["url"].findall(text))
    results["iocs"]["urls"] = list(urls_found)

    url_domains = set()
    for url in urls_found:
        m = re.match(r'https?://([^/]+)', url)
        if m:
            url_domains.add(m.group(1).lower())

    for dom in set(PATTERNS["domain"].findall(text)):
        dom_lower = dom.lower()
        if dom_lower not in EXCLUDED_DOMAINS and dom_lower not in url_domains:
            results["iocs"]["domains"].append(dom)

    # Extract hashes (in priority order — SHA256 first to avoid overlap)
    sha256_found = set(PATTERNS["sha256"].findall(text))
    results["iocs"]["sha256"] = list(sha256_found)

    # Remove SHA256 matches from remaining text before SHA1/MD5 search
    cleaned = text
    for h in sha256_found:
        cleaned = cleaned.replace(h, "")

    sha1_found = set(PATTERNS["sha1"].findall(cleaned))
    results["iocs"]["sha1"] = list(sha1_found)
    for h in sha1_found:
        cleaned = cleaned.replace(h, "")

    results["iocs"]["md5"] = list(set(PATTERNS["md5"].findall(cleaned)))

    # Other IOC types
    results["iocs"]["emails"]        = list(set(PATTERNS["email"].findall(text)))
    results["iocs"]["cves"]          = list(set(PATTERNS["cve"].findall(text)))
    results["iocs"]["registry_keys"] = list(set(PATTERNS["registry_key"].findall(text)))
    results["iocs"]["file_paths"]    = list(set(PATTERNS["file_path"].findall(text)))[:10]

    # Count totals
    total = sum(len(v) for v in results["iocs"].values())
    results["total_found"] = total

    # Build summary
    for key, vals in results["iocs"].items():
        if vals:
            results["summary"].append({
                "type":  key.upper().replace("_", " "),
                "count": len(vals),
                "items": vals[:5]
            })

    # Build investigation queue (what can be auto-investigated)
    queue = []
    for ip in results["iocs"]["ips"][:10]:
        queue.append({"target": ip, "type": "ip"})
    for dom in results["iocs"]["domains"][:5]:
        queue.append({"target": dom, "type": "domain"})
    for h in (results["iocs"]["sha256"] + results["iocs"]["md5"])[:5]:
        queue.append({"target": h, "type": "hash"})
    for url in results["iocs"]["urls"][:5]:
        queue.append({"target": url, "type": "url"})
    for email in results["iocs"]["emails"][:5]:
        queue.append({"target": email, "type": "email"})

    results["investigation_queue"] = queue

    return results


def defang(text):
    """
    Defang IOCs in text for safe sharing
    (e.g. 1.2.3.4 → 1[.]2[.]3[.]4)
    """
    text = re.sub(r'\.', '[.]', text)
    text = re.sub(r'https?://', 'hxxps://', text, flags=re.IGNORECASE)
    text = re.sub(r'@', '[@]', text)
    return text


def refang(text):
    """Reverse defanging to restore original IOCs."""
    text = text.replace('[.]', '.')
    text = re.sub(r'hxxps?://', 'https://', text, flags=re.IGNORECASE)
    text = text.replace('[@]', '@')
    return text
