import requests
import socket
import json
import re
from datetime import datetime

# ─── API KEYS ──────────────────────────────────────────────────────────────────
# Replace these with your real keys. Free tiers are enough for this project.
# VirusTotal: https://www.virustotal.com/gui/join-us
# AbuseIPDB:  https://www.abuseipdb.com/register
VIRUSTOTAL_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
ABUSEIPDB_API_KEY  = "YOUR_ABUSEIPDB_API_KEY"
# ───────────────────────────────────────────────────────────────────────────────

def run_osint(target, target_type):
    """Run all OSINT checks and return combined results."""
    results = {
        "target": target,
        "target_type": target_type,
        "timestamp": datetime.now().isoformat(),
        "virustotal": {},
        "abuseipdb": {},
        "geolocation": {},
        "dns": {},
        "whois_summary": "",
        "open_ports": [],
        "errors": []
    }

    # Determine which checks to run
    if target_type == "ip":
        results["virustotal"]  = check_virustotal_ip(target)
        results["abuseipdb"]   = check_abuseipdb(target)
        results["geolocation"] = get_geolocation(target)
        results["open_ports"]  = scan_common_ports(target)
    elif target_type == "domain":
        results["virustotal"]  = check_virustotal_domain(target)
        results["dns"]         = get_dns_records(target)
        # Resolve to IP then geolocate
        try:
            ip = socket.gethostbyname(target)
            results["resolved_ip"]  = ip
            results["geolocation"]  = get_geolocation(ip)
            results["abuseipdb"]    = check_abuseipdb(ip)
        except Exception as e:
            results["errors"].append(f"DNS resolution failed: {e}")
    elif target_type == "hash":
        results["virustotal"] = check_virustotal_hash(target)
    elif target_type == "url":
        results["virustotal"] = check_virustotal_url(target)
    elif target_type == "email":
        results["email_info"] = check_email(target)

    return results


def check_virustotal_ip(ip):
    if VIRUSTOTAL_API_KEY == "YOUR_VIRUSTOTAL_API_KEY":
        return _demo_vt_result("ip", ip)
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "status": "success",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "country": data.get("country", "Unknown"),
                "as_owner": data.get("as_owner", "Unknown"),
                "reputation": data.get("reputation", 0)
            }
        return {"status": "error", "message": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def check_virustotal_domain(domain):
    if VIRUSTOTAL_API_KEY == "YOUR_VIRUSTOTAL_API_KEY":
        return _demo_vt_result("domain", domain)
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "status": "success",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "registrar": data.get("registrar", "Unknown"),
                "creation_date": data.get("creation_date", "Unknown"),
                "reputation": data.get("reputation", 0)
            }
        return {"status": "error", "message": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def check_virustotal_hash(file_hash):
    if VIRUSTOTAL_API_KEY == "YOUR_VIRUSTOTAL_API_KEY":
        return _demo_vt_result("hash", file_hash)
    try:
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "status": "success",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "file_name": data.get("meaningful_name", "Unknown"),
                "file_type": data.get("type_description", "Unknown"),
                "file_size": data.get("size", 0),
                "threat_names": list(set(
                    v.get("result", "") for v in
                    data.get("last_analysis_results", {}).values()
                    if v.get("category") == "malicious"
                ))[:5]
            }
        elif r.status_code == 404:
            return {"status": "not_found", "message": "Hash not found in VirusTotal"}
        return {"status": "error", "message": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def check_virustotal_url(target_url):
    if VIRUSTOTAL_API_KEY == "YOUR_VIRUSTOTAL_API_KEY":
        return _demo_vt_result("url", target_url)
    try:
        import base64
        url_id = base64.urlsafe_b64encode(target_url.encode()).decode().rstrip("=")
        url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "status": "success",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "final_url": data.get("last_final_url", target_url),
                "title": data.get("title", "Unknown")
            }
        return {"status": "error", "message": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def check_abuseipdb(ip):
    if ABUSEIPDB_API_KEY == "YOUR_ABUSEIPDB_API_KEY":
        return _demo_abuse_result(ip)
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}
        r = requests.get(url, headers=headers, params=params, timeout=10)
        if r.status_code == 200:
            data = r.json().get("data", {})
            return {
                "status": "success",
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "country": data.get("countryCode", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "domain": data.get("domain", "Unknown"),
                "is_tor": data.get("isTor", False),
                "last_reported": data.get("lastReportedAt", "Never"),
                "usage_type": data.get("usageType", "Unknown")
            }
        return {"status": "error", "message": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def get_geolocation(ip):
    try:
        r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=8)
        if r.status_code == 200:
            data = r.json()
            if "error" not in data:
                return {
                    "status": "success",
                    "ip": ip,
                    "city": data.get("city", "Unknown"),
                    "region": data.get("region", "Unknown"),
                    "country": data.get("country_name", "Unknown"),
                    "country_code": data.get("country_code", "XX"),
                    "latitude": data.get("latitude", 0),
                    "longitude": data.get("longitude", 0),
                    "isp": data.get("org", "Unknown"),
                    "timezone": data.get("timezone", "Unknown")
                }
        return {"status": "error", "message": "Could not fetch location"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def get_dns_records(domain):
    try:
        import dns.resolver
        records = {}
        for rtype in ["A", "MX", "NS", "TXT"]:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                records[rtype] = [str(r) for r in answers]
            except Exception:
                records[rtype] = []
        return {"status": "success", "records": records}
    except ImportError:
        # Fallback: use socket for A records
        try:
            ip = socket.gethostbyname(domain)
            return {"status": "success", "records": {"A": [ip]}}
        except Exception as e:
            return {"status": "error", "message": str(e)}


def scan_common_ports(ip):
    """Quick scan of common suspicious ports."""
    suspicious_ports = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        80: "HTTP", 443: "HTTPS", 445: "SMB", 1433: "MSSQL",
        3306: "MySQL", 3389: "RDP", 4444: "Metasploit",
        6667: "IRC", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
    }
    open_ports = []
    for port, service in suspicious_ports.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append({"port": port, "service": service, "state": "open"})
            sock.close()
        except Exception:
            pass
    return open_ports


def check_email(email):
    domain = email.split("@")[-1] if "@" in email else ""
    result = {"email": email, "domain": domain}
    if domain:
        result["dns"] = get_dns_records(domain)
    return result


# ─── DEMO DATA (shown when API keys are not configured) ─────────────────────

def _demo_vt_result(kind, target):
    import random
    mal = random.randint(0, 15)
    return {
        "status": "demo",
        "note": "Demo data — add your VirusTotal API key in modules/osint.py",
        "malicious": mal,
        "suspicious": random.randint(0, 5),
        "harmless": random.randint(40, 70),
        "undetected": random.randint(10, 30),
        "reputation": -mal * 3,
        "country": "US",
        "as_owner": "Demo ISP Inc.",
        "threat_names": ["Trojan.GenericKD", "Backdoor.Agent"] if mal > 5 else []
    }

def _demo_abuse_result(ip):
    import random
    score = random.randint(0, 95)
    return {
        "status": "demo",
        "note": "Demo data — add your AbuseIPDB API key in modules/osint.py",
        "abuse_score": score,
        "total_reports": random.randint(0, 200),
        "country": "RU",
        "isp": "Demo Hosting LLC",
        "domain": "demo-host.com",
        "is_tor": random.choice([True, False]),
        "last_reported": "2025-04-20T10:30:00+00:00",
        "usage_type": "Data Center/Web Hosting/Transit"
    }
