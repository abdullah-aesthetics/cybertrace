"""
Port Banner Grabbing Module
Connects to open ports, grabs service banners, identifies
software versions, and checks for known vulnerable versions.
"""
import socket
import re
from datetime import datetime

# Known vulnerable version patterns (for educational/defensive awareness)
VULNERABLE_VERSIONS = [
    {"pattern": r"OpenSSH[_ ]([67]\.[0-9])",      "cve": "CVE-2016-6210", "desc": "OpenSSH user enumeration"},
    {"pattern": r"Apache[/ ]([12]\.[0-3]\.[0-9])", "cve": "CVE-2021-41773","desc": "Apache path traversal"},
    {"pattern": r"nginx[/ ](1\.[0-9]\.[0-9])",     "cve": "Multiple",      "desc": "Check nginx version"},
    {"pattern": r"vsftpd 2\.3\.4",                 "cve": "CVE-2011-2523", "desc": "vsftpd backdoor"},
    {"pattern": r"ProFTPD 1\.3\.[0-3]",            "cve": "CVE-2010-4221", "desc": "ProFTPD buffer overflow"},
    {"pattern": r"Microsoft-IIS[/ ]([456]\.[0-9])","cve": "Multiple",      "desc": "Outdated IIS version"},
    {"pattern": r"OpenSSL[/ ](1\.0\.[01])",        "cve": "CVE-2014-0160", "desc": "Heartbleed vulnerability"},
]

# Port-specific probes to elicit banners
PORT_PROBES = {
    21:   b"",
    22:   b"",
    23:   b"",
    25:   b"EHLO cybertrace.local\r\n",
    80:   b"HEAD / HTTP/1.0\r\n\r\n",
    443:  b"HEAD / HTTP/1.0\r\n\r\n",
    110:  b"",
    143:  b"",
    3306: b"",
    5432: b"",
    6379: b"PING\r\n",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\n\r\n",
}


def grab_banner(ip, port, timeout=3):
    """Grab banner from a single port."""
    result = {
        "ip":       ip,
        "port":     port,
        "banner":   None,
        "service":  _guess_service(port),
        "version":  None,
        "cves":     [],
        "findings": []
    }
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))

        probe = PORT_PROBES.get(port, b"")
        if probe:
            s.send(probe)

        banner_bytes = s.recv(1024)
        s.close()

        banner = banner_bytes.decode(errors="ignore").strip()
        result["banner"] = banner[:300]

        # Extract version
        version_match = re.search(r'([\w\-]+)[/ ]([\d\.]+)', banner)
        if version_match:
            result["version"] = f"{version_match.group(1)} {version_match.group(2)}"

        # Check against vulnerable versions
        for vuln in VULNERABLE_VERSIONS:
            if re.search(vuln["pattern"], banner, re.IGNORECASE):
                result["cves"].append({
                    "cve":  vuln["cve"],
                    "desc": vuln["desc"]
                })
                result["findings"].append(f"Potentially vulnerable: {vuln['desc']} ({vuln['cve']})")

        if not result["findings"] and banner:
            result["findings"].append("Banner grabbed — no known vulnerabilities matched")
        elif not banner:
            result["findings"].append("Port open but no banner returned")

    except socket.timeout:
        result["findings"].append("Connection timed out")
    except ConnectionRefusedError:
        result["findings"].append("Port closed")
    except Exception as e:
        result["findings"].append(f"Error: {str(e)[:80]}")

    return result


def scan_and_grab(ip, ports=None):
    """
    Scan a list of ports and grab banners from open ones.
    Returns a full report with all open ports and their banners.
    """
    if ports is None:
        ports = [21, 22, 23, 25, 80, 110, 143, 443, 3306, 5432, 6379, 8080, 8443]

    results = {
        "ip":          ip,
        "timestamp":   datetime.now().isoformat(),
        "open_ports":  [],
        "cve_summary": [],
        "risk_score":  0,
        "findings":    []
    }

    dangerous_ports = {23, 4444, 6667, 1337, 31337}

    for port in ports:
        banner_result = grab_banner(ip, port)
        if banner_result["banner"] is not None or "closed" not in str(banner_result["findings"]):
            # Only include if port responded
            if not any("closed" in f or "timed out" in f for f in banner_result["findings"]):
                results["open_ports"].append(banner_result)

                if banner_result["cves"]:
                    results["cve_summary"].extend(banner_result["cves"])
                    results["risk_score"] += 20

                if port in dangerous_ports:
                    results["findings"].append(f"Dangerous port {port} is open — {_guess_service(port)}")
                    results["risk_score"] += 25

    results["risk_score"] = min(results["risk_score"], 100)
    if not results["findings"] and results["open_ports"]:
        results["findings"].append(f"{len(results['open_ports'])} port(s) open — no critical issues found")
    elif not results["open_ports"]:
        results["findings"].append("No open ports found in scanned range")

    return results


def _guess_service(port):
    services = {
        21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
        80:"HTTP", 110:"POP3", 143:"IMAP", 443:"HTTPS",
        445:"SMB", 3306:"MySQL", 3389:"RDP", 5432:"PostgreSQL",
        6379:"Redis", 8080:"HTTP-Alt", 8443:"HTTPS-Alt",
        4444:"Metasploit/C2", 6667:"IRC", 27017:"MongoDB"
    }
    return services.get(port, f"Port-{port}")
