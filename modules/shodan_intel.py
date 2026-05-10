"""
Shodan Integration Module
Deep intelligence on any public IP: open ports, services,
vulnerabilities, device type, historical data.
Free API key: https://account.shodan.io/register
"""
import requests
from datetime import datetime

SHODAN_API_KEY = "YOUR_SHODAN_API_KEY"


def lookup_ip(ip):
    """Full Shodan lookup for an IP address."""
    result = {
        "ip":          ip,
        "timestamp":   datetime.now().isoformat(),
        "hostnames":   [],
        "domains":     [],
        "country":     "Unknown",
        "city":        "Unknown",
        "org":         "Unknown",
        "isp":         "Unknown",
        "asn":         "Unknown",
        "os":          "Unknown",
        "ports":       [],
        "services":    [],
        "vulns":       [],
        "tags":        [],
        "last_update": "Unknown",
        "risk_score":  0,
        "findings":    [],
        "status":      "success"
    }

    if SHODAN_API_KEY == "YOUR_SHODAN_API_KEY":
        return _demo_shodan(ip)

    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
        r   = requests.get(url, timeout=12)

        if r.status_code == 404:
            result["status"]   = "not_found"
            result["findings"] = ["IP not indexed in Shodan"]
            return result
        if r.status_code == 401:
            result["status"]   = "auth_error"
            result["findings"] = ["Invalid Shodan API key"]
            return result

        d = r.json()
        result["hostnames"]   = d.get("hostnames", [])
        result["domains"]     = d.get("domains", [])
        result["country"]     = d.get("country_name", "Unknown")
        result["city"]        = d.get("city", "Unknown")
        result["org"]         = d.get("org", "Unknown")
        result["isp"]         = d.get("isp", "Unknown")
        result["asn"]         = d.get("asn", "Unknown")
        result["os"]          = d.get("os", "Unknown")
        result["tags"]        = d.get("tags", [])
        result["last_update"] = d.get("last_update", "Unknown")
        result["ports"]       = d.get("ports", [])

        # Parse services
        for item in d.get("data", []):
            svc = {
                "port":      item.get("port"),
                "protocol":  item.get("transport", "tcp"),
                "service":   item.get("_shodan", {}).get("module", "unknown"),
                "banner":    (item.get("data", "") or "")[:200],
                "product":   item.get("product", ""),
                "version":   item.get("version", ""),
                "cpe":       item.get("cpe", []),
            }
            result["services"].append(svc)

        # Vulnerabilities
        vulns = d.get("vulns", {})
        for cve_id, cve_info in vulns.items():
            result["vulns"].append({
                "cve":     cve_id,
                "cvss":    cve_info.get("cvss", 0),
                "summary": cve_info.get("summary", "")[:200]
            })

        # Risk scoring
        result["risk_score"] += min(len(result["vulns"]) * 15, 50)
        if "honeypot" in result["tags"]:
            result["findings"].append("Shodan tagged as honeypot")
        if "tor" in result["tags"]:
            result["risk_score"] += 15
            result["findings"].append("Shodan tagged as Tor node")
        if "malware" in result["tags"]:
            result["risk_score"] += 30
            result["findings"].append("Shodan tagged as malware host")
        if result["vulns"]:
            result["findings"].append(f"{len(result['vulns'])} CVE(s) found on this host")
            high_cvss = [v for v in result["vulns"] if (v.get("cvss") or 0) >= 7.0]
            if high_cvss:
                result["findings"].append(f"{len(high_cvss)} high/critical severity CVE(s)")
                result["risk_score"] += 20

        # Dangerous open ports
        dangerous = {4444, 23, 6667, 1337, 31337, 5900, 3389}
        for p in result["ports"]:
            if p in dangerous:
                result["findings"].append(f"Dangerous port open: {p}")
                result["risk_score"] += 10

        result["risk_score"] = min(result["risk_score"], 100)
        if not result["findings"]:
            result["findings"].append("No critical issues found in Shodan data")

    except Exception as e:
        result["status"]   = "error"
        result["findings"] = [f"Shodan error: {str(e)}"]

    return result


def search_shodan(query, limit=5):
    """Search Shodan for devices matching a query string."""
    if SHODAN_API_KEY == "YOUR_SHODAN_API_KEY":
        return {"error": "Add your Shodan API key in modules/shodan_intel.py", "results": []}
    try:
        url = f"https://api.shodan.io/shodan/host/search?key={SHODAN_API_KEY}&query={query}&minify=true"
        r   = requests.get(url, timeout=12)
        d   = r.json()
        matches = []
        for m in d.get("matches", [])[:limit]:
            matches.append({
                "ip":      m.get("ip_str"),
                "port":    m.get("port"),
                "org":     m.get("org", "Unknown"),
                "country": m.get("location", {}).get("country_name", "Unknown"),
                "product": m.get("product", "Unknown"),
                "version": m.get("version", ""),
            })
        return {"total": d.get("total", 0), "results": matches}
    except Exception as e:
        return {"error": str(e), "results": []}


def _demo_shodan(ip):
    import random
    ports   = random.sample([22, 80, 443, 3306, 8080, 23, 6379], k=random.randint(2, 5))
    has_vuln= random.random() > 0.5
    vulns   = [{"cve": "CVE-2021-44228", "cvss": 10.0, "summary": "Log4Shell RCE vulnerability"}] if has_vuln else []
    score   = random.randint(20, 85) if has_vuln else random.randint(0, 30)
    return {
        "ip": ip, "timestamp": datetime.now().isoformat(),
        "status":      "demo",
        "hostnames":   [f"host-{ip.replace('.', '-')}.example.com"],
        "domains":     ["example.com"],
        "country":     random.choice(["Russia", "China", "United States", "Germany"]),
        "city":        random.choice(["Moscow", "Beijing", "New York", "Frankfurt"]),
        "org":         random.choice(["Frantech Solutions", "Choopa LLC", "Digital Ocean"]),
        "isp":         "Demo ISP",
        "asn":         f"AS{random.randint(1000,60000)}",
        "os":          random.choice(["Linux 3.x", "Windows Server 2019", "Unknown"]),
        "ports":       ports,
        "services":    [{"port": p, "protocol": "tcp", "service": _port_name(p), "banner": f"Demo banner port {p}", "product": "", "version": "", "cpe": []} for p in ports],
        "vulns":       vulns,
        "tags":        ["demo"],
        "last_update": datetime.now().isoformat()[:10],
        "risk_score":  score,
        "findings":    [f"Demo mode — add Shodan API key", f"{len(ports)} ports found"] + ([f"{len(vulns)} CVE(s) found"] if vulns else [])
    }

def _port_name(p):
    return {22:"SSH",80:"HTTP",443:"HTTPS",3306:"MySQL",8080:"HTTP-Alt",23:"Telnet",6379:"Redis"}.get(p, f"port-{p}")
