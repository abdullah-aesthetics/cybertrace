"""
DNS Anomaly Detection Module
Detects Domain Generation Algorithms (DGA), DNS tunneling,
fast-flux, and other suspicious DNS patterns.
"""
import math
import re
import socket
from datetime import datetime

# Common legitimate TLDs used by DGA malware to blend in
SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".pw", ".cc", ".su"}

# Known DGA-generated domain patterns
DGA_FAMILIES = {
    "Conficker":  r"^[a-z]{8,16}\.(com|net|org|info|biz)$",
    "Locky":      r"^[a-z]{16,32}\.(com|ru|org)$",
    "Cryptolocker": r"^[a-z0-9]{10,20}\.(biz|info|org)$",
}

COMMON_WORDS = {
    "google","facebook","youtube","amazon","microsoft","apple","twitter",
    "instagram","linkedin","github","stackoverflow","reddit","netflix",
    "paypal","ebay","yahoo","bing","wikipedia","wordpress","shopify"
}


def analyze_domain(domain):
    """Full DNS anomaly analysis for a domain."""
    domain = domain.lower().strip()
    base   = domain.split(".")[0]

    results = {
        "domain":           domain,
        "timestamp":        datetime.now().isoformat(),
        "entropy":          calculate_entropy(base),
        "dga_suspected":    False,
        "dga_family":       None,
        "suspicious_tld":   False,
        "dns_tunneling":    False,
        "fast_flux":        False,
        "subdomain_depth":  domain.count("."),
        "domain_length":    len(domain),
        "digit_ratio":      _digit_ratio(base),
        "consonant_ratio":  _consonant_ratio(base),
        "is_known_good":    base in COMMON_WORDS,
        "anomaly_score":    0,
        "findings":         [],
        "dns_records":      {},
        "resolved_ips":     []
    }

    # TLD check
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            results["suspicious_tld"] = True
            results["findings"].append(f"Suspicious TLD: {tld}")
            results["anomaly_score"] += 15

    # Entropy check — DGA domains have high randomness
    if results["entropy"] > 3.8:
        results["dga_suspected"] = True
        results["findings"].append(f"High entropy ({results['entropy']:.2f}) — likely DGA-generated")
        results["anomaly_score"] += 30
    elif results["entropy"] > 3.2:
        results["findings"].append(f"Moderate entropy ({results['entropy']:.2f})")
        results["anomaly_score"] += 10

    # Consonant ratio — DGA domains have unusually high consonant clusters
    if results["consonant_ratio"] > 0.75:
        results["findings"].append(f"High consonant ratio ({results['consonant_ratio']:.2f}) — DGA indicator")
        results["anomaly_score"] += 15

    # Digit ratio
    if results["digit_ratio"] > 0.4:
        results["findings"].append(f"High digit ratio ({results['digit_ratio']:.2f})")
        results["anomaly_score"] += 10

    # Domain length
    if len(base) > 20:
        results["findings"].append(f"Unusually long domain name ({len(base)} chars)")
        results["anomaly_score"] += 10
    elif len(base) < 4:
        results["findings"].append(f"Very short domain name ({len(base)} chars)")
        results["anomaly_score"] += 5

    # Subdomain depth
    if results["subdomain_depth"] > 4:
        results["dns_tunneling"] = True
        results["findings"].append(f"Deep subdomain nesting ({results['subdomain_depth']} levels) — possible DNS tunneling")
        results["anomaly_score"] += 25

    # Known DGA pattern matching
    for family, pattern in DGA_FAMILIES.items():
        if re.match(pattern, domain):
            results["dga_family"] = family
            results["dga_suspected"] = True
            results["findings"].append(f"Matches {family} DGA pattern")
            results["anomaly_score"] += 35
            break

    # DNS resolution — check for fast-flux (many IPs)
    try:
        ips = list(set(str(r[4][0]) for r in socket.getaddrinfo(domain, None)))
        results["resolved_ips"] = ips
        if len(ips) > 5:
            results["fast_flux"] = True
            results["findings"].append(f"Fast-flux suspected: {len(ips)} different IPs resolved")
            results["anomaly_score"] += 20
    except Exception:
        results["findings"].append("Domain does not resolve (possible DGA or inactive)")
        results["anomaly_score"] += 5

    results["anomaly_score"] = min(results["anomaly_score"], 100)

    if results["is_known_good"]:
        results["anomaly_score"] = max(0, results["anomaly_score"] - 30)
        results["findings"].insert(0, "Known legitimate domain base — score reduced")

    results["verdict"] = _dns_verdict(results["anomaly_score"], results["dga_suspected"])
    return results


def analyze_dns_query_stream(queries):
    """
    Analyze a stream of DNS queries for tunneling or beaconing.
    queries: list of {"domain": str, "timestamp": str}
    """
    if not queries:
        return {"findings": [], "tunneling_suspected": False}

    findings = []
    domain_freq = {}
    long_queries = []

    for q in queries:
        d = q.get("domain", "")
        domain_freq[d] = domain_freq.get(d, 0) + 1
        if len(d) > 50:
            long_queries.append(d)

    # Beaconing: same domain queried many times at regular intervals
    for domain, count in domain_freq.items():
        if count > 20:
            findings.append({
                "type": "DNS Beaconing",
                "detail": f"{domain} queried {count} times",
                "severity": "high"
            })

    # DNS tunneling: very long query names (data encoded in subdomain)
    for q in long_queries:
        findings.append({
            "type": "DNS Tunneling Suspected",
            "detail": f"Unusually long query: {q[:60]}...",
            "severity": "critical"
        })

    # High entropy queries (data exfil over DNS)
    high_entropy = [q.get("domain","") for q in queries if calculate_entropy(q.get("domain","")) > 4.0]
    if len(high_entropy) > 3:
        findings.append({
            "type": "High-Entropy DNS Queries",
            "detail": f"{len(high_entropy)} queries with entropy > 4.0 — possible data exfiltration",
            "severity": "high"
        })

    return {
        "total_queries":       len(queries),
        "unique_domains":      len(domain_freq),
        "tunneling_suspected": len(long_queries) > 0,
        "findings":            findings
    }


def calculate_entropy(s):
    """Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f/n) * math.log2(f/n) for f in freq.values())


def _digit_ratio(s):
    if not s: return 0.0
    return sum(c.isdigit() for c in s) / len(s)


def _consonant_ratio(s):
    if not s: return 0.0
    consonants = set("bcdfghjklmnpqrstvwxyz")
    letters = [c for c in s.lower() if c.isalpha()]
    if not letters: return 0.0
    return sum(c in consonants for c in letters) / len(letters)


def _dns_verdict(score, dga):
    if dga or score >= 70: return "MALICIOUS"
    if score >= 40:        return "SUSPICIOUS"
    if score >= 15:        return "LOW RISK"
    return "CLEAN"
