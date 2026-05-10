"""
Enhanced Threat Correlation Engine
Combines OSINT + ML + DNS + SSL + WHOIS + Threat Feeds + Packets + Malware
into a single unified risk score and recommendation set.
"""
from datetime import datetime


def calculate_risk(osint_data, packet_data=None, malware_data=None,
                   dns_data=None, ssl_data=None, whois_data=None,
                   feed_data=None, ml_data=None, banner_data=None,
                   email_data=None):

    score   = 0
    factors = []

    # OSINT
    vt  = osint_data.get("virustotal", {})
    mal = vt.get("malicious", 0)
    if mal >= 10: score += 40; factors.append(f"VirusTotal: {mal} engines flagged malicious")
    elif mal >= 3: score += 25; factors.append(f"VirusTotal: {mal} engines flagged malicious")
    elif mal >= 1: score += 10; factors.append(f"VirusTotal: {mal} engine flagged malicious")

    sus = vt.get("suspicious", 0)
    if sus >= 5: score += 10; factors.append(f"VirusTotal: {sus} suspicious detections")
    elif sus >= 1: score += 5

    abuse = osint_data.get("abuseipdb", {})
    ab    = abuse.get("abuse_score", 0)
    if ab >= 80: score += 30; factors.append(f"AbuseIPDB score: {ab}%")
    elif ab >= 50: score += 20; factors.append(f"AbuseIPDB score: {ab}%")
    elif ab >= 20: score += 10; factors.append(f"AbuseIPDB score: {ab}%")

    if abuse.get("is_tor"):
        score += 10; factors.append("Traffic routed through Tor exit node")

    for p in osint_data.get("open_ports", []):
        if p["port"] in [4444, 23, 6667, 1337]:
            score += 15; factors.append(f"Dangerous open port: {p['port']} ({p['service']})")

    # ML Prediction
    if ml_data:
        ml_score = ml_data.get("ml_score", 0)
        if ml_score >= 75: score += 20; factors.append(f"ML model: {ml_score}% malicious probability")
        elif ml_score >= 50: score += 12; factors.append(f"ML model: {ml_score}% suspicious probability")
        elif ml_score >= 30: score += 5

    # Threat Intel Feeds
    if feed_data and feed_data.get("found"):
        score += 35
        for f in feed_data.get("feeds", []):
            factors.append(f"Found in threat feed: {f}")

    # DNS Anomaly
    if dns_data:
        dns_score = dns_data.get("anomaly_score", 0)
        if dns_score >= 70: score += 20; factors.append(f"DNS: DGA domain suspected (score {dns_score})")
        elif dns_score >= 40: score += 12; factors.append(f"DNS anomaly score: {dns_score}")
        if dns_data.get("dns_tunneling"):
            score += 15; factors.append("DNS tunneling detected")
        if dns_data.get("fast_flux"):
            score += 10; factors.append("Fast-flux DNS detected")

    # SSL Certificate
    if ssl_data:
        ssl_score = ssl_data.get("risk_score", 0)
        if ssl_score >= 60: score += 15; factors.append(f"SSL: suspicious certificate (score {ssl_score})")
        elif ssl_score >= 30: score += 7; factors.append(f"SSL certificate anomaly (score {ssl_score})")

    # WHOIS / Domain Age
    if whois_data:
        age = whois_data.get("age_days")
        if age is not None:
            if age < 7:   score += 25; factors.append(f"Domain registered only {age} day(s) ago")
            elif age < 30: score += 15; factors.append(f"Domain registered {age} days ago (very new)")
            elif age < 90: score += 5
        if whois_data.get("risk_score", 0) >= 40:
            score += 10; factors.append("WHOIS registration anomalies detected")

    # Banner / CVEs
    if banner_data:
        cves = banner_data.get("cve_summary", [])
        if cves:
            score += min(len(cves) * 10, 25)
            factors.append(f"Banner grabbing found {len(cves)} potential CVE(s): {', '.join(c['cve'] for c in cves[:3])}")

    # Email Forensics
    if email_data:
        if email_data.get("spoofing_detected"):
            score += 30; factors.append("Email spoofing detected (SPF/DKIM/DMARC failure)")
        elif email_data.get("risk_score", 0) >= 30:
            score += 10; factors.append("Email header anomalies detected")

    # Packet Analysis
    if packet_data:
        sp = packet_data.get("suspicious_count", 0)
        if sp > 50: score += 15; factors.append(f"{sp} suspicious packets detected")
        elif sp > 10: score += 8
        for finding in packet_data.get("findings", []):
            if finding["severity"] == "high":
                score += 8; factors.append(f"Packet: {finding['detail']}")

    # Malware
    if malware_data:
        verdict = malware_data.get("verdict", "clean")
        sev     = malware_data.get("severity", "none")
        if verdict == "malicious" and sev == "critical":
            score += 40; factors.append(f"Malware: {malware_data.get('threat_name','Unknown')}")
        elif verdict == "malicious":
            score += 25; factors.append(f"Malware detected: {malware_data.get('threat_name','Unknown')}")
        elif verdict == "suspicious":
            score += 10; factors.append("File flagged as suspicious")

    score = min(score, 100)

    if score >= 75:   level = "CRITICAL"
    elif score >= 50: level = "HIGH"
    elif score >= 25: level = "MEDIUM"
    elif score >= 5:  level = "LOW"
    else:             level = "CLEAN"

    recommendations = _build_recommendations(
        score, level, osint_data, packet_data, malware_data,
        dns_data, ssl_data, whois_data, feed_data, email_data
    )

    return {
        "risk_score":      score,
        "threat_level":    level,
        "factors":         factors,
        "recommendations": recommendations,
        "analyzed_at":     datetime.now().isoformat()
    }


def _build_recommendations(score, level, osint, packets, malware,
                            dns=None, ssl=None, whois=None,
                            feeds=None, email=None):
    recs = []

    if level in ("CRITICAL", "HIGH"):
        recs.append("Immediately block this target at the firewall and perimeter level")
        recs.append("Isolate any machines that communicated with this target")
        recs.append("Preserve all logs and memory images for forensic analysis")
        recs.append("Notify your security team and trigger incident response plan")

    if level == "MEDIUM":
        recs.append("Add to watchlist and monitor closely for 72 hours")
        recs.append("Review all connections to/from this target in the last 30 days")

    if osint.get("abuseipdb", {}).get("is_tor"):
        recs.append("Block Tor exit nodes at perimeter using a live Tor blocklist feed")

    ports = osint.get("open_ports", [])
    if ports:
        recs.append(f"Close or firewall unnecessary ports: {', '.join(str(p['port']) for p in ports)}")

    if feeds and feeds.get("found"):
        recs.append("Target confirmed in threat intelligence feed — block immediately and hunt for lateral movement")

    if dns:
        if dns.get("dga_suspected"):
            recs.append("DGA domain detected — block entire domain family and check for C2 beaconing")
        if dns.get("dns_tunneling"):
            recs.append("DNS tunneling suspected — restrict DNS to authoritative servers only")
        if dns.get("fast_flux"):
            recs.append("Fast-flux DNS detected — block at DNS resolver level, not just by IP")

    if ssl and ssl.get("risk_score", 0) >= 30:
        recs.append("SSL certificate anomalies found — verify certificate chain before trusting this host")

    if whois and (whois.get("age_days") or 999) < 30:
        recs.append("Newly registered domain — treat with extreme caution, likely phishing or malware campaign")

    if malware and malware.get("verdict") == "malicious":
        recs.append("Delete or quarantine the malicious file immediately")
        recs.append("Run full AV scan on affected systems")
        recs.append("Reset credentials of all users on infected machines")

    if email and email.get("spoofing_detected"):
        recs.append("Email spoofing confirmed — do not click any links, report to your email admin")
        recs.append("Implement strict DMARC policy (p=reject) on your domain")

    if not recs:
        recs.append("No immediate action required — continue routine monitoring")
        recs.append("Keep threat intelligence feeds and AV signatures up to date")

    return recs
