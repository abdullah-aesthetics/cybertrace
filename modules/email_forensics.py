"""
Email Header Forensics Module
Analyzes email headers to trace real sender IP, detect spoofing,
check SPF/DKIM/DMARC, and identify phishing indicators.
"""
import re
import socket
from datetime import datetime


def analyze_email_headers(raw_headers):
    """
    Full forensic analysis of raw email headers.
    raw_headers: string of full email headers pasted by user
    """
    result = {
        "timestamp":      datetime.now().isoformat(),
        "from_address":   None,
        "reply_to":       None,
        "return_path":    None,
        "subject":        None,
        "message_id":     None,
        "sending_ips":    [],
        "hop_path":       [],
        "spf":            None,
        "dkim":           None,
        "dmarc":          None,
        "spoofing_detected": False,
        "findings":       [],
        "risk_score":     0,
        "verdict":        "CLEAN"
    }

    lines = raw_headers.splitlines()

    # ── Extract fields ────────────────────────────────────────────────────────
    result["from_address"] = _extract_field(lines, "From:")
    result["reply_to"]     = _extract_field(lines, "Reply-To:")
    result["return_path"]  = _extract_field(lines, "Return-Path:")
    result["subject"]      = _extract_field(lines, "Subject:")
    result["message_id"]   = _extract_field(lines, "Message-ID:")

    # Auth results
    auth_line = _extract_field(lines, "Authentication-Results:")
    if auth_line:
        result["spf"]   = "pass" if "spf=pass"  in auth_line.lower() else \
                          "fail" if "spf=fail"  in auth_line.lower() else "none"
        result["dkim"]  = "pass" if "dkim=pass" in auth_line.lower() else \
                          "fail" if "dkim=fail" in auth_line.lower() else "none"
        result["dmarc"] = "pass" if "dmarc=pass"in auth_line.lower() else \
                          "fail" if "dmarc=fail"in auth_line.lower() else "none"

    # ── Extract all Received headers (hop path) ───────────────────────────────
    received_blocks = []
    current = []
    for line in lines:
        if line.lower().startswith("received:"):
            if current:
                received_blocks.append(" ".join(current))
            current = [line]
        elif current and (line.startswith(" ") or line.startswith("\t")):
            current.append(line.strip())
    if current:
        received_blocks.append(" ".join(current))

    for block in received_blocks:
        ip_matches = re.findall(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', block)
        for ip in ip_matches:
            if not _is_private_ip(ip) and ip not in result["sending_ips"]:
                result["sending_ips"].append(ip)
        result["hop_path"].append({
            "raw":  block[:200],
            "ips":  ip_matches
        })

    # ── Checks ────────────────────────────────────────────────────────────────

    # SPF/DKIM/DMARC failures
    if result["spf"] == "fail":
        result["findings"].append("SPF FAILED — email may be spoofed (sender domain does not authorize this IP)")
        result["risk_score"] += 30
        result["spoofing_detected"] = True
    elif result["spf"] is None:
        result["findings"].append("No SPF record found — domain has no sender policy")
        result["risk_score"] += 10

    if result["dkim"] == "fail":
        result["findings"].append("DKIM FAILED — email content may have been tampered with")
        result["risk_score"] += 25
        result["spoofing_detected"] = True
    elif result["dkim"] is None:
        result["findings"].append("No DKIM signature found")
        result["risk_score"] += 5

    if result["dmarc"] == "fail":
        result["findings"].append("DMARC FAILED — email does not comply with domain's authentication policy")
        result["risk_score"] += 20

    # From vs Reply-To mismatch (common phishing trick)
    if result["from_address"] and result["reply_to"]:
        from_domain   = _extract_domain(result["from_address"])
        replyto_domain= _extract_domain(result["reply_to"])
        if from_domain and replyto_domain and from_domain != replyto_domain:
            result["findings"].append(
                f"Reply-To domain ({replyto_domain}) differs from From domain ({from_domain}) — common phishing trick"
            )
            result["risk_score"] += 25
            result["spoofing_detected"] = True

    # Return-Path mismatch
    if result["from_address"] and result["return_path"]:
        from_domain  = _extract_domain(result["from_address"])
        return_domain= _extract_domain(result["return_path"])
        if from_domain and return_domain and from_domain != return_domain:
            result["findings"].append(
                f"Return-Path domain ({return_domain}) differs from From domain ({from_domain})"
            )
            result["risk_score"] += 15

    # Suspicious subject patterns
    subj = (result["subject"] or "").lower()
    phishing_keywords = [
        "urgent", "verify your account", "suspended", "click here",
        "confirm your", "password reset", "winner", "congratulations",
        "invoice", "payment required", "action required", "unusual activity"
    ]
    matched = [k for k in phishing_keywords if k in subj]
    if matched:
        result["findings"].append(f"Subject contains phishing keywords: {', '.join(matched)}")
        result["risk_score"] += 20

    # Unusual number of hops
    if len(result["hop_path"]) > 8:
        result["findings"].append(f"Unusually many mail hops ({len(result['hop_path'])}) — may indicate routing obfuscation")
        result["risk_score"] += 10

    # Sending IPs geolocation
    result["ip_geolocations"] = []
    for ip in result["sending_ips"][:3]:
        geo = _quick_geolocate(ip)
        if geo:
            result["ip_geolocations"].append(geo)

    if not result["findings"]:
        result["findings"].append("No obvious email spoofing or phishing indicators detected")

    result["risk_score"] = min(result["risk_score"], 100)
    result["verdict"]    = _email_verdict(result["risk_score"], result["spoofing_detected"])
    return result


def _extract_field(lines, prefix):
    for i, line in enumerate(lines):
        if line.lower().startswith(prefix.lower()):
            value = line[len(prefix):].strip()
            # Continuation lines
            for j in range(i+1, min(i+5, len(lines))):
                if lines[j].startswith((" ", "\t")):
                    value += " " + lines[j].strip()
                else:
                    break
            return value
    return None


def _extract_domain(email_str):
    if not email_str:
        return None
    match = re.search(r'@([\w\.\-]+)', email_str)
    return match.group(1).lower() if match else None


def _is_private_ip(ip):
    parts = list(map(int, ip.split(".")))
    return (
        parts[0] == 10 or
        parts[0] == 127 or
        (parts[0] == 172 and 16 <= parts[1] <= 31) or
        (parts[0] == 192 and parts[1] == 168)
    )


def _quick_geolocate(ip):
    try:
        import requests
        r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
        if r.status_code == 200:
            d = r.json()
            return {
                "ip":      ip,
                "country": d.get("country_name", "Unknown"),
                "city":    d.get("city", "Unknown"),
                "isp":     d.get("org", "Unknown")
            }
    except Exception:
        pass
    return {"ip": ip, "country": "Unknown", "city": "Unknown", "isp": "Unknown"}


def _email_verdict(score, spoofing):
    if spoofing or score >= 60: return "PHISHING SUSPECTED"
    if score >= 30:             return "SUSPICIOUS"
    return "CLEAN"
