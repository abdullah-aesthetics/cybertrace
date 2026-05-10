"""
WHOIS & Domain Age Analysis Module
Checks domain registration age, registrar reputation,
privacy shields, and other registration anomalies.
"""
import socket
import re
from datetime import datetime, timezone

SUSPICIOUS_REGISTRARS = [
    "namecheap", "internet bs", "pdr", "publicdomainregistry",
    "1api", "regru", "beget", "nicline"
]

HIGH_RISK_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
    ".pw", ".cc", ".su", ".bit", ".onion"
}


def analyze_whois(domain):
    """Full WHOIS analysis for a domain."""
    result = {
        "domain":        domain,
        "timestamp":     datetime.now().isoformat(),
        "registered":    None,
        "expires":       None,
        "updated":       None,
        "registrar":     "Unknown",
        "registrant":    "Unknown",
        "age_days":      None,
        "findings":      [],
        "risk_score":    0,
        "verdict":       "CLEAN",
        "raw_whois":     ""
    }

    # Try python-whois library
    try:
        import whois
        w = whois.whois(domain)

        # Creation date
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created:
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            result["registered"] = str(created)[:10]
            result["age_days"]   = (datetime.now(timezone.utc) - created).days

        # Expiry date
        expiry = w.expiration_date
        if isinstance(expiry, list):
            expiry = expiry[0]
        if expiry:
            result["expires"] = str(expiry)[:10]

        # Updated date
        updated = w.updated_date
        if isinstance(updated, list):
            updated = updated[0]
        if updated:
            result["updated"] = str(updated)[:10]

        result["registrar"]  = str(w.registrar or "Unknown")
        result["registrant"] = str(w.name or w.org or "Privacy Protected")
        result["raw_whois"]  = str(w.text or "")[:1000]

    except ImportError:
        # Fallback: raw socket WHOIS query
        result = _raw_whois_lookup(domain, result)
    except Exception as e:
        result["findings"].append(f"WHOIS lookup failed: {e}")
        result["risk_score"] += 10

    # ── Checks ────────────────────────────────────────────────────────────────

    age = result.get("age_days")
    if age is not None:
        if age < 7:
            result["findings"].append(f"Domain registered only {age} day(s) ago — extremely new")
            result["risk_score"] += 40
        elif age < 30:
            result["findings"].append(f"Domain registered {age} days ago — very new (phishing risk)")
            result["risk_score"] += 25
        elif age < 90:
            result["findings"].append(f"Domain registered {age} days ago — relatively new")
            result["risk_score"] += 10
        else:
            result["findings"].append(f"Domain is {age} days old — established")
    else:
        result["findings"].append("Could not determine domain age")
        result["risk_score"] += 5

    # Suspicious registrar
    reg_lower = result["registrar"].lower()
    for susp in SUSPICIOUS_REGISTRARS:
        if susp in reg_lower:
            result["findings"].append(f"Registrar '{result['registrar']}' commonly used for malicious domains")
            result["risk_score"] += 15
            break

    # Privacy protection
    registrant_lower = result["registrant"].lower()
    if any(w in registrant_lower for w in ["privacy", "proxy", "protect", "redacted", "whoisguard"]):
        result["findings"].append("Registrant identity hidden behind privacy protection")
        result["risk_score"] += 10

    # High-risk TLD
    for tld in HIGH_RISK_TLDS:
        if domain.endswith(tld):
            result["findings"].append(f"High-risk TLD: {tld}")
            result["risk_score"] += 20
            break

    # Expiring very soon
    if result["expires"]:
        try:
            exp = datetime.fromisoformat(result["expires"].replace("Z",""))
            days_left = (exp - datetime.now()).days
            if 0 < days_left < 14:
                result["findings"].append(f"Domain expires in {days_left} days — may be abandoned soon")
                result["risk_score"] += 10
        except Exception:
            pass

    if not result["findings"]:
        result["findings"].append("Domain registration appears normal")

    result["risk_score"] = min(result["risk_score"], 100)
    result["verdict"]    = _whois_verdict(result["risk_score"])
    return result


def _raw_whois_lookup(domain, result):
    """Minimal WHOIS via raw socket when python-whois is unavailable."""
    tld = "." + domain.split(".")[-1]
    whois_servers = {
        ".com": "whois.verisign-grs.com",
        ".net": "whois.verisign-grs.com",
        ".org": "whois.pir.org",
        ".io":  "whois.nic.io",
        ".co":  "whois.nic.co",
    }
    server = whois_servers.get(tld, "whois.iana.org")

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(8)
        s.connect((server, 43))
        s.send((domain + "\r\n").encode())
        raw = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            raw += chunk
        s.close()
        text = raw.decode(errors="ignore")
        result["raw_whois"] = text[:1000]

        # Parse key fields
        for line in text.splitlines():
            low = line.lower()
            if "creation date" in low or "registered on" in low:
                date_str = line.split(":", 1)[-1].strip()[:10]
                result["registered"] = date_str
                try:
                    created = datetime.fromisoformat(date_str)
                    result["age_days"] = (datetime.now() - created).days
                except Exception:
                    pass
            elif "registrar:" in low:
                result["registrar"] = line.split(":", 1)[-1].strip()
            elif "expir" in low and "date" in low:
                result["expires"] = line.split(":", 1)[-1].strip()[:10]
    except Exception as e:
        result["findings"].append(f"Raw WHOIS failed: {e}")

    return result


def _whois_verdict(score):
    if score >= 60: return "SUSPICIOUS"
    if score >= 30: return "LOW RISK"
    return "CLEAN"
