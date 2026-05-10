"""
SSL/TLS Certificate Analysis Module
Analyzes certificates for suspicious indicators: self-signed,
newly issued, weak ciphers, mismatched domains.
"""
import ssl
import socket
import json
from datetime import datetime, timezone


def analyze_certificate(domain, port=443):
    result = {
        "domain": domain,
        "port": port,
        "timestamp": datetime.now().isoformat(),
        "certificate": {},
        "findings": [],
        "risk_score": 0,
        "verdict": "CLEAN"
    }

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((domain, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

        if not cert:
            result["findings"].append("No certificate returned")
            result["risk_score"] = 40
            result["verdict"] = "SUSPICIOUS"
            return result

        # Parse dates
        not_before = _parse_cert_date(cert.get("notBefore", ""))
        not_after  = _parse_cert_date(cert.get("notAfter", ""))
        now        = datetime.now(timezone.utc)

        cert_age_days    = (now - not_before).days if not_before else 0
        days_until_expiry = (not_after - now).days if not_after else 0

        # Issuer
        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject= dict(x[0] for x in cert.get("subject", []))
        issuer_org = issuer.get("organizationName", "Unknown")
        subject_cn = subject.get("commonName", "Unknown")

        # SANs
        sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

        result["certificate"] = {
            "subject_cn":       subject_cn,
            "issuer_org":       issuer_org,
            "not_before":       str(not_before)[:10] if not_before else "Unknown",
            "not_after":        str(not_after)[:10] if not_after  else "Unknown",
            "cert_age_days":    cert_age_days,
            "days_to_expiry":   days_until_expiry,
            "sans":             sans[:10],
            "tls_version":      version,
            "cipher":           cipher[0] if cipher else "Unknown",
        }

        # ── Checks ──────────────────────────────────────────────────────────

        # Self-signed check
        if issuer_org == subject.get("organizationName", "DIFFERENT") or \
           issuer.get("commonName") == subject_cn:
            result["findings"].append("Self-signed certificate — not trusted by browsers")
            result["risk_score"] += 30

        # Let's Encrypt is fine but common in phishing too
        if "let's encrypt" in issuer_org.lower():
            result["findings"].append("Let's Encrypt cert — free certs are common in phishing sites")
            result["risk_score"] += 5

        # Very new certificate
        if 0 <= cert_age_days < 7:
            result["findings"].append(f"Certificate issued only {cert_age_days} day(s) ago — very new")
            result["risk_score"] += 25
        elif cert_age_days < 30:
            result["findings"].append(f"Certificate issued {cert_age_days} days ago — recently created")
            result["risk_score"] += 10

        # Expiring soon or already expired
        if days_until_expiry < 0:
            result["findings"].append("Certificate has EXPIRED")
            result["risk_score"] += 20
        elif days_until_expiry < 7:
            result["findings"].append(f"Certificate expires in {days_until_expiry} day(s)")
            result["risk_score"] += 10

        # Domain mismatch
        if subject_cn and domain not in subject_cn and domain not in sans:
            result["findings"].append(f"Domain mismatch: cert is for '{subject_cn}' not '{domain}'")
            result["risk_score"] += 25

        # Wildcard abuse
        wildcard_sans = [s for s in sans if s.startswith("*.")]
        if len(wildcard_sans) > 3:
            result["findings"].append(f"Excessive wildcard SANs ({len(wildcard_sans)}) — possible abuse")
            result["risk_score"] += 10

        # Weak TLS version
        if version in ("TLSv1", "TLSv1.1", "SSLv3"):
            result["findings"].append(f"Weak TLS version: {version}")
            result["risk_score"] += 15

        if not result["findings"]:
            result["findings"].append("Certificate appears legitimate")

    except ssl.SSLError as e:
        result["findings"].append(f"SSL error: {e}")
        result["risk_score"] += 20
    except socket.timeout:
        result["findings"].append("Connection timed out")
        result["risk_score"] += 5
    except ConnectionRefusedError:
        result["findings"].append("Port 443 is closed — no HTTPS")
        result["risk_score"] += 10
    except Exception as e:
        result["findings"].append(f"Analysis error: {e}")

    result["risk_score"] = min(result["risk_score"], 100)
    result["verdict"] = _ssl_verdict(result["risk_score"])
    return result


def _parse_cert_date(date_str):
    if not date_str:
        return None
    try:
        # e.g. "Jan  1 00:00:00 2024 GMT"
        from email.utils import parsedate_to_datetime
        return parsedate_to_datetime(date_str).replace(tzinfo=timezone.utc)
    except Exception:
        try:
            return datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        except Exception:
            return None


def _ssl_verdict(score):
    if score >= 60: return "SUSPICIOUS"
    if score >= 30: return "LOW RISK"
    return "CLEAN"
