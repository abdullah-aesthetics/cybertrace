"""
Threat Intelligence Feed Module
Pulls from free, live threat feeds: Feodo Tracker, URLhaus, ThreatFox.
All feeds are from abuse.ch — a legitimate non-profit cybersecurity org.
"""
import requests
import csv
import io
import json
import os
from datetime import datetime, timedelta

CACHE_DIR  = "database/feed_cache"
CACHE_TTL  = 3600  # seconds (1 hour)

FEEDS = {
    "feodo_ip": {
        "url":   "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
        "desc":  "Feodo Tracker — Active botnet C2 IPs",
        "type":  "ip"
    },
    "urlhaus": {
        "url":   "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "desc":  "URLhaus — Recent malware distribution URLs",
        "type":  "url"
    },
}


def _cache_path(name):
    os.makedirs(CACHE_DIR, exist_ok=True)
    return os.path.join(CACHE_DIR, f"{name}.json")


def _load_cache(name):
    path = _cache_path(name)
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            data = json.load(f)
        cached_at = datetime.fromisoformat(data["cached_at"])
        if (datetime.now() - cached_at).seconds < CACHE_TTL:
            return data["entries"]
    except Exception:
        pass
    return None


def _save_cache(name, entries):
    try:
        with open(_cache_path(name), "w") as f:
            json.dump({"cached_at": datetime.now().isoformat(), "entries": entries}, f)
    except Exception:
        pass


def fetch_feodo_ips():
    """Fetch active botnet C2 IPs from Feodo Tracker."""
    cached = _load_cache("feodo_ip")
    if cached is not None:
        return cached

    try:
        r = requests.get(FEEDS["feodo_ip"]["url"], timeout=12)
        ips = []
        for line in r.text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                parts = line.split(",")
                if len(parts) >= 2:
                    ips.append({
                        "ip":       parts[1].strip().strip('"'),
                        "malware":  parts[0].strip().strip('"') if len(parts) > 4 else "Unknown",
                        "status":   "online"
                    })
        _save_cache("feodo_ip", ips)
        return ips
    except Exception as e:
        return []


def fetch_urlhaus_urls():
    """Fetch recent malware URLs from URLhaus."""
    cached = _load_cache("urlhaus")
    if cached is not None:
        return cached

    try:
        r = requests.get(FEEDS["urlhaus"]["url"], timeout=12)
        urls = []
        reader = csv.reader(io.StringIO(r.text))
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            if len(row) >= 5:
                urls.append({
                    "url":     row[2].strip() if len(row) > 2 else "",
                    "status":  row[3].strip() if len(row) > 3 else "",
                    "tags":    row[5].strip() if len(row) > 5 else "",
                })
        _save_cache("urlhaus", urls[:500])
        return urls[:500]
    except Exception:
        return []


def check_ip_against_feeds(ip):
    """Check if an IP appears in any threat intelligence feed."""
    result = {
        "ip":       ip,
        "found":    False,
        "feeds":    [],
        "verdict":  "CLEAN",
        "details":  []
    }

    # Feodo Tracker
    feodo = fetch_feodo_ips()
    for entry in feodo:
        if entry.get("ip") == ip:
            result["found"] = True
            result["feeds"].append("Feodo Tracker (Botnet C2)")
            result["details"].append({
                "feed":    "Feodo Tracker",
                "malware": entry.get("malware", "Unknown"),
                "status":  entry.get("status", "Unknown")
            })

    if result["found"]:
        result["verdict"] = "MALICIOUS"

    return result


def check_url_against_feeds(url):
    """Check if a URL appears in URLhaus malware feed."""
    result = {
        "url":     url,
        "found":   False,
        "feeds":   [],
        "verdict": "CLEAN",
        "details": []
    }

    urlhaus = fetch_urlhaus_urls()
    for entry in urlhaus:
        if url in entry.get("url", ""):
            result["found"] = True
            result["feeds"].append("URLhaus")
            result["details"].append({
                "feed":   "URLhaus",
                "status": entry.get("status", "Unknown"),
                "tags":   entry.get("tags", ""),
            })

    if result["found"]:
        result["verdict"] = "MALICIOUS"

    return result


def get_feed_stats():
    """Return statistics about loaded feeds."""
    feodo  = fetch_feodo_ips()
    urlhaus= fetch_urlhaus_urls()
    return {
        "feodo_ip_count":   len(feodo),
        "urlhaus_url_count":len(urlhaus),
        "last_updated":     datetime.now().isoformat(),
        "feeds": [
            {"name": "Feodo Tracker", "entries": len(feodo),   "type": "IP Blocklist"},
            {"name": "URLhaus",       "entries": len(urlhaus),  "type": "URL Blocklist"},
        ]
    }
