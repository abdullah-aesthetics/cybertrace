import os, sys, uuid, json
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file

sys.path.insert(0, os.path.dirname(__file__))

# Create required folders on startup
for folder in ["uploads", "reports", "database", "database/feed_cache"]:
    os.makedirs(folder, exist_ok=True)

from database.db import init_db, save_investigation, get_all_investigations, get_investigation, get_packet_logs
from modules.osint import run_osint
from modules.malware import scan_hash, scan_file
from modules.engine import calculate_risk
from modules.packets import start_monitoring, stop_monitoring, get_live_stats, analyze_packets
from modules.dns_analyzer import analyze_domain
from modules.ssl_analyzer import analyze_certificate
from modules.whois_analyzer import analyze_whois
from modules.threat_feeds import check_ip_against_feeds, check_url_against_feeds, get_feed_stats
from modules.ml_model import predict_threat
from modules.banner_grabber import scan_and_grab
from modules.email_forensics import analyze_email_headers
from modules.ioc_extractor import extract_iocs
from modules.shodan_intel import lookup_ip as shodan_lookup
from modules.case_manager import (init_case_management, get_case_status,
    update_case_status, mark_false_positive, add_note, get_notes,
    delete_note, attach_evidence, get_evidence, get_case_management_stats)
from modules.ml_retrain import retrain_model, get_training_history

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = "uploads"
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

with app.app_context():
    init_db()
    init_case_management()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/investigate", methods=["POST"])
def investigate():
    data = request.get_json()
    target = data.get("target", "").strip()
    target_type = data.get("target_type", "ip").strip()
    investigator = data.get("investigator", "Analyst").strip() or "Analyst"
    if not target: return jsonify({"error": "Target required"}), 400

    case_id = f"CT-{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:6].upper()}"
    osint_data = run_osint(target, target_type)
    ml_data = predict_threat(osint_data)

    feed_data = {}
    if target_type == "ip": feed_data = check_ip_against_feeds(target)
    elif target_type == "url": feed_data = check_url_against_feeds(target)

    shodan_data = None
    if target_type == "ip":
        try: shodan_data = shodan_lookup(target)
        except: pass

    dns_data = analyze_domain(target) if target_type == "domain" else None
    ssl_data = None
    if target_type == "domain":
        try: ssl_data = analyze_certificate(target)
        except: pass
    whois_data = analyze_whois(target) if target_type == "domain" else None
    banner_data = None
    if target_type == "ip":
        try: banner_data = scan_and_grab(target, ports=[21,22,23,25,80,443,3306,8080])
        except: pass

    risk = calculate_risk(osint_data, ml_data=ml_data, feed_data=feed_data,
        dns_data=dns_data, ssl_data=ssl_data, whois_data=whois_data, banner_data=banner_data)

    inv = {"case_id":case_id,"target":target,"target_type":target_type,
           "investigator":investigator,"timestamp":datetime.now().isoformat(),
           "risk_score":risk["risk_score"],"threat_level":risk["threat_level"],
           "osint_data":osint_data,"packet_data":{},"malware_data":{},
           "recommendations":risk["recommendations"]}
    save_investigation(inv)
    update_case_status(case_id, "Open", assigned_to=investigator)

    return jsonify({"case_id":case_id,"risk_score":risk["risk_score"],
        "threat_level":risk["threat_level"],"factors":risk["factors"],
        "recommendations":risk["recommendations"],"osint":osint_data,
        "ml":ml_data,"feed":feed_data,"dns":dns_data,"ssl":ssl_data,
        "whois":whois_data,"banner":banner_data,"shodan":shodan_data})

@app.route("/api/ioc/extract", methods=["POST"])
def ioc_extract():
    text = request.get_json().get("text","").strip()
    if not text: return jsonify({"error":"Text required"}),400
    return jsonify(extract_iocs(text))

@app.route("/api/shodan/<ip>")
def shodan_ip(ip): return jsonify(shodan_lookup(ip))

@app.route("/api/cases/<case_id>/status", methods=["GET"])
def case_status_get(case_id): return jsonify(get_case_status(case_id))

@app.route("/api/cases/<case_id>/status", methods=["POST"])
def case_status_update(case_id):
    d = request.get_json()
    return jsonify(update_case_status(case_id, d.get("status","Open"), d.get("assigned_to"), d.get("priority")))

@app.route("/api/cases/<case_id>/false_positive", methods=["POST"])
def false_positive(case_id):
    d = request.get_json()
    return jsonify(mark_false_positive(case_id, d.get("reason",""), d.get("author","Analyst")))

@app.route("/api/cases/<case_id>/notes", methods=["GET"])
def notes_get(case_id): return jsonify(get_notes(case_id))

@app.route("/api/cases/<case_id>/notes", methods=["POST"])
def notes_add(case_id):
    d = request.get_json()
    return jsonify(add_note(case_id, d.get("author","Analyst"), d.get("note",""), d.get("type","general")))

@app.route("/api/cases/<case_id>/notes/<int:note_id>", methods=["DELETE"])
def notes_delete(case_id, note_id): return jsonify(delete_note(note_id))

@app.route("/api/cases/<case_id>/evidence", methods=["GET"])
def evidence_get(case_id): return jsonify(get_evidence(case_id))

@app.route("/api/cases/<case_id>/evidence", methods=["POST"])
def evidence_upload(case_id):
    if "file" not in request.files: return jsonify({"error":"No file"}),400
    f = request.files["file"]
    path = os.path.join("uploads", f"evidence_{case_id}_{f.filename.replace('/','_')}")
    f.save(path)
    return jsonify(attach_evidence(case_id, f.filename, path,
        f.content_type or "application/octet-stream",
        request.form.get("description",""), request.form.get("author","Analyst")))

@app.route("/api/cases/stats/management")
def case_mgmt_stats(): return jsonify(get_case_management_stats())

@app.route("/api/ml/retrain", methods=["POST"])
def ml_retrain_api(): return jsonify(retrain_model())

@app.route("/api/ml/history")
def ml_history(): return jsonify(get_training_history())

@app.route("/api/map/data")
def map_data():
    cases = get_all_investigations()
    points = []
    for c in cases:
        try:
            osint = json.loads(c["osint_data"]) if isinstance(c["osint_data"],str) else c.get("osint_data",{})
            geo = osint.get("geolocation",{})
            if geo.get("latitude") and geo.get("longitude"):
                points.append({"case_id":c["case_id"],"target":c["target"],
                    "threat_level":c["threat_level"],"risk_score":c["risk_score"],
                    "lat":geo["latitude"],"lng":geo["longitude"],
                    "country":geo.get("country","Unknown"),"city":geo.get("city","Unknown"),
                    "isp":geo.get("isp","Unknown")})
        except: pass
    return jsonify(points)

@app.route("/api/analyze/dns", methods=["POST"])
def dns_analysis():
    domain = request.get_json().get("domain","").strip()
    if not domain: return jsonify({"error":"Domain required"}),400
    return jsonify(analyze_domain(domain))

@app.route("/api/analyze/ssl", methods=["POST"])
def ssl_analysis():
    domain = request.get_json().get("domain","").strip()
    if not domain: return jsonify({"error":"Domain required"}),400
    return jsonify(analyze_certificate(domain))

@app.route("/api/analyze/whois", methods=["POST"])
def whois_analysis():
    domain = request.get_json().get("domain","").strip()
    if not domain: return jsonify({"error":"Domain required"}),400
    return jsonify(analyze_whois(domain))

@app.route("/api/analyze/email", methods=["POST"])
def email_analysis():
    headers = request.get_json().get("headers","").strip()
    if not headers: return jsonify({"error":"Headers required"}),400
    return jsonify(analyze_email_headers(headers))

@app.route("/api/analyze/banner", methods=["POST"])
def banner_analysis():
    ip = request.get_json().get("ip","").strip()
    if not ip: return jsonify({"error":"IP required"}),400
    return jsonify(scan_and_grab(ip))

@app.route("/api/feeds/stats")
def feed_stats(): return jsonify(get_feed_stats())

@app.route("/api/feeds/check", methods=["POST"])
def feed_check():
    d = request.get_json()
    target, kind = d.get("target","").strip(), d.get("type","ip")
    if kind == "ip": return jsonify(check_ip_against_feeds(target))
    if kind == "url": return jsonify(check_url_against_feeds(target))
    return jsonify({"error":"Type must be ip or url"}),400

@app.route("/api/scan/hash", methods=["POST"])
def scan_hash_api():
    h = request.get_json().get("hash","").strip()
    if not h: return jsonify({"error":"Hash required"}),400
    return jsonify(scan_hash(h))

@app.route("/api/scan/file", methods=["POST"])
def scan_file_api():
    if "file" not in request.files: return jsonify({"error":"No file"}),400
    f = request.files["file"]
    path = os.path.join(app.config["UPLOAD_FOLDER"], f.filename.replace("/","_"))
    f.save(path)
    return jsonify(scan_file(path))

@app.route("/api/packets/start", methods=["POST"])
def start_packets():
    d = request.get_json() or {}
    return jsonify(start_monitoring(case_id=d.get("case_id"), duration=int(d.get("duration",30))))

@app.route("/api/packets/stop", methods=["POST"])
def stop_packets():
    result = stop_monitoring()
    stats = get_live_stats()
    analysis = analyze_packets(stats["packets"])
    return jsonify({**result,"analysis":analysis,"packets":stats["packets"][-20:]})

@app.route("/api/packets/live")
def live_packets(): return jsonify(get_live_stats())

@app.route("/api/cases")
def list_cases(): return jsonify(get_all_investigations())

@app.route("/api/cases/<case_id>")
def get_case(case_id):
    inv = get_investigation(case_id)
    if not inv: return jsonify({"error":"Not found"}),404
    inv["notes"] = get_notes(case_id)
    inv["evidence"] = get_evidence(case_id)
    inv["status"] = get_case_status(case_id)
    inv["packet_logs"] = get_packet_logs(case_id)
    return jsonify(inv)

@app.route("/api/report/<case_id>", methods=["POST"])
def generate_report_api(case_id):
    inv = get_investigation(case_id)
    if not inv: return jsonify({"error":"Not found"}),404
    from reports.report import generate_report
    result = generate_report(inv)
    if result.get("status") == "success":
        return send_file(result["path"], as_attachment=True,
                         download_name=os.path.basename(result["filename"]),
                         mimetype="application/pdf")
    return jsonify(result), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print("\n" + "="*60)
    print("  CyberTrace v2.0 — Advanced Forensic Intelligence Platform")
    print(f"  http://0.0.0.0:{port}")
    print("="*60 + "\n")
    app.run(debug=False, host="0.0.0.0", port=port)
