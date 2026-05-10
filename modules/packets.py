import threading
import time
import random
from datetime import datetime
from collections import defaultdict

# Global state for packet monitoring
_monitoring = False
_packet_buffer = []
_stats = defaultdict(int)
_lock = threading.Lock()

def start_monitoring(case_id=None, interface=None, duration=30):
    """
    Start packet monitoring in a background thread.
    On most systems this requires root/admin privileges.
    Falls back to simulated data if Wireshark/pyshark not available.
    """
    global _monitoring, _packet_buffer, _stats
    with _lock:
        _monitoring = True
        _packet_buffer = []
        _stats = defaultdict(int)

    thread = threading.Thread(
        target=_capture_packets,
        args=(case_id, interface, duration),
        daemon=True
    )
    thread.start()
    return {"status": "started", "case_id": case_id, "duration": duration}


def stop_monitoring():
    global _monitoring
    with _lock:
        _monitoring = False
    return {"status": "stopped"}


def get_live_stats():
    with _lock:
        packets = list(_packet_buffer[-50:])  # last 50 packets
        stats = dict(_stats)
    return {
        "packets": packets,
        "stats": stats,
        "monitoring": _monitoring
    }


def _capture_packets(case_id, interface, duration):
    """Try real capture, fall back to simulation."""
    try:
        _real_capture(case_id, interface, duration)
    except Exception:
        _simulated_capture(case_id, duration)


def _real_capture(case_id, interface, duration):
    """Real packet capture using PyShark (requires Wireshark + privileges)."""
    import pyshark
    cap = pyshark.LiveCapture(interface=interface or "eth0")
    end_time = time.time() + duration

    for packet in cap.sniff_continuously():
        if not _monitoring or time.time() > end_time:
            cap.close()
            break
        try:
            pkt = _parse_pyshark_packet(packet)
            _add_packet(pkt)
        except Exception:
            pass


def _simulated_capture(case_id, duration):
    """
    Simulated packet capture for demo / testing.
    Generates realistic-looking network traffic.
    """
    protocols = ["TCP", "UDP", "HTTP", "DNS", "ICMP", "TLS"]
    suspicious_ips = ["185.220.101.45", "91.108.4.1", "45.33.32.156"]
    normal_ips = [f"192.168.1.{i}" for i in range(2, 20)]
    all_ips = normal_ips + suspicious_ips

    end_time = time.time() + duration
    while _monitoring and time.time() < end_time:
        is_suspicious = random.random() < 0.15
        proto = random.choice(protocols)
        src = random.choice(suspicious_ips if is_suspicious else normal_ips)
        dst = random.choice(all_ips)

        pkt = {
            "timestamp": datetime.now().isoformat(),
            "src_ip": src,
            "dst_ip": dst,
            "protocol": proto,
            "src_port": random.randint(1024, 65535),
            "dst_port": _common_port(proto),
            "length": random.randint(64, 1500),
            "flags": _random_flags(proto),
            "suspicious": is_suspicious
        }
        _add_packet(pkt)
        time.sleep(random.uniform(0.05, 0.3))


def _parse_pyshark_packet(packet):
    """Parse a pyshark packet into our standard format."""
    src_ip = dst_ip = proto = ""
    src_port = dst_port = 0

    if hasattr(packet, "ip"):
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
    if hasattr(packet, "tcp"):
        proto = "TCP"
        src_port = int(packet.tcp.srcport)
        dst_port = int(packet.tcp.dstport)
    elif hasattr(packet, "udp"):
        proto = "UDP"
        src_port = int(packet.udp.srcport)
        dst_port = int(packet.udp.dstport)
    elif hasattr(packet, "icmp"):
        proto = "ICMP"
    else:
        proto = packet.highest_layer

    suspicious = (
        dst_port in [4444, 6667, 1337, 31337] or
        src_port in [4444, 6667, 1337, 31337]
    )

    return {
        "timestamp": datetime.now().isoformat(),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": proto,
        "src_port": src_port,
        "dst_port": dst_port,
        "length": int(packet.length) if hasattr(packet, "length") else 0,
        "flags": "",
        "suspicious": suspicious
    }


def _add_packet(pkt):
    global _packet_buffer, _stats
    with _lock:
        _packet_buffer.append(pkt)
        if len(_packet_buffer) > 500:
            _packet_buffer = _packet_buffer[-500:]
        _stats["total"] += 1
        _stats[pkt["protocol"]] += 1
        if pkt.get("suspicious"):
            _stats["suspicious"] += 1


def _common_port(proto):
    mapping = {
        "HTTP": 80, "HTTPS": 443, "TLS": 443,
        "DNS": 53, "FTP": 21, "SSH": 22, "SMTP": 25
    }
    return mapping.get(proto, random.choice([80, 443, 53, 8080, 22, 3306]))


def _random_flags(proto):
    if proto == "TCP":
        return random.choice(["SYN", "ACK", "SYN-ACK", "FIN", "RST", "PSH-ACK"])
    return ""


def analyze_packets(packets):
    """Analyze packet buffer for suspicious patterns."""
    if not packets:
        return {"findings": [], "suspicious_count": 0, "total": 0}

    suspicious_ports = {4444, 6667, 1337, 31337, 9001, 8888}
    ip_frequency = defaultdict(int)
    port_frequency = defaultdict(int)
    suspicious_findings = []

    for p in packets:
        ip_frequency[p.get("src_ip", "")] += 1
        port_frequency[p.get("dst_port", 0)] += 1

    # Detect port scan (many different ports from same IP)
    for ip, count in ip_frequency.items():
        if count > 20:
            suspicious_findings.append({
                "type": "High Frequency Traffic",
                "detail": f"{ip} sent {count} packets",
                "severity": "medium"
            })

    # Detect suspicious ports
    for p in packets:
        if p.get("dst_port") in suspicious_ports or p.get("src_port") in suspicious_ports:
            suspicious_findings.append({
                "type": "Suspicious Port",
                "detail": f"Traffic on port {p.get('dst_port')} ({p.get('src_ip')} → {p.get('dst_ip')})",
                "severity": "high"
            })

    return {
        "findings": suspicious_findings[:20],
        "suspicious_count": len([p for p in packets if p.get("suspicious")]),
        "total": len(packets),
        "top_talkers": sorted(ip_frequency.items(), key=lambda x: -x[1])[:5],
        "top_ports": sorted(port_frequency.items(), key=lambda x: -x[1])[:5]
    }
