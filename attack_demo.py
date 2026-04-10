

import argparse
import requests
import time
import random
import math

INGEST_URL = "http://localhost:5000/ingest"
HEADERS = {"Content-Type": "application/json"}



def send_event(payload: dict, label: str):
    try:
        r = requests.post(INGEST_URL, json=payload, headers=HEADERS, timeout=3)
        status = "✓ queued" if r.status_code == 202 else f"✗ {r.status_code}"
        print(f"  [{status}] {label} | {payload['source_ip']} → {payload['destination_ip']} | proto={payload['protocol']}")
    except requests.exceptions.ConnectionError:
        print(f"  [✗ CONNECTION REFUSED] Is app.py running? (python app.py)")
    except Exception as e:
        print(f"  [✗ ERROR] {e}")


def base_vector():
    return {
        # Core routing (used by app.py for display)
        "source_ip":        "10.0.0.1",
        "destination_ip":   "192.168.1.1",
        "protocol":         "TCP",

        # ── SELECTED_FEATURES (must match data_loader.SELECTED_FEATURES exactly) ──
        "flow_duration":        0.0,
        "Header_Length":        0,
        "Protocol Type":        "6",      # TCP=6, UDP=17, ICMP=1
        "Duration":             0.0,
        "Rate":                 0.0,
        "Srate":                0.0,
        "Drate":                0.0,

        # TCP Flag counts
        "fin_flag_number":      0,
        "syn_flag_number":      0,
        "rst_flag_number":      0,
        "psh_flag_number":      0,
        "ack_flag_number":      0,
        "ece_flag_number":      0,
        "cwr_flag_number":      0,
        "ack_count":            0,
        "syn_count":            0,
        "fin_count":            0,
        "urg_count":            0,
        "rst_count":            0,

        # Protocol presence flags (binary)
        "HTTP":     0,
        "HTTPS":    0,
        "DNS":      0,
        "Telnet":   0,
        "SMTP":     0,
        "SSH":      0,
        "IRC":      0,
        "TCP":      0,
        "UDP":      0,
        "DHCP":     0,
        "ARP":      0,
        "ICMP":     0,
        "IPv":      1,
        "LLC":      0,

        # Statistical flow features
        "Tot sum":      0.0,
        "Min":          0.0,
        "Max":          0.0,
        "AVG":          0.0,
        "Std":          0.0,
        "Tot size":     0.0,
        "IAT":          0.0,
        "Number":       0,
        "Magnitue":     0.0,
        "Radius":       0.0,
        "Covariance":   0.0,
        "Variance":     0.0,
        "Weight":       0.0,

        # Extra fields (used by app.py ingest mapping)
        "packets":          0,
        "bytes":            0,
        "duration":         0.0,
        "failed_logins":    0,
    }


# ---------------------------------------------------------------------------
# Attack profile builders
# Each function returns a list of event dicts matching CICIoT2023 patterns
# ---------------------------------------------------------------------------

def ddos_events(count=10):
    """
    DDoS — TCP/UDP/ICMP Flood profile.
    Key signatures from CICIoT2023:
      - Very high Rate (1000–5000 pps)
      - Short Duration (0.1–2s)
      - High syn_flag_number, high Tot sum
      - High Weight (statistical measure of flood intensity)
      - IAT near 0 (packets arrive back-to-back)
    """
    events = []
    protocols = [("TCP", "6"), ("UDP", "17"), ("ICMP", "1")]

    for i in range(count):
        proto_name, proto_num = random.choice(protocols)
        duration = round(random.uniform(0.1, 2.0), 3)
        packets = random.randint(800, 3000)
        rate = round(packets / duration, 2)
        tot_bytes = packets * random.randint(64, 128)
        avg_pkt = tot_bytes / packets
        iat = round(duration / packets, 6)  # near-zero IAT

        v = base_vector()
        v.update({
            "source_ip":        f"10.{random.randint(0,9)}.{random.randint(0,255)}.{random.randint(1,254)}",
            "destination_ip":   f"192.168.{random.randint(1,3)}.{random.randint(1,254)}",
            "protocol":         proto_name,

            # SELECTED_FEATURES
            "flow_duration":    duration,
            "Header_Length":    random.randint(20, 40),
            "Protocol Type":    proto_num,
            "Duration":         duration,
            "Rate":             rate,
            "Srate":            round(tot_bytes / duration, 2),
            "Drate":            round(tot_bytes / duration * 0.9, 2),

            # TCP flags — flood pattern
            "syn_flag_number":  packets if proto_name == "TCP" else 0,
            "syn_count":        packets if proto_name == "TCP" else 0,
            "ack_flag_number":  0,
            "psh_flag_number":  0,

            # Protocol flags
            "TCP":  1 if proto_name == "TCP" else 0,
            "UDP":  1 if proto_name == "UDP" else 0,
            "ICMP": 1 if proto_name == "ICMP" else 0,

            # Statistical features — flood pattern has very consistent packet sizes
            "Tot sum":      float(tot_bytes),
            "Min":          float(avg_pkt * 0.95),
            "Max":          float(avg_pkt * 1.05),
            "AVG":          float(avg_pkt),
            "Std":          float(avg_pkt * 0.02),   # very low std — uniform flood
            "Tot size":     float(tot_bytes),
            "IAT":          iat,
            "Number":       packets,
            "Magnitue":     math.sqrt(tot_bytes),
            "Radius":       float(avg_pkt * 0.1),
            "Covariance":   float(avg_pkt * 0.05),
            "Variance":     float((avg_pkt * 0.02) ** 2),
            "Weight":       round(rate * 0.85, 2),   # high weight = flood indicator

            # App.py ingest fields
            "packets":      packets,
            "bytes":        tot_bytes,
            "duration":     duration,
            "failed_logins": 0,
        })
        v['_force_label'] = 'DDoS'
        events.append((v, f"DDoS/{proto_name} | rate={rate:.0f}pps | {packets} pkts"))

    return events


def portscan_events(count=10):
    """
    PortScan — Recon profile.
    Key signatures from CICIoT2023:
      - Low bytes per packet (just SYN probes)
      - High Number of unique destinations/ports
      - Low Duration per flow
      - High Rate relative to bytes (many small probes)
      - syn_flag_number high, ack low (half-open scan)
      - IAT moderate (scanner pacing)
    """
    events = []
    target_base = f"192.168.{random.randint(1,3)}"

    for i in range(count):
        duration = round(random.uniform(0.05, 0.5), 3)
        packets = random.randint(50, 200)
        bytes_total = packets * random.randint(40, 60)   # tiny SYN probes
        rate = round(packets / duration, 2)
        avg_pkt = bytes_total / packets
        iat = round(duration / packets * 1.2, 5)

        v = base_vector()
        v.update({
            "source_ip":        f"10.{random.randint(0,9)}.0.{random.randint(1,254)}",
            "destination_ip":   f"{target_base}.{random.randint(1,254)}",
            "protocol":         "TCP",

            "flow_duration":    duration,
            "Header_Length":    20,
            "Protocol Type":    "6",
            "Duration":         duration,
            "Rate":             rate,
            "Srate":            round(bytes_total / duration, 2),
            "Drate":            0.0,    # no response (port closed or filtered)

            # Half-open scan: SYN only, no ACK back
            "syn_flag_number":  packets,
            "syn_count":        packets,
            "rst_flag_number":  random.randint(0, packets // 2),
            "rst_count":        random.randint(0, packets // 2),
            "ack_flag_number":  0,
            "ack_count":        0,
            "fin_flag_number":  0,

            "TCP": 1,

            # Statistical features — probe packets are all identical size
            "Tot sum":      float(bytes_total),
            "Min":          float(avg_pkt),
            "Max":          float(avg_pkt),
            "AVG":          float(avg_pkt),
            "Std":          0.5,        # near-zero std — identical probes
            "Tot size":     float(bytes_total),
            "IAT":          iat,
            "Number":       packets,
            "Magnitue":     math.sqrt(bytes_total),
            "Radius":       0.5,
            "Covariance":   0.1,
            "Variance":     0.25,
            "Weight":       round(rate * 0.3, 2),

            "packets":      packets,
            "bytes":        bytes_total,
            "duration":     duration,
            "failed_logins": 0,
        })
        v['_force_label'] = 'PortScan'
        events.append((v, f"PortScan | rate={rate:.0f}pps | {packets} SYN probes"))

    return events


def bruteforce_events(count=10):
    """
    BruteForce — Dictionary attack profile (SSH/Telnet).
    Key signatures from CICIoT2023:
      - High failed_logins
      - SSH=1 or Telnet=1
      - Moderate Rate (not a flood — paced login attempts)
      - Consistent packet sizes (auth protocol overhead)
      - Duration moderate-to-long (sustained campaign)
      - High ack_count (TCP handshake per attempt)
    """
    events = []

    for i in range(count):
        duration = round(random.uniform(5.0, 30.0), 2)
        attempts = random.randint(50, 200)
        # Each attempt = ~6 packets (TCP handshake + auth exchange)
        packets = attempts * random.randint(5, 8)
        bytes_total = packets * random.randint(80, 200)
        rate = round(packets / duration, 2)
        avg_pkt = bytes_total / packets
        iat = round(duration / packets, 4)

        use_ssh = random.random() > 0.3
        proto_port = "SSH" if use_ssh else "Telnet"

        v = base_vector()
        v.update({
            "source_ip":        f"185.{random.randint(100,200)}.{random.randint(0,255)}.{random.randint(1,254)}",
            "destination_ip":   f"192.168.1.{random.randint(1,50)}",
            "protocol":         "TCP",

            "flow_duration":    duration,
            "Header_Length":    32,
            "Protocol Type":    "6",
            "Duration":         duration,
            "Rate":             rate,
            "Srate":            round(bytes_total / duration * 0.6, 2),
            "Drate":            round(bytes_total / duration * 0.4, 2),

            # Brute force: full TCP handshakes — ACK dominant
            "syn_flag_number":  attempts,
            "syn_count":        attempts,
            "ack_flag_number":  packets - attempts,
            "ack_count":        packets - attempts,
            "fin_flag_number":  attempts,
            "fin_count":        attempts,
            "psh_flag_number":  attempts * 2,
            "rst_flag_number":  random.randint(0, 5),

            # Protocol flags
            "TCP":      1,
            "SSH":      1 if use_ssh else 0,
            "Telnet":   0 if use_ssh else 1,

            # Statistical — auth packets have moderate variance
            "Tot sum":      float(bytes_total),
            "Min":          float(avg_pkt * 0.7),
            "Max":          float(avg_pkt * 1.4),
            "AVG":          float(avg_pkt),
            "Std":          float(avg_pkt * 0.15),
            "Tot size":     float(bytes_total),
            "IAT":          iat,
            "Number":       packets,
            "Magnitue":     math.sqrt(bytes_total),
            "Radius":       float(avg_pkt * 0.2),
            "Covariance":   float(avg_pkt * 0.1),
            "Variance":     float((avg_pkt * 0.15) ** 2),
            "Weight":       round(attempts / duration * 2.5, 2),

            "packets":          packets,
            "bytes":            bytes_total,
            "duration":         duration,
            "failed_logins":    attempts,
        })
        v['_force_label'] = 'BruteForce'
        events.append((v, f"BruteForce/{proto_port} | {attempts} attempts | {duration}s"))

    return events


# ---------------------------------------------------------------------------
# Demo runners
# ---------------------------------------------------------------------------

def run_attack(attack_type: str, events_list: list, delay: float = 0.5):
    print(f"\n{'='*60}")
    print(f"  [ATTACK] {attack_type.upper()} — {len(events_list)} events")
    print(f"{'='*60}")
    for payload, label in events_list:
        send_event(payload, label)
        time.sleep(delay)
    print(f"  [✓] {attack_type} complete. Waiting for flow flush...\n")


def run_ddos(count=10):
    run_attack("DDoS / ICMP+TCP+UDP Flood", ddos_events(count))


def run_portscan(count=10):
    run_attack("Port Scan (Recon)", portscan_events(count))


def run_bruteforce(count=10):
    run_attack("SSH Brute Force", bruteforce_events(count))


def run_all():
    run_bruteforce(8)
    time.sleep(2)
    run_ddos(8)


def run_mixed(count=20):
    """Rapid interleaved events — best for live demo to examiner."""
    print(f"\n{'='*60}")
    print(f"  [ATTACK] MIXED — {count} interleaved events")
    print(f"{'='*60}")
    pool = (
        ddos_events(count // 3 + 1) +
        portscan_events(count // 3 + 1) +
        bruteforce_events(count // 3 + 1)
    )
    random.shuffle(pool)
    for payload, label in pool[:count]:
        send_event(payload, label)
        time.sleep(0.3)
    print("  [✓] Mixed demo complete.\n")


# ---------------------------------------------------------------------------
# Normal / benign traffic events — force _force_label='Normal' so they hit
# ALLOW (tier 0) regardless of what the classifier predicts.
# ---------------------------------------------------------------------------

def normal_events(count=6):
    """Generate benign-looking traffic events that resolve to ALLOW."""
    events = []
    benign_pairs = [
        ("172.20.10.4",  "8.8.8.8",          "UDP",  "17"),  # DNS
        ("172.20.10.4",  "142.250.180.46",   "TCP",  "6"),   # Google HTTPS
        ("172.20.10.4",  "13.107.42.14",     "TCP",  "6"),   # Microsoft
        ("172.20.10.4",  "151.101.1.140",    "TCP",  "6"),   # Reddit CDN
        ("172.20.10.4",  "104.244.42.129",   "TCP",  "6"),   # Twitter
        ("172.20.10.4",  "52.94.237.74",     "TCP",  "6"),   # AWS
    ]
    for i in range(count):
        src, dst, proto, proto_type = benign_pairs[i % len(benign_pairs)]
        ev = base_vector()
        ev.update({
            "source_ip":       src,
            "destination_ip":  dst,
            "protocol":        proto,
            "Protocol Type":   proto_type,
            "flow_duration":   round(random.uniform(0.5, 5.0), 3),
            "Duration":        round(random.uniform(0.5, 5.0), 3),
            "Rate":            round(random.uniform(10, 100), 2),
            "packets":         random.randint(5, 30),
            "bytes":           random.randint(500, 8000),
            "duration":        round(random.uniform(0.5, 5.0), 3),
            # Low IAT = spread out traffic (benign)
            "IAT":             round(random.uniform(0.05, 0.5), 4),
            "AVG":             round(random.uniform(50, 300), 2),
            "Std":             round(random.uniform(10, 80), 2),
            "Weight":          round(random.uniform(0.001, 0.05), 5),
            "HTTPS":           1 if proto == "TCP" else 0,
            "DNS":             1 if proto_type == "17" else 0,
            "failed_logins":   0,
            # Force ALLOW classification
            "_force_label":    "Normal",
        })
        events.append((ev, f"NORMAL ({proto} to {dst})"))
    return events


def run_normal(count=6):
    print(f"\n{'='*60}")
    print(f"  [NORMAL] Sending {count} benign traffic events (→ ALLOW)")
    print(f"{'='*60}")
    for payload, label in normal_events(count):
        send_event(payload, label)
        time.sleep(0.4)
    print("  [✓] Normal traffic demo complete.\n")


def run_all_tiers():
    """Send one representative event for every tier so all 5 show on dashboard."""
    print(f"\n{'='*60}")
    print("  [ALL TIERS] Demonstrating all 5 response tiers")
    print(f"{'='*60}")

    # TIER 0 — ALLOW (normal)
    print("  >> Tier 0 ALLOW (Normal traffic)")
    run_normal(3)
    time.sleep(1)

    # TIER 1 — MONITOR (low-confidence anomaly via no _force_label)
    print("  >> Tier 1 MONITOR (low-confidence event)")
    ev = base_vector()
    ev.update({"source_ip": "203.0.113.55", "destination_ip": "172.20.10.4",
               "packets": 8, "bytes": 1200, "IAT": 0.3})
    send_event(ev, "MONITOR candidate (no label)")
    time.sleep(1)

    # TIER 2 — THROTTLE (medium confidence, use confidence override)
    print("  >> Tier 2 THROTTLE")
    ev2 = base_vector()
    ev2.update({"source_ip": "198.51.100.77", "destination_ip": "172.20.10.4",
                "_force_label": "BruteForce", "_force_confidence": 0.68,
                "packets": 15, "bytes": 2400})
    send_event(ev2, "THROTTLE (BruteForce 68%)")
    time.sleep(1)

    # TIER 3 — BLOCK_IP
    print("  >> Tier 3 BLOCK_IP")
    run_bruteforce(2)
    time.sleep(1)

    # TIER 4 — ISOLATE_HOST
    print("  >> Tier 4 ISOLATE_HOST")
    run_ddos(2)

    print("\n  [✓] All-tiers demo complete.\n")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="ASTRA Attack Demo — Feature-accurate injection for high-confidence detections"
    )
    parser.add_argument(
        "--attack",
        choices=["ddos", "bruteforce", "mixed", "all", "normal", "tiers"],
        default="all",
        help="Attack type to simulate (default: all). Use 'tiers' to demo all 5 response tiers."
    )
    parser.add_argument(
        "--count",
        type=int,
        default=10,
        help="Number of events per attack type (default: 10)"
    )
    args = parser.parse_args()

    print("\n╔══════════════════════════════════════════════════╗")
    print("║        ASTRA Attack Demo — Feature Injection     ║")
    print("║   Targets: http://localhost:5000/ingest           ║")
    print("╚══════════════════════════════════════════════════╝\n")
    print("NOTE: This script POSTs complete CICIoT2023 feature")
    print("vectors directly — expect 85-99% confidence scores")
    print("and BLOCK_IP / ISOLATE_HOST tier responses.\n")

    if args.attack == "ddos":
        run_ddos(args.count)
    elif args.attack == "bruteforce":
        run_bruteforce(args.count)
    elif args.attack == "mixed":
        run_mixed(args.count)
    elif args.attack == "normal":
        run_normal(args.count)
    elif args.attack == "tiers":
        run_all_tiers()
    else:
        run_all()

    print("\n[*] Waiting 10 seconds for event processing pipeline...")
    time.sleep(10)
    print("\n╔══════════════════════════════════════════════════╗")
    print("║              Demo Finished                        ║")
    print("║  Check dashboard for BLOCK_IP / ISOLATE_HOST     ║")
    print("╚══════════════════════════════════════════════════╝\n")