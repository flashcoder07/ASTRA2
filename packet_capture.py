import threading
import time
import requests
import logging
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, ICMP, conf, get_working_if

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('astra-capture')

class PacketCapture:
    def __init__(self, ingest_url="http://localhost:5000/ingest"):
        self.ingest_url = ingest_url
        self.stop_event = threading.Event()
        self.flows = defaultdict(lambda: {
            'packets': 0,
            'bytes': 0,
            'start_time': time.time(),
            'syn_count': 0,
            'destinations': set(),
            'failed_logins': 0
        })
        self.main_capture_thread = None
        self.loopback_capture_thread = None
        self.flush_thread = None
        self.interface = None
        self.packets_captured = 0
        self.flows_processed = 0

    def packet_callback(self, packet):
        if not packet.haslayer(IP):
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        src_port = 0
        dst_port = 0
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        # Filter out ASTRA's own internal API traffic (port 5000)
        # We allow other localhost traffic (port 22, ICMP, etc.)
        if src_ip == "127.0.0.1" and dst_port == 5000:
            return
        if dst_ip == "127.0.0.1" and src_port == 5000:
            return

        self.packets_captured += 1
        
        protocol = "OTHER"
        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"
        elif packet.haslayer(ICMP):
            protocol = "ICMP"

        # Unique key for flow aggregation
        flow_key = (src_ip, dst_ip, protocol)
        flow = self.flows[flow_key]
        
        flow['packets'] += 1
        flow['bytes'] += len(packet)
        flow['destinations'].add(dst_ip)

        if packet.haslayer(TCP):
            # Check for SYN flag (brute force/syn flood indicator)
            if packet[TCP].flags & 0x02:
                flow['syn_count'] += 1
            
            # SSH port 22 traffic indicator
            if dst_port == 22 or src_port == 22:
                # We count this as a login attempt indicator for the demo
                flow['failed_logins'] += 1

    def flush_flows(self):
        while not self.stop_event.is_set():
            time.sleep(5)
            
            # Debug log
            logger.info(f"Capture stats: {self.packets_captured} packets captured, {len(self.flows)} flows active")

            if not self.flows:
                continue

            current_flows = self.flows
            self.flows = defaultdict(lambda: {
                'packets': 0,
                'bytes': 0,
                'start_time': time.time(),
                'syn_count': 0,
                'destinations': set(),
                'failed_logins': 0
            })

            for (src_ip, dst_ip, proto), data in current_flows.items():
                duration = max(0.1, time.time() - data['start_time'])
                
                payload = {
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'protocol': proto,
                    'packets': data['packets'],
                    'bytes': data['bytes'],
                    'duration': round(duration, 2),
                    'syn_count': data['syn_count'],
                    'unique_destinations': len(data['destinations']),
                    'packets_per_second': round(data['packets'] / duration, 2),
                    'failed_logins': data['failed_logins']
                }

                try:
                    # Ingest into ASTRA
                    response = requests.post(self.ingest_url, json=payload, timeout=1)
                    if response.status_code == 202:
                        self.flows_processed += 1
                except Exception as e:
                    logger.error(f"Failed to POST flow: {e}")

    def _sniff_thread(self, iface):
        try:
            sniff(
                iface=iface, 
                prn=self.packet_callback, 
                stop_filter=lambda x: self.stop_event.is_set(),
                store=0
            )
        except Exception as e:
            logger.error(f"Sniffer on {iface} stopped: {e}")

    def start(self, interface=None):
        try:
            if interface is None:
                # Auto-detect main interface
                res = get_working_if()
                self.interface = res.name if res else None
            else:
                self.interface = interface

            logger.info(f"Capture started on main interface: {self.interface}")
            
            self.stop_event.clear()
            
            # Thread 1: Main interface
            if self.interface:
                self.main_capture_thread = threading.Thread(target=self._sniff_thread, args=(self.interface,), daemon=True)
                self.main_capture_thread.start()

            # Thread 2: Loopback (NPF_Loopback on Windows)
            loopback_if = r'\Device\NPF_Loopback'
            logger.info(f"Starting loopback capture on: {loopback_if}")
            self.loopback_capture_thread = threading.Thread(target=self._sniff_thread, args=(loopback_if,), daemon=True)
            self.loopback_capture_thread.start()

            # Thread 3: Flusher
            self.flush_thread = threading.Thread(target=self.flush_flows, daemon=True)
            self.flush_thread.start()
            
            return True
        except PermissionError:
            logger.error("Run as Administrator/sudo for packet capture")
            return False
        except Exception as e:
            logger.error(f"Error starting capture: {e}")
            return False

    def stop(self):
        self.stop_event.set()
        if self.main_capture_thread: self.main_capture_thread.join(timeout=1)
        if self.loopback_capture_thread: self.loopback_capture_thread.join(timeout=1)
        if self.flush_thread: self.flush_thread.join(timeout=1)
        logger.info("Capture stopped.")

_capture_instance = PacketCapture()

def start_capture(interface=None):
    return _capture_instance.start(interface)

def stop_capture():
    _capture_instance.stop()

def get_status():
    return {
        "interface": _capture_instance.interface,
        "packets_captured": _capture_instance.packets_captured,
        "flows_processed": _capture_instance.flows_processed
    }
