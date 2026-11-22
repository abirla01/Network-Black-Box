"""
Network Monitor module for Network Black Box.
Manages network interface detection, live packet sniffing lifecycle,
safe packet header parsing, and deterministic simulated DEMO mode.
"""

from collections import deque
import random
import sys
import threading
import time
from typing import Any, Callable, Dict, List, Optional

try:
    from scapy.all import sniff, conf, get_if_list, AsyncSniffer
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import ARP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def get_available_interfaces() -> List[Dict[str, str]]:
    """
    Returns available network interfaces formatted for Windows with friendly names.
    Includes an automatic/default fallback option.
    """
    interfaces = [
        {
            "id": "AUTO",
            "name": "Auto (Default Interface)",
            "description": "Scapy automatic default network interface"
        }
    ]

    if not SCAPY_AVAILABLE:
        return interfaces

    try:
        from scapy.arch.windows import get_windows_if_list
        win_list = get_windows_if_list()
    except Exception:
        win_list = []

    # Map GUIDs to friendly names
    guid_map = {}
    for item in win_list:
        guid = item.get("guid", "").strip("{}").lower()
        if guid:
            guid_map[guid] = {
                "name": item.get("name", "Interface"),
                "description": item.get("description", "")
            }

    try:
        raw_ifaces = get_if_list()
    except Exception:
        raw_ifaces = []

    seen = set()
    for iface in raw_ifaces:
        if iface in seen:
            continue
        seen.add(iface)

        # Check if GUID matches
        matched_info = None
        for guid, info in guid_map.items():
            if guid in iface.lower():
                matched_info = info
                break

        if matched_info:
            friendly_title = f"{matched_info['name']} - {matched_info['description'][:35]}"
            interfaces.append({
                "id": iface,
                "name": friendly_title,
                "description": matched_info['description']
            })
        elif "loopback" in iface.lower():
            interfaces.append({
                "id": iface,
                "name": "Loopback Adapter (Localhost)",
                "description": "Npcap / Windows Loopback Interface"
            })
        else:
            interfaces.append({
                "id": iface,
                "name": iface,
                "description": iface
            })

    return interfaces


def parse_packet(packet, interface_name: str = "") -> Optional[Dict[str, Any]]:
    """
    Extracts headers and metadata from a Scapy packet safely.
    Does NOT store full application payload to preserve privacy and performance.
    """
    try:
        size = len(packet)
        now_str = time.strftime("%H:%M:%S")

        source = "UNKNOWN"
        destination = "UNKNOWN"
        protocol = "OTHER"
        source_port = "-"
        destination_port = "-"
        is_syn = False
        source_mac = ""

        if IP in packet:
            source = packet[IP].src
            destination = packet[IP].dst
        elif IPv6 in packet:
            source = packet[IPv6].src
            destination = packet[IPv6].dst
        elif ARP in packet:
            source = packet[ARP].psrc
            destination = packet[ARP].pdst
            protocol = "ARP"
            source_mac = getattr(packet[ARP], "hwsrc", "")
        else:
            # Non-IP layer 2 frame
            return None

        if TCP in packet:
            protocol = "TCP"
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport
            flags = packet[TCP].flags
            try:
                # SYN flag (0x02) without ACK flag (0x10)
                flag_val = int(flags)
                is_syn = bool((flag_val & 0x02) and not (flag_val & 0x10))
            except Exception:
                is_syn = "S" in str(flags) and "A" not in str(flags)

        elif UDP in packet:
            protocol = "UDP"
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

        elif ICMP in packet:
            protocol = "ICMP"

        return {
            "timestamp": now_str,
            "source_ip": source,
            "destination_ip": destination,
            "protocol": protocol,
            "source_port": str(source_port),
            "destination_port": str(destination_port),
            "packet_size": size,
            "is_syn": is_syn,
            "source_mac": source_mac,
            "interface_name": interface_name,
        }
    except Exception:
        return None


class NetworkMonitor:
    """
    Controls capture-thread lifecycle, interface selection,
    and simulated demo-traffic generation.
    """

    def __init__(
        self,
        on_packet: Optional[Callable[[Dict[str, Any]], None]] = None,
        on_error: Optional[Callable[[str], None]] = None
    ):
        self.on_packet = on_packet
        self.on_error = on_error

        self._running = False
        self._demo_mode = False
        self._thread: Optional[threading.Thread] = None
        self._sniffer: Optional[Any] = None
        self.selected_interface: Optional[str] = None

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def is_demo(self) -> bool:
        return self._demo_mode

    def start_capture(self, interface: Optional[str] = None, demo_mode: bool = False) -> None:
        """Start packet capture or demo simulation thread."""
        if self._running:
            return

        self._running = True
        self._demo_mode = demo_mode
        self.selected_interface = interface

        if demo_mode:
            self._thread = threading.Thread(
                target=self._run_demo_simulation,
                daemon=True,
                name="DemoSimulationThread"
            )
            self._thread.start()
        else:
            self._thread = threading.Thread(
                target=self._run_live_sniff,
                daemon=True,
                name="LiveSniffThread"
            )
            self._thread.start()

    def stop_capture(self) -> None:
        """Gracefully stop packet capture or simulation."""
        self._running = False

        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.5)
        self._thread = None

    def _run_live_sniff(self) -> None:
        """Executes Scapy packet sniffing in a dedicated worker thread."""
        if not SCAPY_AVAILABLE:
            if self.on_error:
                self.on_error("Scapy library is not installed or available.")
            self._running = False
            return

        iface_arg = None
        if self.selected_interface and self.selected_interface != "AUTO":
            iface_arg = self.selected_interface

        iface_display = iface_arg or "Default"

        def _packet_handler(pkt):
            if not self._running:
                return
            parsed = parse_packet(pkt, interface_name=iface_display)
            if parsed and self.on_packet:
                self.on_packet(parsed)

        try:
            # We use AsyncSniffer for clean start/stop control
            self._sniffer = AsyncSniffer(
                iface=iface_arg,
                prn=_packet_handler,
                store=False
            )
            self._sniffer.start()

            # Keep thread alive while sniffing is active
            while self._running and self._sniffer.running:
                time.sleep(0.3)

            if self._sniffer and self._sniffer.running:
                self._sniffer.stop()

        except PermissionError:
            err_msg = (
                "Capture failed: Administrator privileges required for raw packet sniffing on Windows. "
                "Run VS Code / PowerShell as Administrator or switch to Demo Mode."
            )
            if self.on_error:
                self.on_error(err_msg)
        except Exception as exc:
            err_msg = f"Capture error on interface '{iface_display}': {exc}"
            if self.on_error:
                self.on_error(err_msg)
        finally:
            self._running = False
            self._sniffer = None

    def _run_demo_simulation(self) -> None:
        """
        Generates synthetic packet metadata safely without any network transmission.
        Demonstrates normal traffic, high bandwidth, port scans, SYN floods,
        spikes, and ARP conflicts deterministically.
        """
        cycle = 0

        # Known mock devices
        gateway_ip = "192.168.1.1"
        gateway_mac = "AA:BB:CC:DD:EE:01"
        laptop_ip = "192.168.1.102"
        smart_tv_ip = "192.168.1.115"
        attacker_ip = "192.168.1.200"

        web_servers = [
            "142.250.190.46",  # Google
            "151.101.65.140",  # Reddit
            "104.244.42.1",    # Twitter
            "1.1.1.1",         # Cloudflare DNS
            "8.8.8.8"          # Google DNS
        ]

        while self._running:
            cycle += 1
            now_str = time.strftime("%H:%M:%S")

            # 1. Normal background browsing traffic (always present)
            dst_srv = random.choice(web_servers)
            is_dns = dst_srv in ("1.1.1.1", "8.8.8.8")
            proto = "UDP" if is_dns else "TCP"
            dport = 53 if is_dns else (443 if random.random() > 0.1 else 80)
            pkt_size = random.randint(64, 1460)

            sample_pkt = {
                "timestamp": now_str,
                "source_ip": laptop_ip,
                "destination_ip": dst_srv,
                "protocol": proto,
                "source_port": str(random.randint(49152, 65535)),
                "destination_port": str(dport),
                "packet_size": pkt_size,
                "is_syn": False,
                "source_mac": "AA:BB:CC:11:22:33",
                "interface_name": "SIMULATED_DEMO",
            }
            if self.on_packet and self._running:
                self.on_packet(sample_pkt)

            # 2. Stage-based deterministic anomalies for demonstration
            mod_cycle = cycle % 120

            # Scenario A: Simulated Port Scan from attacker (cycles 20-35)
            if 20 <= mod_cycle < 35:
                scan_port = 20 + (mod_cycle - 20) * 10
                scan_pkt = {
                    "timestamp": now_str,
                    "source_ip": attacker_ip,
                    "destination_ip": laptop_ip,
                    "protocol": "TCP",
                    "source_port": str(random.randint(50000, 60000)),
                    "destination_port": str(scan_port),
                    "packet_size": 60,
                    "is_syn": True,
                    "source_mac": "DE:AD:BE:EF:00:01",
                    "interface_name": "SIMULATED_DEMO",
                }
                if self.on_packet and self._running:
                    self.on_packet(scan_pkt)

            # Scenario B: Simulated SYN Flood from attacker (cycles 45-60)
            elif 45 <= mod_cycle < 60:
                for _ in range(4):
                    syn_pkt = {
                        "timestamp": now_str,
                        "source_ip": "10.0.0.99",
                        "destination_ip": gateway_ip,
                        "protocol": "TCP",
                        "source_port": str(random.randint(1024, 65535)),
                        "destination_port": "80",
                        "packet_size": 54,
                        "is_syn": True,
                        "source_mac": "DE:AD:BE:EF:00:02",
                        "interface_name": "SIMULATED_DEMO",
                    }
                    if self.on_packet and self._running:
                        self.on_packet(syn_pkt)

            # Scenario C: Simulated High Bandwidth / Streaming Spike (cycles 70-85)
            elif 70 <= mod_cycle < 85:
                for _ in range(6):
                    stream_pkt = {
                        "timestamp": now_str,
                        "source_ip": smart_tv_ip,
                        "destination_ip": "142.250.190.46",
                        "protocol": "TCP",
                        "source_port": "443",
                        "destination_port": str(random.randint(50000, 52000)),
                        "packet_size": 250000,  # ~250 KB chunks
                        "is_syn": False,
                        "source_mac": "11:22:33:44:55:66",
                        "interface_name": "SIMULATED_DEMO",
                    }
                    if self.on_packet and self._running:
                        self.on_packet(stream_pkt)

            # Scenario D: Simulated ARP Spoofing Conflict (cycle 95)
            elif mod_cycle == 95:
                # Gateway initial ARP broadcast
                initial_arp = {
                    "timestamp": now_str,
                    "source_ip": gateway_ip,
                    "destination_ip": laptop_ip,
                    "protocol": "ARP",
                    "source_port": "-",
                    "destination_port": "-",
                    "packet_size": 42,
                    "is_syn": False,
                    "source_mac": gateway_mac,
                    "interface_name": "SIMULATED_DEMO",
                }
                if self.on_packet and self._running:
                    self.on_packet(initial_arp)

                # Conflicting rogue ARP with conflicting MAC
                conflict_arp = {
                    "timestamp": now_str,
                    "source_ip": gateway_ip,
                    "destination_ip": laptop_ip,
                    "protocol": "ARP",
                    "source_port": "-",
                    "destination_port": "-",
                    "packet_size": 42,
                    "is_syn": False,
                    "source_mac": "DE:AD:BE:EF:AA:99",
                    "interface_name": "SIMULATED_DEMO",
                }
                if self.on_packet and self._running:
                    self.on_packet(conflict_arp)

            time.sleep(0.15)


# Standalone CLI mode support for quick command-line test
if __name__ == "__main__":
    print("==========================================")
    print("       NETWORK BLACK BOX - CLI SNIFFER    ")
    print("==========================================")
    ifaces = get_available_interfaces()
    print("Available Interfaces:")
    for idx, iface in enumerate(ifaces):
        print(f" [{idx}] {iface['name']}")

    def _cli_print(p):
        print(
            f"{p['timestamp']} | {p['source_ip']:15} -> {p['destination_ip']:15} | "
            f"{p['protocol']:5} | {p['destination_port']} | {p['packet_size']} bytes"
        )

    monitor = NetworkMonitor(on_packet=_cli_print)
    print("\nStarting simulated demo capture for 5 seconds (Press Ctrl+C to abort)...")
    monitor.start_capture(demo_mode=True)
    try:
        time.sleep(5)
    except KeyboardInterrupt:
        pass
    monitor.stop_capture()
    print("Finished.")