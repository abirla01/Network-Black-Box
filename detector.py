"""
Anomaly Detection Engine for Network Black Box.
Implements rule-based anomaly detection algorithms:
- High-Bandwidth Source Detection
- Packet-Flood Detection
- Port-Scan Detection
- SYN-Flood Detection
- Traffic-Spike Detection (Rolling baseline comparison)
- ARP-Spoofing / MAC Conflict Detection

Configurable thresholds, rolling time windows, and cooldown mechanisms
prevent false positives and unbounded memory growth.
"""

from collections import defaultdict, deque
import time
from typing import Any, Dict, List, Optional, Tuple


class NetworkAlert:
    """Structured network security alert object with backwards-compatible unpacking."""

    def __init__(
        self,
        alert_type: str,
        description: str,
        severity: str = "MEDIUM",
        source_ip: str = "",
        destination_ip: str = "",
        measured_value: float = 0.0,
        threshold_info: str = "",
        timestamp: Optional[str] = None
    ):
        self.alert_type = alert_type
        self.description = description
        self.severity = severity.upper()
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.measured_value = round(float(measured_value), 2)
        self.threshold_info = threshold_info
        self.timestamp = timestamp or time.strftime("%Y-%m-%d %H:%M:%S")

    def __iter__(self):
        """Allows unpacking as (alert_type, description) for backwards compatibility."""
        return iter((self.alert_type, self.description))

    def __getitem__(self, item: int):
        if item == 0:
            return self.alert_type
        elif item == 1:
            return self.description
        raise IndexError("Alert index out of range (0=alert_type, 1=description)")

    def __repr__(self) -> str:
        return f"[{self.severity}] {self.alert_type}: {self.description}"

    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to a dictionary representation."""
        return {
            "timestamp": self.timestamp,
            "severity": self.severity,
            "alert_type": self.alert_type,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "description": self.description,
            "measured_value": self.measured_value,
            "threshold_info": self.threshold_info,
        }


class NetworkDetector:
    """
    Lightweight, modular rule-based anomaly detection engine.
    Maintains bounded rolling history windows and alert cooldowns.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        cfg = config or {}

        # 1. Port scan parameters
        self.port_scan_threshold = cfg.get("port_scan_threshold", 15)  # distinct ports
        self.port_scan_window = cfg.get("port_scan_window", 10.0)      # seconds
        self.port_activity = defaultdict(deque)                        # src_ip -> deque((ts, port))

        # 2. SYN flood parameters
        self.syn_threshold = cfg.get("syn_threshold", 50)             # SYN packets
        self.syn_window = cfg.get("syn_window", 5.0)                  # seconds
        self.syn_activity = defaultdict(deque)                        # src_ip -> deque((ts, dst_ip))

        # 3. High-bandwidth parameters
        self.bandwidth_threshold = cfg.get("bandwidth_threshold", 5 * 1024 * 1024)  # 5 MB
        self.bandwidth_window = cfg.get("bandwidth_window", 10.0)                   # seconds
        self.traffic_activity = defaultdict(deque)                                 # src_ip -> deque((ts, size))

        # 4. Packet flood parameters
        self.packet_flood_threshold = cfg.get("packet_flood_threshold", 300)  # packets
        self.packet_flood_window = cfg.get("packet_flood_window", 5.0)        # seconds
        self.packet_activity = defaultdict(deque)                             # src_ip -> deque(ts)

        # 5. Traffic spike parameters (comparing current rate to historical baseline)
        self.spike_multiplier = cfg.get("spike_multiplier", 3.0)       # 3x baseline
        self.spike_min_mb_s = cfg.get("spike_min_mb_s", 0.5)           # min 0.5 MB/s to avoid noise
        self.spike_baseline_window = cfg.get("spike_baseline_window", 30)  # samples
        self.rate_history = deque(maxlen=self.spike_baseline_window)

        # 6. ARP spoofing / IP-MAC conflict detection
        self.ip_to_mac: Dict[str, str] = {}                           # ip -> mac

        # Alert cooldown tracker: (alert_type, key) -> last_alert_time
        self.alert_cooldown = cfg.get("alert_cooldown", 10.0)          # seconds
        self.last_alert_time: Dict[Tuple[str, str], float] = {}

    def _cleanup_tuples(self, dq: deque, now: float, window: float) -> None:
        """Purge entries older than rolling window where items are tuples (timestamp, ...)."""
        cutoff = now - window
        while dq and dq[0][0] < cutoff:
            dq.popleft()

    def _cleanup_timestamps(self, dq: deque, now: float, window: float) -> None:
        """Purge scalar timestamp entries older than rolling window."""
        cutoff = now - window
        while dq and dq[0] < cutoff:
            dq.popleft()

    def can_alert(self, alert_type: str, source_key: str, now: Optional[float] = None) -> bool:
        """Check if an alert is permitted based on duplicate cooldown timers."""
        current_time = now if now is not None else time.time()
        key = (alert_type, str(source_key))
        last_time = self.last_alert_time.get(key, 0.0)

        if current_time - last_time >= self.alert_cooldown:
            self.last_alert_time[key] = current_time
            return True
        return False

    def check_port_scan(
        self,
        source_ip: str,
        destination_port: Any,
        now: Optional[float] = None
    ) -> Optional[NetworkAlert]:
        """
        Detects if a single source IP contacts unusually many distinct ports
        within the rolling time window.
        """
        if not source_ip or destination_port in (None, "-", "", 0):
            return None

        try:
            port_num = int(destination_port)
        except (ValueError, TypeError):
            return None

        curr_time = now if now is not None else time.time()
        ports = self.port_activity[source_ip]
        ports.append((curr_time, port_num))
        self._cleanup_tuples(ports, curr_time, self.port_scan_window)

        unique_ports = {p for _, p in ports}
        port_count = len(unique_ports)

        if port_count >= self.port_scan_threshold:
            if self.can_alert("PORT_SCAN", source_ip, curr_time):
                return NetworkAlert(
                    alert_type="PORT_SCAN",
                    description=(
                        f"Possible port scan detected from {source_ip} "
                        f"({port_count} unique ports in {int(self.port_scan_window)}s)"
                    ),
                    severity="HIGH",
                    source_ip=source_ip,
                    measured_value=port_count,
                    threshold_info=f"{self.port_scan_threshold} ports in {int(self.port_scan_window)}s"
                )
        return None

    def check_syn_flood(
        self,
        source_ip: str,
        destination_ip: str = "",
        now: Optional[float] = None
    ) -> Optional[NetworkAlert]:
        """
        Detects TCP SYN floods by tracking high volumes of SYN requests without completions.
        """
        if not source_ip:
            return None

        curr_time = now if now is not None else time.time()
        syns = self.syn_activity[source_ip]
        syns.append((curr_time, destination_ip))
        self._cleanup_tuples(syns, curr_time, self.syn_window)

        syn_count = len(syns)
        if syn_count >= self.syn_threshold:
            if self.can_alert("SYN_FLOOD", source_ip, curr_time):
                rate = syn_count / self.syn_window if self.syn_window > 0 else syn_count
                return NetworkAlert(
                    alert_type="SYN_FLOOD",
                    description=(
                        f"Possible SYN flood from {source_ip}: {syn_count} SYN packets "
                        f"in {int(self.syn_window)}s ({rate:.1f} SYN/s)"
                    ),
                    severity="CRITICAL",
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    measured_value=rate,
                    threshold_info=f"{self.syn_threshold} SYNs in {int(self.syn_window)}s"
                )
        return None

    def check_bandwidth(
        self,
        source_ip: str,
        packet_size: int,
        now: Optional[float] = None
    ) -> Optional[NetworkAlert]:
        """
        Identifies individual source IPs generating excessive traffic volume over time window.
        """
        if not source_ip or packet_size <= 0:
            return None

        curr_time = now if now is not None else time.time()
        traffic = self.traffic_activity[source_ip]
        traffic.append((curr_time, int(packet_size)))
        self._cleanup_tuples(traffic, curr_time, self.bandwidth_window)

        total_bytes = sum(sz for _, sz in traffic)
        if total_bytes >= self.bandwidth_threshold:
            if self.can_alert("HIGH_BANDWIDTH", source_ip, curr_time):
                mb = total_bytes / (1024 * 1024)
                rate_mb_s = mb / self.bandwidth_window if self.bandwidth_window > 0 else mb
                threshold_mb = self.bandwidth_threshold / (1024 * 1024)
                return NetworkAlert(
                    alert_type="HIGH_BANDWIDTH",
                    description=(
                        f"High bandwidth source {source_ip}: {mb:.2f} MB in "
                        f"{int(self.bandwidth_window)}s ({rate_mb_s:.2f} MB/s)"
                    ),
                    severity="HIGH",
                    source_ip=source_ip,
                    measured_value=rate_mb_s,
                    threshold_info=f"{threshold_mb:.2f} MB in {int(self.bandwidth_window)}s"
                )
        return None

    def check_packet_flood(
        self,
        source_ip: str,
        now: Optional[float] = None
    ) -> Optional[NetworkAlert]:
        """
        Detects packet rate surges exceeding packet-rate thresholds per source IP.
        """
        if not source_ip:
            return None

        curr_time = now if now is not None else time.time()
        packets = self.packet_activity[source_ip]
        packets.append(curr_time)
        self._cleanup_timestamps(packets, curr_time, self.packet_flood_window)

        pkt_count = len(packets)
        if pkt_count >= self.packet_flood_threshold:
            if self.can_alert("PACKET_FLOOD", source_ip, curr_time):
                rate = pkt_count / self.packet_flood_window if self.packet_flood_window > 0 else pkt_count
                return NetworkAlert(
                    alert_type="PACKET_FLOOD",
                    description=(
                        f"High packet rate (packet flood) from {source_ip}: "
                        f"{pkt_count} packets in {int(self.packet_flood_window)}s ({rate:.1f} pkts/s)"
                    ),
                    severity="HIGH",
                    source_ip=source_ip,
                    measured_value=rate,
                    threshold_info=f"{self.packet_flood_threshold} pkts in {int(self.packet_flood_window)}s"
                )
        return None

    def check_traffic_spike(
        self,
        current_rate_mb_s: float,
        now: Optional[float] = None
    ) -> Optional[NetworkAlert]:
        """
        Detects sudden network-wide traffic spikes by comparing current rate
        against a rolling baseline average.
        """
        curr_time = now if now is not None else time.time()
        rate = max(0.0, float(current_rate_mb_s))

        alert = None
        # Require at least 5 baseline points before evaluating spikes
        if len(self.rate_history) >= 5:
            baseline_avg = sum(self.rate_history) / len(self.rate_history)
            if baseline_avg > 0.0 and rate >= self.spike_min_mb_s:
                ratio = rate / baseline_avg
                if ratio >= self.spike_multiplier:
                    if self.can_alert("TRAFFIC_SPIKE", "NETWORK", curr_time):
                        alert = NetworkAlert(
                            alert_type="TRAFFIC_SPIKE",
                            description=(
                                f"Traffic spike: {rate:.2f} MB/s is {ratio:.1f}x "
                                f"baseline average ({baseline_avg:.2f} MB/s)"
                            ),
                            severity="MEDIUM",
                            source_ip="NETWORK",
                            measured_value=rate,
                            threshold_info=(
                                f"{self.spike_multiplier}x baseline (min {self.spike_min_mb_s} MB/s)"
                            )
                        )

        # Update historical rate rolling window
        self.rate_history.append(rate)
        return alert

    def check_arp_spoofing(
        self,
        source_ip: str,
        source_mac: str,
        now: Optional[float] = None
    ) -> Optional[NetworkAlert]:
        """
        Detects potential ARP spoofing / poison attacks by identifying conflicting MAC addresses
        for an observed IP address.
        """
        if not source_ip or not source_mac:
            return None

        norm_mac = source_mac.strip().upper()
        # Ignore broadcast and multicast MAC addresses
        if norm_mac in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00") or norm_mac.startswith("01:00:5E"):
            return None

        curr_time = now if now is not None else time.time()

        if source_ip in self.ip_to_mac:
            existing_mac = self.ip_to_mac[source_ip]
            if existing_mac != norm_mac:
                # Potential ARP spoofing / IP conflict observed!
                if self.can_alert("ARP_SPOOFING", source_ip, curr_time):
                    alert = NetworkAlert(
                        alert_type="ARP_SPOOFING",
                        description=(
                            f"Potential ARP spoofing / MAC conflict for IP {source_ip}: "
                            f"MAC changed from {existing_mac} to {norm_mac}"
                        ),
                        severity="CRITICAL",
                        source_ip=source_ip,
                        measured_value=0.0,
                        threshold_info=f"Conflicting MAC: {norm_mac} != {existing_mac}"
                    )
                    # Update to avoid continuous alerts for legitimate changes
                    self.ip_to_mac[source_ip] = norm_mac
                    return alert

        self.ip_to_mac[source_ip] = norm_mac
        return None

    # Alias for method name consistency
    check_arp_packet = check_arp_spoofing

    def reset(self) -> None:
        """Reset all detector state, history windows, and cooldown timers."""
        self.port_activity.clear()
        self.syn_activity.clear()
        self.traffic_activity.clear()
        self.packet_activity.clear()
        self.rate_history.clear()
        self.ip_to_mac.clear()
        self.last_alert_time.clear()
