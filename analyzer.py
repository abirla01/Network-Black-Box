"""
Network Analyzer module for Network Black Box.
Maintains thread-safe traffic statistics, packet counts, per-IP totals,
protocol distributions, and real-time throughput calculations.
"""

from collections import Counter, defaultdict, deque
import threading
import time
from typing import Any, Dict, List, Optional, Tuple


class NetworkAnalyzer:
    """Thread-safe statistics and throughput analyzer for network traffic."""

    def __init__(self, history_len: int = 60, window_seconds: float = 1.0):
        self._lock = threading.Lock()
        self.history_len = history_len
        self.window_seconds = window_seconds

        # Counters and aggregates
        self.packet_count = 0
        self.total_bytes = 0
        self.traffic_by_ip = defaultdict(int)
        self.packets_by_ip = defaultdict(int)
        self.protocol_count = Counter()
        self.protocol_bytes = Counter()

        # Throughput tracking
        self.current_window_bytes = 0
        self.window_start = time.time()
        self.current_throughput_mb_s = 0.0

        # Bounded historical throughput for Matplotlib graphing
        self.throughput_history = deque([0.0] * 10, maxlen=self.history_len)
        self.throughput_times = deque(["--:--:--"] * 10, maxlen=self.history_len)

    def analyze_packet(
        self,
        source_ip: str,
        packet_size: int,
        protocol: str = "OTHER",
        timestamp: Optional[float] = None
    ) -> None:
        """
        Record a single captured packet into statistics.
        Thread-safe under lock.
        """
        if packet_size < 0:
            packet_size = 0
        if not source_ip:
            source_ip = "UNKNOWN"

        norm_proto = protocol.upper() if protocol else "OTHER"

        with self._lock:
            self.packet_count += 1
            self.total_bytes += packet_size
            self.current_window_bytes += packet_size

            self.traffic_by_ip[source_ip] += packet_size
            self.packets_by_ip[source_ip] += 1
            self.protocol_count[norm_proto] += 1
            self.protocol_bytes[norm_proto] += packet_size

    def update_throughput(self, now: Optional[float] = None) -> float:
        """
        Calculates throughput for the elapsed window and updates the graph history.
        Must be called periodically (e.g., every 0.5s - 1s) to handle idle periods correctly.
        """
        if now is None:
            now = time.time()

        with self._lock:
            elapsed = now - self.window_start
            if elapsed >= self.window_seconds:
                bytes_per_sec = self.current_window_bytes / elapsed if elapsed > 0 else 0.0
                mb_per_sec = bytes_per_sec / (1024 * 1024)

                self.current_throughput_mb_s = mb_per_sec
                self.throughput_history.append(mb_per_sec)
                self.throughput_times.append(time.strftime("%H:%M:%S", time.localtime(now)))

                # Reset window
                self.current_window_bytes = 0
                self.window_start = now

            return self.current_throughput_mb_s

    def get_statistics(self) -> Dict[str, Any]:
        """Return a complete, thread-safe snapshot dictionary of all current metrics."""
        with self._lock:
            total_pkts = self.packet_count
            total_bytes = self.total_bytes
            total_mb = total_bytes / (1024 * 1024) if total_bytes > 0 else 0.0
            unique_ips = len(self.traffic_by_ip)

            # Top traffic sources sorted by bytes descending
            sorted_ips = sorted(self.traffic_by_ip.items(), key=lambda item: item[1], reverse=True)
            top_sources = [
                {
                    "ip": ip,
                    "bytes": bytes_used,
                    "mb": bytes_used / (1024 * 1024),
                    "packets": self.packets_by_ip.get(ip, 0)
                }
                for ip, bytes_used in sorted_ips[:10]
            ]

            # Protocol distribution with percentages
            protocol_stats = {}
            for proto, count in self.protocol_count.most_common():
                pct = (count / total_pkts * 100.0) if total_pkts > 0 else 0.0
                protocol_stats[proto] = {
                    "count": count,
                    "bytes": self.protocol_bytes.get(proto, 0),
                    "percentage": round(pct, 1)
                }

            return {
                "packet_count": total_pkts,
                "total_bytes": total_bytes,
                "total_mb": round(total_mb, 2),
                "unique_ips": unique_ips,
                "current_throughput_mb_s": round(self.current_throughput_mb_s, 3),
                "top_sources": top_sources,
                "protocol_distribution": protocol_stats,
                "throughput_history": list(self.throughput_history),
                "throughput_times": list(self.throughput_times),
            }

    def reset(self) -> None:
        """Reset all statistics and throughput history."""
        with self._lock:
            self.packet_count = 0
            self.total_bytes = 0
            self.traffic_by_ip.clear()
            self.packets_by_ip.clear()
            self.protocol_count.clear()
            self.protocol_bytes.clear()
            self.current_window_bytes = 0
            self.window_start = time.time()
            self.current_throughput_mb_s = 0.0
            self.throughput_history.clear()
            self.throughput_times.clear()
            self.throughput_history.extend([0.0] * 10)
            self.throughput_times.extend(["--:--:--"] * 10)
