"""
Automated unit test suite for Network Black Box.
Tests:
- Protocol classification (TCP, UDP, ICMP, ARP, OTHER)
- Packet and byte counting
- Per-source-IP traffic tracking
- Real-time throughput calculations
- Port-scan detection
- SYN-flood detection
- Packet-flood detection
- High-bandwidth source detection
- Traffic-spike detection (rolling baseline)
- ARP spoofing / MAC conflict detection
- Alert duplicate cooldown timers
- SQLite initialization, packet logging, and alert logging
- Malformed data, None inputs, and edge cases

All tests use safe, synthetic in-memory metadata.
Zero network activity. Zero administrator privileges required.
Runnable with: python test_detector.py
"""

import os
import tempfile
import time
import unittest

from analyzer import NetworkAnalyzer
from detector import NetworkDetector, NetworkAlert
from database import DatabaseManager, init_database
from network_monitor import parse_packet


class TestAnalyzer(unittest.TestCase):
    """Tests for NetworkAnalyzer statistics and throughput module."""

    def setUp(self):
        self.analyzer = NetworkAnalyzer(history_len=20, window_seconds=1.0)

    def test_packet_and_byte_counting(self):
        self.analyzer.analyze_packet("192.168.1.10", 500, "TCP")
        self.analyzer.analyze_packet("192.168.1.10", 300, "TCP")
        self.analyzer.analyze_packet("192.168.1.20", 200, "UDP")

        stats = self.analyzer.get_statistics()
        self.assertEqual(stats["packet_count"], 3)
        self.assertEqual(stats["total_bytes"], 1000)
        self.assertEqual(stats["unique_ips"], 2)

    def test_protocol_classification(self):
        self.analyzer.analyze_packet("10.0.0.1", 100, "TCP")
        self.analyzer.analyze_packet("10.0.0.2", 100, "UDP")
        self.analyzer.analyze_packet("10.0.0.3", 100, "ICMP")
        self.analyzer.analyze_packet("10.0.0.4", 100, "ARP")
        self.analyzer.analyze_packet("10.0.0.5", 100, "OTHER")

        stats = self.analyzer.get_statistics()
        dist = stats["protocol_distribution"]
        self.assertEqual(dist["TCP"]["count"], 1)
        self.assertEqual(dist["UDP"]["count"], 1)
        self.assertEqual(dist["ICMP"]["count"], 1)
        self.assertEqual(dist["ARP"]["count"], 1)
        self.assertEqual(dist["OTHER"]["count"], 1)
        self.assertEqual(dist["TCP"]["percentage"], 20.0)

    def test_per_source_ip_statistics(self):
        self.analyzer.analyze_packet("192.168.1.50", 1000, "TCP")
        self.analyzer.analyze_packet("192.168.1.50", 500, "TCP")
        self.analyzer.analyze_packet("192.168.1.99", 200, "UDP")

        stats = self.analyzer.get_statistics()
        top = stats["top_sources"]
        self.assertEqual(top[0]["ip"], "192.168.1.50")
        self.assertEqual(top[0]["bytes"], 1500)
        self.assertEqual(top[0]["packets"], 2)
        self.assertEqual(top[1]["ip"], "192.168.1.99")
        self.assertEqual(top[1]["bytes"], 200)

    def test_throughput_calculation(self):
        now = time.time()
        self.analyzer.window_start = now - 1.0  # simulate 1 second elapsed
        # 1 MB in 1 second = 1 MB/s
        self.analyzer.analyze_packet("10.0.0.1", 1024 * 1024, "TCP")
        rate = self.analyzer.update_throughput(now=now)
        self.assertAlmostEqual(rate, 1.0, places=1)

    def test_empty_and_edge_cases(self):
        # Negative packet size should be clamped to 0
        self.analyzer.analyze_packet("", -50, None)
        stats = self.analyzer.get_statistics()
        self.assertEqual(stats["total_bytes"], 0)
        self.assertEqual(stats["packet_count"], 1)

        # Reset should restore pristine state
        self.analyzer.reset()
        clean_stats = self.analyzer.get_statistics()
        self.assertEqual(clean_stats["packet_count"], 0)
        self.assertEqual(clean_stats["total_bytes"], 0)
        self.assertEqual(clean_stats["unique_ips"], 0)


class TestDetector(unittest.TestCase):
    """Tests for NetworkDetector anomaly detection rules."""

    def setUp(self):
        self.detector = NetworkDetector({
            "port_scan_threshold": 10,
            "port_scan_window": 5.0,
            "syn_threshold": 20,
            "syn_window": 5.0,
            "bandwidth_threshold": 1024 * 1024,  # 1 MB
            "bandwidth_window": 5.0,
            "packet_flood_threshold": 50,
            "packet_flood_window": 5.0,
            "spike_multiplier": 3.0,
            "spike_min_mb_s": 0.5,
            "alert_cooldown": 10.0,
        })
        self.base_time = 1000.0

    def test_port_scan_detection(self):
        triggered_alerts = []
        for port in range(1, 15):
            res = self.detector.check_port_scan("192.168.1.99", port, now=self.base_time + (port * 0.1))
            if res:
                triggered_alerts.append(res)

        self.assertTrue(len(triggered_alerts) >= 1)
        alert = triggered_alerts[0]
        self.assertEqual(alert.alert_type, "PORT_SCAN")
        self.assertEqual(alert.severity, "HIGH")
        self.assertEqual(alert.source_ip, "192.168.1.99")
        self.assertIn("Possible port scan detected", alert.description)

        # Verify backwards-compatible tuple unpacking:
        atype, msg = alert
        self.assertEqual(atype, "PORT_SCAN")
        self.assertTrue(len(msg) > 0)

    def test_syn_flood_detection(self):
        triggered_alerts = []
        for i in range(25):
            res = self.detector.check_syn_flood("10.0.0.50", "192.168.1.1", now=self.base_time + (i * 0.05))
            if res:
                triggered_alerts.append(res)

        self.assertTrue(len(triggered_alerts) >= 1)
        alert = triggered_alerts[0]
        self.assertEqual(alert.alert_type, "SYN_FLOOD")
        self.assertEqual(alert.severity, "CRITICAL")
        self.assertEqual(alert.source_ip, "10.0.0.50")
        self.assertIn("Possible SYN flood", alert.description)

    def test_high_bandwidth_detection(self):
        triggered_alerts = []
        # Send 3 chunks of 500 KB = 1.5 MB total (threshold is 1 MB)
        for i in range(3):
            res = self.detector.check_bandwidth("192.168.1.75", 500 * 1024, now=self.base_time + i)
            if res:
                triggered_alerts.append(res)

        self.assertTrue(len(triggered_alerts) >= 1)
        alert = triggered_alerts[0]
        self.assertEqual(alert.alert_type, "HIGH_BANDWIDTH")
        self.assertEqual(alert.severity, "HIGH")
        self.assertIn("High bandwidth source", alert.description)

    def test_packet_flood_detection(self):
        triggered_alerts = []
        for i in range(55):
            res = self.detector.check_packet_flood("192.168.1.120", now=self.base_time + (i * 0.05))
            if res:
                triggered_alerts.append(res)

        self.assertTrue(len(triggered_alerts) >= 1)
        alert = triggered_alerts[0]
        self.assertEqual(alert.alert_type, "PACKET_FLOOD")
        self.assertEqual(alert.severity, "HIGH")

    def test_traffic_spike_detection(self):
        # Establish stable historical baseline at 0.2 MB/s
        for i in range(10):
            alert = self.detector.check_traffic_spike(0.2, now=self.base_time + i)
            self.assertIsNone(alert)

        # Inject sudden spike of 2.0 MB/s (10x baseline, well above 3x multiplier and min 0.5 MB/s)
        spike_alert = self.detector.check_traffic_spike(2.0, now=self.base_time + 11)
        self.assertIsNotNone(spike_alert)
        self.assertEqual(spike_alert.alert_type, "TRAFFIC_SPIKE")
        self.assertIn("Traffic spike", spike_alert.description)

    def test_arp_spoofing_detection(self):
        # Legitimate gateway observation
        alert1 = self.detector.check_arp_spoofing("192.168.1.1", "AA:BB:CC:DD:EE:01", now=self.base_time)
        self.assertIsNone(alert1)

        # Conflicting MAC claiming the same IP
        alert2 = self.detector.check_arp_spoofing("192.168.1.1", "DE:AD:BE:EF:00:99", now=self.base_time + 1)
        self.assertIsNotNone(alert2)
        self.assertEqual(alert2.alert_type, "ARP_SPOOFING")
        self.assertEqual(alert2.severity, "CRITICAL")
        self.assertIn("Potential ARP spoofing", alert2.description)

    def test_alert_cooldown_behavior(self):
        # First check triggers alert
        alert1 = None
        for port in range(1, 15):
            res = self.detector.check_port_scan("192.168.1.250", port, now=self.base_time + (port * 0.1))
            if res:
                alert1 = res
                break
        self.assertIsNotNone(alert1)

        # Immediate subsequent trigger within cooldown period (10s) must be suppressed
        alert2 = self.detector.check_port_scan("192.168.1.250", 999, now=self.base_time + 2.0)
        self.assertIsNone(alert2)

        # After cooldown duration expires (e.g. 15s later), new alert is allowed
        alert3 = None
        for port in range(20, 35):
            res = self.detector.check_port_scan("192.168.1.250", port, now=self.base_time + 15.0 + (port * 0.1))
            if res:
                alert3 = res
                break
        self.assertIsNotNone(alert3)

    def test_detector_edge_cases(self):
        # None and malformed inputs should not cause exceptions
        self.assertIsNone(self.detector.check_port_scan(None, "-"))
        self.assertIsNone(self.detector.check_port_scan("", "invalid_port"))
        self.assertIsNone(self.detector.check_syn_flood(None))
        self.assertIsNone(self.detector.check_bandwidth(None, -100))
        self.assertIsNone(self.detector.check_packet_flood(None))
        self.assertIsNone(self.detector.check_arp_spoofing("", "FF:FF:FF:FF:FF:FF"))


class TestDatabase(unittest.TestCase):
    """Tests for SQLite database persistence, batching, and query operations."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_black_box.db")
        self.db = DatabaseManager(db_path=self.db_path, batch_size=5, flush_interval=0.1)
        self.db.start()

    def tearDown(self):
        self.db.stop()
        self.temp_dir.cleanup()

    def test_packet_and_alert_logging(self):
        # Log packets
        for i in range(5):
            self.db.log_packet({
                "timestamp": "12:00:00",
                "source_ip": f"192.168.1.{10+i}",
                "destination_ip": "8.8.8.8",
                "protocol": "TCP",
                "source_port": "50000",
                "destination_port": "443",
                "packet_size": 128,
                "interface_name": "TestIface",
            })

        # Log alert
        self.db.log_alert({
            "timestamp": "12:00:01",
            "severity": "HIGH",
            "alert_type": "PORT_SCAN",
            "source_ip": "192.168.1.99",
            "destination_ip": "",
            "description": "Test port scan alert",
            "measured_value": 15.0,
            "threshold_info": "15 ports in 10s"
        })

        # Give background batch worker brief moment to commit
        time.sleep(0.3)

        pkts = self.db.get_recent_packets(limit=10)
        alerts = self.db.get_recent_alerts(limit=10)
        stats = self.db.get_summary_statistics()

        self.assertEqual(len(pkts), 5)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(stats["total_packets"], 5)
        self.assertEqual(stats["total_alerts"], 1)
        self.assertEqual(stats["protocols"]["TCP"], 5)


def run_tests():
    """Run all tests with a detailed test runner."""
    suite = unittest.TestSuite()
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TestAnalyzer))
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TestDetector))
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TestDatabase))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    exit(0 if success else 1)
