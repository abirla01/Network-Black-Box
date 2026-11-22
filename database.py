"""
Database module for Network Black Box.
Handles SQLite schema creation, migrations, batched background persistence,
and record retrieval without blocking the GUI.
"""

import os
import queue
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_DB_PATH = "network_black_box.db"


def init_database(db_path: str = DEFAULT_DB_PATH) -> None:
    """Initialize SQLite database with required tables, indexes, and migrations."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Enable WAL mode for high concurrency between reader and writer
    try:
        cursor.execute("PRAGMA journal_mode=WAL;")
    except Exception:
        pass

    # 1. Packets table
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            destination_ip TEXT NOT NULL,
            protocol TEXT NOT NULL,
            source_port TEXT,
            destination_port TEXT,
            packet_size INTEGER NOT NULL,
            interface_name TEXT DEFAULT ''
        )
        """
    )

    # 2. Security alerts table
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            severity TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            destination_ip TEXT DEFAULT '',
            description TEXT NOT NULL,
            measured_value REAL DEFAULT 0.0,
            threshold_info TEXT DEFAULT ''
        )
        """
    )

    # Schema migration: Check for missing columns in existing databases
    cursor.execute("PRAGMA table_info(packets)")
    packet_cols = [row[1] for row in cursor.fetchall()]
    if "interface_name" not in packet_cols:
        try:
            cursor.execute("ALTER TABLE packets ADD COLUMN interface_name TEXT DEFAULT ''")
        except sqlite3.OperationalError:
            pass

    cursor.execute("PRAGMA table_info(alerts)")
    alert_cols = [row[1] for row in cursor.fetchall()]
    for col_name, col_type in [
        ("severity", "TEXT DEFAULT 'MEDIUM'"),
        ("source_ip", "TEXT DEFAULT ''"),
        ("destination_ip", "TEXT DEFAULT ''"),
        ("description", "TEXT DEFAULT ''"),
        ("measured_value", "REAL DEFAULT 0.0"),
        ("threshold_info", "TEXT DEFAULT ''"),
    ]:
        if col_name not in alert_cols:
            try:
                cursor.execute(f"ALTER TABLE alerts ADD COLUMN {col_name} {col_type}")
            except sqlite3.OperationalError:
                pass

    # Create helpful indexes for performance
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_time ON packets(timestamp);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_src ON packets(source_ip);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(timestamp);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(alert_type);")

    conn.commit()
    conn.close()


class DatabaseManager:
    """Thread-safe, batched background database manager."""

    def __init__(self, db_path: str = DEFAULT_DB_PATH, batch_size: int = 50, flush_interval: float = 0.5):
        self.db_path = db_path
        self.batch_size = batch_size
        self.flush_interval = flush_interval

        self._queue: queue.Queue = queue.Queue(maxsize=10000)
        self._running = False
        self._worker_thread: Optional[threading.Thread] = None

        init_database(self.db_path)

    def start(self) -> None:
        """Start the background database persistence worker."""
        if self._running:
            return
        self._running = True
        self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True, name="DBWorkerThread")
        self._worker_thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        """Stop worker and flush pending items."""
        if not self._running:
            return
        self._running = False
        try:
            self._queue.put(None, timeout=0.5)
        except queue.Full:
            pass
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=timeout)

    def log_packet(self, packet_info: Dict[str, Any]) -> None:
        """Queue a packet record for background batch insertion."""
        if not self._running:
            return
        try:
            self._queue.put_nowait(("packet", packet_info))
        except queue.Full:
            # Drop logging if queue is saturated to protect memory under extreme floods
            pass

    def log_alert(self, alert_info: Dict[str, Any]) -> None:
        """Queue an alert record for background insertion."""
        if not self._running:
            return
        try:
            self._queue.put_nowait(("alert", alert_info))
        except queue.Full:
            pass

    def _worker_loop(self) -> None:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        cursor = conn.cursor()

        pending_packets = []
        pending_alerts = []
        last_flush = time.time()

        while self._running or not self._queue.empty():
            try:
                item = self._queue.get(timeout=self.flush_interval)
            except queue.Empty:
                item = None

            if item is None and not self._running and self._queue.empty():
                break

            if item is not None:
                item_type, data = item
                if item_type == "packet":
                    pending_packets.append((
                        data.get("timestamp") or time.strftime("%Y-%m-%d %H:%M:%S"),
                        data.get("source_ip", ""),
                        data.get("destination_ip", ""),
                        data.get("protocol", "OTHER"),
                        str(data.get("source_port", "-")),
                        str(data.get("destination_port", "-")),
                        int(data.get("packet_size", 0)),
                        data.get("interface_name", "")
                    ))
                elif item_type == "alert":
                    # Handle legacy/compat message field if description omitted
                    desc = data.get("description") or data.get("message") or ""
                    pending_alerts.append((
                        data.get("timestamp") or time.strftime("%Y-%m-%d %H:%M:%S"),
                        data.get("severity", "MEDIUM"),
                        data.get("alert_type", "INFO"),
                        data.get("source_ip", ""),
                        data.get("destination_ip", ""),
                        desc,
                        float(data.get("measured_value", 0.0)),
                        str(data.get("threshold_info", ""))
                    ))

            now = time.time()
            # Flush when batch size reached or flush interval elapsed
            should_flush = (
                len(pending_packets) >= self.batch_size or
                len(pending_alerts) >= 10 or
                (now - last_flush >= self.flush_interval and (pending_packets or pending_alerts)) or
                (not self._running and (pending_packets or pending_alerts))
            )

            if should_flush:
                try:
                    if pending_packets:
                        cursor.executemany(
                            """
                            INSERT INTO packets (
                                timestamp, source_ip, destination_ip, protocol,
                                source_port, destination_port, packet_size, interface_name
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            pending_packets
                        )
                        pending_packets.clear()

                    if pending_alerts:
                        cursor.executemany(
                            """
                            INSERT INTO alerts (
                                timestamp, severity, alert_type, source_ip,
                                destination_ip, description, measured_value, threshold_info
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            pending_alerts
                        )
                        pending_alerts.clear()

                    conn.commit()
                except Exception as err:
                    # Rollback and continue in case of lock/disk error
                    try:
                        conn.rollback()
                    except Exception:
                        pass
                last_flush = now

        # Final cleanup flush
        try:
            if pending_packets:
                cursor.executemany(
                    """
                    INSERT INTO packets (
                        timestamp, source_ip, destination_ip, protocol,
                        source_port, destination_port, packet_size, interface_name
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    pending_packets
                )
            if pending_alerts:
                cursor.executemany(
                    """
                    INSERT INTO alerts (
                        timestamp, severity, alert_type, source_ip,
                        destination_ip, description, measured_value, threshold_info
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    pending_alerts
                )
            conn.commit()
        except Exception:
            pass
        finally:
            conn.close()

    def get_recent_packets(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent packet records."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, timestamp, source_ip, destination_ip, protocol,
                   source_port, destination_port, packet_size, interface_name
            FROM packets
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,)
        )
        rows = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return rows

    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent security alerts."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, timestamp, severity, alert_type, source_ip,
                   destination_ip, description, measured_value, threshold_info
            FROM alerts
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,)
        )
        rows = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return rows

    def get_summary_statistics(self) -> Dict[str, Any]:
        """Return total counts of packets, alerts, and unique IPs stored."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*), COALESCE(SUM(packet_size), 0), COUNT(DISTINCT source_ip) FROM packets")
        pkt_count, total_bytes, unique_ips = cursor.fetchone()

        cursor.execute("SELECT COUNT(*) FROM alerts")
        alert_count = cursor.fetchone()[0]

        cursor.execute(
            """
            SELECT protocol, COUNT(*)
            FROM packets
            GROUP BY protocol
            ORDER BY COUNT(*) DESC
            """
        )
        protocol_breakdown = dict(cursor.fetchall())

        cursor.execute(
            """
            SELECT alert_type, COUNT(*)
            FROM alerts
            GROUP BY alert_type
            ORDER BY COUNT(*) DESC
            """
        )
        alert_breakdown = dict(cursor.fetchall())

        conn.close()
        return {
            "total_packets": pkt_count,
            "total_bytes": total_bytes,
            "unique_source_ips": unique_ips,
            "total_alerts": alert_count,
            "protocols": protocol_breakdown,
            "alerts_by_type": alert_breakdown,
        }

    def clear_database(self) -> Tuple[int, int]:
        """Clear packets and alerts tables."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM packets")
        pkts_deleted = cursor.rowcount
        cursor.execute("DELETE FROM alerts")
        alerts_deleted = cursor.rowcount
        conn.commit()
        conn.close()
        return pkts_deleted, alerts_deleted
