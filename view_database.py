"""
Database inspection utility for Network Black Box.
Inspects saved packets, security alerts, and statistics summaries from the command line.
Supports options for viewing logs or clearing old records.
"""

import argparse
import os
import sys
from database import DatabaseManager, DEFAULT_DB_PATH, init_database


def format_bytes(num_bytes: int) -> str:
    """Helper to format byte count into readable KB/MB."""
    if num_bytes < 1024:
        return f"{num_bytes} B"
    elif num_bytes < 1024 * 1024:
        return f"{num_bytes / 1024:.2f} KB"
    else:
        return f"{num_bytes / (1024 * 1024):.2f} MB"


def print_summary(db: DatabaseManager) -> None:
    """Print overall database statistics summary."""
    stats = db.get_summary_statistics()
    print("\n=======================================================")
    print("           NETWORK BLACK BOX DATABASE SUMMARY          ")
    print("=======================================================")
    print(f" Total Captured Packets: {stats['total_packets']:,}")
    print(f" Total Logged Volume:   {format_bytes(stats['total_bytes'])}")
    print(f" Unique Source IPs:     {stats['unique_source_ips']:,}")
    print(f" Total Security Alerts: {stats['total_alerts']:,}")

    print("\nProtocol Breakdown:")
    if stats["protocols"]:
        for proto, count in stats["protocols"].items():
            pct = (count / stats['total_packets'] * 100) if stats['total_packets'] else 0
            print(f"  - {proto:<8} : {count:>7,} packets ({pct:>5.1f}%)")
    else:
        print("  (No packets recorded)")

    print("\nSecurity Alerts by Category:")
    if stats["alerts_by_type"]:
        for atype, count in stats["alerts_by_type"].items():
            print(f"  - {atype:<18} : {count:>5,} alerts")
    else:
        print("  (No security alerts recorded)")
    print("=======================================================\n")


def print_packets(db: DatabaseManager, limit: int = 15) -> None:
    """Display recent packet log entries."""
    rows = db.get_recent_packets(limit=limit)
    print(f"\n--- Recent Packets (Latest {len(rows)}) ---")
    if not rows:
        print(" No packet records found.")
        return

    header = f"{'ID':<6} | {'Timestamp':<19} | {'Source IP':<18} | {'Destination IP':<18} | {'Proto':<5} | {'Ports':<13} | {'Size':<10}"
    print(header)
    print("-" * len(header))
    for r in rows:
        ports = f"{r.get('source_port', '-')}:{r.get('destination_port', '-')}"
        size_str = f"{r.get('packet_size', 0)} B"
        print(
            f"{r['id']:<6} | {r['timestamp'][:19]:<19} | {r['source_ip']:<18} | "
            f"{r['destination_ip']:<18} | {r['protocol']:<5} | {ports:<13} | {size_str:<10}"
        )


def print_alerts(db: DatabaseManager, limit: int = 15) -> None:
    """Display recent security alert log entries."""
    rows = db.get_recent_alerts(limit=limit)
    print(f"\n--- Recent Security Alerts (Latest {len(rows)}) ---")
    if not rows:
        print(" No security alerts recorded.")
        return

    header = f"{'ID':<6} | {'Timestamp':<19} | {'Severity':<8} | {'Alert Type':<16} | {'Source IP':<16} | {'Description'}"
    print(header)
    print("-" * len(header))
    for r in rows:
        sev = r.get("severity") or "INFO"
        desc = r.get("description") or ""
        src = r.get("source_ip") or "-"
        print(
            f"{r['id']:<6} | {r['timestamp'][:19]:<19} | {sev:<8} | "
            f"{r['alert_type']:<16} | {src:<16} | {desc}"
        )


def main():
    parser = argparse.ArgumentParser(description="Network Black Box Database Inspection Utility")
    parser.add_argument("--db", default=DEFAULT_DB_PATH, help=f"Database file path (default: {DEFAULT_DB_PATH})")
    parser.add_argument("--packets", type=int, nargs="?", const=20, default=None, help="Show latest N packets")
    parser.add_argument("--alerts", type=int, nargs="?", const=20, default=None, help="Show latest N alerts")
    parser.add_argument("--summary", action="store_true", help="Show database summary only")
    parser.add_argument("--clear", action="store_true", help="Clear all stored packets and alerts")

    args = parser.parse_args()

    if not os.path.exists(args.db):
        print(f"Database file '{args.db}' not found. Initializing new database...")
        init_database(args.db)

    db = DatabaseManager(db_path=args.db)

    if args.clear:
        confirm = input(f"Are you sure you want to delete all records from '{args.db}'? (y/N): ").strip().lower()
        if confirm == "y":
            pkts, alerts = db.clear_database()
            print(f"Cleared database: {pkts} packets and {alerts} alerts removed.")
        else:
            print("Operation aborted.")
        return

    if args.summary:
        print_summary(db)
        return

    if args.packets is not None and args.alerts is None:
        print_packets(db, limit=args.packets)
        return

    if args.alerts is not None and args.packets is None:
        print_alerts(db, limit=args.alerts)
        return

    # Default action: summary + recent samples
    print_summary(db)
    print_alerts(db, limit=args.alerts or 10)
    print_packets(db, limit=args.packets or 10)


if __name__ == "__main__":
    main()
