"""
NETWORK BLACK BOX — Desktop Dashboard Application
Real-Time Network Monitoring & Anomaly Detection System

Designed for College Viva Demonstration and Visual Studio Code on Windows.
Features:
- Live packet capture via Scapy or deterministic simulated Demo Mode
- Multi-rule anomaly detection (Port Scan, SYN Flood, High Bandwidth, Packet Flood, Traffic Spike, ARP Spoofing)
- Real-time Matplotlib bandwidth throughput graph
- Live packet stream and security alerts with severity tagging
- SQLite batched database persistence and interactive history viewer
- Clean, thread-safe asynchronous GUI updates using Tkinter and TTK
"""

import queue
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Any, Dict, List, Optional

# Matplotlib embedding for Tkinter
import matplotlib
matplotlib.use("TkAgg")
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# Modular backend imports
from analyzer import NetworkAnalyzer
from detector import NetworkDetector, NetworkAlert
from database import DatabaseManager, DEFAULT_DB_PATH
from network_monitor import NetworkMonitor, get_available_interfaces


class NetworkBlackBoxApp:
    """Main desktop application class for Network Black Box."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("NETWORK BLACK BOX — Real-Time Network Monitoring & Anomaly Detection")
        self.root.geometry("1320x880")
        self.root.minsize(1100, 750)
        self.root.configure(bg="#1a1a1a")

        # Backend components
        self.analyzer = NetworkAnalyzer(history_len=60, window_seconds=1.0)
        self.detector = NetworkDetector()
        self.db = DatabaseManager(db_path=DEFAULT_DB_PATH)
        self.db.start()

        # Thread-safe queues for GUI consumption
        self.packet_queue = queue.Queue(maxsize=5000)
        self.alert_queue = queue.Queue(maxsize=1000)

        # Network monitor instance
        self.monitor = NetworkMonitor(
            on_packet=self._on_packet_captured,
            on_error=self._on_capture_error
        )

        # GUI state
        self.demo_mode_var = tk.BooleanVar(value=False)
        self.interface_map: Dict[str, str] = {}
        self.recent_alerts: List[Dict[str, Any]] = []

        # Configure TTK styles
        self._setup_styles()

        # Build GUI Layout
        self._build_header()
        self._build_control_bar()
        self._build_metric_cards()
        self._build_middle_panels()
        self._build_graph_panel()
        self._build_live_packets_panel()

        # Handle clean window closing
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Start periodic GUI update loop (every 300 ms)
        self.root.after(300, self._gui_update_loop)

        # Initial ready alert
        self.add_alert(NetworkAlert(
            alert_type="SYSTEM",
            description="Network Black Box initialized. Select interface and press START MONITORING or DEMO MODE.",
            severity="INFO"
        ))

    def _setup_styles(self) -> None:
        """Configure modern dark ttk widget themes."""
        self.style = ttk.Style()
        try:
            self.style.theme_use("clam")
        except Exception:
            pass

        # Global Dark Backgrounds
        self.style.configure(".", background="#1a1a1a", foreground="#ffffff")
        self.style.configure("TLabel", background="#1a1a1a", foreground="#ffffff", font=("Segoe UI", 10))
        self.style.configure("TFrame", background="#1a1a1a")

        # Treeview (tables) styling
        self.style.configure(
            "Treeview",
            background="#252526",
            foreground="#d4d4d4",
            fieldbackground="#252526",
            rowheight=22,
            font=("Segoe UI", 9)
        )
        self.style.configure(
            "Treeview.Heading",
            background="#333333",
            foreground="#ffffff",
            font=("Segoe UI", 9, "bold")
        )
        self.style.map("Treeview", background=[("selected", "#094771")])

        # Combobox styling
        self.style.configure("TCombobox", fieldbackground="#2d2d2d", background="#333333", foreground="#ffffff")

    def _build_header(self) -> None:
        """Top banner header."""
        header_frame = tk.Frame(self.root, bg="#111111", height=75)
        header_frame.pack(fill="x", side="top")

        title_lbl = tk.Label(
            header_frame,
            text="NETWORK BLACK BOX",
            bg="#111111",
            fg="#00e5ff",
            font=("Segoe UI", 20, "bold")
        )
        title_lbl.pack(pady=(8, 0))

        sub_lbl = tk.Label(
            header_frame,
            text="Real-Time Network Monitoring & Anomaly Detection System — Find Who Is Killing the Network",
            bg="#111111",
            fg="#aaaaaa",
            font=("Segoe UI", 10)
        )
        sub_lbl.pack(pady=(0, 8))

    def _build_control_bar(self) -> None:
        """Control frame with buttons, interface selector, and demo mode toggle."""
        control_frame = tk.Frame(self.root, bg="#222222", relief="raised", bd=1)
        control_frame.pack(fill="x", padx=12, pady=6)

        # Status Indicator
        self.status_label = tk.Label(
            control_frame,
            text="● STOPPED",
            bg="#222222",
            fg="#ff4d4d",
            font=("Segoe UI", 11, "bold"),
            width=18,
            anchor="w"
        )
        self.status_label.pack(side="left", padx=12, pady=6)

        # Interface Selector Dropdown
        tk.Label(control_frame, text="Interface:", bg="#222222", fg="#cccccc", font=("Segoe UI", 9, "bold")).pack(
            side="left", padx=(10, 4)
        )

        self.iface_combobox = ttk.Combobox(control_frame, state="readonly", width=38)
        self.iface_combobox.pack(side="left", padx=4, pady=6)
        self._populate_interfaces()

        # Demo Mode Checkbox
        self.demo_chk = tk.Checkbutton(
            control_frame,
            text="Demo Mode (Safe Simulation)",
            variable=self.demo_mode_var,
            bg="#222222",
            fg="#00e5ff",
            selectcolor="#333333",
            activebackground="#222222",
            activeforeground="#00e5ff",
            font=("Segoe UI", 9, "bold")
        )
        self.demo_chk.pack(side="left", padx=12)

        # Action Buttons
        self.start_btn = tk.Button(
            control_frame,
            text="▶ START MONITORING",
            bg="#007acc",
            fg="white",
            activebackground="#005999",
            activeforeground="white",
            font=("Segoe UI", 9, "bold"),
            relief="groove",
            padx=12,
            pady=4,
            command=self.start_monitoring
        )
        self.start_btn.pack(side="left", padx=6)

        self.stop_btn = tk.Button(
            control_frame,
            text="⏹ STOP",
            bg="#444444",
            fg="#888888",
            activebackground="#cc3333",
            activeforeground="white",
            font=("Segoe UI", 9, "bold"),
            relief="groove",
            state="disabled",
            padx=12,
            pady=4,
            command=self.stop_monitoring
        )
        self.stop_btn.pack(side="left", padx=6)

        self.clear_btn = tk.Button(
            control_frame,
            text="🧹 CLEAR DISPLAY",
            bg="#333333",
            fg="#dddddd",
            activebackground="#555555",
            activeforeground="white",
            font=("Segoe UI", 9),
            relief="groove",
            padx=10,
            pady=4,
            command=self.clear_display
        )
        self.clear_btn.pack(side="left", padx=6)

        self.history_btn = tk.Button(
            control_frame,
            text="🗄 DATABASE HISTORY",
            bg="#2d4f2d",
            fg="#a8f0a8",
            activebackground="#3e6f3e",
            activeforeground="white",
            font=("Segoe UI", 9, "bold"),
            relief="groove",
            padx=10,
            pady=4,
            command=self.show_database_history
        )
        self.history_btn.pack(side="right", padx=12)

    def _populate_interfaces(self) -> None:
        """Scan system interfaces and populate combobox."""
        try:
            ifaces = get_available_interfaces()
            names = []
            self.interface_map.clear()
            for item in ifaces:
                names.append(item["name"])
                self.interface_map[item["name"]] = item["id"]
            self.iface_combobox["values"] = names
            if names:
                self.iface_combobox.current(0)
        except Exception as err:
            self.iface_combobox["values"] = ["Auto (Default Interface)"]
            self.iface_combobox.current(0)

    def _build_metric_cards(self) -> None:
        """Four main metric cards displaying network vital statistics."""
        cards_frame = tk.Frame(self.root, bg="#1a1a1a")
        cards_frame.pack(fill="x", padx=12, pady=4)

        # Helper to construct individual styled metric card
        def make_card(parent, title, default_val, text_color):
            frame = tk.Frame(parent, bg="#252526", relief="solid", bd=1)
            frame.pack(side="left", fill="both", expand=True, padx=4)

            tk.Label(frame, text=title, bg="#252526", fg="#999999", font=("Segoe UI", 9, "bold")).pack(pady=(4, 0))
            val_lbl = tk.Label(frame, text=default_val, bg="#252526", fg=text_color, font=("Segoe UI", 16, "bold"))
            val_lbl.pack(pady=(0, 6))
            return val_lbl

        self.card_packets = make_card(cards_frame, "TOTAL PACKETS", "0", "#00e5ff")
        self.card_throughput = make_card(cards_frame, "THROUGHPUT", "0.00 MB/s", "#00ff88")
        self.card_devices = make_card(cards_frame, "UNIQUE SOURCE IPS", "0", "#ffcc00")
        self.card_volume = make_card(cards_frame, "TOTAL LOGGED VOLUME", "0.00 MB", "#ff99ff")

    def _build_middle_panels(self) -> None:
        """Panels for Top Sources, Protocol Breakdown, and Security Alerts."""
        middle_frame = tk.Frame(self.root, bg="#1a1a1a")
        middle_frame.pack(fill="x", padx=12, pady=4)

        # 1. Top Traffic Sources Table
        top_frame = tk.LabelFrame(
            middle_frame,
            text=" Top Traffic Sources ",
            bg="#252526",
            fg="#00e5ff",
            font=("Segoe UI", 10, "bold")
        )
        top_frame.pack(side="left", fill="both", expand=True, padx=4)

        self.top_tree = ttk.Treeview(
            top_frame,
            columns=("ip", "mb", "pkts"),
            show="headings",
            height=6
        )
        self.top_tree.heading("ip", text="Source IP")
        self.top_tree.heading("mb", text="Volume (MB)")
        self.top_tree.heading("pkts", text="Packets")
        self.top_tree.column("ip", width=130, anchor="w")
        self.top_tree.column("mb", width=80, anchor="e")
        self.top_tree.column("pkts", width=70, anchor="e")
        self.top_tree.pack(fill="both", expand=True, padx=4, pady=4)

        # 2. Protocol Distribution Table
        proto_frame = tk.LabelFrame(
            middle_frame,
            text=" Protocol Distribution ",
            bg="#252526",
            fg="#00e5ff",
            font=("Segoe UI", 10, "bold")
        )
        proto_frame.pack(side="left", fill="both", expand=True, padx=4)

        self.proto_tree = ttk.Treeview(
            proto_frame,
            columns=("proto", "count", "pct"),
            show="headings",
            height=6
        )
        self.proto_tree.heading("proto", text="Protocol")
        self.proto_tree.heading("count", text="Packets")
        self.proto_tree.heading("pct", text="Share")
        self.proto_tree.column("proto", width=75, anchor="w")
        self.proto_tree.column("count", width=75, anchor="e")
        self.proto_tree.column("pct", width=65, anchor="e")
        self.proto_tree.pack(fill="both", expand=True, padx=4, pady=4)

        # 3. Security Alerts Panel
        alert_frame = tk.LabelFrame(
            middle_frame,
            text=" Security Alerts & Anomaly Feed ",
            bg="#252526",
            fg="#ff9933",
            font=("Segoe UI", 10, "bold")
        )
        alert_frame.pack(side="left", fill="both", expand=True, padx=4)

        self.alert_text = tk.Text(
            alert_frame,
            bg="#1e1e1e",
            fg="#ffffff",
            font=("Courier New", 9),
            height=6,
            relief="flat",
            wrap="word"
        )
        self.alert_text.pack(side="left", fill="both", expand=True, padx=(4, 0), pady=4)

        # Scrollbar for alerts
        alert_scroll = ttk.Scrollbar(alert_frame, orient="vertical", command=self.alert_text.yview)
        alert_scroll.pack(side="right", fill="y", pady=4, padx=(0, 4))
        self.alert_text.configure(yscrollcommand=alert_scroll.set)

        # Tag configurations for color-coded severity
        self.alert_text.tag_config("CRITICAL", foreground="#ff4d4d", font=("Courier New", 9, "bold"))
        self.alert_text.tag_config("HIGH", foreground="#ff9933", font=("Courier New", 9, "bold"))
        self.alert_text.tag_config("MEDIUM", foreground="#ffcc00")
        self.alert_text.tag_config("INFO", foreground="#00e5ff")
        self.alert_text.tag_config("SYSTEM", foreground="#a8f0a8")

    def _build_graph_panel(self) -> None:
        """Embedded real-time Matplotlib bandwidth throughput graph."""
        graph_frame = tk.LabelFrame(
            self.root,
            text=" Real-Time Network Bandwidth (MB/s Observed) ",
            bg="#252526",
            fg="#00e5ff",
            font=("Segoe UI", 10, "bold")
        )
        graph_frame.pack(fill="x", padx=12, pady=4)

        # Matplotlib figure with dark theme styling
        self.graph_figure = Figure(figsize=(9, 1.8), dpi=100, facecolor="#1e1e1e")
        self.graph_axes = self.graph_figure.add_subplot(111)
        self.graph_axes.set_facecolor("#181818")

        self.graph_canvas = FigureCanvasTkAgg(self.graph_figure, master=graph_frame)
        self.graph_widget = self.graph_canvas.get_tk_widget()
        self.graph_widget.pack(fill="both", expand=True, padx=4, pady=4)

        self._draw_graph_initial()

    def _draw_graph_initial(self) -> None:
        """Initial graph render."""
        self.graph_axes.clear()
        self.graph_axes.set_title("Network Throughput Over Time", color="#cccccc", fontsize=9)
        self.graph_axes.set_ylabel("MB/s", color="#cccccc", fontsize=8)
        self.graph_axes.tick_params(colors="#888888", labelsize=8)
        self.graph_axes.grid(True, color="#333333", linestyle="--", alpha=0.5)
        self.graph_canvas.draw_idle()

    def _build_live_packets_panel(self) -> None:
        """Live network packets table."""
        live_frame = tk.LabelFrame(
            self.root,
            text=" Live Network Packets (Metadata & Headers) ",
            bg="#252526",
            fg="#00e5ff",
            font=("Segoe UI", 10, "bold")
        )
        live_frame.pack(fill="both", expand=True, padx=12, pady=(4, 8))

        columns = ("time", "src", "dst", "proto", "ports", "size", "iface")
        self.packet_tree = ttk.Treeview(
            live_frame,
            columns=columns,
            show="headings",
            height=7
        )

        self.packet_tree.heading("time", text="Timestamp")
        self.packet_tree.heading("src", text="Source IP")
        self.packet_tree.heading("dst", text="Destination IP")
        self.packet_tree.heading("proto", text="Protocol")
        self.packet_tree.heading("ports", text="Ports (Src:Dst)")
        self.packet_tree.heading("size", text="Length")
        self.packet_tree.heading("iface", text="Interface")

        self.packet_tree.column("time", width=85, anchor="center")
        self.packet_tree.column("src", width=140, anchor="w")
        self.packet_tree.column("dst", width=140, anchor="w")
        self.packet_tree.column("proto", width=75, anchor="center")
        self.packet_tree.column("ports", width=110, anchor="center")
        self.packet_tree.column("size", width=80, anchor="e")
        self.packet_tree.column("iface", width=130, anchor="w")

        # Scrollbar
        pkt_scroll = ttk.Scrollbar(live_frame, orient="vertical", command=self.packet_tree.yview)
        self.packet_tree.configure(yscrollcommand=pkt_scroll.set)

        self.packet_tree.pack(side="left", fill="both", expand=True, padx=(4, 0), pady=4)
        pkt_scroll.pack(side="right", fill="y", padx=(0, 4), pady=4)

    # ============================================================
    # MONITORING CONTROL & CALLBACKS
    # ============================================================

    def start_monitoring(self) -> None:
        """Start packet capture or simulated demo."""
        if self.monitor.is_running:
            return

        is_demo = self.demo_mode_var.get()
        selected_display = self.iface_combobox.get()
        iface_id = self.interface_map.get(selected_display, "AUTO")

        self.status_label.config(
            text="● STARTING...",
            fg="#ffcc00"
        )
        self.start_btn.config(state="disabled", bg="#444444", fg="#888888")
        self.stop_btn.config(state="normal", bg="#cc3333", fg="white")
        self.demo_chk.config(state="disabled")
        self.iface_combobox.config(state="disabled")

        self.monitor.start_capture(interface=iface_id, demo_mode=is_demo)

        mode_text = "DEMO SIMULATION" if is_demo else f"LIVE ({selected_display[:25]})"
        status_color = "#00e5ff" if is_demo else "#00ff88"
        self.status_label.config(text=f"● MONITORING ({'DEMO' if is_demo else 'LIVE'})", fg=status_color)

        self.add_alert(NetworkAlert(
            alert_type="SYSTEM",
            description=f"Capture started in {mode_text} mode.",
            severity="INFO"
        ))

    def stop_monitoring(self) -> None:
        """Stop packet capture or simulation."""
        if not self.monitor.is_running:
            return

        self.monitor.stop_capture()

        self.status_label.config(text="● STOPPED", fg="#ff4d4d")
        self.start_btn.config(state="normal", bg="#007acc", fg="white")
        self.stop_btn.config(state="disabled", bg="#444444", fg="#888888")
        self.demo_chk.config(state="normal")
        self.iface_combobox.config(state="readonly")

        self.add_alert(NetworkAlert(
            alert_type="SYSTEM",
            description="Network monitoring stopped by user.",
            severity="INFO"
        ))

    def _on_packet_captured(self, packet_dict: Dict[str, Any]) -> None:
        """
        Invoked by NetworkMonitor background thread when a packet is parsed.
        Executes analyzer calculations and anomaly detection, then queues for GUI and DB.
        """
        # 1. Feed analyzer
        src = packet_dict["source_ip"]
        sz = packet_dict["packet_size"]
        proto = packet_dict["protocol"]
        self.analyzer.analyze_packet(src, sz, proto)

        # 2. Queue packet for GUI display
        try:
            self.packet_queue.put_nowait(packet_dict)
        except queue.Full:
            pass

        # 3. Queue packet for asynchronous SQLite database logging
        self.db.log_packet(packet_dict)

        # 4. Anomaly detection checks
        detected_alerts = []

        # Check port scan
        if proto in ("TCP", "UDP"):
            res = self.detector.check_port_scan(src, packet_dict.get("destination_port"))
            if res:
                detected_alerts.append(res)

        # Check SYN flood
        if packet_dict.get("is_syn"):
            res = self.detector.check_syn_flood(src, packet_dict.get("destination_ip", ""))
            if res:
                detected_alerts.append(res)

        # Check high bandwidth source
        res = self.detector.check_bandwidth(src, sz)
        if res:
            detected_alerts.append(res)

        # Check packet flood
        res = self.detector.check_packet_flood(src)
        if res:
            detected_alerts.append(res)

        # Check ARP spoofing / conflict
        if proto == "ARP" and packet_dict.get("source_mac"):
            res = self.detector.check_arp_spoofing(src, packet_dict["source_mac"])
            if res:
                detected_alerts.append(res)

        for alert in detected_alerts:
            self.add_alert(alert)

    def _on_capture_error(self, err_msg: str) -> None:
        """Callback for sniffing runtime errors (e.g., administrator permissions)."""
        self.root.after(0, self._handle_capture_error, err_msg)

    def _handle_capture_error(self, err_msg: str) -> None:
        """Executed on GUI thread when capture error occurs."""
        self.status_label.config(text="● ERROR", fg="#ff0000")
        self.start_btn.config(state="normal", bg="#007acc", fg="white")
        self.stop_btn.config(state="disabled", bg="#444444", fg="#888888")
        self.demo_chk.config(state="normal")
        self.iface_combobox.config(state="readonly")

        self.add_alert(NetworkAlert(
            alert_type="ERROR",
            description=err_msg,
            severity="CRITICAL"
        ))

        messagebox.showerror(
            "Packet Capture Error",
            f"{err_msg}\n\nTip: You can enable 'Demo Mode' to evaluate the application without administrator privileges."
        )

    # ============================================================
    # GUI UPDATE LOOP
    # ============================================================

    def _gui_update_loop(self) -> None:
        """Periodic GUI refresh cycle invoked via Tkinter event loop."""
        try:
            # 1. Update throughput calculation and check for network-wide traffic spikes
            current_rate = self.analyzer.update_throughput()
            spike_alert = self.detector.check_traffic_spike(current_rate)
            if spike_alert:
                self.add_alert(spike_alert)

            # 2. Process pending security alerts from queue
            self._flush_alert_queue()

            # 3. Process batch of pending packets to Live Packets table
            self._flush_packet_queue()

            # 4. Refresh Statistics Cards, Top Sources, and Protocol distribution
            self._refresh_statistics_panels()

            # 5. Redraw Bandwidth Graph
            self._draw_graph_update()

        except Exception as err:
            pass
        finally:
            self.root.after(350, self._gui_update_loop)

    def _flush_alert_queue(self) -> None:
        """Drain alert queue and render to text box."""
        while not self.alert_queue.empty():
            try:
                alert: NetworkAlert = self.alert_queue.get_nowait()
            except queue.Empty:
                break

            self.recent_alerts.append(alert.to_dict())
            if len(self.recent_alerts) > 50:
                self.recent_alerts.pop(0)

            # Format colored alert line
            ts = alert.timestamp[-8:]
            line = f"[{ts}] [{alert.severity:<8}] {alert.alert_type}: {alert.description}\n"

            self.alert_text.insert("1.0", line, alert.severity)

        # Cap text lines to avoid slow rendering
        lines_count = int(float(self.alert_text.index("end-1c")))
        if lines_count > 60:
            self.alert_text.delete("50.0", tk.END)

    def _flush_packet_queue(self) -> None:
        """Drain up to 40 packets per cycle to keep UI silky smooth."""
        processed = 0
        while not self.packet_queue.empty() and processed < 40:
            try:
                pkt = self.packet_queue.get_nowait()
            except queue.Empty:
                break

            ports_str = f"{pkt.get('source_port', '-')}:{pkt.get('destination_port', '-')}"
            size_str = f"{pkt.get('packet_size', 0)} B"

            self.packet_tree.insert(
                "",
                0,
                values=(
                    pkt.get("timestamp", ""),
                    pkt.get("source_ip", ""),
                    pkt.get("destination_ip", ""),
                    pkt.get("protocol", ""),
                    ports_str,
                    size_str,
                    pkt.get("interface_name", "")[:20]
                )
            )
            processed += 1

        # Maintain maximum 100 rows in treeview
        children = self.packet_tree.get_children()
        if len(children) > 100:
            for item in children[100:]:
                self.packet_tree.delete(item)

    def _refresh_statistics_panels(self) -> None:
        """Update metric cards, top sources, and protocols."""
        stats = self.analyzer.get_statistics()

        # Update cards
        self.card_packets.config(text=f"{stats['packet_count']:,}")
        self.card_throughput.config(text=f"{stats['current_throughput_mb_s']:.2f} MB/s")
        self.card_devices.config(text=f"{stats['unique_ips']:,}")
        self.card_volume.config(text=f"{stats['total_mb']:.2f} MB")

        # Update Top Sources Treeview
        self.top_tree.delete(*self.top_tree.get_children())
        for src in stats["top_sources"][:6]:
            self.top_tree.insert("", "end", values=(src["ip"], f"{src['mb']:.2f}", f"{src['packets']:,}"))

        # Update Protocol Distribution Treeview
        self.proto_tree.delete(*self.proto_tree.get_children())
        for proto, data in stats["protocol_distribution"].items():
            self.proto_tree.insert("", "end", values=(proto, f"{data['count']:,}", f"{data['percentage']}%"))

    def _draw_graph_update(self) -> None:
        """Update line graph with rolling throughput data."""
        stats = self.analyzer.get_statistics()
        history = stats["throughput_history"]

        self.graph_axes.clear()
        self.graph_axes.set_facecolor("#181818")

        x_vals = list(range(len(history)))
        self.graph_axes.plot(x_vals, history, color="#00ffcc", linewidth=1.8, label="Throughput (MB/s)")
        self.graph_axes.fill_between(x_vals, history, color="#00ffcc", alpha=0.15)

        max_val = max(history) if history else 0.0
        self.graph_axes.set_ylim(bottom=0.0, top=max(1.0, max_val * 1.25))

        self.graph_axes.set_title("Network Throughput Over Time (Observed)", color="#cccccc", fontsize=9)
        self.graph_axes.set_ylabel("MB/s", color="#cccccc", fontsize=8)
        self.graph_axes.set_xlabel("Time intervals (seconds)", color="#cccccc", fontsize=8)
        self.graph_axes.tick_params(colors="#888888", labelsize=8)
        self.graph_axes.grid(True, color="#333333", linestyle="--", alpha=0.5)

        self.graph_canvas.draw_idle()

    def add_alert(self, alert: NetworkAlert) -> None:
        """Add alert to queue and database."""
        try:
            self.alert_queue.put_nowait(alert)
        except queue.Full:
            pass
        self.db.log_alert(alert.to_dict())

    def clear_display(self) -> None:
        """Clear GUI statistics, tables, and in-memory detector state."""
        self.analyzer.reset()
        self.detector.reset()

        self.packet_tree.delete(*self.packet_tree.get_children())
        self.top_tree.delete(*self.top_tree.get_children())
        self.proto_tree.delete(*self.proto_tree.get_children())
        self.alert_text.delete("1.0", tk.END)

        self.add_alert(NetworkAlert(
            alert_type="SYSTEM",
            description="Display statistics and detection buffers cleared.",
            severity="INFO"
        ))

    # ============================================================
    # DATABASE HISTORY VIEWER WINDOW
    # ============================================================

    def show_database_history(self) -> None:
        """Open a dedicated history inspection window."""
        hist_win = tk.Toplevel(self.root)
        hist_win.title("Database History — Network Black Box")
        hist_win.geometry("900x580")
        hist_win.configure(bg="#202020")
        hist_win.transient(self.root)

        tk.Label(
            hist_win,
            text="SAVED DATABASE LOGS & AUDIT TRAIL",
            bg="#202020",
            fg="#00e5ff",
            font=("Segoe UI", 14, "bold")
        ).pack(pady=8)

        # Notebook tabs for Alerts and Packets
        notebook = ttk.Notebook(hist_win)
        notebook.pack(fill="both", expand=True, padx=12, pady=6)

        # Tab 1: Recorded Security Alerts
        alerts_tab = ttk.Frame(notebook)
        notebook.add(alerts_tab, text="Security Alerts Log")

        alert_cols = ("id", "time", "sev", "type", "src", "desc")
        alert_tree = ttk.Treeview(alerts_tab, columns=alert_cols, show="headings", height=14)
        alert_tree.heading("id", text="ID")
        alert_tree.heading("time", text="Timestamp")
        alert_tree.heading("sev", text="Severity")
        alert_tree.heading("type", text="Alert Type")
        alert_tree.heading("src", text="Source IP")
        alert_tree.heading("desc", text="Description")

        alert_tree.column("id", width=50, anchor="center")
        alert_tree.column("time", width=140, anchor="center")
        alert_tree.column("sev", width=80, anchor="center")
        alert_tree.column("type", width=120, anchor="w")
        alert_tree.column("src", width=120, anchor="w")
        alert_tree.column("desc", width=340, anchor="w")

        alert_scroll = ttk.Scrollbar(alerts_tab, orient="vertical", command=alert_tree.yview)
        alert_tree.configure(yscrollcommand=alert_scroll.set)
        alert_tree.pack(side="left", fill="both", expand=True, padx=(4, 0), pady=4)
        alert_scroll.pack(side="right", fill="y", padx=(0, 4), pady=4)

        # Tab 2: Historical Packets
        pkts_tab = ttk.Frame(notebook)
        notebook.add(pkts_tab, text="Recent Packets Log")

        pkt_cols = ("id", "time", "src", "dst", "proto", "ports", "size")
        pkt_tree = ttk.Treeview(pkts_tab, columns=pkt_cols, show="headings", height=14)
        pkt_tree.heading("id", text="ID")
        pkt_tree.heading("time", text="Timestamp")
        pkt_tree.heading("src", text="Source IP")
        pkt_tree.heading("dst", text="Destination IP")
        pkt_tree.heading("proto", text="Protocol")
        pkt_tree.heading("ports", text="Ports")
        pkt_tree.heading("size", text="Length")

        pkt_tree.column("id", width=60, anchor="center")
        pkt_tree.column("time", width=140, anchor="center")
        pkt_tree.column("src", width=140, anchor="w")
        pkt_tree.column("dst", width=140, anchor="w")
        pkt_tree.column("proto", width=70, anchor="center")
        pkt_tree.column("ports", width=100, anchor="center")
        pkt_tree.column("size", width=80, anchor="e")

        pkt_scroll = ttk.Scrollbar(pkts_tab, orient="vertical", command=pkt_tree.yview)
        pkt_tree.configure(yscrollcommand=pkt_scroll.set)
        pkt_tree.pack(side="left", fill="both", expand=True, padx=(4, 0), pady=4)
        pkt_scroll.pack(side="right", fill="y", padx=(0, 4), pady=4)

        def _refresh_hist_views():
            # Populate alerts
            alert_tree.delete(*alert_tree.get_children())
            alerts = self.db.get_recent_alerts(limit=100)
            for a in alerts:
                alert_tree.insert(
                    "",
                    "end",
                    values=(
                        a.get("id"),
                        a.get("timestamp"),
                        a.get("severity"),
                        a.get("alert_type"),
                        a.get("source_ip"),
                        a.get("description")
                    )
                )

            # Populate packets
            pkt_tree.delete(*pkt_tree.get_children())
            pkts = self.db.get_recent_packets(limit=100)
            for p in pkts:
                ports_display = f"{p.get('source_port', '-')}:{p.get('destination_port', '-')}"
                pkt_tree.insert(
                    "",
                    "end",
                    values=(
                        p.get("id"),
                        p.get("timestamp"),
                        p.get("source_ip"),
                        p.get("destination_ip"),
                        p.get("protocol"),
                        ports_display,
                        f"{p.get('packet_size', 0)} B"
                    )
                )

        _refresh_hist_views()

        # Bottom buttons for history window
        btn_box = tk.Frame(hist_win, bg="#202020")
        btn_box.pack(fill="x", padx=12, pady=8)

        tk.Button(
            btn_box,
            text="🔄 Refresh Records",
            bg="#007acc",
            fg="white",
            command=_refresh_hist_views
        ).pack(side="left", padx=6)

        def _clear_all_db():
            if messagebox.askyesno("Confirm Purge", "Are you sure you want to delete ALL database packet and alert logs?"):
                self.db.clear_database()
                _refresh_hist_views()
                messagebox.showinfo("Database Purged", "All historical records were removed successfully.")

        tk.Button(
            btn_box,
            text="🗑 Purge Database Records",
            bg="#772222",
            fg="white",
            command=_clear_all_db
        ).pack(side="left", padx=6)

        tk.Button(
            btn_box,
            text="Close",
            bg="#444444",
            fg="white",
            command=hist_win.destroy
        ).pack(side="right", padx=6)

    def on_closing(self) -> None:
        """Safely terminates all background threads and closes database on application exit."""
        if self.monitor.is_running:
            self.monitor.stop_capture()
        self.db.stop()
        self.root.destroy()


def main():
    root = tk.Tk()
    app = NetworkBlackBoxApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()