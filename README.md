# NETWORK BLACK BOX — Real-Time Network Monitoring & Anomaly Detection System

> **Sub-title:** Find Who Is Killing the Network  
> **Course:** Third-Year Computer Networks Mini-Project (B.Tech / B.E. / BCA / MCA / B.Sc CS)  
> **Platform:** Windows 10 / 11, Visual Studio Code, Python 3.10+  

---

## 1. Abstract

Modern computer networks suffer from localized performance degradation, bandwidth hogging, and stealthy reconnaissance attacks (such as port scanning and SYN flooding). Traditional enterprise intrusion detection systems (IDS) like Snort or Zeek are computationally heavy, require complex configuration, and lack beginner-friendly visual dashboards.

**Network Black Box** is a lightweight, real-time network monitoring and anomaly detection desktop system developed in Python. Designed for undergraduate academic demonstration, it passively captures network packets, analyzes protocol distributions (TCP, UDP, ICMP, ARP), tracks per-source-IP traffic volumes, computes real-time throughput in megabytes per second (MB/s), visualizes bandwidth usage dynamically via Matplotlib, flags suspicious traffic patterns using rule-based heuristics, and logs all events asynchronously to an embedded SQLite database. For risk-free, permission-free college laboratory evaluations, a deterministic **Demo Mode** generates synthetic attack patterns without transmitting hostile traffic.

---

## 2. Problem Statement & Motivation

In shared campus, dorm, or office local area networks (LANs):
- Users frequently experience abrupt network slowdowns without knowing which host is responsible ("who is killing the network").
- Malicious or compromised hosts perform internal reconnaissance (TCP port scans, SYN floods, ARP cache poisoning) that bypass standard perimeter firewalls.
- Commercial packet analyzers (like Wireshark) provide exhaustive packet dumps but overwhelm non-specialists and lack automated threshold-based anomaly alerts.
- College laboratory environments often restrict raw packet capture permissions on student accounts, hindering practical network security learning.

---

## 3. Objectives

1. **Passive Packet Capture:** Sniff live network traffic on selected Windows physical, wireless, or loopback interfaces using Scapy.
2. **Metadata Header Extraction:** Safely parse IP, TCP, UDP, ICMP, and ARP headers without recording sensitive application payloads.
3. **Statistical Aggregation:** Maintain thread-safe counters for total packets, observed source IPs, per-protocol distributions, and per-host bandwidth consumption.
4. **Bandwidth Visualization:** Graph network throughput dynamically in real time using an embedded Matplotlib canvas within a Tkinter desktop GUI.
5. **Rule-Based Anomaly Detection:** Implement sliding-window detectors with duplicate-alert cooldowns for:
   - High-bandwidth consumption
   - Packet-rate surges (Packet Flood)
   - Distinct destination port reconnaissance (Port Scan)
   - Half-open connection flooding (SYN Flood)
   - Rolling baseline deviation (Traffic Spike)
   - Address resolution conflicts (Potential ARP Spoofing)
6. **Non-Blocking Persistence:** Persist packet summaries and structured security alerts to a SQLite database using a batched background worker.
7. **Safe Academic Demonstration:** Provide an offline, synthetic Demo Mode for presentations where administrative privileges or active network connections are unavailable.

---

## 4. Existing System vs. Proposed System

| Feature | Existing General Tools (Wireshark / CLI Sniffers) | Proposed Network Black Box |
| :--- | :--- | :--- |
| **Complexity** | High; thousands of protocols and deep packet dissection | Focused on core metrics: IP, TCP, UDP, ICMP, ARP |
| **Anomaly Detection** | Manual filter writing; no built-in threshold alert engine | Automated rule-based engine with severity tags |
| **Bandwidth Graphing** | Static post-capture IO graphs | Live, real-time rolling MB/s throughput line graph |
| **Resource Footprint** | Heavy memory usage storing full payload bytes | Lightweight; extracts header metadata only |
| **Database Audit** | Proprietary pcap/pcapng files | Open SQLite database with query and purge utilities |
| **Lab Demo Safety** | Requires active network and admin/Npcap privileges | Built-in offline Demo Mode generating deterministic synthetic anomalies |
| **Target Audience** | Network administrators and packet engineers | Undergraduate students, viva examiners, and educators |

---

## 5. System Architecture & Modular Structure

```
NetworkBlackBox/
├── app.py                 # Desktop GUI (Tkinter/TTK), Matplotlib graph, and application lifecycle
├── analyzer.py            # Thread-safe traffic statistics, per-IP tracking, and throughput calculations
├── detector.py            # Rule-based anomaly detection engine (Port Scan, SYN Flood, ARP, Spikes)
├── network_monitor.py     # Scapy AsyncSniffer interface, Windows adapter discovery, and Demo Mode
├── database.py            # SQLite schema, WAL mode, migrations, and batched background persistence
├── test_detector.py       # Automated unit test suite (14 comprehensive offline tests)
├── view_database.py       # Command-line database inspection, audit, and maintenance tool
├── requirements.txt       # Pinned library dependencies
├── .gitignore             # Git exclusion rules
├── README.md              # Project documentation and Viva preparation guide
└── network_black_box.db   # Embedded SQLite database (generated automatically at runtime)
```

### Architecture Data Flow Diagram

```
       [ Live Network Interface ]              [ Demo Mode Simulation ]
                   │                                       │
                   ▼ (Scapy AsyncSniffer)                  ▼ (Synthetic Metadata)
          ┌──────────────────────────────────────────────────────────┐
          │                  network_monitor.py                      │
          │         parse_packet() -> Metadata Dictionary            │
          └────────────────────────────┬─────────────────────────────┘
                                       │
                     ┌─────────────────┴─────────────────┐
                     ▼                                   ▼
        ┌─────────────────────────┐         ┌─────────────────────────┐
        │       analyzer.py       │         │       detector.py       │
        │ - Packet & byte counters│         │ - Port Scan Detector    │
        │ - Per-IP volume maps    │         │ - SYN Flood Detector    │
        │ - Protocol breakdown    │         │ - High Bandwidth Alert  │
        │ - Real-time MB/s rate   │         │ - Traffic Spike (3x)    │
        └────────────┬────────────┘         │ - ARP Spoof / Conflict  │
                     │                      └────────────┬────────────┘
                     │  Thread-Safe Queues               │
                     └─────────────────┬─────────────────┘
                                       ▼
        ┌─────────────────────────────────────────────────────────────┐
        │                           app.py                            │
        │ - Tkinter/TTK Desktop Dashboard (Dark Cyber Theme)          │
        │ - Metric Cards (Packets, Throughput, Devices, Total MB)     │
        │ - Protocol Distribution & Top Traffic Sources Tables        │
        │ - Colored Security Alerts Feed (INFO/MED/HIGH/CRITICAL)     │
        │ - Real-Time Matplotlib Bandwidth Canvas                     │
        │ - Interactive Database History Dialog                       │
        └──────────────────────────────┬──────────────────────────────┘
                                       │
                                       ▼
        ┌─────────────────────────────────────────────────────────────┐
        │                        database.py                          │
        │ - SQLite3 Persistence (network_black_box.db)                │
        │ - Batched Background Commit Worker (Non-blocking)           │
        └─────────────────────────────────────────────────────────────┘
```

---

## 6. Detailed Module Descriptions

### 1. `app.py`
- Implements the primary desktop interface using Python's native `tkinter` and `tkinter.ttk`.
- Hosts an embedded Matplotlib figure displaying rolling bandwidth in MB/s over 60 sampling windows.
- Decouples GUI rendering from packet capture using thread-safe `queue.Queue` structures, guaranteeing a smooth 60 FPS without UI freezes.
- Features a dark theme with color-coded severity tags (`#00e5ff` INFO, `#ffcc00` MEDIUM, `#ff9933` HIGH, `#ff4d4d` CRITICAL).
- Provides an interactive **Database History** window with tabular views and log-purging controls.

### 2. `analyzer.py`
- Encapsulates network statistical counters guarded by an internal `threading.Lock`.
- Computes throughput over sliding windows:
  $$\text{Throughput (MB/s)} = \frac{\Delta \text{Bytes}}{\Delta t \times 1024 \times 1024}$$
- Sorts and maintains top talkers (IPs consuming the highest byte volumes).
- Categorizes protocols and computes relative percentages for TCP, UDP, ICMP, ARP, and OTHER.
- Maintains bounded rolling histories of MB/s values for plotting, correctly showing 0.00 MB/s during network idle periods.

### 3. `detector.py`
- Implements 6 distinct detection algorithms with configurable thresholds and sliding time windows.
- Prevents alert storms by enforcing duplicate cooldown periods per `(alert_type, source_ip)`.
- Prunes expired records using double-ended queues (`collections.deque`), avoiding unbounded memory growth.
- Emits structured `NetworkAlert` objects supporting backwards-compatible tuple unpacking `(alert_type, description)`.

### 4. `network_monitor.py`
- Discovers Windows network adapters by querying Scapy's Windows interface tables and mapping NPF device GUIDs to user-friendly adapter names (e.g., *"Wi-Fi - Realtek WiFi 6"*).
- Uses Scapy's `AsyncSniffer` for clean background sniffing and responsive start/stop behavior.
- Implements an offline **Demo Simulation** thread that produces realistic background web traffic alongside deterministic anomaly stages (port scans, SYN floods, bandwidth spikes, and ARP conflicts).

### 5. `database.py`
- Automatically provisions `network_black_box.db` with indexes on timestamp, IP, and alert types.
- Enables SQLite Write-Ahead Logging (WAL) for high concurrency.
- Runs a background worker thread (`DBWorkerThread`) that flushes batched inserts every 50 records or 0.5 seconds, avoiding disk I/O bottlenecks.
- Handles database schema migrations gracefully if older schema versions exist.

### 6. `test_detector.py`
- Standalone automated test suite containing 14 unit tests across analyzer, detector, and database components.
- Requires no external network access, no administrative rights, and finishes in under 0.5 seconds.

### 7. `view_database.py`
- Command-line audit utility for inspecting stored packets, security alerts, and aggregate summaries without launching the GUI.

---

## 7. Detection Algorithms & Mathematical Heuristics

### A. High-Bandwidth Source Detection
- **Objective:** Detect when a single endpoint consumes excessive bandwidth.
- **Algorithm:** For each source IP, record incoming packet sizes into a sliding deque.
  $$\text{Volume}(src) = \sum_{t_i \ge t_{now} - W_{bw}} \text{size}_i$$
  If $\text{Volume}(src) \ge \text{Threshold}_{bw}$ (default 5 MB in 10 s):
  An alert with severity **HIGH** is dispatched with measured rate $\frac{\text{Volume}}{W_{bw} \times 1024^2}$ MB/s.

### B. Packet-Flood Detection
- **Objective:** Detect DoS packet-flooding attempts.
- **Algorithm:** Track timestamps of all packets emitted by a source IP over window $W_{pkt}$ (default 5 s).
  If count $N(src) \ge \text{Threshold}_{pkt}$ (default 300 packets in 5 s):
  An alert with severity **HIGH** is dispatched with measured packet rate.

### C. Port-Scan Detection
- **Objective:** Detect TCP/UDP horizontal or vertical port scanning reconnaissance.
- **Algorithm:** Track contacted destination ports per source IP in window $W_{scan}$ (default 10 s).
  $$\text{UniquePorts}(src) = |\{ \text{dst\_port}_i : t_i \ge t_{now} - W_{scan} \}|$$
  If $|\text{UniquePorts}(src)| \ge \text{Threshold}_{scan}$ (default 15 ports):
  An alert with severity **HIGH** is dispatched.

### D. SYN-Flood Detection
- **Objective:** Identify TCP half-open connection attacks (SYN flood).
- **Algorithm:** Inspect TCP control flags. A packet is classified as an initial SYN if:
  $$\text{Flags} \ \& \ 0\text{x}02 \neq 0 \quad \text{and} \quad \text{Flags} \ \& \ 0\text{x}10 = 0$$
  If count of SYN packets from a source in $W_{syn}$ (default 5 s) $\ge \text{Threshold}_{syn}$ (default 50):
  An alert with severity **CRITICAL** is triggered.

### E. Traffic-Spike Detection
- **Objective:** Detect anomalous sudden surges across the entire network.
- **Algorithm:** Maintain rolling historical throughput averages:
  $$\mu_{baseline} = \frac{1}{K} \sum_{j=1}^{K} \text{rate}_j$$
  If $\text{rate}_{current} \ge \mu_{baseline} \times M_{spike}$ (default multiplier $3.0\times$) and $\text{rate}_{current} \ge 0.5\text{ MB/s}$ (minimum noise threshold), a **MEDIUM** severity alert is emitted.

### F. ARP Spoofing / MAC Conflict Detection
- **Objective:** Detect potential Man-in-the-Middle (MitM) ARP poisoning attacks.
- **Algorithm:** Maintain an in-memory IP-to-MAC resolution map:
  $$\text{Cache}: \text{IP} \to \text{MAC}$$
  When an ARP packet is inspected with source IP $S_{ip}$ and source MAC $M_{src}$:
  If $S_{ip} \in \text{Cache}$ and $\text{Cache}[S_{ip}] \neq M_{src}$:
  A potential ARP spoofing alert with severity **CRITICAL** is flagged.

---

## 8. Database Schema

### Table: `packets`
| Field | Type | Description |
| :--- | :--- | :--- |
| `id` | INTEGER PRIMARY KEY AUTOINCREMENT | Unique packet log identifier |
| `timestamp` | TEXT | Time of capture (`HH:MM:SS` or `YYYY-MM-DD HH:MM:SS`) |
| `source_ip` | TEXT | Source IPv4 / IPv6 / ARP address |
| `destination_ip` | TEXT | Destination IPv4 / IPv6 / ARP address |
| `protocol` | TEXT | Protocol name (`TCP`, `UDP`, `ICMP`, `ARP`, `OTHER`) |
| `source_port` | TEXT | Transport layer source port (or `-`) |
| `destination_port`| TEXT | Transport layer destination port (or `-`) |
| `packet_size` | INTEGER | Packet size in bytes |
| `interface_name` | TEXT | Name of capturing network interface |

### Table: `alerts`
| Field | Type | Description |
| :--- | :--- | :--- |
| `id` | INTEGER PRIMARY KEY AUTOINCREMENT | Unique alert record identifier |
| `timestamp` | TEXT | Time of anomaly detection |
| `severity` | TEXT | Severity level (`INFO`, `MEDIUM`, `HIGH`, `CRITICAL`) |
| `alert_type` | TEXT | Anomaly category code (e.g. `PORT_SCAN`, `SYN_FLOOD`) |
| `source_ip` | TEXT | Suspect host IP address |
| `destination_ip` | TEXT | Targeted IP address (if applicable) |
| `description` | TEXT | Human-readable explanation of the anomaly |
| `measured_value` | REAL | Numerical measurement (e.g. rate or port count) |
| `threshold_info` | TEXT | Configured rule threshold for verification |

---

## 9. Windows Step-by-Step Installation & Execution Guide

### Prerequisites
- Windows 10 or 11 (64-bit)
- Visual Studio Code installed
- Python 3.10, 3.11, 3.12, 3.13, or 3.14 installed with the *"Add Python to PATH"* option enabled
- [Npcap for Windows](https://npcap.com/) (Required only for live packet sniffing; **not required for Demo Mode**)
  - *Note: During Npcap installation, select "Install Npcap in WinPcap API-compatible Mode".*

---

### Step 1: Open Project in Visual Studio Code
Open VS Code, click **File > Open Folder...**, and select the `NetworkBlackBox backup` folder.

---

### Step 2: Open PowerShell Terminal in VS Code
Open the integrated terminal in VS Code using the shortcut:
```powershell
Ctrl + `
```

---

### Step 3: (Recommended) Create and Activate Virtual Environment
```powershell
# Create a virtual environment named 'venv'
python -m venv venv

# Activate the virtual environment in PowerShell
.\venv\Scripts\Activate.ps1
```
*(If PowerShell shows an execution policy error, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` and reactivate).*

---

### Step 4: Install Dependencies
```powershell
pip install -r requirements.txt
```
This installs `scapy` and `matplotlib`. Standard modules (`tkinter`, `sqlite3`, `threading`, `queue`, `collections`, `time`) come pre-installed with Python.

---

### Step 5: Run Automated Unit Tests
Before launching the GUI, run the offline verification test suite:
```powershell
python test_detector.py
```
**Expected Output:**
```
Ran 14 tests in 0.345s
OK
```

---

### Step 6: Launch Desktop Application

#### Option A: Regular Launch (Ideal for Demo Mode)
```powershell
python app.py
```
- Check the **Demo Mode (Safe Simulation)** box.
- Click **▶ START MONITORING**.
- Watch packets, throughput graph, and security alerts populate safely!

#### Option B: Administrator Launch (For Live Packet Sniffing)
On Windows, raw packet capture requires Administrator privileges.
1. Right-click PowerShell or VS Code and choose **Run as Administrator**.
2. Navigate to the project directory:
   ```powershell
   cd "C:\path\to\NetworkBlackBox"
   ```
3. Run the application:
   ```powershell
   python app.py
   ```
4. Select your active Wi-Fi or Ethernet adapter from the **Interface** dropdown.
5. Click **▶ START MONITORING**.
6. Open your web browser and load websites (e.g. YouTube, Wikipedia) to generate live network traffic.

---

### Step 7: Inspect Stored Records Using Database Utility
In a separate terminal window, inspect the database anytime:
```powershell
# Display complete summary statistics
python view_database.py --summary

# Display the latest 15 packets
python view_database.py --packets 15

# Display the latest 10 security alerts
python view_database.py --alerts 10
```

---

## 10. Demonstration Guide for College Evaluation

When presenting to your professor or viva examiner:

1. **Launch the Application:**
   Run `python app.py`. Point out the clean dark cyber-themed layout, metric cards, and interface selector.
2. **Explain Architecture & Safety:**
   Explain that the project has two modes:
   - **Live Capture:** Sniffs real NIC frames via Npcap/Scapy.
   - **Demo Mode:** Deterministic simulation that demonstrates all 6 detection rules safely without sending hostile traffic over campus Wi-Fi.
3. **Trigger Demo Mode:**
   - Check the **Demo Mode (Safe Simulation)** checkbox.
   - Click **▶ START MONITORING**.
4. **Observe the Live Telemetry:**
   - **Packets & Throughput:** Watch the packet counter and MB/s line graph rise and fall dynamically.
   - **Top Traffic Sources:** Observe the top talkers table updating per IP.
   - **Protocol Distribution:** Show TCP, UDP, and ICMP percentages updating.
   - **Security Alerts:** Highlight alerts appearing with color-coded severity:
     - `PORT_SCAN` from `192.168.1.200`
     - `SYN_FLOOD` from `10.0.0.99`
     - `HIGH_BANDWIDTH` from `192.168.1.115`
     - `ARP_SPOOFING` when MAC conflict is detected on `192.168.1.1`
5. **Show Database History:**
   - Click **🗄 DATABASE HISTORY**.
   - Show the examiner the historical records and explain how batched SQLite commits prevent GUI freezing.
6. **Show Test Suite Verification:**
   - Switch to the terminal and execute `python test_detector.py` to prove that all 14 unit tests pass with zero network dependencies.

---

## 11. Viva Voce Preparation (Q&A)

### Q1: What is the primary purpose of Network Black Box?
**Answer:** Network Black Box is a real-time passive network monitoring and anomaly detection system. It captures packets on a local network interface, calculates bandwidth throughput in MB/s, aggregates per-host traffic metrics, and flags suspicious activity like port scans, SYN floods, traffic spikes, and ARP spoofing.

### Q2: How does packet sniffing work?
**Answer:** In standard operation, a Network Interface Card (NIC) only accepts packets destined for its own MAC address or broadcast addresses. Packet sniffing places the network driver (via Npcap on Windows) into *promiscuous mode*, allowing the driver to capture all Ethernet frames visible on that physical or wireless segment.

### Q3: What is Scapy and why is it used?
**Answer:** Scapy is a powerful Python library for packet manipulation, sniffing, and protocol parsing. In this project, Scapy's `AsyncSniffer` captures raw frames asynchronously and decodes layer-2 (ARP/Ethernet), layer-3 (IPv4/IPv6), and layer-4 (TCP/UDP/ICMP) headers.

### Q4: How do you prevent the desktop GUI from freezing during high packet rates?
**Answer:** By using a multi-threaded architecture with thread-safe queues (`queue.Queue`). Packet sniffing and database writes run on separate background threads. The GUI thread never performs blocking operations; it consumes batches of up to 40 packets every 300 ms via `root.after()`.

### Q5: What is a Port Scan and how does your system detect it?
**Answer:** A port scan is an automated reconnaissance technique where an attacker probes multiple TCP/UDP ports on a target to find open services. The detector uses a sliding window (10 seconds) to count distinct destination ports contacted by each source IP. If distinct ports $\ge 15$, an alert is triggered.

### Q6: What is a SYN Flood attack and how is it detected?
**Answer:** In TCP's three-way handshake (SYN, SYN-ACK, ACK), an attacker sends a flood of SYN packets without completing the handshake, exhausting server connection tables. The detector identifies packets with the SYN flag set ($0\text{x}02$) and ACK flag clear ($0\text{x}10$). If the volume exceeds 50 SYNs in 5 seconds from a single host, it flags a potential SYN flood.

### Q7: What is ARP Spoofing?
**Answer:** ARP (Address Resolution Protocol) resolves IP addresses to MAC addresses on a local subnet. Because ARP lacks authentication, an attacker can broadcast fake ARP responses claiming to own the default gateway's IP. Network Black Box detects this by caching IP-to-MAC mappings and raising an alert whenever an existing IP address is suddenly claimed by a conflicting MAC address.

### Q8: What are false positives in anomaly detection?
**Answer:** A false positive occurs when legitimate traffic is incorrectly flagged as an attack (e.g., a legitimate high-definition video stream triggering a high-bandwidth alert, or a network gateway reboot triggering an ARP conflict). To minimize false positives, the system employs sliding time windows, minimum rate thresholds, and alert cooldown timers.

### Q9: Why did you use SQLite instead of a full database server?
**Answer:** SQLite is serverless, zero-configuration, and embedded directly inside Python. It requires no separate daemon (like MySQL or PostgreSQL), making the application self-contained and portable for college demonstrations. Write-Ahead Logging (WAL) and batched commits prevent database lock contention.

### Q10: What are the ethical considerations of network monitoring?
**Answer:** Network monitoring should only be performed on networks and devices you own or have explicit authorization to inspect. Network Black Box respects privacy by logging only protocol headers and packet sizes, explicitly discarding application layer payloads.

---

## 12. Troubleshooting Common Issues

### Issue 1: "Capture error: Administrator privileges required"
- **Cause:** Raw socket capture via Npcap requires elevated privileges on Windows.
- **Fix:** Either launch VS Code / PowerShell as Administrator, or enable **Demo Mode** to test the system safely without admin rights.

### Issue 2: Matplotlib is missing (`ModuleNotFoundError: No module named 'matplotlib'`)
- **Fix:** Run `pip install -r requirements.txt` or `pip install matplotlib`.

### Issue 3: No packets captured when monitoring starts
- **Cause:** The default interface selected in the dropdown may not be the adapter carrying active internet traffic (e.g., Bluetooth or an inactive virtual adapter).
- **Fix:** In the **Interface** dropdown, select your active **Wi-Fi** or **Ethernet** adapter.

---

## 13. Limitations & Future Enhancements

### Current Limitations:
1. **Encrypted Traffic Payloads:** Cannot inspect contents of TLS/HTTPS encrypted traffic (by design, for privacy).
2. **Single Host Scope:** Monitors traffic visible to the local machine's NIC; cannot monitor isolated switched traffic on other ports without port mirroring / SPAN.
3. **Rule-Based Thresholds:** Relies on heuristic thresholds rather than machine-learning behavioral baselines.

### Future Enhancements:
1. **Machine Learning Classifiers:** Integrate lightweight Random Forest or Isolation Forest models for unsupervised anomaly detection.
2. **GeoIP Lookup:** Map external source/destination IPs to geographical countries.
3. **Automated Incident Response:** Implement automated firewall rules (e.g., Windows Defender Firewall block commands) for confirmed high-severity attackers.
4. **Email / Webhook Notifications:** Send real-time Discord/Slack alerts for critical events.

---

## 14. Conclusion

The **Network Black Box** project demonstrates that an intuitive, responsive, and reliable network security monitoring tool can be engineered using standard Python tools. By integrating packet capture, statistical analysis, heuristic anomaly detection, dynamic charting, and SQLite persistence into an accessible desktop application, it fulfills all requirements of a comprehensive third-year Computer Networks mini-project.
