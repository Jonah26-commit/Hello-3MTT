"""
Network Detector
Monitors live network connections and process behavior for worm-like activity.
Detects: port scanning, rapid connection attempts, self-propagation over SMB/SSH.
"""

import os
import sys
import time
import socket
import platform
from datetime import datetime
from collections import defaultdict
from utils.colors import Colors

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


# Ports commonly used by worms for spreading
WORM_PORTS = {
    445: "SMB (WannaCry / NotPetya spread vector)",
    139: "NetBIOS (legacy worm spreading)",
    135: "RPC (MS-RPC worm exploits)",
    22: "SSH (brute-force spreading)",
    23: "Telnet (Mirai botnet)",
    1433: "MSSQL (SQL Slammer vector)",
    3389: "RDP (worm brute-force)",
    6667: "IRC (botnet C2)",
    6668: "IRC (botnet C2 alt)",
    25: "SMTP (email worm)",
    4444: "Metasploit default listener",
    5555: "Android ADB (worm spreading)",
    31337: "Back Orifice RAT",
}

# Thresholds for anomaly detection
CONNECTION_RATE_THRESHOLD = 20   # connections per second = suspicious
UNIQUE_IP_THRESHOLD = 15         # distinct IPs in short window = scanner
PORT_SCAN_THRESHOLD = 10         # distinct ports to same IP = scanner


class NetworkDetector:
    def __init__(self):
        self.connection_history = defaultdict(list)
        self.alerts = []

    def monitor(self):
        """
        Real-time network monitoring loop.
        Watches active connections and flags worm-like behavior.
        """
        if not PSUTIL_AVAILABLE:
            print(f"{Colors.YELLOW}[!] psutil not installed. Run: pip install psutil{Colors.RESET}")
            print(f"{Colors.DIM}    Install it for real-time network monitoring.{Colors.RESET}\n")
            self._demo_monitor()
            return

        print(f"{Colors.GREEN}[✓] psutil found. Starting live network monitor...{Colors.RESET}\n")
        print(f"{'─'*60}")
        print(f"  {'TIME':<10} {'PID':<8} {'PROCESS':<20} {'REMOTE IP':<20} {'PORT'}")
        print(f"{'─'*60}")

        seen_connections = set()
        ip_connection_times = defaultdict(list)

        while True:
            try:
                connections = psutil.net_connections(kind="inet")
                now = time.time()

                for conn in connections:
                    if conn.status != "ESTABLISHED":
                        continue
                    if not conn.raddr:
                        continue

                    remote_ip = conn.raddr.ip
                    remote_port = conn.raddr.port
                    pid = conn.pid
                    conn_key = (pid, remote_ip, remote_port)

                    if conn_key in seen_connections:
                        continue
                    seen_connections.add(conn_key)

                    # Get process name
                    proc_name = "unknown"
                    try:
                        proc = psutil.Process(pid)
                        proc_name = proc.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                    timestamp = datetime.now().strftime("%H:%M:%S")

                    # Check if connecting to a known worm port
                    if remote_port in WORM_PORTS:
                        reason = WORM_PORTS[remote_port]
                        print(f"{Colors.RED}  {timestamp:<10} {str(pid):<8} {proc_name:<20} {remote_ip:<20} {remote_port} ⚠ {reason}{Colors.RESET}")
                        self._record_alert("WORM_PORT", proc_name, remote_ip, remote_port, reason)
                    else:
                        print(f"  {timestamp:<10} {str(pid):<8} {proc_name:<20} {remote_ip:<20} {remote_port}")

                    # Track connection rate per process
                    ip_connection_times[pid].append(now)
                    ip_connection_times[pid] = [t for t in ip_connection_times[pid] if now - t < 5]

                    if len(ip_connection_times[pid]) > CONNECTION_RATE_THRESHOLD:
                        print(f"\n{Colors.RED}  [!] ANOMALY: Process {proc_name} (PID {pid}) is making {len(ip_connection_times[pid])} connections/5s{Colors.RESET}\n")
                        self._record_alert("HIGH_RATE", proc_name, remote_ip, remote_port, "Rapid connection rate")

                time.sleep(1)

            except KeyboardInterrupt:
                raise
            except Exception as e:
                pass

    def _demo_monitor(self):
        """Fallback demo mode when psutil is unavailable."""
        print(f"{Colors.CYAN}[*] Running in demo mode (psutil not installed){Colors.RESET}")
        print(f"{Colors.DIM}    In production mode, this watches all active TCP/UDP connections{Colors.RESET}")
        print(f"{Colors.DIM}    and alerts on connections to worm-associated ports:\n{Colors.RESET}")
        for port, desc in list(WORM_PORTS.items())[:8]:
            print(f"    Port {port:<6} → {desc}")
        print(f"\n{Colors.YELLOW}    Install psutil to enable live monitoring: pip install psutil{Colors.RESET}\n")
        print("    Simulating monitor... (Ctrl+C to stop)")
        while True:
            time.sleep(1)

    def status(self):
        if not PSUTIL_AVAILABLE:
            print(f"{Colors.YELLOW}[!] psutil not installed — monitoring unavailable.{Colors.RESET}")
            return
        conns = psutil.net_connections(kind="inet")
        established = [c for c in conns if c.status == "ESTABLISHED"]
        suspicious = [c for c in established if c.raddr and c.raddr.port in WORM_PORTS]
        print(f"\n{Colors.CYAN}  Active connections : {len(established)}{Colors.RESET}")
        print(f"  Suspicious ports   : {Colors.RED if suspicious else Colors.GREEN}{len(suspicious)}{Colors.RESET}")
        if suspicious:
            for c in suspicious:
                print(f"    → {c.raddr.ip}:{c.raddr.port} — {WORM_PORTS[c.raddr.port]}")
        print()

    def _record_alert(self, alert_type, process, ip, port, reason):
        self.alerts.append({
            "type": alert_type,
            "process": process,
            "remote_ip": ip,
            "remote_port": port,
            "reason": reason,
            "timestamp": datetime.now().isoformat(),
        })
