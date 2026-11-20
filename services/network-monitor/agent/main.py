"""
CyberShield Network Monitoring Agent - Command Line Interface & Live Terminal Dashboard.
Executes the autonomous Windows network monitoring agent with real-time telemetry updates.
"""

import argparse
import os
import signal
import sys
import time
from typing import Optional

# Ensure services/network-monitor root is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from agent.controller import AgentController
from core.interface_manager import InterfaceManager
from utils.logger import setup_logger, logger
from utils.system_checks import check_system_readiness


def format_bytes(num_bytes: float) -> str:
    """Format bytes into human-friendly string (B, KB, MB, GB)."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:6.2f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.2f} PB"


def render_dashboard(controller: AgentController) -> None:
    """Render real-time status and traffic statistics in the terminal."""
    status = controller.get_status()
    bw = status.bandwidth
    cap = status.capture
    recent_conns = controller.data_manager.get_active_connections()

    # ANSI Codes
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    MAGENTA = "\033[95m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    # Terminal clear and reposition cursor to top-left
    sys.stdout.write("\033[H\033[J")

    sys.stdout.write(f"{CYAN}{BOLD}╔═══════════════════════════════════════════════════════════════════════════════╗{RESET}\n")
    sys.stdout.write(f"{CYAN}{BOLD}║                     CYBERSHIELD NETWORK MONITOR AGENT                        ║{RESET}\n")
    sys.stdout.write(f"{CYAN}{BOLD}╚═══════════════════════════════════════════════════════════════════════════════╝{RESET}\n")

    state_color = GREEN if status.state == "RUNNING" else YELLOW
    sys.stdout.write(
        f" Status: {state_color}{BOLD}{status.state}{RESET} | "
        f"Interface: {CYAN}{status.monitored_interface or 'N/A'}{RESET} | "
        f"Uptime: {status.uptime_seconds:.0f}s | "
        f"Memory Ring: {status.memory_buffer_usage.get('packet_events', 0)}/{status.memory_buffer_usage.get('max_packet_events', 5000)}\n"
    )
    sys.stdout.write("─" * 79 + "\n")

    # Bandwidth Section
    sys.stdout.write(f"{BOLD}[ BANDWIDTH & INTERFACE THROUGHPUT ]{RESET}\n")
    if bw:
        up_kb = bw.upload_bytes_per_sec / 1024.0
        down_kb = bw.download_bytes_per_sec / 1024.0
        tot_sent = format_bytes(bw.total_bytes_sent)
        tot_recv = format_bytes(bw.total_bytes_received)

        sys.stdout.write(
            f" ▲ Upload:   {GREEN}{bw.upload_mbps:8.4f} Mbps{RESET} ({up_kb:7.1f} KB/s) | Sent:     {tot_sent} ({bw.packets_sent_per_sec:.1f} pkts/s)\n"
        )
        sys.stdout.write(
            f" ▼ Download: {GREEN}{bw.download_mbps:8.4f} Mbps{RESET} ({down_kb:7.1f} KB/s) | Received: {tot_recv} ({bw.packets_recv_per_sec:.1f} pkts/s)\n"
        )
    else:
        sys.stdout.write(" Establishing throughput baseline...\n")

    sys.stdout.write("─" * 79 + "\n")

    # Packet Capture Section
    sys.stdout.write(f"{BOLD}[ PACKET CAPTURE METADATA ]{RESET}\n")
    if cap:
        proto_str = ", ".join(f"{k}: {v}" for k, v in sorted(cap.protocol_distribution.items(), key=lambda x: -x[1])[:6]) or "None"
        dir_str = f"In: {cap.direction_distribution.get('inbound', 0)} | Out: {cap.direction_distribution.get('outbound', 0)} | Int: {cap.direction_distribution.get('internal', 0)}"

        sys.stdout.write(
            f" Observed Packets: {BOLD}{cap.total_packets_captured}{RESET} | "
            f"Rate: {YELLOW}{cap.packets_per_sec:.1f} pkts/s{RESET} | "
            f"Drops: {cap.dropped_packets}\n"
        )
        sys.stdout.write(f" Protocols: {DIM}{proto_str}{RESET}\n")
        sys.stdout.write(f" Traffic:   {DIM}{dir_str}{RESET}\n")
    else:
        sys.stdout.write(" Packet capture inactive.\n")

    sys.stdout.write("─" * 79 + "\n")

    # Active Connections Section
    sys.stdout.write(f"{BOLD}[ ACTIVE CONNECTIONS ({len(recent_conns)}) ]{RESET}\n")
    sys.stdout.write(f" {DIM}{'PROTO':5s} {'LOCAL ADDRESS':21s} {'REMOTE ADDRESS':21s} {'STATUS':12s} {'PID':7s} {'PROCESS'}{RESET}\n")

    # Display up to 8 connections with preference for established external connections
    sorted_conns = sorted(
        recent_conns,
        key=lambda c: (0 if c.status == "ESTABLISHED" and c.remote_ip else 1, c.protocol),
    )

    for c in sorted_conns[:8]:
        l_addr = f"{c.local_ip}:{c.local_port}"[:21]
        r_addr = f"{c.remote_ip}:{c.remote_port}"[:21] if c.remote_ip else "*:*"
        p_name = c.process_name or "-"
        pid_str = str(c.pid) if c.pid else "-"
        st_color = GREEN if c.status == "ESTABLISHED" else (YELLOW if c.status == "LISTEN" else DIM)

        sys.stdout.write(
            f" {c.protocol.upper():5s} {l_addr:21s} {r_addr:21s} {st_color}{c.status:12s}{RESET} {pid_str:7s} {p_name[:18]}\n"
        )

    sys.stdout.write("─" * 79 + "\n")

    # Subsystem Health Footer
    health_parts = [f"{name}: {h.status}" for name, h in status.components.items()]
    sys.stdout.write(f"{DIM}Subsystems: {' | '.join(health_parts)}{RESET}\n")
    sys.stdout.write(f"{DIM}Press Ctrl+C to terminate agent gracefully.{RESET}\n")
    sys.stdout.flush()


def run_agent(args) -> int:
    """Run the monitoring agent loop."""
    config_overrides = {"monitoring": {}, "intervals": {}}

    if args.interface:
        config_overrides["monitoring"]["interface"] = args.interface

    if args.tshark_path:
        config_overrides["tshark_path"] = args.tshark_path

    if args.synthetic:
        config_overrides["monitoring"]["force_adapter"] = "synthetic"

    if args.no_capture:
        config_overrides["monitoring"]["capture_packets"] = False

    if args.no_connections:
        config_overrides["monitoring"]["monitor_connections"] = False

    if args.no_bandwidth:
        config_overrides["monitoring"]["monitor_bandwidth"] = False

    controller = AgentController(config_overrides)

    # Signal handlers
    def handle_shutdown(signum, frame):
        sys.stdout.write("\nReceived shutdown signal. Stopping agent...\n")
        controller.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_shutdown)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, handle_shutdown)

    if not controller.start():
        logger.error("Failed to start agent controller.")
        return 1

    try:
        while controller.state == "RUNNING":
            if not args.no_dashboard:
                render_dashboard(controller)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        pass
    finally:
        controller.stop()

    return 0


def main():
    parser = argparse.ArgumentParser(description="CyberShield Network Monitor - Windows Agent")
    parser.add_argument("-i", "--interface", help="Network interface to monitor (or 'auto')", default=None)
    parser.add_argument("--tshark-path", help="Path to tshark.exe binary", default=None)
    parser.add_argument("--synthetic", action="store_true", help="Force synthetic packet simulation mode")
    parser.add_argument("--no-capture", action="store_true", help="Disable packet capture")
    parser.add_argument("--no-connections", action="store_true", help="Disable connection monitoring")
    parser.add_argument("--no-bandwidth", action="store_true", help="Disable bandwidth monitoring")
    parser.add_argument("--no-dashboard", action="store_true", help="Disable visual ANSI terminal dashboard")
    parser.add_argument("--interval", type=float, default=1.0, help="Terminal dashboard refresh interval (seconds)")
    parser.add_argument("--check", action="store_true", help="Check system readiness and dependencies")
    parser.add_argument("--list-interfaces", action="store_true", help="List detected network interfaces")

    args = parser.parse_args()

    if args.check:
        readiness = check_system_readiness(args.tshark_path)
        print("=== CyberShield System Readiness Report ===")
        print(f"Python 3.11+: {readiness['python']['message']}")
        print(f"TShark Binary: {readiness['tshark']['message']}")
        print(f"Npcap Driver:  {readiness['npcap']['message']}")
        print(f"Admin Rights:  {readiness['admin']['message']}")
        print(f"Full Capture:  {'READY' if readiness['full_live_capture_ready'] else 'PARTIAL (Simulation/Basic)'}")
        return 0

    if args.list_interfaces:
        im = InterfaceManager()
        ifaces = im.get_all_interfaces()
        default_iface = im.get_default_interface()
        print(f"Detected {len(ifaces)} interfaces (Default: '{default_iface}'):\n")
        for name, details in ifaces.items():
            status_tag = "[UP]" if details["is_up"] else "[DOWN]"
            ips = ", ".join(details["ipv4"] + details["ipv6"]) or "No IP assigned"
            default_marker = " * DEFAULT *" if name == default_iface else ""
            print(f" - {name} {status_tag}{default_marker}")
            print(f"     IPs: {ips}")
            print(f"     MAC: {details['mac_address'] or 'N/A'}")
        return 0

    return run_agent(args)


if __name__ == "__main__":
    sys.exit(main())
