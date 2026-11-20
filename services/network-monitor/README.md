# CyberShield Network Monitor (Phase 1 Agent)

An autonomous Windows-based network monitoring agent written in Python 3.11+. The agent operates as an independent daemon with its own lifecycle, strictly adhering to an **in-memory zero-payload** data policy (no persistent packet captures, no packet payloads stored, no database).

---

## Architecture Overview

```
services/network-monitor/
├── agent/
│   ├── __init__.py
│   ├── main.py              # CLI entry point & live terminal dashboard
│   ├── controller.py        # Central agent lifecycle & thread coordinator
│   └── config.py            # Configuration loader and environment overrides
├── core/
│   ├── __init__.py
│   ├── interface_manager.py # Network adapter enumeration and routing selection
│   ├── packet_capture.py    # Adapter architecture: TShark direct, PyShark, and Synthetic
│   ├── packet_parser.py     # Metadata extraction, direction inference, no payload
│   ├── connection_monitor.py# Active TCP/UDP socket tracking with PID/process resolution
│   ├── bandwidth_monitor.py # Interface counters, speed deltas, baseline spike avoidance
│   └── data_manager.py      # Bounded ring buffers, rolling statistics, zero persistence
├── models/
│   ├── __init__.py
│   ├── packet_event.py      # Normalized packet metadata event
│   ├── connection.py        # Active socket connection model
│   └── traffic_stats.py     # Bandwidth, capture, and health report dataclasses
├── utils/
│   ├── __init__.py
│   ├── logger.py            # Sanitized console logging
│   └── system_checks.py     # Python, TShark, Npcap, and admin permission checks
├── tests/
│   ├── test_interfaces.py   # Adapter detection and mock tests
│   ├── test_parser.py       # Direction inference and TSV parsing tests
│   ├── test_bandwidth.py    # Delta calculations and Mbps tests
│   ├── test_connections.py # Process caching and socket status tests
│   ├── test_data_manager.py # Ring buffer bounds and thread safety tests
│   └── test_controller.py   # Full lifecycle and resilience tests
├── .env.example
├── requirements.txt
├── README.md
└── run.py                   # Standalone agent runner
```

---

## Core Capabilities (Phase 1)

1. **Interface Detection & Selection:**
   - Detects all physical, virtual, Wi-Fi, and Ethernet adapters.
   - Identifies active IPv4 and IPv6 configurations.
   - Automatically resolves default active outbound route without generating traffic.

2. **Packet Capture & Parsing:**
   - Direct high-performance TShark subprocess TSV streaming.
   - PyShark live capture adapter support.
   - Synthetic packet simulation adapter for unprivileged and automated test environments.
   - Direction inference (`inbound`, `outbound`, `internal`, `unknown`) based on interface IP bindings.
   - **Zero Payload Retention:** Packet payloads are never stored, logged, or retained.

3. **Active Connection Tracking:**
   - Polls active internet sockets (`psutil.net_connections`).
   - Best-effort process attribution (PID -> executable name) with in-memory TTL caching to minimize syscall overhead.
   - Graceful handling of permissions (`AccessDenied`) and short-lived processes.

4. **Bandwidth Throughput:**
   - Measures upload and download throughput using operating system counters (`psutil.net_io_counters`).
   - Initial measurement establishes baseline to prevent artificial spike anomalies.
   - Calculates Mbps: `(BytesPerSecond * 8) / 1,000,000`.

5. **In-Memory Bounded Data Management:**
   - Thread-safe bounded ring buffers (`collections.deque(maxlen=5000)`).
   - Rolling packet rate calculation over sliding window.
   - Complete in-memory purge upon agent shutdown.

---

## Setup & Running

### 1. Requirements

- Python 3.11+
- Npcap / Wireshark (for live packet capture; simulation mode available without them)

### 2. Verify System Readiness

```powershell
python services/network-monitor/run.py --check
```

### 3. List Network Interfaces

```powershell
python services/network-monitor/run.py --list-interfaces
```

### 4. Start Live Terminal Dashboard

Run with default auto-detection:
```powershell
python services/network-monitor/run.py
```

Run with synthetic packet simulation mode:
```powershell
python services/network-monitor/run.py --synthetic
```

Target a specific interface:
```powershell
python services/network-monitor/run.py -i "Wi-Fi"
```

Specify custom TShark binary path:
```powershell
python services/network-monitor/run.py --tshark-path "C:\Program Files\Wireshark\tshark.exe"
```

---

## Running Unit Tests

Run all unit tests via `pytest`:

```powershell
pytest services/network-monitor/tests -v
```
