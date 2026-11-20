"""
Packet Capture Engine for CyberShield Network Monitor.
Provides an extensible adapter architecture supporting TShark direct subprocess,
PyShark live capture, and synthetic simulation mode for unprivileged/test environments.
Strictly captures metadata only; payloads are never accessed or retained.
"""

import abc
import os
import random
import subprocess
import threading
import time
from typing import Callable, Optional, Dict, Any, Set

from models.packet_event import PacketEvent
from core.packet_parser import PacketParser
from utils.logger import logger
from utils.system_checks import find_tshark_executable


class BaseCaptureAdapter(abc.ABC):
    """Abstract base class for packet capture adapters."""

    def __init__(self, parser: Optional[PacketParser] = None):
        self.parser = parser or PacketParser()
        self._is_running = False
        self._error: Optional[str] = None
        self._packets_captured = 0
        self._dropped_count = 0

    @abc.abstractmethod
    def start(
        self,
        interface: str,
        callback: Callable[[PacketEvent], None],
        local_ips: Optional[Set[str]] = None,
    ) -> bool:
        """Start capturing packets on the target interface."""
        pass

    @abc.abstractmethod
    def stop(self) -> None:
        """Stop packet capture cleanly."""
        pass

    def is_running(self) -> bool:
        return self._is_running

    def get_status(self) -> Dict[str, Any]:
        return {
            "adapter": self.__class__.__name__,
            "is_running": self._is_running,
            "packets_captured": self._packets_captured,
            "dropped_count": self._dropped_count,
            "error": self._error,
        }


class TSharkSubprocessAdapter(BaseCaptureAdapter):
    """
    High-performance, low-memory direct TShark subprocess capture adapter.
    Extracts strictly defined metadata fields via line-by-line TSV stream.
    Zero packet payload retention, zero disk writes.
    """

    def __init__(self, tshark_path: Optional[str] = None, parser: Optional[PacketParser] = None):
        super().__init__(parser)
        self.tshark_path = find_tshark_executable(tshark_path)
        self._process: Optional[subprocess.Popen] = None
        self._worker_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def start(
        self,
        interface: str,
        callback: Callable[[PacketEvent], None],
        local_ips: Optional[Set[str]] = None,
    ) -> bool:
        if self._is_running:
            return True

        if not self.tshark_path or not os.path.isfile(self.tshark_path):
            self._error = f"TShark executable not found: {self.tshark_path}"
            logger.error(self._error)
            return False

        if local_ips:
            self.parser.set_local_ips(local_ips)

        self._stop_event.clear()
        self._error = None

        # Build TShark command targeting only metadata fields
        cmd = [
            self.tshark_path,
            "-i", interface,
            "-l",  # Line-buffered stdout
            "-n",  # Disable network name resolution for performance
            "-T", "fields",
            "-E", "separator=\t",
            "-E", "occurrence=f",
            "-e", "frame.time_epoch",
            "-e", "frame.len",
            "-e", "_ws.col.Protocol",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "ipv6.src",
            "-e", "ipv6.dst",
            "-e", "tcp.srcport",
            "-e", "tcp.dstport",
            "-e", "udp.srcport",
            "-e", "udp.dstport",
            "-e", "arp.src.proto_ipv4",
            "-e", "arp.dst.proto_ipv4",
        ]

        try:
            # Hide console window on Windows if spawned
            creationflags = 0
            if os.name == "nt":
                creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)

            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                creationflags=creationflags,
            )
        except Exception as e:
            self._error = f"Failed to spawn TShark subprocess: {e}"
            logger.error(self._error)
            return False

        self._is_running = True

        def capture_worker():
            logger.info(f"TShark subprocess capture active on interface '{interface}'")
            try:
                for line in self._process.stdout:
                    if self._stop_event.is_set():
                        break
                    line = line.strip()
                    if not line:
                        continue

                    event = self.parser.parse_tshark_tsv_line(line, interface)
                    if event:
                        self._packets_captured += 1
                        try:
                            callback(event)
                        except Exception as cb_err:
                            logger.debug(f"Callback error in packet capture: {cb_err}")
            except Exception as read_err:
                if not self._stop_event.is_set():
                    self._error = f"TShark stream read error: {read_err}"
                    logger.warning(self._error)
            finally:
                self._is_running = False
                logger.info("TShark capture worker finished.")

        self._worker_thread = threading.Thread(
            target=capture_worker,
            name="TSharkCaptureWorker",
            daemon=True,
        )
        self._worker_thread.start()
        return True

    def stop(self) -> None:
        if not self._is_running and not self._process:
            return

        self._stop_event.set()
        if self._process:
            try:
                self._process.terminate()
                self._process.wait(timeout=2.0)
            except Exception:
                try:
                    self._process.kill()
                except Exception:
                    pass
            self._process = None

        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)
            self._worker_thread = None

        self._is_running = False


class PySharkCaptureAdapter(BaseCaptureAdapter):
    """
    PyShark LiveCapture adapter wrapping TShark.
    Provided as the initial high-level Python interface to TShark as specified.
    """

    def __init__(self, tshark_path: Optional[str] = None, parser: Optional[PacketParser] = None):
        super().__init__(parser)
        self.tshark_path = find_tshark_executable(tshark_path)
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None
        self._capture_obj = None

    def start(
        self,
        interface: str,
        callback: Callable[[PacketEvent], None],
        local_ips: Optional[Set[str]] = None,
    ) -> bool:
        if self._is_running:
            return True

        try:
            import pyshark
        except ImportError:
            self._error = "PyShark is not installed. Please install pyshark or use TSharkSubprocessAdapter."
            logger.warning(self._error)
            return False

        if self.tshark_path:
            pyshark.tshark.tshark.get_process_path = lambda: self.tshark_path

        if local_ips:
            self.parser.set_local_ips(local_ips)

        self._stop_event.clear()
        self._error = None

        try:
            self._capture_obj = pyshark.LiveCapture(
                interface=interface,
                only_summaries=False,
                include_raw=False,
            )
        except Exception as e:
            self._error = f"Failed to initialize PyShark LiveCapture: {e}"
            logger.error(self._error)
            return False

        self._is_running = True

        def pyshark_worker():
            logger.info(f"PyShark capture active on interface '{interface}'")
            try:
                for packet in self._capture_obj.sniff_continuously():
                    if self._stop_event.is_set():
                        break
                    event = self.parser.parse_pyshark_packet(packet, interface)
                    if event:
                        self._packets_captured += 1
                        try:
                            callback(event)
                        except Exception as cb_err:
                            logger.debug(f"Callback error in PyShark capture: {cb_err}")
            except Exception as e:
                if not self._stop_event.is_set():
                    self._error = f"PyShark capture loop exited: {e}"
                    logger.warning(self._error)
            finally:
                self._is_running = False
                logger.info("PyShark capture worker stopped.")

        self._worker_thread = threading.Thread(
            target=pyshark_worker,
            name="PySharkWorker",
            daemon=True,
        )
        self._worker_thread.start()
        return True

    def stop(self) -> None:
        self._stop_event.set()
        if self._capture_obj:
            try:
                self._capture_obj.close()
            except Exception:
                pass
            self._capture_obj = None

        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)
            self._worker_thread = None

        self._is_running = False


class SyntheticCaptureAdapter(BaseCaptureAdapter):
    """
    Simulated traffic generator adapter producing synthetic PacketEvents.
    Enables complete pipeline testing and validation without requiring TShark,
    Npcap, or administrative network capture privileges.
    """

    COMMON_PROTOCOLS = ["TCP", "UDP", "TLS", "HTTP", "DNS", "ARP", "ICMP"]
    EXTERNAL_IPS = [
        "142.250.183.14",   # Google
        "1.1.1.1",          # Cloudflare DNS
        "8.8.8.8",          # Google DNS
        "151.101.65.140",   # Fastly CDN
        "13.107.42.14",     # Microsoft
        "104.244.42.1",     # Twitter / X
        "185.199.108.153",  # GitHub
    ]

    def __init__(self, parser: Optional[PacketParser] = None, rate_per_second: float = 10.0):
        super().__init__(parser)
        self.rate = max(0.1, rate_per_second)
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None

    def start(
        self,
        interface: str,
        callback: Callable[[PacketEvent], None],
        local_ips: Optional[Set[str]] = None,
    ) -> bool:
        if self._is_running:
            return True

        if local_ips:
            self.parser.set_local_ips(local_ips)

        self._stop_event.clear()
        self._is_running = True
        local_ip = next(iter(local_ips)) if local_ips else "192.168.1.105"

        def simulation_worker():
            logger.info(f"Synthetic packet capture simulator active on interface '{interface}' (~{self.rate} pkts/sec)")
            sleep_interval = 1.0 / self.rate

            while not self._stop_event.is_set():
                now = time.time()
                proto = random.choices(
                    self.COMMON_PROTOCOLS,
                    weights=[40, 20, 20, 10, 5, 3, 2],
                    k=1,
                )[0]

                is_outbound = random.choice([True, False])
                remote_ip = random.choice(self.EXTERNAL_IPS)

                if is_outbound:
                    src_ip = local_ip
                    dst_ip = remote_ip
                    src_port = random.randint(49152, 65535)
                    dst_port = 443 if proto in ("TLS", "TCP") else (80 if proto == "HTTP" else 53)
                else:
                    src_ip = remote_ip
                    dst_ip = local_ip
                    src_port = 443 if proto in ("TLS", "TCP") else (80 if proto == "HTTP" else 53)
                    dst_port = random.randint(49152, 65535)

                if proto == "ARP":
                    src_port, dst_port = None, None
                elif proto == "ICMP":
                    src_port, dst_port = None, None

                dns_query = (
                    random.choice(["api.github.com", "dns.google", "connectivitycheck.gstatic.com", "time.windows.com"])
                    if proto == "DNS" else None
                )
                dns_rcode = 0 if proto == "DNS" else None

                size = random.randint(64, 1514)
                direction = "outbound" if is_outbound else "inbound"

                event = PacketEvent(
                    timestamp=now,
                    interface=interface,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    source_port=src_port,
                    destination_port=dst_port,
                    protocol=proto,
                    packet_size=size,
                    direction=direction,
                    dns_query=dns_query,
                    dns_rcode=dns_rcode,
                )

                self._packets_captured += 1
                try:
                    callback(event)
                except Exception as cb_err:
                    logger.debug(f"Synthetic callback error: {cb_err}")

                time.sleep(sleep_interval)

            self._is_running = False
            logger.info("Synthetic packet capture simulator stopped.")

        self._worker_thread = threading.Thread(
            target=simulation_worker,
            name="SyntheticPacketWorker",
            daemon=True,
        )
        self._worker_thread.start()
        return True

    def stop(self) -> None:
        self._stop_event.set()
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)
            self._worker_thread = None
        self._is_running = False


class PacketCaptureEngine:
    """
    Main Packet Capture Engine coordinator.
    Selects, instantiates, and manages adapters (TShark direct, PyShark, or Synthetic simulation).
    """

    def __init__(
        self,
        tshark_path: Optional[str] = None,
        force_adapter: Optional[str] = None,
        fallback_to_synthetic: bool = True,
    ):
        self.tshark_path = tshark_path
        self.force_adapter = force_adapter
        self.fallback_to_synthetic = fallback_to_synthetic
        self.parser = PacketParser()
        self.adapter: Optional[BaseCaptureAdapter] = None
        self._current_interface: Optional[str] = None

    def _select_adapter(self) -> BaseCaptureAdapter:
        """Select best available capture adapter based on environment and config."""
        adapter_type = (self.force_adapter or "auto").lower()

        if adapter_type == "synthetic":
            return SyntheticCaptureAdapter(self.parser)

        if adapter_type == "pyshark":
            try:
                import pyshark
                return PySharkCaptureAdapter(self.tshark_path, self.parser)
            except ImportError:
                logger.warning("PyShark requested but not installed. Falling back.")

        # Default / auto: Try TShark subprocess first
        tshark_bin = find_tshark_executable(self.tshark_path)
        if tshark_bin:
            return TSharkSubprocessAdapter(tshark_bin, self.parser)

        # Try PyShark if tshark found through pyshark
        try:
            import pyshark
            return PySharkCaptureAdapter(self.tshark_path, self.parser)
        except ImportError:
            pass

        # Fallback to synthetic if allowed
        if self.fallback_to_synthetic:
            logger.warning(
                "Neither TShark nor PyShark available. Falling back to Synthetic Packet Simulator "
                "so monitoring agent pipeline operates normally."
            )
            return SyntheticCaptureAdapter(self.parser)

        raise RuntimeError(
            "TShark executable not found on host and fallback_to_synthetic is disabled. "
            "Please install Wireshark/Npcap or specify a valid TShark path."
        )

    def start_capture(
        self,
        interface_name: str,
        callback: Callable[[PacketEvent], None],
        local_ips: Optional[Set[str]] = None,
    ) -> bool:
        """
        Start packet capture on specified interface.
        """
        self.stop_capture()
        self._current_interface = interface_name
        self.adapter = self._select_adapter()
        return self.adapter.start(interface_name, callback, local_ips)

    def stop_capture(self) -> None:
        """Stop current packet capture cleanly."""
        if self.adapter:
            try:
                self.adapter.stop()
            except Exception as e:
                logger.debug(f"Error stopping capture adapter: {e}")
            self.adapter = None
        self._current_interface = None

    def is_running(self) -> bool:
        return self.adapter is not None and self.adapter.is_running()

    def get_capture_status(self) -> Dict[str, Any]:
        """Get live status of capture engine and active adapter."""
        if not self.adapter:
            return {
                "active": False,
                "interface": self._current_interface,
                "adapter": None,
                "is_running": False,
                "packets_captured": 0,
            }
        status = self.adapter.get_status()
        status["interface"] = self._current_interface
        status["active"] = self.adapter.is_running()
        return status
