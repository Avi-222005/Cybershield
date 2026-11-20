"""
Bandwidth Monitor for CyberShield Network Monitor.
Computes real-time upload and download speeds, bytes transferred, and packet rates
using operating system interface counters from psutil.
"""

import time
import threading
import psutil
from typing import Dict, Optional, Any
from models.traffic_stats import BandwidthStats
from utils.logger import logger


class BandwidthMonitor:
    """
    Monitors interface-level network bandwidth and throughput.
    Maintains baseline counters to prevent initial spike anomalies.
    """

    def __init__(self, interface: Optional[str] = None):
        self.interface = interface
        self._lock = threading.Lock()
        self._previous_counters: Dict[str, Any] = {}
        self._previous_time: Dict[str, float] = {}
        self._latest_stats: Dict[str, BandwidthStats] = {}

    def set_interface(self, interface: str) -> None:
        """Change or set monitored interface and reset its baseline."""
        with self._lock:
            self.interface = interface
            self._previous_counters.pop(interface, None)
            self._previous_time.pop(interface, None)

    def reset_baseline(self, interface: Optional[str] = None) -> None:
        """Reset historical counter baseline for one or all interfaces."""
        with self._lock:
            if interface:
                self._previous_counters.pop(interface, None)
                self._previous_time.pop(interface, None)
                self._latest_stats.pop(interface, None)
            else:
                self._previous_counters.clear()
                self._previous_time.clear()
                self._latest_stats.clear()

    def update(self, interface_name: Optional[str] = None) -> Optional[BandwidthStats]:
        """
        Poll interface counters and calculate transmission rates.
        Returns None if interface counters cannot be read.
        """
        target_iface = interface_name or self.interface
        if not target_iface:
            return None

        now = time.time()
        try:
            counters_per_nic = psutil.net_io_counters(pernic=True)
        except Exception as e:
            logger.debug(f"Failed to read net_io_counters: {e}")
            return None

        counters = counters_per_nic.get(target_iface)
        if not counters:
            return None

        with self._lock:
            prev_counters = self._previous_counters.get(target_iface)
            prev_time = self._previous_time.get(target_iface)

            # Store current measurement for next delta computation
            self._previous_counters[target_iface] = counters
            self._previous_time[target_iface] = now

            # If this is the initial measurement, establish baseline without artificial spikes
            if prev_counters is None or prev_time is None:
                stats = BandwidthStats(
                    interface=target_iface,
                    upload_bytes_per_sec=0.0,
                    download_bytes_per_sec=0.0,
                    upload_mbps=0.0,
                    download_mbps=0.0,
                    total_bytes_sent=counters.bytes_sent,
                    total_bytes_received=counters.bytes_recv,
                    packets_sent=counters.packets_sent,
                    packets_received=counters.packets_recv,
                    packets_sent_per_sec=0.0,
                    packets_recv_per_sec=0.0,
                    timestamp=now,
                )
                self._latest_stats[target_iface] = stats
                return stats

            # Compute time delta
            delta_t = now - prev_time
            if delta_t <= 0:
                return self._latest_stats.get(target_iface)

            # Compute counter differences (handle counter resets / overflow safely)
            bytes_sent_diff = max(0, counters.bytes_sent - prev_counters.bytes_sent)
            bytes_recv_diff = max(0, counters.bytes_recv - prev_counters.bytes_recv)
            pkts_sent_diff = max(0, counters.packets_sent - prev_counters.packets_sent)
            pkts_recv_diff = max(0, counters.packets_recv - prev_counters.packets_recv)

            upload_bytes_sec = bytes_sent_diff / delta_t
            download_bytes_sec = bytes_recv_diff / delta_t

            # Convert bytes per second to Megabits per second (Mbps): (BytesPerSec * 8) / 1,000,000
            upload_mbps = (upload_bytes_sec * 8.0) / 1_000_000.0
            download_mbps = (download_bytes_sec * 8.0) / 1_000_000.0

            pkts_sent_sec = pkts_sent_diff / delta_t
            pkts_recv_sec = pkts_recv_diff / delta_t

            stats = BandwidthStats(
                interface=target_iface,
                upload_bytes_per_sec=round(upload_bytes_sec, 2),
                download_bytes_per_sec=round(download_bytes_sec, 2),
                upload_mbps=round(upload_mbps, 5),
                download_mbps=round(download_mbps, 5),
                total_bytes_sent=counters.bytes_sent,
                total_bytes_received=counters.bytes_recv,
                packets_sent=counters.packets_sent,
                packets_received=counters.packets_recv,
                packets_sent_per_sec=round(pkts_sent_sec, 2),
                packets_recv_per_sec=round(pkts_recv_sec, 2),
                timestamp=now,
            )

            self._latest_stats[target_iface] = stats
            return stats

    def get_latest_stats(self, interface_name: Optional[str] = None) -> Optional[BandwidthStats]:
        """Return the most recently computed bandwidth stats without triggering a poll."""
        target_iface = interface_name or self.interface
        if not target_iface:
            return None
        with self._lock:
            return self._latest_stats.get(target_iface)
