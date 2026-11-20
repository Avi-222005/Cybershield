"""
Baseline Manager for CyberShield Threat Detection.
Maintains bounded sliding-window moving averages, traffic standard deviations,
and known external session endpoint registries.
"""

import math
import threading
import time
from collections import deque
from typing import Dict, Any, Tuple, Deque, Set, Optional


class BaselineManager:
    """
    Tracks session baselines for bandwidth throughput and host communication patterns.
    Thread-safe and strictly bounded to prevent unbounded memory growth.
    """

    def __init__(self, window_seconds: int = 120, max_known_ips: int = 2000):
        self._lock = threading.RLock()
        self.window_seconds = window_seconds
        self.max_known_ips = max_known_ips

        # Bandwidth sliding windows: (timestamp, upload_bps, download_bps)
        self._bandwidth_history: Deque[Tuple[float, float, float]] = deque(maxlen=240)

        # Known session external IPs
        self._seen_external_ips: Set[str] = set()

    def record_bandwidth(self, upload_bps: float, download_bps: float, now: Optional[float] = None) -> None:
        """Record a bandwidth measurement sample into the sliding window."""
        t = now or time.time()
        with self._lock:
            self._bandwidth_history.append((t, upload_bps, download_bps))
            cutoff = t - self.window_seconds
            while self._bandwidth_history and self._bandwidth_history[0][0] < cutoff:
                self._bandwidth_history.popleft()

    def get_bandwidth_stats(self) -> Dict[str, Any]:
        """
        Calculate rolling mean and standard deviation for upload and download rates.
        Returns sample count and statistics.
        """
        with self._lock:
            samples = list(self._bandwidth_history)

        count = len(samples)
        if count < 5:
            return {
                "sample_count": count,
                "has_sufficient_data": False,
                "upload_mean": 0.0,
                "upload_std": 0.0,
                "download_mean": 0.0,
                "download_std": 0.0,
            }

        up_vals = [s[1] for s in samples]
        down_vals = [s[2] for s in samples]

        up_mean = sum(up_vals) / count
        down_mean = sum(down_vals) / count

        up_var = sum((x - up_mean) ** 2 for x in up_vals) / count
        down_var = sum((x - down_mean) ** 2 for x in down_vals) / count

        return {
            "sample_count": count,
            "has_sufficient_data": True,
            "upload_mean": up_mean,
            "upload_std": math.sqrt(up_var),
            "download_mean": down_mean,
            "download_std": math.sqrt(down_var),
        }

    def is_known_ip(self, ip: str) -> bool:
        """Check whether an IP has been observed during the current monitoring session."""
        with self._lock:
            return ip in self._seen_external_ips

    def register_ip(self, ip: str) -> None:
        """Register an observed IP address into the session cache."""
        with self._lock:
            if len(self._seen_external_ips) < self.max_known_ips:
                self._seen_external_ips.add(ip)

    def reset(self) -> None:
        """Purge all baseline tracking structures on shutdown."""
        with self._lock:
            self._bandwidth_history.clear()
            self._seen_external_ips.clear()
