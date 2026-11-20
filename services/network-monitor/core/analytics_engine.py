"""
Analytics Engine for CyberShield Network Monitor.
Provides incremental bounded session-level IP aggregation, hourly traffic time-bucketing,
speed averages and peaks, and best-effort socket-correlated process analytics.
Strictly in-memory and temporary for the duration of the monitoring session.
"""

import threading
import time
from collections import defaultdict
from typing import Dict, Any, List, Optional
from models.packet_event import PacketEvent
from models.connection import Connection


class AnalyticsEngine:
    """
    Session-level analytics engine maintaining bounded telemetry aggregations.
    """

    def __init__(self, max_tracked_ips: int = 1000, max_hourly_buckets: int = 24):
        self._lock = threading.RLock()
        self.max_tracked_ips = max_tracked_ips
        self.max_hourly_buckets = max_hourly_buckets

        self.session_start_time: float = time.time()

        # IP Aggregates: ip -> { ip, packets, bytes, inbound_count, outbound_count, first_seen, last_seen }
        self._ip_stats: Dict[str, Dict[str, Any]] = {}

        # Hourly buckets: bucket_index (1, 2, ...) -> { hour_label, upload_bytes, download_bytes, packets, start_time }
        self._hourly_buckets: Dict[int, Dict[str, Any]] = {}

        # Speed peak and averages tracking
        self._peak_upload_mbps: float = 0.0
        self._peak_download_mbps: float = 0.0
        self._speed_samples_count: int = 0
        self._sum_upload_mbps: float = 0.0
        self._sum_download_mbps: float = 0.0

    def start_session(self) -> None:
        """Initialize session timestamps."""
        with self._lock:
            self.session_start_time = time.time()
            self._ensure_hourly_bucket(self.session_start_time)

    def _ensure_hourly_bucket(self, now: float) -> int:
        elapsed = max(0.0, now - self.session_start_time)
        bucket_idx = int(elapsed // 3600) + 1

        if bucket_idx not in self._hourly_buckets and len(self._hourly_buckets) < self.max_hourly_buckets:
            self._hourly_buckets[bucket_idx] = {
                "bucket_id": bucket_idx,
                "label": f"Hour {bucket_idx}",
                "upload_bytes": 0,
                "download_bytes": 0,
                "packets": 0,
                "start_time": self.session_start_time + (bucket_idx - 1) * 3600,
            }
        return bucket_idx

    def record_packet(self, event: PacketEvent) -> None:
        """Incrementally update session-level IP counters and time buckets."""
        if not event:
            return

        now = event.timestamp or time.time()
        size = event.packet_size or 0
        direction = event.direction or "unknown"
        src = event.source_ip
        dst = event.destination_ip

        with self._lock:
            # 1. Update hourly bucket
            bucket_idx = self._ensure_hourly_bucket(now)
            if bucket_idx in self._hourly_buckets:
                b = self._hourly_buckets[bucket_idx]
                b["packets"] += 1
                if direction == "outbound":
                    b["upload_bytes"] += size
                elif direction == "inbound":
                    b["download_bytes"] += size
                else:
                    # Internal or unknown: attribute evenly
                    b["upload_bytes"] += size // 2
                    b["download_bytes"] += size - (size // 2)

            # 2. Update Source IP stats
            if src and src not in ("None", "0.0.0.0", "255.255.255.255"):
                if src not in self._ip_stats and len(self._ip_stats) < self.max_tracked_ips:
                    self._ip_stats[src] = {
                        "ip": src,
                        "packets": 0,
                        "bytes": 0,
                        "inbound_count": 0,
                        "outbound_count": 0,
                        "first_seen": now,
                        "last_seen": now,
                    }
                if src in self._ip_stats:
                    s = self._ip_stats[src]
                    s["packets"] += 1
                    s["bytes"] += size
                    s["last_seen"] = now
                    if direction == "outbound":
                        s["outbound_count"] += 1
                    else:
                        s["inbound_count"] += 1

            # 3. Update Destination IP stats
            if dst and dst not in ("None", "0.0.0.0", "255.255.255.255"):
                if dst not in self._ip_stats and len(self._ip_stats) < self.max_tracked_ips:
                    self._ip_stats[dst] = {
                        "ip": dst,
                        "packets": 0,
                        "bytes": 0,
                        "inbound_count": 0,
                        "outbound_count": 0,
                        "first_seen": now,
                        "last_seen": now,
                    }
                if dst in self._ip_stats:
                    d = self._ip_stats[dst]
                    d["packets"] += 1
                    d["bytes"] += size
                    d["last_seen"] = now
                    if direction == "inbound":
                        d["inbound_count"] += 1
                    else:
                        d["outbound_count"] += 1

    def record_bandwidth_sample(self, upload_mbps: float, download_mbps: float) -> None:
        """Update speed peaks and moving sums."""
        with self._lock:
            if upload_mbps > self._peak_upload_mbps:
                self._peak_upload_mbps = upload_mbps
            if download_mbps > self._peak_download_mbps:
                self._peak_download_mbps = download_mbps

            if upload_mbps > 0 or download_mbps > 0:
                self._speed_samples_count += 1
                self._sum_upload_mbps += upload_mbps
                self._sum_download_mbps += download_mbps

    def get_analytics(
        self,
        connections: List[Connection],
        traffic: Dict[str, Any],
        protocols: Dict[str, Any],
        limit_ips: int = 15,
    ) -> Dict[str, Any]:
        """Compile comprehensive session analytics dictionary."""
        with self._lock:
            now = time.time()
            uptime = max(0.0, now - self.session_start_time)

            # Averages
            avg_up = (self._sum_upload_mbps / self._speed_samples_count) if self._speed_samples_count > 0 else 0.0
            avg_down = (self._sum_download_mbps / self._speed_samples_count) if self._speed_samples_count > 0 else 0.0

            # Top IPs sorted by packet count
            sorted_ips = sorted(self._ip_stats.values(), key=lambda x: x["packets"], reverse=True)
            top_ips = sorted_ips[:limit_ips]

            # Hourly buckets list sorted chronologically
            buckets = sorted(self._hourly_buckets.values(), key=lambda x: x["bucket_id"])

            # Best-effort process correlation from connections
            proc_map: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
                "process_name": "Unattributed / System",
                "pid": None,
                "socket_count": 0,
                "protocols": set(),
                "remote_endpoints": set(),
            })

            for c in connections:
                proc = getattr(c, "process_name", None) or "Unattributed"
                pid = getattr(c, "pid", None)
                proto = getattr(c, "protocol", "tcp")
                remote = f"{getattr(c, 'remote_ip', '')}:{getattr(c, 'remote_port', 0)}"

                key = f"{proc}:{pid}" if pid else proc
                entry = proc_map[key]
                entry["process_name"] = proc
                entry["pid"] = pid
                entry["socket_count"] += 1
                entry["protocols"].add(proto)
                if remote != ":0" and remote != "*:*":
                    entry["remote_endpoints"].add(remote)

            process_list = []
            for item in proc_map.values():
                process_list.append({
                    "process_name": item["process_name"],
                    "pid": item["pid"],
                    "socket_count": item["socket_count"],
                    "protocols": list(item["protocols"]),
                    "remote_endpoints_sample": list(item["remote_endpoints"])[:5],
                    "attribution_type": "best_effort_socket_correlation",
                })
            process_list.sort(key=lambda p: p["socket_count"], reverse=True)

            tot_sent = traffic.get("total_bytes_sent", 0)
            tot_recv = traffic.get("total_bytes_received", 0)
            tot_combined = tot_sent + tot_recv

            total_pkts = protocols.get("total_packets_captured", 0)
            avg_pps = (total_pkts / uptime) if uptime > 0 else 0.0

            return {
                "session": {
                    "start_time": self.session_start_time,
                    "uptime_seconds": round(uptime, 1),
                    "storage_policy": "IN_MEMORY_SESSION_ONLY",
                    "data_cleared_on_stop": True,
                },
                "bandwidth": {
                    "total_bytes_sent": tot_sent,
                    "total_bytes_received": tot_recv,
                    "total_bytes_combined": tot_combined,
                    "peak_upload_mbps": round(self._peak_upload_mbps, 3),
                    "peak_download_mbps": round(self._peak_download_mbps, 3),
                    "average_upload_mbps": round(avg_up, 3),
                    "average_download_mbps": round(avg_down, 3),
                    "samples_count": self._speed_samples_count,
                    "has_sufficient_samples": self._speed_samples_count >= 5,
                },
                "packets": {
                    "total_captured": total_pkts,
                    "average_packets_per_sec": round(avg_pps, 2),
                    "current_packets_per_sec": protocols.get("packets_per_sec", 0.0),
                    "dropped_packets": protocols.get("dropped_packets", 0),
                },
                "top_ips": top_ips,
                "total_tracked_ips_count": len(self._ip_stats),
                "processes": process_list[:15],
                "protocols": protocols.get("protocol_distribution", {}),
                "directions": protocols.get("direction_distribution", {}),
                "hourly_traffic": buckets,
            }

    def reset(self) -> None:
        """Purge all in-memory analytics metrics on session shutdown."""
        with self._lock:
            self._ip_stats.clear()
            self._hourly_buckets.clear()
            self._peak_upload_mbps = 0.0
            self._peak_download_mbps = 0.0
            self._speed_samples_count = 0
            self._sum_upload_mbps = 0.0
            self._sum_download_mbps = 0.0
            self.session_start_time = time.time()
