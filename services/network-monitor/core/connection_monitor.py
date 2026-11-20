"""
Connection Monitor for CyberShield Network Monitor.
Tracks active network sockets, connection states, and resolves process attribution
using psutil with intelligent caching to avoid redundant lookups.
"""

import time
import socket
import threading
import psutil
from typing import List, Dict, Optional, Tuple
from models.connection import Connection
from utils.logger import logger


class ConnectionMonitor:
    """
    Polls active TCP and UDP sockets from the operating system,
    associating sockets with process IDs and process executable names.
    """

    def __init__(self, cache_ttl_seconds: float = 30.0):
        self.cache_ttl = cache_ttl_seconds
        self._lock = threading.Lock()
        # PID -> (process_name, last_resolved_timestamp)
        self._process_cache: Dict[int, Tuple[str, float]] = {}
        self._latest_connections: List[Connection] = []

    def get_connection_process(self, pid: Optional[int]) -> Optional[str]:
        """
        Resolve process name for a given PID with caching to minimize system call overhead.
        Handles AccessDenied, NoSuchProcess, and terminated processes gracefully.
        """
        if pid is None or pid <= 0:
            return None

        now = time.time()
        with self._lock:
            cached = self._process_cache.get(pid)
            if cached and (now - cached[1]) < self.cache_ttl:
                return cached[0]

        # Resolve outside lock to avoid contention
        process_name = None
        try:
            p = psutil.Process(pid)
            process_name = p.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            process_name = None
        except Exception:
            process_name = None

        if process_name:
            with self._lock:
                self._process_cache[pid] = (process_name, now)
        else:
            with self._lock:
                # Invalidate if process died
                self._process_cache.pop(pid, None)

        return process_name

    def get_active_connections(self) -> List[Connection]:
        """
        Retrieve snapshot of all current active internet sockets (TCP/UDP).
        Best-effort process name attribution.
        """
        connections: List[Connection] = []

        try:
            # kind='inet' queries IPv4 and IPv6 TCP and UDP sockets
            raw_conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError) as e:
            logger.debug(f"Permission denied while reading net_connections: {e}")
            return []
        except Exception as e:
            logger.debug(f"Error querying net_connections: {e}")
            return []

        for conn in raw_conns:
            # Sockets can be SOCK_STREAM (TCP) or SOCK_DGRAM (UDP)
            proto = "tcp" if conn.type == socket.SOCK_STREAM else "udp"
            status = conn.status if conn.status else "NONE"

            local_ip = conn.laddr.ip if conn.laddr else ""
            local_port = conn.laddr.port if conn.laddr else 0

            # Remote address may be empty (e.g. LISTEN sockets or unbound UDP)
            remote_ip = conn.raddr.ip if conn.raddr else ""
            remote_port = conn.raddr.port if conn.raddr else 0

            pid = conn.pid
            proc_name = self.get_connection_process(pid) if pid else None

            connections.append(
                Connection(
                    local_ip=local_ip,
                    local_port=local_port,
                    remote_ip=remote_ip,
                    remote_port=remote_port,
                    protocol=proto,
                    status=status,
                    pid=pid,
                    process_name=proc_name,
                )
            )

        with self._lock:
            self._latest_connections = connections

        return connections

    def get_connection_details(self, key: str) -> Optional[Connection]:
        """Find a specific connection by key from the most recent snapshot."""
        with self._lock:
            for conn in self._latest_connections:
                if conn.key == key:
                    return conn
        return None

    def get_latest_snapshot(self) -> List[Connection]:
        """Return the most recently fetched connections without triggering a re-poll."""
        with self._lock:
            return list(self._latest_connections)

    def clean_cache(self) -> None:
        """Prune expired PID cache entries."""
        now = time.time()
        with self._lock:
            expired = [pid for pid, (_, ts) in self._process_cache.items() if (now - ts) > self.cache_ttl]
            for pid in expired:
                del self._process_cache[pid]
