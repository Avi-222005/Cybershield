"""
Unit tests for ConnectionMonitor.
"""

import unittest
from unittest.mock import patch, MagicMock
from collections import namedtuple
import socket
import psutil

from core.connection_monitor import ConnectionMonitor

saddr = namedtuple("saddr", ["ip", "port"])
sconn = namedtuple("sconn", ["fd", "family", "type", "laddr", "raddr", "status", "pid"])


class TestConnectionMonitor(unittest.TestCase):

    def setUp(self):
        self.monitor = ConnectionMonitor(cache_ttl_seconds=10.0)

    @patch("psutil.net_connections")
    @patch("psutil.Process")
    def test_connection_parsing_and_process_attribution(self, mock_process_cls, mock_net_conns):
        """Verify active connection retrieval, protocol identification, and PID resolution."""
        mock_proc_instance = MagicMock()
        mock_proc_instance.name.return_value = "chrome.exe"
        mock_process_cls.return_value = mock_proc_instance

        mock_net_conns.return_value = [
            sconn(
                fd=1,
                family=2,  # AF_INET
                type=socket.SOCK_STREAM,
                laddr=saddr("192.168.1.100", 52341),
                raddr=saddr("142.250.183.14", 443),
                status="ESTABLISHED",
                pid=4321,
            ),
            sconn(
                fd=2,
                family=2,
                type=socket.SOCK_STREAM,
                laddr=saddr("0.0.0.0", 8080),
                raddr=None,  # Listen socket has no remote endpoint
                status="LISTEN",
                pid=1234,
            ),
        ]

        conns = self.monitor.get_active_connections()
        self.assertEqual(len(conns), 2)

        tcp_conn = conns[0]
        self.assertEqual(tcp_conn.local_ip, "192.168.1.100")
        self.assertEqual(tcp_conn.local_port, 52341)
        self.assertEqual(tcp_conn.remote_ip, "142.250.183.14")
        self.assertEqual(tcp_conn.remote_port, 443)
        self.assertEqual(tcp_conn.protocol, "tcp")
        self.assertEqual(tcp_conn.status, "ESTABLISHED")
        self.assertEqual(tcp_conn.pid, 4321)
        self.assertEqual(tcp_conn.process_name, "chrome.exe")

        listen_conn = conns[1]
        self.assertEqual(listen_conn.remote_ip, "")
        self.assertEqual(listen_conn.remote_port, 0)
        self.assertEqual(listen_conn.status, "LISTEN")

    @patch("psutil.Process")
    def test_process_name_caching(self, mock_process_cls):
        """Verify PID resolution uses in-memory cache to avoid repeated system calls."""
        mock_p = MagicMock()
        mock_p.name.return_value = "python.exe"
        mock_process_cls.return_value = mock_p

        # First resolution calls psutil.Process
        name1 = self.monitor.get_connection_process(9999)
        self.assertEqual(name1, "python.exe")
        self.assertEqual(mock_process_cls.call_count, 1)

        # Second resolution should hit cache and NOT invoke psutil.Process
        name2 = self.monitor.get_connection_process(9999)
        self.assertEqual(name2, "python.exe")
        self.assertEqual(mock_process_cls.call_count, 1)

    @patch("psutil.Process")
    def test_process_access_denied_handling(self, mock_process_cls):
        """Verify AccessDenied or NoSuchProcess returns None gracefully without raising."""
        mock_process_cls.side_effect = psutil.AccessDenied(pid=1)
        name = self.monitor.get_connection_process(1)
        self.assertIsNone(name)

    @patch("psutil.net_connections")
    def test_permission_denied_on_net_connections(self, mock_net_conns):
        """Verify net_connections permission denial returns empty list gracefully."""
        mock_net_conns.side_effect = psutil.AccessDenied()
        conns = self.monitor.get_active_connections()
        self.assertEqual(conns, [])


if __name__ == "__main__":
    unittest.main()
