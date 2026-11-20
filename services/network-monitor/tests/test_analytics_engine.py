"""
Unit tests for CyberShield Analytics Engine.
Verifies incremental IP aggregation, hourly time-bucketing, speed averages/peaks,
and best-effort process correlation from socket connections.
"""

import time
import unittest
from core.analytics_engine import AnalyticsEngine
from models.packet_event import PacketEvent
from models.connection import Connection


class TestAnalyticsEngine(unittest.TestCase):

    def setUp(self):
        self.engine = AnalyticsEngine(max_tracked_ips=50, max_hourly_buckets=24)
        self.engine.start_session()

    def test_record_packet_ip_aggregation(self):
        """Verify incremental IP counters track packets, bytes, and directions."""
        now = time.time()
        p1 = PacketEvent(
            timestamp=now,
            interface="eth0",
            source_ip="192.168.1.10",
            destination_ip="93.184.216.34",
            source_port=49152,
            destination_port=443,
            protocol="TCP",
            packet_size=1024,
            direction="outbound",
        )
        self.engine.record_packet(p1)

        p2 = PacketEvent(
            timestamp=now + 1.0,
            interface="eth0",
            source_ip="93.184.216.34",
            destination_ip="192.168.1.10",
            source_port=443,
            destination_port=49152,
            protocol="TCP",
            packet_size=2048,
            direction="inbound",
        )
        self.engine.record_packet(p2)

        analytics = self.engine.get_analytics(
            connections=[],
            traffic={"total_bytes_sent": 1024, "total_bytes_received": 2048},
            protocols={"total_packets_captured": 2, "packets_per_sec": 1.0},
        )

        top_ips = analytics["top_ips"]
        self.assertEqual(len(top_ips), 2)
        # Both IPs have 2 total interactions in session
        for item in top_ips:
            self.assertIn(item["ip"], ["192.168.1.10", "93.184.216.34"])
            self.assertEqual(item["packets"], 2)
            self.assertEqual(item["bytes"], 3072)

    def test_hourly_time_bucketing(self):
        """Verify hourly buckets are created and incremented chronologically."""
        now = time.time()
        p = PacketEvent(
            timestamp=now,
            interface="eth0",
            source_ip="10.0.0.1",
            destination_ip="10.0.0.2",
            source_port=1234,
            destination_port=80,
            protocol="TCP",
            packet_size=500,
            direction="outbound",
        )
        self.engine.record_packet(p)

        analytics = self.engine.get_analytics(
            connections=[],
            traffic={},
            protocols={},
        )
        buckets = analytics["hourly_traffic"]
        self.assertGreaterEqual(len(buckets), 1)
        self.assertEqual(buckets[0]["bucket_id"], 1)
        self.assertEqual(buckets[0]["packets"], 1)
        self.assertEqual(buckets[0]["upload_bytes"], 500)

    def test_speed_samples_peaks_and_averages(self):
        """Verify speed samples track peaks and compute rolling arithmetic mean."""
        self.engine.record_bandwidth_sample(upload_mbps=5.0, download_mbps=20.0)
        self.engine.record_bandwidth_sample(upload_mbps=15.0, download_mbps=10.0)

        analytics = self.engine.get_analytics(
            connections=[],
            traffic={},
            protocols={},
        )
        bw = analytics["bandwidth"]
        self.assertEqual(bw["peak_upload_mbps"], 15.0)
        self.assertEqual(bw["peak_download_mbps"], 20.0)
        self.assertEqual(bw["average_upload_mbps"], 10.0)
        self.assertEqual(bw["average_download_mbps"], 15.0)
        self.assertEqual(bw["samples_count"], 2)

    def test_process_attribution(self):
        """Verify best-effort process correlation from socket connection snapshot."""
        conns = [
            Connection(
                local_ip="127.0.0.1",
                local_port=5000,
                remote_ip="0.0.0.0",
                remote_port=0,
                protocol="tcp",
                status="LISTEN",
                pid=9999,
                process_name="python.exe",
            ),
            Connection(
                local_ip="192.168.1.5",
                local_port=52000,
                remote_ip="142.250.190.46",
                remote_port=443,
                protocol="tcp",
                status="ESTABLISHED",
                pid=9999,
                process_name="python.exe",
            ),
        ]

        analytics = self.engine.get_analytics(
            connections=conns,
            traffic={},
            protocols={},
        )
        processes = analytics["processes"]
        self.assertEqual(len(processes), 1)
        p = processes[0]
        self.assertEqual(p["process_name"], "python.exe")
        self.assertEqual(p["pid"], 9999)
        self.assertEqual(p["socket_count"], 2)
        self.assertEqual(p["attribution_type"], "best_effort_socket_correlation")

    def test_reset_purges_all_state(self):
        """Verify reset() empties all telemetry data structures."""
        self.engine.record_packet(
            PacketEvent(
                timestamp=time.time(),
                interface="eth0",
                source_ip="1.1.1.1",
                destination_ip="2.2.2.2",
                source_port=100,
                destination_port=200,
                protocol="TCP",
                packet_size=100,
                direction="outbound",
            )
        )
        self.engine.reset()
        analytics = self.engine.get_analytics(connections=[], traffic={}, protocols={})
        self.assertEqual(len(analytics["top_ips"]), 0)
        self.assertEqual(len(analytics["hourly_traffic"]), 0)


if __name__ == "__main__":
    unittest.main()
