"""
Unit tests for In-Memory DataManager.
"""

import unittest
import threading
import time

from core.data_manager import DataManager
from models.packet_event import PacketEvent
from models.connection import Connection


class TestDataManager(unittest.TestCase):

    def setUp(self):
        self.dm = DataManager(max_packet_events=100, max_connections=50, max_alerts=20)

    def test_bounded_packet_ring_buffer(self):
        """Ensure inserting more than max_packet_events drops oldest and never overflows."""
        for i in range(150):
            event = PacketEvent(
                timestamp=time.time(),
                interface="Wi-Fi",
                source_ip="192.168.1.10",
                destination_ip="8.8.8.8",
                source_port=1000 + i,
                destination_port=53,
                protocol="DNS" if i % 2 == 0 else "TCP",
                packet_size=100,
                direction="outbound",
            )
            self.dm.add_packet(event)

        self.assertEqual(len(self.dm.packet_events), 100, "Buffer size must not exceed maxlen=100")
        # Oldest events should have been dropped; newest should remain
        newest = self.dm.get_recent_packets(1)[0]
        self.assertEqual(newest.source_port, 1000 + 149)

    def test_protocol_and_direction_aggregation(self):
        """Verify protocol breakdown and direction counters update correctly."""
        p1 = PacketEvent(timestamp=time.time(), interface="Wi-Fi", source_ip="1.1.1.1", destination_ip="1.1.1.2", source_port=80, destination_port=80, protocol="TCP", packet_size=50, direction="inbound")
        p2 = PacketEvent(timestamp=time.time(), interface="Wi-Fi", source_ip="1.1.1.1", destination_ip="1.1.1.2", source_port=80, destination_port=80, protocol="TCP", packet_size=50, direction="outbound")
        p3 = PacketEvent(timestamp=time.time(), interface="Wi-Fi", source_ip="1.1.1.1", destination_ip="1.1.1.2", source_port=53, destination_port=53, protocol="UDP", packet_size=60, direction="inbound")

        self.dm.add_packet(p1)
        self.dm.add_packet(p2)
        self.dm.add_packet(p3)

        self.assertEqual(self.dm.protocol_stats.get("TCP"), 2)
        self.assertEqual(self.dm.protocol_stats.get("UDP"), 1)
        self.assertEqual(self.dm.direction_stats.get("inbound"), 2)
        self.assertEqual(self.dm.direction_stats.get("outbound"), 1)

    def test_concurrent_writes(self):
        """Test thread safety under multi-threaded simultaneous insertions."""
        def worker(thread_id: int):
            for i in range(50):
                ev = PacketEvent(
                    timestamp=time.time(),
                    interface="Wi-Fi",
                    source_ip=f"10.0.0.{thread_id}",
                    destination_ip="8.8.8.8",
                    source_port=2000 + i,
                    destination_port=443,
                    protocol="TLS",
                    packet_size=200,
                    direction="outbound",
                )
                self.dm.add_packet(ev)

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Total added = 250, buffer cap = 100
        self.assertEqual(len(self.dm.packet_events), 100)
        self.assertEqual(self.dm._total_packets_captured, 250)

    def test_clear_all_zero_retention(self):
        """Verify clear_all purges all buffers and resets metrics on shutdown."""
        ev = PacketEvent(timestamp=time.time(), interface="Wi-Fi", source_ip="1.1.1.1", destination_ip="2.2.2.2", source_port=80, destination_port=80, protocol="HTTP", packet_size=100, direction="outbound")
        self.dm.add_packet(ev)
        self.dm.update_connections([Connection(local_ip="1.1.1.1", local_port=80, remote_ip="2.2.2.2", remote_port=80, protocol="tcp", status="ESTABLISHED")])

        self.dm.clear_all()
        self.assertEqual(len(self.dm.packet_events), 0)
        self.assertEqual(len(self.dm.connections), 0)
        self.assertEqual(self.dm._total_packets_captured, 0)
        self.assertEqual(len(self.dm.protocol_stats), 0)


if __name__ == "__main__":
    unittest.main()
