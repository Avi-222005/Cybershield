"""
Unit tests for PacketParser and packet direction inference.
"""

import unittest
from core.packet_parser import PacketParser
from models.packet_event import PacketEvent


class TestPacketParser(unittest.TestCase):

    def setUp(self):
        self.local_ips = {"192.168.1.100", "fe80::abc"}
        self.parser = PacketParser(default_interface="Wi-Fi", local_ips=self.local_ips)

    def test_direction_inference(self):
        """Test direction determination: outbound, inbound, internal, and unknown."""
        # Outbound: source is local IP, dest is remote
        self.assertEqual(
            self.parser.determine_direction("192.168.1.100", "142.250.183.14"),
            "outbound",
        )

        # Inbound: source is remote, dest is local IP
        self.assertEqual(
            self.parser.determine_direction("142.250.183.14", "192.168.1.100"),
            "inbound",
        )

        # Internal: both IPs are local
        self.assertEqual(
            self.parser.determine_direction("192.168.1.100", "fe80::abc"),
            "internal",
        )

        # Unknown: neither is recognized as local
        self.assertEqual(
            self.parser.determine_direction("8.8.8.8", "1.1.1.1"),
            "unknown",
        )

        # Missing IP
        self.assertEqual(self.parser.determine_direction(None, "8.8.8.8"), "unknown")

    def test_parse_dict_valid(self):
        """Test parsing structured dictionary into PacketEvent."""
        raw = {
            "timestamp": 1700000000.0,
            "source_ip": "192.168.1.100",
            "destination_ip": "8.8.8.8",
            "source_port": 54321,
            "destination_port": 53,
            "protocol": "DNS",
            "packet_size": 74,
        }
        event = self.parser.parse_dict(raw, interface="Wi-Fi")
        self.assertIsNotNone(event)
        self.assertEqual(event.interface, "Wi-Fi")
        self.assertEqual(event.source_ip, "192.168.1.100")
        self.assertEqual(event.destination_ip, "8.8.8.8")
        self.assertEqual(event.source_port, 54321)
        self.assertEqual(event.destination_port, 53)
        self.assertEqual(event.protocol, "DNS")
        self.assertEqual(event.packet_size, 74)
        self.assertEqual(event.direction, "outbound")
        # Ensure no payload attribute exists
        self.assertFalse(hasattr(event, "payload"))

    def test_parse_tshark_tsv_line_tcp(self):
        """Test parsing TShark TSV line for TCP packet."""
        # Columns:
        # time_epoch, frame.len, _ws.col.Protocol, ip.src, ip.dst, ipv6.src, ipv6.dst, tcp.src, tcp.dst, udp.src, udp.dst, arp.src, arp.dst
        tsv = "1700000100.123\t1460\tTCP\t142.250.183.14\t192.168.1.100\t\t\t443\t52341\t\t\t\t"
        event = self.parser.parse_tshark_tsv_line(tsv, interface="Wi-Fi")

        self.assertIsNotNone(event)
        self.assertEqual(event.timestamp, 1700000100.123)
        self.assertEqual(event.packet_size, 1460)
        self.assertEqual(event.protocol, "TCP")
        self.assertEqual(event.source_ip, "142.250.183.14")
        self.assertEqual(event.destination_ip, "192.168.1.100")
        self.assertEqual(event.source_port, 443)
        self.assertEqual(event.destination_port, 52341)
        self.assertEqual(event.direction, "inbound")

    def test_parse_tshark_tsv_line_arp(self):
        """Test parsing ARP frame where transport ports and IP headers are absent."""
        tsv = "1700000200.0\t42\tARP\t\t\t\t\t\t\t\t\t192.168.1.1\t192.168.1.100"
        event = self.parser.parse_tshark_tsv_line(tsv, interface="Wi-Fi")

        self.assertIsNotNone(event)
        self.assertEqual(event.protocol, "ARP")
        self.assertEqual(event.source_ip, "192.168.1.1")
        self.assertEqual(event.destination_ip, "192.168.1.100")
        self.assertIsNone(event.source_port)
        self.assertIsNone(event.destination_port)
        self.assertEqual(event.direction, "inbound")

    def test_parse_malformed_input(self):
        """Test parser handles corrupt or truncated lines gracefully without throwing."""
        self.assertIsNone(self.parser.parse_tshark_tsv_line("", "Wi-Fi"))
        self.assertIsNone(self.parser.parse_tshark_tsv_line("invalid\tdata", "Wi-Fi"))


if __name__ == "__main__":
    unittest.main()
