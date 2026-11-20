"""
Unit tests for InterfaceManager.
"""

import socket
import unittest
from unittest.mock import patch, MagicMock
from collections import namedtuple

from core.interface_manager import InterfaceManager

snicaddr = namedtuple("snicaddr", ["family", "address", "netmask", "broadcast", "ptp"])
snicstats = namedtuple("snicstats", ["isup", "duplex", "speed", "mtu", "flags"])


class TestInterfaceManager(unittest.TestCase):

    def setUp(self):
        self.mgr = InterfaceManager()

    def test_live_interface_enumeration(self):
        """Verify real system enumeration returns valid interface mappings."""
        ifaces = self.mgr.get_all_interfaces()
        self.assertIsInstance(ifaces, dict)
        self.assertGreater(len(ifaces), 0, "Should detect at least one network adapter on host")

        for name, details in ifaces.items():
            self.assertIn("name", details)
            self.assertIn("is_up", details)
            self.assertIn("ipv4", details)
            self.assertIn("ipv6", details)
            self.assertIn("has_ip", details)

    def test_get_default_interface(self):
        """Verify default interface selection returns an active or existing interface."""
        default_iface = self.mgr.get_default_interface()
        self.assertIsNotNone(default_iface)
        all_ifaces = self.mgr.get_all_interfaces()
        self.assertIn(default_iface, all_ifaces)

    @patch("psutil.net_if_addrs")
    @patch("psutil.net_if_stats")
    def test_mocked_interface_detection(self, mock_stats, mock_addrs):
        """Test parsing of varied interfaces: Wi-Fi (active), Ethernet (down), Virtual (no IP)."""
        mock_addrs.return_value = {
            "Wi-Fi": [
                snicaddr(socket.AF_INET, "192.168.1.50", "255.255.255.0", None, None),
                snicaddr(socket.AF_INET6, "fe80::100%12", None, None, None),
            ],
            "Ethernet": [
                snicaddr(socket.AF_INET, "10.0.0.5", "255.255.255.0", None, None),
            ],
            "vEthernet": [],
        }

        mock_stats.return_value = {
            "Wi-Fi": snicstats(isup=True, duplex=0, speed=100, mtu=1500, flags=""),
            "Ethernet": snicstats(isup=False, duplex=0, speed=0, mtu=1500, flags=""),
            "vEthernet": snicstats(isup=False, duplex=0, speed=0, mtu=1500, flags=""),
        }

        mgr = InterfaceManager()
        all_ifaces = mgr.get_all_interfaces()
        self.assertEqual(len(all_ifaces), 3)

        # Wi-Fi should be active and up
        self.assertTrue(all_ifaces["Wi-Fi"]["is_up"])
        self.assertIn("192.168.1.50", all_ifaces["Wi-Fi"]["ipv4"])
        self.assertIn("fe80::100", all_ifaces["Wi-Fi"]["ipv6"])

        # Active filter should only return Wi-Fi
        active = mgr.get_active_interfaces()
        self.assertIn("Wi-Fi", active)
        self.assertNotIn("Ethernet", active)
        self.assertNotIn("vEthernet", active)

        # Local IPs test
        ips = mgr.get_interface_ips("Wi-Fi")
        self.assertIn("192.168.1.50", ips)
        self.assertIn("fe80::100", ips)


if __name__ == "__main__":
    unittest.main()
