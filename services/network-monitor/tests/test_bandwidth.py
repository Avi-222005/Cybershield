"""
Unit tests for BandwidthMonitor.
"""

import time
import unittest
from unittest.mock import patch
from collections import namedtuple

from core.bandwidth_monitor import BandwidthMonitor

snetio = namedtuple("snetio", ["bytes_sent", "bytes_recv", "packets_sent", "packets_recv", "errin", "errout", "dropin", "dropout"])


class TestBandwidthMonitor(unittest.TestCase):

    def setUp(self):
        self.monitor = BandwidthMonitor(interface="Wi-Fi")

    @patch("psutil.net_io_counters")
    def test_initial_baseline_no_spike(self, mock_counters):
        """Verify the first measurement establishes a baseline and reports 0.0 Mbps."""
        mock_counters.return_value = {
            "Wi-Fi": snetio(
                bytes_sent=10_000_000,
                bytes_recv=20_000_000,
                packets_sent=5000,
                packets_recv=10000,
                errin=0, errout=0, dropin=0, dropout=0,
            )
        }

        stats = self.monitor.update("Wi-Fi")
        self.assertIsNotNone(stats)
        self.assertEqual(stats.upload_bytes_per_sec, 0.0)
        self.assertEqual(stats.download_bytes_per_sec, 0.0)
        self.assertEqual(stats.upload_mbps, 0.0)
        self.assertEqual(stats.download_mbps, 0.0)
        self.assertEqual(stats.total_bytes_sent, 10_000_000)
        self.assertEqual(stats.total_bytes_received, 20_000_000)

    @patch("psutil.net_io_counters")
    def test_speed_calculation(self, mock_counters):
        """Verify correct delta calculations for bytes per second and Mbps."""
        # 1. First sample at t = 0
        mock_counters.return_value = {
            "Wi-Fi": snetio(bytes_sent=1_000_000, bytes_recv=2_000_000, packets_sent=100, packets_recv=200, errin=0, errout=0, dropin=0, dropout=0)
        }
        self.monitor.update("Wi-Fi")

        # 2. Second sample exactly 1.0 second later
        # Transferred: 125,000 bytes sent (1,000,000 bits = 1.0 Mbps)
        # Transferred: 250,000 bytes recv (2,000,000 bits = 2.0 Mbps)
        with patch("time.time") as mock_time:
            # Set baseline time
            self.monitor._previous_time["Wi-Fi"] = 1000.0
            mock_time.return_value = 1001.0  # Exactly 1.0 second delta

            mock_counters.return_value = {
                "Wi-Fi": snetio(
                    bytes_sent=1_000_000 + 125_000,
                    bytes_recv=2_000_000 + 250_000,
                    packets_sent=100 + 50,
                    packets_recv=200 + 100,
                    errin=0, errout=0, dropin=0, dropout=0,
                )
            }

            stats = self.monitor.update("Wi-Fi")
            self.assertIsNotNone(stats)
            self.assertAlmostEqual(stats.upload_bytes_per_sec, 125_000.0, places=1)
            self.assertAlmostEqual(stats.download_bytes_per_sec, 250_000.0, places=1)
            # Mbps = (125000 * 8) / 1,000,000 = 1.00000 Mbps
            self.assertAlmostEqual(stats.upload_mbps, 1.0, places=4)
            # Mbps = (250000 * 8) / 1,000,000 = 2.00000 Mbps
            self.assertAlmostEqual(stats.download_mbps, 2.0, places=4)
            self.assertEqual(stats.packets_sent_per_sec, 50.0)
            self.assertEqual(stats.packets_recv_per_sec, 100.0)

    def test_live_interface_update(self):
        """Test on actual host interfaces without mocking."""
        from core.interface_manager import InterfaceManager
        im = InterfaceManager()
        iface = im.get_default_interface()
        if iface:
            stats = self.monitor.update(iface)
            self.assertIsNotNone(stats)
            self.assertEqual(stats.interface, iface)


if __name__ == "__main__":
    unittest.main()
