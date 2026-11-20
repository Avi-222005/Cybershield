"""
Unit tests for AgentController lifecycle and error resilience.
"""

import time
import unittest
from agent.controller import AgentController


class TestAgentController(unittest.TestCase):

    def test_controller_lifecycle_synthetic(self):
        """
        Verify complete controller lifecycle:
        INITIALIZING -> RUNNING -> STOPPING -> STOPPED
        using synthetic packet generation.
        """
        overrides = {
            "monitoring": {
                "force_adapter": "synthetic",
                "capture_packets": True,
                "monitor_bandwidth": True,
                "monitor_connections": True,
            },
            "intervals": {
                "bandwidth": 0.5,
                "connections": 0.5,
                "aggregation": 0.5,
                "health_check": 1.0,
            },
        }

        controller = AgentController(overrides)
        self.assertEqual(controller.state, "STOPPED")

        started = controller.start()
        self.assertTrue(started, "AgentController should start successfully")
        self.assertEqual(controller.state, "RUNNING")

        # Let worker threads run for 1.5 seconds
        time.sleep(1.5)

        # Verify status report
        status = controller.get_status()
        self.assertEqual(status.state, "RUNNING")
        self.assertGreater(status.uptime_seconds, 0)
        self.assertIsNotNone(status.monitored_interface)

        # Check packet capture received simulated events
        self.assertGreater(status.capture.total_packets_captured, 0)

        # Stop controller gracefully
        stop_start = time.time()
        controller.stop()
        stop_duration = time.time() - stop_start

        self.assertEqual(controller.state, "STOPPED")
        self.assertLess(stop_duration, 5.0, "Shutdown must complete within 5.0 seconds")
        self.assertEqual(len(controller.data_manager.packet_events), 0, "In-memory buffers must be cleared")

    def test_independent_component_resilience(self):
        """
        Verify that a failure in one component does not stop the entire agent.
        """
        controller = AgentController({
            "monitoring": {
                "capture_packets": False,  # disabled packet capture
                "monitor_connections": False,
                "monitor_bandwidth": True,
            }
        })
        self.assertTrue(controller.start())
        self.assertEqual(controller.component_health["packet_capture"].status, "DISABLED")
        self.assertEqual(controller.component_health["bandwidth_monitor"].status, "HEALTHY")
        controller.stop()


if __name__ == "__main__":
    unittest.main()
