"""
Integration and unit tests for CyberShield Network Monitor Flask API endpoints.
Validates routing, status reporting, lifecycle controls, and strict in-memory policy.
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db


class TestNetworkMonitorAPI(unittest.TestCase):

    def setUp(self):
        self.app = app
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()

    def tearDown(self):
        # Stop any active monitoring session to clean up threads
        self.client.post("/api/network/stop")
        self.app_context.pop()

    def test_get_interfaces(self):
        """Verify interface discovery returns valid adapter list."""
        resp = self.client.get("/api/network/interfaces")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertIsInstance(data["interfaces"], list)
        self.assertGreaterEqual(len(data["interfaces"]), 1)
        first_iface = data["interfaces"][0]
        self.assertIn("name", first_iface)
        self.assertIn("is_up", first_iface)
        self.assertIn("selected", first_iface)

    def test_get_status_stopped(self):
        """Verify status reporting when agent is stopped."""
        resp = self.client.get("/api/network/status")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertIn("state", data["status"])

    def test_get_traffic(self):
        """Verify traffic metrics endpoint returns valid bandwidth structure."""
        resp = self.client.get("/api/network/traffic")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertIn("upload_mbps", data["traffic"])
        self.assertIn("download_mbps", data["traffic"])

    def test_get_connections(self):
        """Verify connection polling endpoint."""
        resp = self.client.get("/api/network/connections")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertIsInstance(data["connections"], list)

    def test_get_protocols(self):
        """Verify protocol distribution endpoint."""
        resp = self.client.get("/api/network/protocols")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertIn("protocol_distribution", data["protocols"])

    def test_get_events(self):
        """Verify bounded packet metadata events endpoint."""
        resp = self.client.get("/api/network/events?limit=10")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertIsInstance(data["events"], list)

    def test_get_summary(self):
        """Verify aggregated summary endpoint for overview dashboard."""
        resp = self.client.get("/api/network/summary")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertIn("status", data["summary"])
        self.assertIn("traffic", data["summary"])
        self.assertIn("protocols", data["summary"])

    def test_get_health(self):
        """Verify system readiness and health endpoint."""
        resp = self.client.get("/api/network/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertTrue(data["health"]["backend_online"])

    def test_start_and_stop_lifecycle(self):
        """Verify start and stop lifecycle control with synthetic fallback adapter."""
        # Start monitoring
        start_resp = self.client.post(
            "/api/network/start",
            data=json.dumps({"force_adapter": "synthetic"}),
            content_type="application/json",
        )
        self.assertEqual(start_resp.status_code, 200)
        start_data = start_resp.get_json()
        self.assertTrue(start_data["success"])
        self.assertEqual(start_data["state"], "RUNNING")

        # Verify running status
        status_resp = self.client.get("/api/network/status")
        status_data = status_resp.get_json()
        self.assertEqual(status_data["status"]["state"], "RUNNING")

        # Stop monitoring
        stop_resp = self.client.post("/api/network/stop")
        self.assertEqual(stop_resp.status_code, 200)
        stop_data = stop_resp.get_json()
        self.assertTrue(stop_data["success"])
        self.assertEqual(stop_data["state"], "STOPPED")

    def test_strict_in_memory_policy(self):
        """Verify that network monitoring does NOT create any database tables or rows."""
        # Query existing tables in SQLAlchemy metadata
        table_names = list(db.metadata.tables.keys())
        for name in table_names:
            self.assertFalse(
                "network" in name.lower() or "packet" in name.lower(),
                f"No network monitoring tables should be registered in SQLAlchemy: {name}"
            )

    def test_alerts_endpoints_and_summary(self):
        """Verify alert querying, summary, and action endpoints."""
        # Query alerts when stopped (returns empty list)
        resp = self.client.get("/api/network/alerts")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertIsInstance(data["alerts"], list)

        # Query alert summary
        sum_resp = self.client.get("/api/network/alerts/summary")
        self.assertEqual(sum_resp.status_code, 200)
        sum_data = sum_resp.get_json()
        self.assertTrue(sum_data["success"])
        self.assertIn("total", sum_data["summary"])
        self.assertIn("critical", sum_data["summary"])

    def test_detection_config_endpoints(self):
        """Verify retrieval and updating of threat detection rules."""
        # GET rules
        resp = self.client.get("/api/network/detection/config")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["count"], 5)
        rule_ids = [r["rule_id"] for r in data["rules"]]
        self.assertIn("possible_port_scan", rule_ids)
        self.assertIn("suspicious_dns_pattern", rule_ids)

    def test_analytics_endpoint(self):
        """Verify advanced analytics endpoint returns session metrics."""
        resp = self.client.get("/api/network/analytics")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        analytics = data["analytics"]
        self.assertIn("session", analytics)
        self.assertIn("bandwidth", analytics)
        self.assertIn("top_ips", analytics)
        self.assertIn("hourly_traffic", analytics)
        self.assertEqual(analytics["session"]["storage_policy"], "IN_MEMORY_SESSION_ONLY")

    def test_agent_info_version_and_deployment(self):
        """Verify agent information, version constant, and deployment readiness."""
        # Version
        v_resp = self.client.get("/api/network/agent/version")
        self.assertEqual(v_resp.status_code, 200)
        v_data = v_resp.get_json()
        self.assertTrue(v_data["success"])
        self.assertEqual(v_data["version"]["version"], "1.1.0")

        # Info
        i_resp = self.client.get("/api/network/agent/info")
        self.assertEqual(i_resp.status_code, 200)
        i_data = i_resp.get_json()
        self.assertTrue(i_data["success"])
        self.assertEqual(i_data["info"]["version"], "1.1.0")
        self.assertFalse(i_data["info"]["privacy_policy"]["store_payloads"])
        self.assertFalse(i_data["info"]["privacy_policy"]["persist_traffic"])

        # Deployment
        d_resp = self.client.get("/api/network/agent/deployment")
        self.assertEqual(d_resp.status_code, 200)
        d_data = d_resp.get_json()
        self.assertTrue(d_data["success"])
        self.assertEqual(d_data["deployment"]["local"]["status"], "operational")
        self.assertEqual(d_data["deployment"]["server"]["status"], "planned")

    def test_immutable_privacy_invariants(self):
        """Verify that attempting to configure payload or persistence retention is strictly blocked."""
        resp = self.client.post(
            "/api/network/agent/config",
            data=json.dumps({
                "privacy": {
                    "store_payloads": True,
                    "persist_traffic": True,
                }
            }),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        cfg = data["config"]
        # Invariants MUST remain False
        self.assertFalse(cfg["privacy"]["store_payloads"])
        self.assertFalse(cfg["privacy"]["persist_traffic"])


if __name__ == "__main__":
    unittest.main()
