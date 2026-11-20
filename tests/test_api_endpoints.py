"""
API endpoint integration tests for CyberShield Exposure Intelligence Engine.
Tests:
- POST /api/exposure/scan
- POST /api/exposure/graph
- GET /api/exposure/assets/<target>
- GET /api/exposure/history/<target>
- POST /api/exposure/compare
- GET /api/exposure/vulnerabilities/<target>
- GET /api/exposure/remediation/<target>
"""

import json
import unittest
from unittest.mock import patch

from app import app, db, ExposureSnapshot


class TestExposureAPIEndpoints(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        self.app_context = app.app_context()
        self.app_context.push()

    def tearDown(self):
        self.app_context.pop()

    @patch("services.unified_recon_service.unified_recon_scan")
    def test_exposure_scan_and_history(self, mock_recon):
        # Mocking unified_recon_scan to avoid long network calls in automated testing
        mock_recon.return_value = {
            "target": "example.com",
            "overall_score": 35,
            "risk_score": 35,
            "grade": "B",
            "grade_label": "Good",
            "risk_level": "Good",
            "modules": {
                "dns": {
                    "ok": True,
                    "data": {
                        "a": {"records": ["93.184.216.34"]},
                        "spf": {"records": ["v=spf1 -all"]},
                        "dmarc": {"records": ["v=DMARC1; p=reject;"]},
                    }
                },
                "ports": {
                    "ok": True,
                    "data": {
                        "open_ports": [80, 443],
                        "services": [{"port": 80, "service": "http", "banner": "Apache/2.4.49"}],
                    }
                },
                "tech": {
                    "ok": True,
                    "data": {
                        "detected": [
                            {"name": "Apache HTTP Server", "version": "2.4.49", "confidence": 95, "categories": ["Web Server"]}
                        ]
                    }
                },
                "headers": {
                    "ok": True,
                    "data": {
                        "server": "Apache/2.4.49",
                        "missing_headers": ["Content-Security-Policy"],
                    }
                },
                "ssl": {
                    "ok": True,
                    "data": {
                        "valid": True,
                        "issuer": "DigiCert Global Root CA",
                        "days_left": 120,
                    }
                }
            }
        }

        # 1. Test POST /api/exposure/scan
        resp = self.client.post(
            "/api/exposure/scan",
            data=json.dumps({"target": "example.com", "scan_mode": "quick"}),
            content_type="application/json"
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("exposure_score", data)
        self.assertIn("score_breakdown", data)
        self.assertIn("assets", data)
        self.assertIn("exposures", data)
        self.assertIn("graph", data)
        self.assertIn("remediation_plan", data)

        # 2. Test GET /api/exposure/history/example.com
        hist_resp = self.client.get("/api/exposure/history/example.com")
        self.assertEqual(hist_resp.status_code, 200)
        hist_data = hist_resp.get_json()
        self.assertIn("history", hist_data)
        self.assertTrue(len(hist_data["history"]) >= 1)

        # 3. Test GET /api/exposure/assets/example.com
        assets_resp = self.client.get("/api/exposure/assets/example.com")
        self.assertEqual(assets_resp.status_code, 200)
        assets_data = assets_resp.get_json()
        self.assertIn("assets", assets_data)

        # 4. Test GET /api/exposure/vulnerabilities/example.com
        vulns_resp = self.client.get("/api/exposure/vulnerabilities/example.com")
        self.assertEqual(vulns_resp.status_code, 200)
        vulns_data = vulns_resp.get_json()
        self.assertIn("vulnerabilities", vulns_data)

        # 5. Test GET /api/exposure/remediation/example.com
        rem_resp = self.client.get("/api/exposure/remediation/example.com")
        self.assertEqual(rem_resp.status_code, 200)
        rem_data = rem_resp.get_json()
        self.assertIn("remediation_plan", rem_data)

        # 6. Test POST /api/exposure/graph
        graph_resp = self.client.post(
            "/api/exposure/graph",
            data=json.dumps({"target": "example.com"}),
            content_type="application/json"
        )
        self.assertEqual(graph_resp.status_code, 200)
        graph_data = graph_resp.get_json()
        self.assertIn("nodes", graph_data)
        self.assertIn("edges", graph_data)

        # 7. Test POST /api/exposure/compare
        comp_resp = self.client.post(
            "/api/exposure/compare",
            data=json.dumps({"target": "example.com"}),
            content_type="application/json"
        )
        self.assertEqual(comp_resp.status_code, 200)


if __name__ == "__main__":
    unittest.main()
