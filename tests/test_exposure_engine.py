"""
Unit tests for CyberShield Exposure Intelligence Engine.
Tests all 14 required dimensions:
1. Asset normalization
2. Technology normalization
3. Version parsing
4. CVE matching
5. KEV matching
6. EPSS processing
7. Exposure correlation
8. Score calculation
9. Score guardrails
10. Change detection
11. Graph generation
12. Partial API failure
13. Duplicate assets
14. Unknown versions
"""

import unittest
from services.exposure_engine.normalizer import (
    normalize_hostname,
    normalize_ip_address,
    clean_version_string,
    parse_banner_or_header_technology,
    normalize_technology_item,
    normalize_ports_list,
    normalize_cve_id,
)
from services.exposure_engine.asset_model import (
    NormalizedAsset,
    TechObservation,
    ServiceObservation,
    VulnerabilityFinding,
    ExposureFinding,
)
from services.exposure_engine.asset_inventory import (
    AssetInventoryBuilder,
    infer_asset_criticality,
)
from services.exposure_engine.vulnerability_intelligence import (
    VulnerabilityIntelligenceEngine,
    is_version_affected,
)
from services.exposure_engine.correlation_engine import ExposureCorrelationEngine
from services.exposure_engine.exposure_scoring import ExposureScoringEngine
from services.exposure_engine.attack_graph import AttackSurfaceGraphBuilder
from services.exposure_engine.change_detection import ChangeDetectionEngine
from services.exposure_engine.remediation_engine import RemediationEngine


class TestExposureEngine(unittest.TestCase):

    # 1. Asset normalization
    def test_asset_normalization(self):
        self.assertEqual(normalize_hostname("https://API.Example.com:8080/v1/test"), "api.example.com")
        self.assertEqual(normalize_hostname("  Sub.Domain.Org  "), "sub.domain.org")
        ip_v4 = normalize_ip_address("192.168.1.1")
        self.assertIsNotNone(ip_v4)
        self.assertEqual(ip_v4[0], "192.168.1.1")
        self.assertEqual(ip_v4[1], "ipv4")
        ip_v6 = normalize_ip_address("2001:db8::1")
        self.assertIsNotNone(ip_v6)
        self.assertEqual(ip_v6[1], "ipv6")
        self.assertIsNone(normalize_ip_address("invalid-ip"))

    # 2. Technology normalization
    def test_technology_normalization(self):
        raw_tech = {
            "name": "apache",
            "version": "v2.4.49 (Unix)",
            "confidence": 95,
            "categories": ["Web Server"],
            "signals": ["Server header: Apache/2.4.49"],
        }
        normalized = normalize_technology_item(raw_tech)
        self.assertEqual(normalized["name"], "Apache HTTP Server")
        self.assertEqual(normalized["version"], "2.4.49")
        self.assertEqual(normalized["confidence"], 95)
        self.assertIn("Web Server", normalized["categories"])

    # 3. Version parsing
    def test_version_parsing(self):
        self.assertEqual(clean_version_string("v1.24.0-RELEASE"), "1.24.0")
        self.assertEqual(clean_version_string("2.4.49 (Ubuntu)"), "2.4.49")
        self.assertEqual(clean_version_string("8.1.2;"), "8.1.2")
        self.assertEqual(clean_version_string("non-version"), "")

        parsed = parse_banner_or_header_technology("Apache/2.4.49 OpenSSL/1.1.1k")
        self.assertEqual(len(parsed), 2)
        names = [p["name"] for p in parsed]
        self.assertIn("Apache HTTP Server", names)
        self.assertIn("OpenSSL", names)

    # 4. CVE matching
    def test_cve_matching(self):
        vuln_engine = VulnerabilityIntelligenceEngine()
        # Confirmed vulnerable Apache 2.4.49
        vulns = vuln_engine.find_vulnerabilities_for_technology("Apache HTTP Server", "2.4.49", confidence=95)
        self.assertTrue(len(vulns) >= 1)
        cve_ids = [v.cve_id for v in vulns]
        self.assertIn("CVE-2021-41773", cve_ids)
        cve_41773 = next(v for v in vulns if v.cve_id == "CVE-2021-41773")
        self.assertTrue(cve_41773.affected)
        self.assertEqual(cve_41773.status, "CONFIRMED")

        # Safe patched Apache 2.4.58
        safe_vulns = vuln_engine.find_vulnerabilities_for_technology("Apache HTTP Server", "2.4.58", confidence=95)
        # Should NOT match CVE-2021-41773
        self.assertNotIn("CVE-2021-41773", [v.cve_id for v in safe_vulns])

    # 5. KEV matching
    def test_kev_matching(self):
        vuln_engine = VulnerabilityIntelligenceEngine()
        is_kev, date_added = vuln_engine.get_kev_info("CVE-2021-41773")
        self.assertTrue(is_kev)
        self.assertIsNotNone(date_added)

        is_kev_fake, _ = vuln_engine.get_kev_info("CVE-2099-99999")
        self.assertFalse(is_kev_fake)

    # 6. EPSS processing
    def test_epss_processing(self):
        vuln_engine = VulnerabilityIntelligenceEngine()
        epss_results = vuln_engine.get_epss_scores(["CVE-2021-41773", "CVE-2024-4577"])
        self.assertIn("CVE-2021-41773", epss_results)
        self.assertGreater(epss_results["CVE-2021-41773"]["epss"], 0.5)

    # 7. Exposure correlation
    def test_exposure_correlation(self):
        asset = NormalizedAsset(
            asset_id="test1",
            hostname="api.example.com",
            root_domain="example.com",
            ports=[80, 443, 8080],
            ip_addresses=["203.0.113.10"],
        )
        vuln = VulnerabilityFinding(
            cve_id="CVE-2021-41773",
            technology="Apache HTTP Server",
            detected_version="2.4.49",
            affected=True,
            status="CONFIRMED",
            cvss=7.5,
            epss=0.97,
            kev=True,
            evidence=["Version 2.4.49 detected on port 8080"],
        )
        asset.vulnerabilities.append(vuln)

        correlation = ExposureCorrelationEngine()
        exposures = correlation.correlate_asset_exposures(asset)
        self.assertTrue(len(exposures) >= 1)
        vuln_exp = next((e for e in exposures if e.cve_id == "CVE-2021-41773"), None)
        self.assertIsNotNone(vuln_exp)
        self.assertEqual(vuln_exp.severity, "CRITICAL")
        self.assertEqual(vuln_exp.priority, "CRITICAL")
        self.assertEqual(vuln_exp.status, "CONFIRMED")

    # 8. Score calculation
    def test_score_calculation(self):
        scoring = ExposureScoringEngine()
        asset = NormalizedAsset(
            asset_id="test_normal",
            hostname="example.com",
            root_domain="example.com",
            ports=[80, 443],
            is_live=True,
        )
        score_data = scoring.compute_overall_score([asset])
        self.assertIn("overall_score", score_data)
        self.assertIn("breakdown", score_data)
        self.assertTrue(0 <= score_data["overall_score"] <= 100)
        self.assertIn("internet_exposure", score_data["breakdown"])
        self.assertIn("vulnerability", score_data["breakdown"])
        self.assertIn("exploitability", score_data["breakdown"])
        self.assertIn("configuration", score_data["breakdown"])
        self.assertIn("asset_context", score_data["breakdown"])

    # 9. Score guardrails
    def test_score_guardrails(self):
        scoring = ExposureScoringEngine()
        # Normal website with missing CSP only must NOT become HIGH or CRITICAL risk!
        normal_asset = NormalizedAsset(
            asset_id="normal",
            hostname="example.com",
            root_domain="example.com",
            ports=[443],
            is_live=True,
        )
        normal_asset.exposures.append(
            ExposureFinding(
                finding_id="EXP-CSP",
                type="web_security_misconfiguration",
                title="Missing Content-Security-Policy",
                asset="example.com",
                severity="LOW",
                priority="INFORMATIONAL",
                confidence=90,
                status="INFORMATIONAL",
                reason="CSP missing",
            )
        )
        normal_score = scoring.compute_overall_score([normal_asset])
        # Score must remain controlled/low (<= 30)
        self.assertLessEqual(normal_score["overall_score"], 30)
        self.assertIn(normal_score["risk_level"], ("LOW", "MEDIUM"))

    # 10. Change detection
    def test_change_detection(self):
        change_engine = ChangeDetectionEngine()
        asset1 = NormalizedAsset(asset_id="1", hostname="example.com", root_domain="example.com", ports=[80, 443])
        asset2 = NormalizedAsset(asset_id="2", hostname="api.example.com", root_domain="example.com", ports=[8080])

        previous_data = {
            "overall_score": 15,
            "assets": [
                {"hostname": "example.com", "ports": [80], "ip_addresses": ["1.1.1.1"]},
                {"hostname": "dev.example.com", "ports": [80], "ip_addresses": ["1.1.1.2"]},
            ]
        }

        diff = change_engine.compare_snapshots(
            target="example.com",
            current_assets=[asset1, asset2],
            current_score=45,
            previous_data=previous_data,
        )
        self.assertTrue(diff["has_changes"])
        self.assertIn("api.example.com", diff["new_subdomains"])
        self.assertIn("dev.example.com", diff["removed_subdomains"])

    # 11. Graph generation
    def test_graph_generation(self):
        graph_builder = AttackSurfaceGraphBuilder("example.com")
        asset = NormalizedAsset(
            asset_id="1",
            hostname="api.example.com",
            root_domain="example.com",
            ip_addresses=["203.0.113.10"],
            ports=[8080],
        )
        tech = TechObservation(name="Apache HTTP Server", normalized_name="apache-http-server", version="2.4.49")
        asset.technologies.append(tech)
        vuln = VulnerabilityFinding(
            cve_id="CVE-2021-41773",
            technology="Apache HTTP Server",
            detected_version="2.4.49",
            affected=True,
            status="CONFIRMED",
            cvss=7.5,
            epss=0.97,
            kev=True,
        )
        asset.vulnerabilities.append(vuln)

        graph = graph_builder.build_from_assets([asset])
        self.assertIn("nodes", graph)
        self.assertIn("edges", graph)
        self.assertIn("paths", graph)
        self.assertTrue(len(graph["paths"]) >= 1)
        self.assertEqual(graph["paths"][0]["cve_id"], "CVE-2021-41773")

    # 12. Partial API failure handling
    def test_partial_api_failure_handling(self):
        vuln_engine = VulnerabilityIntelligenceEngine()
        status = vuln_engine.get_source_status()
        self.assertIn("cisa_kev", status)
        self.assertIn("epss", status)
        # Even if offline, engine returns curated scores safely without raising unhandled exceptions
        scores = vuln_engine.get_epss_scores(["CVE-2021-41773"])
        self.assertIn("CVE-2021-41773", scores)

    # 13. Duplicate assets
    def test_duplicate_assets_deduplication(self):
        builder = AssetInventoryBuilder("example.com")
        a1 = builder.get_or_create_asset("api.example.com")
        a2 = builder.get_or_create_asset("API.example.com")
        a3 = builder.get_or_create_asset("https://api.example.com:443/test")
        self.assertEqual(a1.asset_id, a2.asset_id)
        self.assertEqual(a1.asset_id, a3.asset_id)
        assets = builder.build()
        # Should only contain 1 asset for api.example.com
        self.assertEqual(len(assets), 1)

    # 14. Unknown versions handling (Part 6)
    def test_unknown_versions_handling(self):
        vuln_engine = VulnerabilityIntelligenceEngine()
        # Technology detected without confirmed version
        vulns = vuln_engine.find_vulnerabilities_for_technology("Apache HTTP Server", "", confidence=80)
        for v in vulns:
            self.assertEqual(v.status, "POTENTIAL")
            self.assertFalse(v.affected)
            self.assertIn("version could not be confirmed", v.summary.lower())


if __name__ == "__main__":
    unittest.main()
