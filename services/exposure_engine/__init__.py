"""
CyberShield External Attack Surface & Exposure Intelligence Engine
Transforms CyberShield from isolated scanners into an integrated, evidence-backed
exposure intelligence platform.
"""

import logging
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from .asset_inventory import AssetInventoryBuilder
from .asset_model import NormalizedAsset
from .attack_graph import AttackSurfaceGraphBuilder
from .change_detection import ChangeDetectionEngine
from .correlation_engine import ExposureCorrelationEngine
from .exposure_scoring import ExposureScoringEngine
from .normalizer import normalize_hostname
from .remediation_engine import RemediationEngine
from .report_generator import ReportGenerator
from .vulnerability_intelligence import get_vulnerability_engine

logger = logging.getLogger(__name__)

# In-memory job registry for async background exposure assessments
_EXPOSURE_JOBS_LOCK = threading.Lock()
_EXPOSURE_JOBS: Dict[str, Dict[str, Any]] = {}
_JOB_TTL_SECONDS = 900


def _cleanup_expired_jobs() -> None:
    now = time.time()
    with _EXPOSURE_JOBS_LOCK:
        expired = [
            jid for jid, job in _EXPOSURE_JOBS.items()
            if job.get("finished_at_epoch", 0) > 0 and (now - job["finished_at_epoch"]) > _JOB_TTL_SECONDS
        ]
        for jid in expired:
            _EXPOSURE_JOBS.pop(jid, None)


def run_exposure_assessment(
    target_input: str,
    scan_mode: str = "standard",
    previous_snapshot: Optional[Dict[str, Any]] = None,
    on_progress: Optional[Callable[[str, int], None]] = None,
) -> Dict[str, Any]:
    """
    Main synchronous entry point for External Attack Surface & Exposure Intelligence.
    Reuses existing CyberShield scanners via unified_recon_scan, normalizes assets,
    correlates exposures, enriches with CVE/EPSS/CISA KEV, calculates the explainable
    score, builds the attack surface graph, detects changes, and generates remediation.
    """
    started = time.perf_counter()
    target = normalize_hostname(target_input)
    if not target:
        return {"error": "Valid target hostname or domain is required."}

    mode = str(scan_mode or "standard").strip().lower()
    if mode not in ("quick", "standard", "deep"):
        mode = "standard"

    if callable(on_progress):
        on_progress("Executing safe perimeter reconnaissance...", 15)

    # Step 1: Run or consume existing unified recon service
    from ..unified_recon_service import unified_recon_scan
    recon_result = unified_recon_scan(target, scan_mode=mode)
    if "error" in recon_result and not recon_result.get("modules"):
        return recon_result

    if callable(on_progress):
        on_progress("Building normalized asset inventory...", 40)

    # Step 2: Build Normalized Asset Inventory
    inventory_builder = AssetInventoryBuilder(target)
    inventory_builder.ingest_unified_recon(recon_result)
    assets: List[NormalizedAsset] = inventory_builder.build()

    if callable(on_progress):
        on_progress("Enriching with CVE, CISA KEV, and FIRST EPSS intelligence...", 65)

    # Step 3: Vulnerability Intelligence (CVE + KEV + EPSS)
    vuln_engine = get_vulnerability_engine()
    vuln_engine.refresh_kev_if_needed()

    for asset in assets:
        for tech in asset.technologies:
            vulns = vuln_engine.find_vulnerabilities_for_technology(
                tech_name=tech.name,
                detected_version=tech.version,
                confidence=tech.confidence,
                asset_hostname=asset.hostname,
            )
            for v in vulns:
                # Deduplicate by CVE on asset
                if not any(x.cve_id == v.cve_id for x in asset.vulnerabilities):
                    asset.vulnerabilities.append(v)

    if callable(on_progress):
        on_progress("Correlating multi-source exposures and security misconfigurations...", 80)

    # Step 4: Multi-Source Exposure Correlation
    correlation_engine = ExposureCorrelationEngine()
    all_exposures = []
    for asset in assets:
        exposures = correlation_engine.correlate_asset_exposures(asset)
        all_exposures.extend(exposures)

    # Step 5: Explainable Exposure Scoring
    scoring_engine = ExposureScoringEngine()
    score_data = scoring_engine.compute_overall_score(assets)

    # Assign individual asset risk scores
    for asset in assets:
        asset_score_info = scoring_engine.compute_asset_score(asset)
        asset.risk_score = asset_score_info["overall_score"]
        asset.risk_breakdown = asset_score_info["breakdown"]

    if callable(on_progress):
        on_progress("Constructing attack surface graph and exposure paths...", 90)

    # Step 6: Attack Surface Graph & Potential Exposure Paths
    graph_builder = AttackSurfaceGraphBuilder(target)
    graph_data = graph_builder.build_from_assets(assets)

    # Step 7: Change Detection
    change_engine = ChangeDetectionEngine()
    change_data = change_engine.compare_snapshots(
        target=target,
        current_assets=assets,
        current_score=score_data["overall_score"],
        previous_data=previous_snapshot,
    )

    # Step 8: Actionable Defensive Remediation Roadmap
    remediation_engine = RemediationEngine()
    remediation_plan = remediation_engine.build_remediation_plan(assets, all_exposures)

    # Step 9: Executive Security Summary
    report_gen = ReportGenerator()
    source_status = vuln_engine.get_source_status()
    summary = report_gen.generate_executive_summary(
        target=target,
        assets=assets,
        exposures=all_exposures,
        score_data=score_data,
        remediation_plan=remediation_plan,
        source_status=source_status,
        scan_mode=mode,
    )

    duration_ms = int((time.perf_counter() - started) * 1000)

    response = {
        "target": target,
        "scan_id": str(uuid.uuid4()),
        "scan_mode": mode,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan_duration_ms": duration_ms,
        "exposure_score": score_data["overall_score"],
        "grade": score_data["grade"],
        "grade_label": score_data["grade_label"],
        "risk_level": score_data["risk_level"],
        "score_breakdown": score_data["breakdown"],
        "summary": summary,
        "assets": [a.to_dict() for a in assets],
        "exposures": [e.to_dict() for e in all_exposures],
        "graph": graph_data,
        "potential_exposure_paths": graph_data.get("paths", []),
        "change_detection": change_data,
        "remediation_plan": remediation_plan,
        "source_status": source_status,
    }

    if callable(on_progress):
        on_progress("Assessment complete.", 100)

    return response


def start_exposure_assessment_job(
    target_input: str,
    scan_mode: str = "standard",
    previous_snapshot: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Starts background exposure assessment job and returns job tracker."""
    _cleanup_expired_jobs()
    target = normalize_hostname(target_input)
    if not target:
        return {"error": "Valid target hostname or domain is required."}

    job_id = uuid.uuid4().hex
    job = {
        "job_id": job_id,
        "target": target,
        "scan_mode": scan_mode,
        "status": "running",
        "progress": 5,
        "status_message": "Initializing external exposure assessment...",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "result": None,
        "error": None,
        "finished_at_epoch": 0,
    }

    with _EXPOSURE_JOBS_LOCK:
        _EXPOSURE_JOBS[job_id] = job

    def _worker():
        def on_prog(msg: str, pct: int):
            with _EXPOSURE_JOBS_LOCK:
                if job_id in _EXPOSURE_JOBS:
                    _EXPOSURE_JOBS[job_id]["status_message"] = msg
                    _EXPOSURE_JOBS[job_id]["progress"] = pct

        try:
            res = run_exposure_assessment(
                target_input=target,
                scan_mode=scan_mode,
                previous_snapshot=previous_snapshot,
                on_progress=on_prog,
            )
            with _EXPOSURE_JOBS_LOCK:
                if job_id in _EXPOSURE_JOBS:
                    _EXPOSURE_JOBS[job_id]["status"] = "completed"
                    _EXPOSURE_JOBS[job_id]["progress"] = 100
                    _EXPOSURE_JOBS[job_id]["result"] = res
                    _EXPOSURE_JOBS[job_id]["finished_at_epoch"] = time.time()
        except Exception as exc:
            logger.exception("Exposure assessment job failed: %s", exc)
            with _EXPOSURE_JOBS_LOCK:
                if job_id in _EXPOSURE_JOBS:
                    _EXPOSURE_JOBS[job_id]["status"] = "failed"
                    _EXPOSURE_JOBS[job_id]["error"] = str(exc)
                    _EXPOSURE_JOBS[job_id]["finished_at_epoch"] = time.time()

    threading.Thread(target=_worker, daemon=True).start()
    return {
        "job_id": job_id,
        "target": target,
        "status": "running",
        "progress": 5,
        "status_message": "Initializing external exposure assessment...",
    }


def get_exposure_assessment_job(job_id: str) -> Dict[str, Any]:
    with _EXPOSURE_JOBS_LOCK:
        job = _EXPOSURE_JOBS.get(job_id)
        if not job:
            return {"error": "Exposure assessment job not found."}
        return dict(job)
