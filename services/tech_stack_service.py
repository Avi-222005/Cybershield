from typing import Any, Dict

from .tech_fingerprint_engine import get_tech_fingerprint_engine


def analyze_tech_stack(target_input: str) -> Dict[str, Any]:
    """Compatibility wrapper used by existing API routes and unified recon."""
    engine = get_tech_fingerprint_engine()
    return engine.analyze_target(target_input)
