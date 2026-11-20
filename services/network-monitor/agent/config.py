"""
Agent Configuration for CyberShield Network Monitor.
Loads settings from environment variables and provides sensible Windows defaults.
Strictly enforces privacy policies (no persistent traffic storage, no payload capture).
"""

import os
from typing import Dict, Any
from dotenv import load_dotenv

# Load .env file if available
load_dotenv()


def get_bool_env(key: str, default: bool) -> bool:
    val = os.getenv(key)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


def get_int_env(key: str, default: int) -> int:
    val = os.getenv(key)
    if val is None:
        return default
    try:
        return int(val.strip())
    except ValueError:
        return default


def get_float_env(key: str, default: float) -> float:
    val = os.getenv(key)
    if val is None:
        return default
    try:
        return float(val.strip())
    except ValueError:
        return default


AGENT_CONFIG: Dict[str, Any] = {
    "agent_name": os.getenv("CYBERSHIELD_AGENT_NAME", "CyberShield Network Agent"),
    "platform": "windows",
    "tshark_path": os.getenv("CYBERSHIELD_TSHARK_PATH", None),
    "monitoring": {
        "enabled": get_bool_env("CYBERSHIELD_MONITORING_ENABLED", True),
        "interface": os.getenv("CYBERSHIELD_INTERFACE", "auto"),
        "capture_packets": get_bool_env("CYBERSHIELD_CAPTURE_PACKETS", True),
        "monitor_connections": get_bool_env("CYBERSHIELD_MONITOR_CONNECTIONS", True),
        "monitor_bandwidth": get_bool_env("CYBERSHIELD_MONITOR_BANDWIDTH", True),
        "force_adapter": os.getenv("CYBERSHIELD_FORCE_ADAPTER", "auto"),  # 'auto', 'tshark', 'pyshark', 'synthetic'
        "fallback_to_synthetic": get_bool_env("CYBERSHIELD_FALLBACK_SYNTHETIC", True),
    },
    "intervals": {
        "bandwidth": get_float_env("CYBERSHIELD_INTERVAL_BANDWIDTH", 1.0),
        "connections": get_float_env("CYBERSHIELD_INTERVAL_CONNECTIONS", 3.0),
        "aggregation": get_float_env("CYBERSHIELD_INTERVAL_AGGREGATION", 1.0),
        "health_check": get_float_env("CYBERSHIELD_INTERVAL_HEALTH_CHECK", 5.0),
    },
    "memory": {
        "max_packet_events": get_int_env("CYBERSHIELD_MAX_PACKET_EVENTS", 5000),
        "max_connections": get_int_env("CYBERSHIELD_MAX_CONNECTIONS", 2000),
        "max_alerts": get_int_env("CYBERSHIELD_MAX_ALERTS", 500),
    },
    "privacy": {
        "store_payloads": False,   # Strictly enforced false
        "persist_traffic": False,  # Strictly enforced false
    },
}


def load_config(overrides: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Retrieve agent configuration dictionary merged with optional runtime overrides.
    """
    import copy
    config = copy.deepcopy(AGENT_CONFIG)
    if not overrides:
        return config

    def deep_update(d, u):
        for k, v in u.items():
            if isinstance(v, dict) and k in d and isinstance(d[k], dict):
                deep_update(d[k], v)
            else:
                d[k] = v

    deep_update(config, overrides)
    # Maintain strict privacy invariant regardless of overrides
    config["privacy"]["store_payloads"] = False
    config["privacy"]["persist_traffic"] = False
    return config
