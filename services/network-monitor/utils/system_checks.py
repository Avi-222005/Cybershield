"""
System readiness and dependency inspection for Windows Network Monitoring.
Validates Python version, TShark availability, Npcap drivers, and permissions.
"""

import ctypes
import os
import shutil
import sys
from typing import Dict, Any, Optional


def check_python_version() -> Dict[str, Any]:
    """Verify Python is 3.11 or newer."""
    major = sys.version_info.major
    minor = sys.version_info.minor
    micro = sys.version_info.micro
    version_str = f"{major}.{minor}.{micro}"
    passed = (major == 3 and minor >= 11) or major > 3
    return {
        "passed": passed,
        "version": version_str,
        "required": ">=3.11",
        "message": f"Python {version_str} detected" if passed else f"Python {version_str} is below required >=3.11"
    }


def find_tshark_executable(configured_path: Optional[str] = None) -> Optional[str]:
    """
    Locate TShark executable via configured path, PATH, or standard Windows installation directories.
    """
    # 1. Explicit configured path
    if configured_path and os.path.isfile(configured_path):
        return os.path.abspath(configured_path)

    # 2. PATH resolution
    which_tshark = shutil.which("tshark")
    if which_tshark and os.path.isfile(which_tshark):
        return os.path.abspath(which_tshark)

    # 3. Standard Windows locations
    standard_paths = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Programs\Wireshark\tshark.exe"),
        os.path.expandvars(r"%ProgramW6432%\Wireshark\tshark.exe"),
    ]

    for p in standard_paths:
        if os.path.isfile(p):
            return os.path.abspath(p)

    return None


def check_tshark_availability(configured_path: Optional[str] = None) -> Dict[str, Any]:
    """Check whether TShark is accessible and can be executed."""
    path = find_tshark_executable(configured_path)
    if path:
        return {
            "passed": True,
            "path": path,
            "message": f"TShark located at {path}"
        }
    return {
        "passed": False,
        "path": None,
        "message": "TShark executable not found in PATH or standard installation folders."
    }


def check_npcap_installed() -> Dict[str, Any]:
    """
    Check if Npcap packet capture driver is present on the Windows system.
    """
    if sys.platform != "win32":
        return {
            "passed": True,
            "npcap_detected": False,
            "message": "Non-Windows platform; Npcap check skipped."
        }

    # Inspect typical driver and DLL files
    system32 = os.path.expandvars(r"%WINDIR%\System32")
    markers = [
        os.path.join(system32, "Npcap"),
        os.path.join(system32, "drivers", "npcap.sys"),
        os.path.join(system32, "wpcap.dll"),
        os.path.join(system32, "Packet.dll"),
        os.path.join(system32, "Npcap", "wpcap.dll"),
    ]

    detected = any(os.path.exists(m) for m in markers)
    return {
        "passed": detected,
        "npcap_detected": detected,
        "message": "Npcap driver / wpcap library detected." if detected else "Npcap not detected in System32."
    }


def check_admin_permissions() -> Dict[str, Any]:
    """
    Check if the current process has administrative/elevated privileges required for live packet capture.
    """
    try:
        if sys.platform == "win32":
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            is_admin = os.geteuid() == 0
    except Exception:
        is_admin = False

    return {
        "passed": is_admin,
        "is_admin": is_admin,
        "message": "Running with Administrator privileges" if is_admin else "Running without Administrator privileges (live packet capture on Npcap may require elevation)"
    }


def check_system_readiness(configured_tshark: Optional[str] = None) -> Dict[str, Any]:
    """
    Run comprehensive health and readiness checks for the network monitoring agent.
    """
    py_check = check_python_version()
    tshark_check = check_tshark_availability(configured_tshark)
    npcap_check = check_npcap_installed()
    admin_check = check_admin_permissions()

    # The agent can run in partial mode (e.g., bandwidth + connections + synthetic packets)
    # even without TShark / Npcap / Admin privileges.
    full_live_capture_ready = (
        py_check["passed"] and
        tshark_check["passed"] and
        npcap_check["passed"] and
        admin_check["passed"]
    )

    basic_monitoring_ready = py_check["passed"]

    return {
        "full_live_capture_ready": full_live_capture_ready,
        "basic_monitoring_ready": basic_monitoring_ready,
        "python": py_check,
        "tshark": tshark_check,
        "npcap": npcap_check,
        "admin": admin_check,
    }
