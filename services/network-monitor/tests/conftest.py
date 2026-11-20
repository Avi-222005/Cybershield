"""
Pytest configuration for CyberShield Network Monitor tests.
Ensures network-monitor root directory is in sys.path.
"""

import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
