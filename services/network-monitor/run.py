#!/usr/bin/env python
"""
Convenience launcher for CyberShield Network Monitor Agent.
Allows starting the agent from the services/network-monitor directory directly.
"""

import os
import sys

# Ensure package directory is on path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from agent.main import main

if __name__ == "__main__":
    sys.exit(main())
