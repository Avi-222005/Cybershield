"""
Logger utility for CyberShield Network Monitor.
Provides sanitized console logging strictly forbidding packet payload or persistent traffic capture.
"""

import logging
import sys
from typing import Optional


class SanitizedFormatter(logging.Formatter):
    """
    Custom formatter ensuring operational messages are clean, formatted,
    and safe from leaking large dumps or payload contents.
    """
    RESET = "\033[0m"
    BOLD = "\033[1m"
    COLORS = {
        logging.DEBUG: "\033[36m",     # Cyan
        logging.INFO: "\033[32m",      # Green
        logging.WARNING: "\033[33m",   # Yellow
        logging.ERROR: "\033[31m",     # Red
        logging.CRITICAL: "\033[41m",  # Red background
    }

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelno, "")
        timestamp = self.formatTime(record, "%Y-%m-%d %H:%M:%S")
        prefix = f"{color}[{timestamp}] [{record.levelname:7s}] [{record.name}]{self.RESET}"
        return f"{prefix} {record.getMessage()}"


def setup_logger(name: str = "cybershield", level: int = logging.INFO, enable_color: bool = True) -> logging.Logger:
    """
    Configure and return a sanitized standard library logger.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Avoid adding duplicate handlers if setup is called multiple times
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(level)
        if enable_color and sys.platform == "win32":
            # Enable Windows ANSI color support if possible
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            except Exception:
                enable_color = False

        if enable_color:
            handler.setFormatter(SanitizedFormatter())
        else:
            handler.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s"))
        logger.addHandler(handler)

    return logger


# Default logger instance
logger = setup_logger()
