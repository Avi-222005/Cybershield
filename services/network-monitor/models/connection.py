"""
Active network connection model for CyberShield Network Monitor.
Tracks OS-level connection endpoints, protocols, state, and process attribution.
"""

from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any


@dataclass
class Connection:
    """
    Representation of an active network connection retrieved from the OS.
    Process attribution is best-effort.
    """
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    protocol: str  # 'tcp', 'udp', etc.
    status: str    # e.g., 'ESTABLISHED', 'LISTEN', 'CLOSE_WAIT', etc.
    pid: Optional[int] = None
    process_name: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert connection data to dictionary."""
        return asdict(self)

    @property
    def key(self) -> str:
        """Unique key identifying the socket connection."""
        return f"{self.protocol}:{self.local_ip}:{self.local_port}->{self.remote_ip}:{self.remote_port}"

    def __hash__(self) -> int:
        return hash(self.key)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Connection):
            return False
        return self.key == other.key
