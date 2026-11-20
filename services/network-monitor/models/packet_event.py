"""
Packet event data model for CyberShield Network Monitor.
Standard normalized representation of packet metadata without payload.
"""

from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any


@dataclass
class PacketEvent:
    """
    Normalized representation of a single captured packet metadata event.
    Strictly excludes payload data to uphold the temporary in-memory zero-payload privacy guarantee.
    """
    timestamp: float
    interface: str
    source_ip: Optional[str]
    destination_ip: Optional[str]
    source_port: Optional[int]
    destination_port: Optional[int]
    protocol: str
    packet_size: int
    direction: str  # 'inbound', 'outbound', 'internal', 'unknown'
    dns_query: Optional[str] = None
    dns_rcode: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert the packet event to a standard dictionary format."""
        return asdict(self)

    def summary(self) -> str:
        """Produce a human-readable one-line summary of the packet."""
        src = f"{self.source_ip}:{self.source_port}" if self.source_port else str(self.source_ip)
        dst = f"{self.destination_ip}:{self.destination_port}" if self.destination_port else str(self.destination_ip)
        return f"[{self.protocol}] {src} -> {dst} ({self.packet_size} bytes, {self.direction})"
