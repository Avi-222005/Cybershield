"""
Packet Parser and Normalizer for CyberShield Network Monitor.
Converts raw capture metadata or PyShark/TShark records into normalized PacketEvent objects.
Strictly excludes payload data to guarantee in-memory privacy.
"""

import time
from typing import Optional, Set, Dict, Any
from models.packet_event import PacketEvent
from utils.logger import logger


class PacketParser:
    """
    Normalizes packet metadata extracted from live capture adapters into standardized PacketEvents.
    """

    def __init__(self, default_interface: str = "auto", local_ips: Optional[Set[str]] = None):
        self.default_interface = default_interface
        self.local_ips: Set[str] = set(local_ips) if local_ips else set()

    def set_local_ips(self, local_ips: Set[str]) -> None:
        """Update the set of local IP addresses for direction inference."""
        self.local_ips = set(local_ips)

    def determine_direction(self, src_ip: Optional[str], dst_ip: Optional[str]) -> str:
        """
        Infer packet direction relative to the monitored interface's IP addresses.
        - outbound: src is local, dst is remote
        - inbound: dst is local, src is remote
        - internal: both src and dst are local (e.g., loopback or local subnet traffic)
        - unknown: neither or IPs missing
        """
        if not src_ip or not dst_ip or not self.local_ips:
            return "unknown"

        src_local = src_ip in self.local_ips
        dst_local = dst_ip in self.local_ips

        if src_local and not dst_local:
            return "outbound"
        elif not src_local and dst_local:
            return "inbound"
        elif src_local and dst_local:
            return "internal"
        return "unknown"

    def parse_dict(self, raw: Dict[str, Any], interface: Optional[str] = None) -> Optional[PacketEvent]:
        """
        Parse a normalized dictionary of packet fields into a PacketEvent.
        Expected keys (all optional except timestamp/packet_size):
          timestamp, source_ip, destination_ip, source_port, destination_port, protocol, packet_size
        """
        try:
            timestamp = float(raw.get("timestamp", time.time()))
            iface = interface or raw.get("interface") or self.default_interface
            src_ip = raw.get("source_ip")
            dst_ip = raw.get("destination_ip")
            
            # Port parsing
            src_port = None
            if raw.get("source_port") is not None and str(raw.get("source_port")).isdigit():
                src_port = int(raw.get("source_port"))

            dst_port = None
            if raw.get("destination_port") is not None and str(raw.get("destination_port")).isdigit():
                dst_port = int(raw.get("destination_port"))

            protocol = str(raw.get("protocol") or "UNKNOWN").upper()
            packet_size = int(raw.get("packet_size", 0))

            direction = raw.get("direction")
            if not direction or direction == "auto":
                direction = self.determine_direction(src_ip, dst_ip)

            return PacketEvent(
                timestamp=timestamp,
                interface=iface,
                source_ip=str(src_ip) if src_ip else None,
                destination_ip=str(dst_ip) if dst_ip else None,
                source_port=src_port,
                destination_port=dst_port,
                protocol=protocol,
                packet_size=max(0, packet_size),
                direction=direction,
                dns_query=raw.get("dns_query"),
                dns_rcode=raw.get("dns_rcode"),
            )
        except Exception as e:
            logger.debug(f"Failed to parse packet dict: {e}")
            return None

    def parse_tshark_tsv_line(self, line: str, interface: str) -> Optional[PacketEvent]:
        """
        Parse a tab-separated line from a direct TShark fields export:
        Columns:
        0: frame.time_epoch
        1: frame.len
        2: _ws.col.Protocol
        3: ip.src
        4: ip.dst
        5: ipv6.src
        6: ipv6.dst
        7: tcp.srcport
        8: tcp.dstport
        9: udp.srcport
        10: udp.dstport
        11: arp.src.proto_ipv4
        12: arp.dst.proto_ipv4
        """
        try:
            parts = line.strip().split("\t")
            if len(parts) < 3:
                return None

            timestamp = float(parts[0]) if parts[0] else time.time()
            packet_size = int(parts[1]) if parts[1].isdigit() else 0
            protocol = parts[2].strip().upper() if len(parts) > 2 and parts[2] else "UNKNOWN"

            # IP Addresses (IPv4 or IPv6)
            ip_src = parts[3] if len(parts) > 3 and parts[3] else None
            ip_dst = parts[4] if len(parts) > 4 and parts[4] else None

            if not ip_src and len(parts) > 5 and parts[5]:
                ip_src = parts[5]
            if not ip_dst and len(parts) > 6 and parts[6]:
                ip_dst = parts[6]

            # ARP Fallback
            if not ip_src and len(parts) > 11 and parts[11]:
                ip_src = parts[11]
                protocol = "ARP"
            if not ip_dst and len(parts) > 12 and parts[12]:
                ip_dst = parts[12]
                protocol = "ARP"

            # Ports (TCP or UDP)
            src_port = None
            dst_port = None

            tcp_src = parts[7] if len(parts) > 7 else None
            tcp_dst = parts[8] if len(parts) > 8 else None
            udp_src = parts[9] if len(parts) > 9 else None
            udp_dst = parts[10] if len(parts) > 10 else None

            if tcp_src and tcp_src.isdigit():
                src_port = int(tcp_src)
            elif udp_src and udp_src.isdigit():
                src_port = int(udp_src)

            if tcp_dst and tcp_dst.isdigit():
                dst_port = int(tcp_dst)
            elif udp_dst and udp_dst.isdigit():
                dst_port = int(udp_dst)

            direction = self.determine_direction(ip_src, ip_dst)

            return PacketEvent(
                timestamp=timestamp,
                interface=interface,
                source_ip=ip_src,
                destination_ip=ip_dst,
                source_port=src_port,
                destination_port=dst_port,
                protocol=protocol,
                packet_size=packet_size,
                direction=direction,
            )
        except Exception as e:
            logger.debug(f"Error parsing TShark TSV line: {e}")
            return None

    def parse_pyshark_packet(self, packet: Any, interface: str) -> Optional[PacketEvent]:
        """
        Parse a PyShark Packet object into a normalized PacketEvent.
        """
        try:
            timestamp = float(getattr(packet, "sniff_timestamp", time.time()))
            packet_size = int(getattr(packet, "length", 0))

            highest_layer = getattr(packet, "highest_layer", "UNKNOWN").upper()
            protocol = highest_layer

            src_ip = None
            dst_ip = None
            src_port = None
            dst_port = None

            # IP Layer
            if hasattr(packet, "ip"):
                src_ip = getattr(packet.ip, "src", None)
                dst_ip = getattr(packet.ip, "dst", None)
            elif hasattr(packet, "ipv6"):
                src_ip = getattr(packet.ipv6, "src", None)
                dst_ip = getattr(packet.ipv6, "dst", None)
            elif hasattr(packet, "arp"):
                src_ip = getattr(packet.arp, "src_proto_ipv4", None)
                dst_ip = getattr(packet.arp, "dst_proto_ipv4", None)
                protocol = "ARP"

            # Transport Layer
            if hasattr(packet, "tcp"):
                src_port = int(packet.tcp.srcport) if hasattr(packet.tcp, "srcport") else None
                dst_port = int(packet.tcp.dstport) if hasattr(packet.tcp, "dstport") else None
                if protocol == "UNKNOWN":
                    protocol = "TCP"
            elif hasattr(packet, "udp"):
                src_port = int(packet.udp.srcport) if hasattr(packet.udp, "udp") else None
                dst_port = int(packet.udp.dstport) if hasattr(packet.udp, "dstport") else None
                if protocol == "UNKNOWN":
                    protocol = "UDP"

            # DNS Layer
            dns_query = None
            dns_rcode = None
            if hasattr(packet, "dns"):
                protocol = "DNS"
                if hasattr(packet.dns, "qry_name"):
                    dns_query = str(packet.dns.qry_name)
                if hasattr(packet.dns, "flags_rcode"):
                    try:
                        dns_rcode = int(packet.dns.flags_rcode)
                    except Exception:
                        pass

            direction = self.determine_direction(src_ip, dst_ip)

            return PacketEvent(
                timestamp=timestamp,
                interface=interface,
                source_ip=src_ip,
                destination_ip=dst_ip,
                source_port=src_port,
                destination_port=dst_port,
                protocol=protocol,
                packet_size=packet_size,
                direction=direction,
                dns_query=dns_query,
                dns_rcode=dns_rcode,
            )
        except Exception as e:
            logger.debug(f"Error parsing PyShark packet: {e}")
            return None
