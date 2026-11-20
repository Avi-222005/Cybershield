"""
Interface Manager for CyberShield Network Monitor.
Identifies physical, virtual, Wi-Fi, and Ethernet network adapters,
extracts IPv4/IPv6 configurations, and identifies the default active route.
"""

import socket
import psutil
from typing import Dict, Any, List, Optional, Set
from utils.logger import logger


class InterfaceManager:
    """
    Manages detection, enumeration, and health monitoring of host network interfaces.
    """

    def __init__(self):
        pass

    def get_all_interfaces(self) -> Dict[str, Dict[str, Any]]:
        """
        Enumerate all host network interfaces with their addresses and status.
        """
        interfaces: Dict[str, Dict[str, Any]] = {}
        net_addrs = psutil.net_if_addrs()
        net_stats = psutil.net_if_stats()

        for iface_name, addrs in net_addrs.items():
            stats = net_stats.get(iface_name)
            is_up = stats.isup if stats else False
            speed = stats.speed if stats else 0
            mtu = stats.mtu if stats else 0

            ipv4_list: List[str] = []
            ipv6_list: List[str] = []
            mac_addr: Optional[str] = None

            for addr in addrs:
                # AF_INET = IPv4
                if addr.family == socket.AF_INET:
                    if addr.address:
                        ipv4_list.append(addr.address)
                # AF_INET6 = IPv6
                elif addr.family == socket.AF_INET6:
                    if addr.address:
                        # Strip Windows interface scope ID if present (e.g., fe80::1%12)
                        clean_ip6 = addr.address.split("%")[0]
                        ipv6_list.append(clean_ip6)
                # MAC address (psutil.AF_LINK or socket.AF_LINK)
                elif getattr(psutil, "AF_LINK", None) is not None and addr.family == psutil.AF_LINK:
                    mac_addr = addr.address

            interfaces[iface_name] = {
                "name": iface_name,
                "is_up": is_up,
                "speed": speed,
                "mtu": mtu,
                "ipv4": ipv4_list,
                "ipv6": ipv6_list,
                "mac_address": mac_addr,
                "has_ip": len(ipv4_list) > 0 or len(ipv6_list) > 0,
            }

        return interfaces

    def get_interface_details(self, interface_name: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information for a specific named interface.
        """
        all_ifaces = self.get_all_interfaces()
        return all_ifaces.get(interface_name)

    def get_active_interfaces(self) -> Dict[str, Dict[str, Any]]:
        """
        Return only operational interfaces that are currently UP and possess an assigned IP address.
        """
        all_ifaces = self.get_all_interfaces()
        active = {}
        for name, details in all_ifaces.items():
            # Must be UP and have at least one IPv4 or IPv6 address (exclude disconnected / unconfigured adapters)
            if details["is_up"] and details["has_ip"]:
                active[name] = details
        return active

    def get_default_interface(self) -> Optional[str]:
        """
        Determine the default active network interface used for outbound traffic.
        Uses non-blocking routing table inspection via UDP connect probe.
        Does NOT transmit any network packets.
        """
        active_ifaces = self.get_active_interfaces()
        if not active_ifaces:
            # Fall back to any UP interface
            all_ifaces = self.get_all_interfaces()
            for name, details in all_ifaces.items():
                if details["is_up"]:
                    return name
            return next(iter(all_ifaces.keys())) if all_ifaces else None

        # Routing socket trick: determine which local IP the OS routing table picks for public internet
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(0.5)
                # Connect to a public destination IP without transmitting data
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]

            # Find which interface holds this local IP
            for name, details in active_ifaces.items():
                if local_ip in details.get("ipv4", []):
                    return name
        except Exception:
            pass

        # Fallback 1: Prefer Wi-Fi or Ethernet adapter with IPv4
        preferred_keywords = ["wi-fi", "wifi", "ethernet", "eth", "wlan", "local area connection"]
        for kw in preferred_keywords:
            for name in active_ifaces:
                if kw in name.lower() and active_ifaces[name]["ipv4"]:
                    return name

        # Fallback 2: Any active interface with IPv4
        for name, details in active_ifaces.items():
            if details["ipv4"]:
                return name

        # Fallback 3: First active interface
        return next(iter(active_ifaces.keys()))

    def get_interface_ips(self, interface_name: str) -> Set[str]:
        """
        Retrieve all assigned IPv4 and IPv6 addresses for an interface as a set.
        Used by the packet parser to identify packet direction (inbound vs outbound).
        """
        details = self.get_interface_details(interface_name)
        if not details:
            return set()
        ips = set(details.get("ipv4", [])) | set(details.get("ipv6", []))
        # Include standard loopbacks if monitoring loopback
        if "loopback" in interface_name.lower():
            ips.add("127.0.0.1")
            ips.add("::1")
        return ips
