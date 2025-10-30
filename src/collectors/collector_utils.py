"""
Common helper functions for network collectors.

Adapted from online_files/Supporting_functions.py with production-grade enhancements.
"""

import socket
import struct
from functools import reduce
from typing import Dict, List, Tuple, Optional, Any
import numpy as np
import logging

logger = logging.getLogger(__name__)


def ip_to_str(ip: bytes) -> str:
    """
    Convert binary IP address to string format.
    
    Args:
        ip: Binary IP address (4 bytes for IPv4)
        
    Returns:
        String representation of IP address
    """
    try:
        return socket.inet_ntoa(ip)
    except (OSError, TypeError):
        # Handle invalid IP bytes
        return str(ip)


def get_protocol_name(protocol_val: int) -> str:
    """
    Convert protocol number to name.
    
    Args:
        protocol_val: IP protocol number
        
    Returns:
        Protocol name string
    """
    protocol_map = {
        0: "IP",
        1: "ICMP",
        2: "IGMP",
        6: "TCP",
        17: "UDP",
        41: "IPv6",
        47: "GRE",
        50: "ESP",
        51: "AH",
        58: "ICMPv6",
        89: "OSPF"
    }
    return protocol_map.get(protocol_val, f"Unknown({protocol_val})")


def get_flow_info(flows: Dict[Tuple, List[Dict]], flow: Tuple) -> Tuple[int, float, float, float, float, float, float, float, float]:
    """
    Generate flow-level features from packet list.
    
    Args:
        flows: Dictionary mapping flow tuple to list of packet dicts
        flow: Flow identifier tuple (src_ip, dst_ip, src_port, dst_port, proto)
        
    Returns:
        Tuple of (bytes, duration, max_duration, min_duration, sum_duration,
                  average_duration, std_duration, idle_time, active_time)
    """
    if flow not in flows or not flows[flow]:
        return (0, 0, 0, 0, 0, 0, 0, 0, 0)
    
    packets = flows[flow]
    
    # Total bytes
    total_bytes = sum(pkt.get('byte_count', 0) for pkt in packets)
    
    # Extract timestamps
    timestamps = sorted([pkt.get('ts', 0) for pkt in packets])
    
    if not timestamps:
        return (total_bytes, 0, 0, 0, 0, 0, 0, 0, 0)
    
    # Calculate idle time (time since last packet)
    if len(timestamps) > 1:
        idle_time = timestamps[-1] - timestamps[-2]
    else:
        idle_time = timestamps[-1] if timestamps else 0
    
    # Duration statistics
    max_duration = max(timestamps)
    min_duration = min(timestamps)
    sum_duration = sum(timestamps)
    average_duration = np.mean(timestamps) if timestamps else 0
    std_duration = np.std(timestamps) if len(timestamps) > 1 else 0
    
    # Flow duration (first to last packet)
    duration = timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0
    active_time = duration
    
    return (
        total_bytes,
        duration,
        max_duration,
        min_duration,
        sum_duration,
        average_duration,
        std_duration,
        idle_time,
        active_time
    )


def get_flag_values(tcp_flags: int) -> List[int]:
    """
    Extract individual TCP flag values as binary list.
    
    Args:
        tcp_flags: TCP flags as integer bitmask
        
    Returns:
        List of 8 integers (0 or 1) for [FIN, SYN, RST, PSH, ACK, URG, ECE, CWR]
    """
    outputs = [
        int(bool(tcp_flags & 0x01)),  # FIN
        int(bool(tcp_flags & 0x02)),  # SYN
        int(bool(tcp_flags & 0x04)),  # RST
        int(bool(tcp_flags & 0x08)),  # PSH
        int(bool(tcp_flags & 0x10)),  # ACK
        int(bool(tcp_flags & 0x20)),  # URG
        int(bool(tcp_flags & 0x40)),  # ECE
        int(bool(tcp_flags & 0x80))   # CWR
    ]
    return outputs


def parse_tcp_flags_dict(tcp_flags: Dict[str, bool]) -> List[int]:
    """
    Parse TCP flags dictionary to binary list.
    
    Args:
        tcp_flags: Dict with keys like 'fin', 'syn', 'rst', etc.
        
    Returns:
        List of 8 integers (0 or 1)
    """
    flag_order = ['fin', 'syn', 'rst', 'psh', 'ack', 'urg', 'ece', 'cwr']
    return [int(tcp_flags.get(flag, False)) for flag in flag_order]


def compare_flow_flags(
    flag_values: List[int],
    ack_count: int,
    syn_count: int,
    fin_count: int,
    urg_count: int,
    rst_count: int
) -> Tuple[int, int, int, int, int]:
    """
    Update flag counters based on packet flag values.
    
    Args:
        flag_values: List of 8 flag values from get_flag_values
        ack_count, syn_count, fin_count, urg_count, rst_count: Current counts
        
    Returns:
        Updated tuple of (ack_count, syn_count, fin_count, urg_count, rst_count)
    """
    if len(flag_values) < 8:
        return (ack_count, syn_count, fin_count, urg_count, rst_count)
    
    # flag_values: [FIN, SYN, RST, PSH, ACK, URG, ECE, CWR]
    fin, syn, rst, psh, ack, urg, ece, cwr = flag_values
    
    return (
        ack_count + ack,
        syn_count + syn,
        fin_count + fin,
        urg_count + urg,
        rst_count + rst
    )


def get_src_dst_packets(
    flows: Dict[Tuple, List[Dict]],
    flow: Tuple
) -> Tuple[int, int, int, int]:
    """
    Calculate bidirectional packet and byte counts.
    
    Args:
        flows: Flow dictionary
        flow: Flow tuple (src_ip, dst_ip, src_port, dst_port, proto)
        
    Returns:
        Tuple of (src_to_dst_pkt, dst_to_src_pkt, src_to_dst_byte, dst_to_src_byte)
    """
    src_to_dst_pkt = 0
    dst_to_src_pkt = 0
    src_to_dst_byte = 0
    dst_to_src_byte = 0
    
    # Forward direction
    if flow in flows:
        packets = flows[flow]
        src_to_dst_pkt = len(packets)
        src_to_dst_byte = sum(pkt.get('byte_count', 0) for pkt in packets)
    
    # Reverse direction (swap src/dst)
    if len(flow) >= 5:
        reverse_flow = (flow[1], flow[0], flow[3], flow[2], flow[4])
        if reverse_flow in flows:
            packets = flows[reverse_flow]
            dst_to_src_pkt = len(packets)
            dst_to_src_byte = sum(pkt.get('byte_count', 0) for pkt in packets)
    
    return (src_to_dst_pkt, dst_to_src_pkt, src_to_dst_byte, dst_to_src_byte)


def calculate_incoming_connections(
    src_pkt: Dict[str, int],
    dst_pkt: Dict[str, int],
    src_port: int,
    dst_port: int,
    src_ip: str,
    dst_ip: str
) -> None:
    """
    Calculate incoming connection counts for well-known ports.
    
    Mutates src_pkt and dst_pkt dictionaries in-place.
    
    Args:
        src_pkt: Dict tracking packet counts per source IP
        dst_pkt: Dict tracking packet counts per destination IP
        src_port, dst_port: Port numbers
        src_ip, dst_ip: IP addresses
    """
    # Only count well-known ports (1-1023)
    if (0 < src_port < 1024) or (0 < dst_port < 1024):
        src_pkt[src_ip] = src_pkt.get(src_ip, 0) + 1
        dst_pkt[dst_ip] = dst_pkt.get(dst_ip, 0) + 1


def calculate_packets_counts_per_ips_proto(
    average_per_proto_src: Dict[str, int],
    protocol_name: str,
    src_ip: str,
    average_per_proto_dst: Dict[str, int],
    dst_ip: str
) -> None:
    """
    Calculate packet counts per (protocol, IP) combination.
    
    Mutates dictionaries in-place.
    
    Args:
        average_per_proto_src: Dict tracking counts per (protocol, src_ip)
        protocol_name: Protocol name string
        src_ip: Source IP
        average_per_proto_dst: Dict tracking counts per (protocol, dst_ip)
        dst_ip: Destination IP
    """
    key_src = f"({protocol_name}, {src_ip})"
    key_dst = f"({protocol_name}, {dst_ip})"
    
    average_per_proto_src[key_src] = average_per_proto_src.get(key_src, 0) + 1
    average_per_proto_dst[key_dst] = average_per_proto_dst.get(key_dst, 0) + 1


def calculate_packets_count_per_ports_proto(
    average_per_proto_src_port: Dict[str, int],
    average_per_proto_dst_port: Dict[str, int],
    protocol_name: str,
    src_port: int,
    dst_port: int
) -> None:
    """
    Calculate packet counts per (protocol, port) combination.
    
    Mutates dictionaries in-place.
    
    Args:
        average_per_proto_src_port: Dict tracking counts per (protocol, src_port)
        average_per_proto_dst_port: Dict tracking counts per (protocol, dst_port)
        protocol_name: Protocol name string
        src_port, dst_port: Port numbers
    """
    key_src = f"({protocol_name}, {src_port})"
    key_dst = f"({protocol_name}, {dst_port})"
    
    average_per_proto_src_port[key_src] = average_per_proto_src_port.get(key_src, 0) + 1
    average_per_proto_dst_port[key_dst] = average_per_proto_dst_port.get(key_dst, 0) + 1


def detect_protocol_by_port(src_port: int, dst_port: int) -> Dict[str, int]:
    """
    Detect application-layer protocols based on port numbers.
    
    Based on Layered_features.py logic.
    
    Args:
        src_port, dst_port: TCP/UDP port numbers
        
    Returns:
        Dict with protocol flags (1 if detected, 0 otherwise)
    """
    protocols = {
        'http': 0,
        'https': 0,
        'dns': 0,
        'telnet': 0,
        'smtp': 0,
        'ssh': 0,
        'ftp': 0,
        'mqtt': 0,
        'coap': 0,
        'dhcp': 0
    }
    
    # Port-based detection
    port_checks = [
        (80, 'http'),
        (443, 'https'),
        (53, 'dns'),
        (23, 'telnet'),
        (25, 'smtp'),
        (22, 'ssh'),
        (21, 'ftp'),
        (1883, 'mqtt'),
        (5683, 'coap')
    ]
    
    for port, proto in port_checks:
        if src_port == port or dst_port == port:
            protocols[proto] = 1
    
    # DHCP special case (67-68)
    if (src_port == 67 and dst_port == 68) or (src_port == 68 and dst_port == 67):
        protocols['dhcp'] = 1
    
    return protocols


def create_flow_key(
    src_ip: str,
    dst_ip: str,
    src_port: Optional[int],
    dst_port: Optional[int],
    protocol: str
) -> Tuple:
    """
    Create a hashable flow identifier.
    
    Args:
        src_ip, dst_ip: IP addresses
        src_port, dst_port: Port numbers (can be None)
        protocol: Protocol name
        
    Returns:
        Tuple that can be used as dict key
    """
    return (src_ip, dst_ip, src_port or 0, dst_port or 0, protocol)


def calculate_rate(total_bytes: int, duration: float) -> float:
    """
    Calculate transmission rate in bytes per second.
    
    Args:
        total_bytes: Total bytes transferred
        duration: Time duration in seconds
        
    Returns:
        Rate in bytes/second
    """
    return total_bytes / duration if duration > 0 else 0.0


def safe_mean(values: List[float]) -> float:
    """Safe mean calculation handling empty lists."""
    return float(np.mean(values)) if values else 0.0


def safe_std(values: List[float]) -> float:
    """Safe standard deviation handling empty/single-value lists."""
    return float(np.std(values)) if len(values) > 1 else 0.0


def safe_var(values: List[float]) -> float:
    """Safe variance calculation."""
    return float(np.var(values)) if len(values) > 1 else 0.0
