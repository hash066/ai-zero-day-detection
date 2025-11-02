"""
Network packet adapter - converts tshark packets to NetworkFeatureRecord.

Maps raw tshark JSON output to structured feature records using logic from
online_files research (Layered_features, Connectivity_features, Supporting_functions).
"""

import logging
from typing import Dict, Any, Optional, Union
from datetime import datetime

from ..preprocessing.network_features import NetworkFeatureRecord
from .collector_utils import (
    get_protocol_name,
    parse_tcp_flags_dict,
    detect_protocol_by_port,
    create_flow_key
)

logger = logging.getLogger(__name__)


class NetworkAdapter:
    """
    Converts tshark packet dictionaries to NetworkFeatureRecord objects.
    
    Handles per-packet feature extraction including:
    - Basic connectivity (IPs, ports, protocol)
    - TCP flags
    - Protocol layer detection
    - Packet size and timing
    """
    
    def __init__(self):
        """Initialize the adapter."""
        self.packet_count = 0
        self.last_timestamp = None
    
    def adapt_packet(self, tshark_packet: Dict[str, Any]) -> Optional[NetworkFeatureRecord]:
        """
        Convert a single tshark packet to NetworkFeatureRecord.
        
        Args:
            tshark_packet: Packet dictionary from TsharkCollector
            
        Returns:
            NetworkFeatureRecord or None if packet cannot be processed
        """
        try:
            # Extract basic fields
            ts = tshark_packet.get('ts')
            if ts is None:
                logger.debug("Packet missing timestamp, skipping")
                return None
            
            src_ip = tshark_packet.get('src_ip')
            dst_ip = tshark_packet.get('dst_ip')
            src_port = tshark_packet.get('src_port')
            dst_port = tshark_packet.get('dst_port')
            protocol = tshark_packet.get('protocol', 'Unknown')
            raw_bytes = tshark_packet.get('raw_bytes', 0)
            ttl = tshark_packet.get('ttl')
            tcp_flags_dict = tshark_packet.get('tcp_flags', {})
            
            # Calculate IAT (inter-arrival time)
            iat = 0.0
            if self.last_timestamp is not None:
                iat = ts - self.last_timestamp
            self.last_timestamp = ts
            
            # Parse TCP flags
            flag_values = [0, 0, 0, 0, 0, 0, 0, 0]  # [FIN, SYN, RST, PSH, ACK, URG, ECE, CWR]
            if tcp_flags_dict:
                flag_values = parse_tcp_flags_dict(tcp_flags_dict)
            
            # Detect application protocols by port
            protocol_flags = {'http': 0, 'https': 0, 'dns': 0, 'telnet': 0,
                            'smtp': 0, 'ssh': 0, 'ftp': 0, 'mqtt': 0,
                            'coap': 0, 'dhcp': 0}
            
            if src_port is not None and dst_port is not None:
                protocol_flags = detect_protocol_by_port(src_port, dst_port)
            
            # Determine transport protocol flags
            tcp_flag = 1 if protocol == "TCP" else 0
            udp_flag = 1 if protocol == "UDP" else 0
            icmp_flag = 1 if protocol in ("ICMP", "ICMPv6") else 0
            arp_flag = 1 if protocol == "ARP" else 0
            igmp_flag = 1 if protocol == "IGMP" else 0
            
            # Determine IP version
            ip_version = tshark_packet.get('ip_version', 0)
            ipv_flag = 1 if ip_version in (4, 6) else 0
            
            # Create flow identifier
            flow_id = create_flow_key(
                src_ip or "0.0.0.0",
                dst_ip or "0.0.0.0",
                src_port,
                dst_port,
                protocol
            )
            
            # Build feature record
            record = NetworkFeatureRecord(
                # Temporal
                ts=float(ts),
                
                # Connectivity
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol_type=protocol,
                time_to_live=int(ttl) if ttl else None,
                
                # TCP flags (individual packet)
                fin_flag_number=flag_values[0],
                syn_flag_number=flag_values[1],
                rst_flag_number=flag_values[2],
                psh_flag_number=flag_values[3],
                ack_flag_number=flag_values[4],
                urg_flag_number=flag_values[5],
                ece_flag_number=flag_values[6],
                cwr_flag_number=flag_values[7],
                
                # Protocol layer detection
                http=protocol_flags['http'],
                https=protocol_flags['https'],
                dns=protocol_flags['dns'],
                telnet=protocol_flags['telnet'],
                smtp=protocol_flags['smtp'],
                ssh=protocol_flags['ssh'],
                irc=protocol_flags.get('ftp', 0),  # Mapping FTP to IRC field
                mqtt=protocol_flags['mqtt'],
                coap=protocol_flags['coap'],
                dhcp=protocol_flags['dhcp'],
                tcp=tcp_flag,
                udp=udp_flag,
                icmp=icmp_flag,
                arp=arp_flag,
                igmp=igmp_flag,
                ipv=ipv_flag,
                
                # Packet size
                tot_size=int(raw_bytes) if raw_bytes else 0,
                
                # Timing
                iat=float(iat),
                
                # Metadata
                flow_id=str(flow_id),
                is_aggregated=False,
                packet_count_in_flow=1,
                
                # Keep raw data for debugging
                raw_data={'tshark': tshark_packet.get('tshark', {})} if logger.isEnabledFor(logging.DEBUG) else {}
            )
            
            self.packet_count += 1
            return record
            
        except Exception as e:
            logger.error(f"Failed to adapt packet: {e}", exc_info=True)
            return None
    
    def reset_stats(self):
        """Reset adapter statistics."""
        self.packet_count = 0
        self.last_timestamp = None
    
    def get_stats(self) -> Dict[str, Any]:
        """Get adapter statistics."""
        return {
            'total_packets_processed': self.packet_count,
            'last_timestamp': self.last_timestamp
        }


class BatchNetworkAdapter:
    """
    Batch adapter that processes multiple packets and maintains flow state.
    
    Useful for creating flow-level aggregations while streaming.
    """
    
    def __init__(self, flow_timeout: float = 120.0):
        """
        Initialize batch adapter.
        
        Args:
            flow_timeout: Time in seconds before a flow is considered inactive
        """
        self.adapter = NetworkAdapter()
        self.flows: Dict[str, list] = {}  # flow_id -> list of records
        self.flow_timeout = flow_timeout
        self.flow_last_seen: Dict[str, float] = {}
    
    def process_packet(self, tshark_packet: Dict[str, Any]) -> Optional[NetworkFeatureRecord]:
        """
        Process packet and add to flow tracking.
        
        Args:
            tshark_packet: Raw packet from TsharkCollector
            
        Returns:
            NetworkFeatureRecord for the packet
        """
        record = self.adapter.adapt_packet(tshark_packet)
        
        if record:
            flow_id = str(record.flow_id)
            
            # Initialize flow if new
            if flow_id not in self.flows:
                self.flows[flow_id] = []
            
            # Add packet to flow
            self.flows[flow_id].append(record)
            self.flow_last_seen[flow_id] = record.ts
            
            # Clean up old flows
            self._cleanup_old_flows(record.ts)
        
        return record
    
    def _cleanup_old_flows(self, current_time: float):
        """Remove flows that have timed out."""
        expired_flows = [
            flow_id for flow_id, last_seen in self.flow_last_seen.items()
            if current_time - last_seen > self.flow_timeout
        ]
        
        for flow_id in expired_flows:
            del self.flows[flow_id]
            del self.flow_last_seen[flow_id]
    
    def get_flow_packets(self, flow_id: str) -> list:
        """Get all packets for a specific flow."""
        return self.flows.get(flow_id, [])
    
    def get_all_flows(self) -> Dict[str, list]:
        """Get all active flows."""
        return self.flows.copy()
    
    def get_flow_count(self) -> int:
        """Get number of active flows."""
        return len(self.flows)
    
    def clear_flows(self):
        """Clear all flow tracking."""
        self.flows.clear()
        self.flow_last_seen.clear()


def create_adapter(batch_mode: bool = False, **kwargs) -> Union[NetworkAdapter, "BatchNetworkAdapter"]:
    """
    Factory function to create appropriate adapter.
    
    Args:
        batch_mode: If True, return BatchNetworkAdapter
        **kwargs: Additional arguments for adapter initialization
        
    Returns:
        NetworkAdapter or BatchNetworkAdapter instance
    """
    if batch_mode:
        return BatchNetworkAdapter(**kwargs)
    return NetworkAdapter()


if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)
    
    # Example packet from tshark
    example_packet = {
        'ts': 1698765432.123456,
        'src_ip': '192.168.1.100',
        'dst_ip': '8.8.8.8',
        'src_port': 52341,
        'dst_port': 443,
        'protocol': 'TCP',
        'raw_bytes': 1500,
        'ttl': 64,
        'tcp_flags': {
            'syn': True,
            'ack': False,
            'fin': False,
            'rst': False,
            'psh': False,
            'urg': False,
            'ece': False,
            'cwr': False
        }
    }
    
    adapter = NetworkAdapter()
    record = adapter.adapt_packet(example_packet)
    
    if record:
        print("Converted packet to feature record:")
        print(f"  Flow: {record.flow_id}")
        print(f"  Protocol: {record.protocol_type}")
        print(f"  HTTPS: {record.https}")
        print(f"  TCP: {record.tcp}")
        print(f"  SYN flag: {record.syn_flag_number}")
        print(f"  Size: {record.tot_size} bytes")
