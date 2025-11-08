"""
Feature extraction from tshark JSON data.

Processes packet data from TsharkCollector, aggregates it into flows,
and generates NetworkFeatureRecord objects for ML training.
"""

import json
from collections import defaultdict
from typing import Dict, List, Optional, Any, Generator

import numpy as np

# Assuming network_features.py is in the same directory or accessible
from .network_features import NetworkFeatureRecord, FlowAggregator


class TsharkFeatureExtractor:
    """
    Extracts features from tshark JSON output.

    Processes normalized packet dictionaries from TsharkCollector and
    aggregates them into flows, producing NetworkFeatureRecord objects.
    """

    def __init__(self, flow_timeout_seconds: int = 120):
        """
        Initialize the feature extractor.

        Args:
            flow_timeout_seconds: Time in seconds to wait before flushing an inactive flow.
        """
        self.flow_timeout = flow_timeout_seconds
        self.active_flows: Dict[str, FlowAggregator] = {}

    def process_packet(self, packet: Dict[str, Any]) -> None:
        """
        Process a single packet and update flow statistics.

        Args:
            packet: A normalized packet dictionary from TsharkCollector.
        """
        # Basic validation
        if not all(k in packet for k in ["ts", "src_ip", "dst_ip", "protocol"]):
            return

        # Create a partial NetworkFeatureRecord from the packet
        record = self._packet_to_record(packet)

        # Generate flow IDs for forward and backward directions
        flow_id = self._generate_flow_id(record)
        
        # Check if packet belongs to an existing flow
        aggregator = self.active_flows.get(flow_id)

        # Determine if the packet is in the "forward" direction relative to the flow's start
        is_forward = (aggregator is not None and 
                      record.src_ip == aggregator.src_ip and 
                      record.dst_ip == aggregator.dst_ip)

        if aggregator:
            # Add packet to existing flow
            aggregator.add_packet(record, is_forward=is_forward)
        else:
            # Create a new flow aggregator
            aggregator = FlowAggregator(
                flow_id=flow_id,
                first_ts=record.ts,
                last_ts=record.ts,
                src_ip=str(record.src_ip or ""),
                dst_ip=str(record.dst_ip or ""),
                src_port=int(record.src_port or 0),
                dst_port=int(record.dst_port or 0),
                protocol=str(record.protocol_type or ""),
            )
            aggregator.add_packet(record, is_forward=True)
            self.active_flows[flow_id] = aggregator

    def flush_inactive_flows(self, current_timestamp: float) -> Generator[NetworkFeatureRecord, None, None]:
        """
        Flush flows that have been inactive for longer than the timeout.

        Args:
            current_timestamp: The current timestamp to compare against.

        Yields:
            NetworkFeatureRecord for each flushed flow.
        """
        inactive_flow_ids = []
        for flow_id, aggregator in self.active_flows.items():
            if current_timestamp - aggregator.last_ts > self.flow_timeout:
                yield aggregator.to_feature_record()
                inactive_flow_ids.append(flow_id)

        for flow_id in inactive_flow_ids:
            if flow_id in self.active_flows:
                del self.active_flows[flow_id]

    def flush_all_flows(self) -> Generator[NetworkFeatureRecord, None, None]:
        """Flush all remaining flows."""
        for flow_id, aggregator in self.active_flows.items():
            yield aggregator.to_feature_record()
        self.active_flows.clear()

    def _packet_to_record(self, packet: Dict[str, Any]) -> NetworkFeatureRecord:
        """Convert a tshark packet dictionary to a NetworkFeatureRecord."""
        tcp_flags = packet.get("tcp_flags", {})
        
        return NetworkFeatureRecord(
            ts=packet["ts"],
            src_ip=packet.get("src_ip"),
            dst_ip=packet.get("dst_ip"),
            src_port=packet.get("src_port"),
            dst_port=packet.get("dst_port"),
            protocol_type=packet.get("protocol"),
            header_length=packet.get("tshark", {}).get("_source", {}).get("layers", {}).get("ip", {}).get("ip.hdr_len", [0])[0],
            time_to_live=packet.get("ttl"),
            
            # TCP flags from normalized collector output
            fin_flag_number=int(tcp_flags.get("fin", False)),
            syn_flag_number=int(tcp_flags.get("syn", False)),
            rst_flag_number=int(tcp_flags.get("rst", False)),
            psh_flag_number=int(tcp_flags.get("psh", False)),
            ack_flag_number=int(tcp_flags.get("ack", False)),
            ece_flag_number=int(tcp_flags.get("ece", False)),
            cwr_flag_number=int(tcp_flags.get("cwr", False)),
            urg_flag_number=int(tcp_flags.get("urg", False)),

            tot_size=packet.get("raw_bytes", 0),
            
            # Set protocol flags
            http=1 if packet.get("protocol") == "HTTP" else 0,
            https=1 if packet.get("protocol") in ["HTTPS", "TLS"] else 0,
            dns=1 if packet.get("protocol") == "DNS" else 0,
            telnet=1 if packet.get("protocol") == "Telnet" else 0,
            smtp=1 if packet.get("protocol") == "SMTP" else 0,
            ssh=1 if packet.get("protocol") == "SSH" else 0,
            irc=1 if packet.get("protocol") == "IRC" else 0,
            tcp=1 if packet.get("protocol") == "TCP" else 0,
            udp=1 if packet.get("protocol") == "UDP" else 0,
            dhcp=1 if packet.get("protocol") == "DHCP" else 0,
            arp=1 if packet.get("protocol") == "ARP" else 0,
            icmp=1 if packet.get("protocol") == "ICMP" else 0,
            igmp=1 if packet.get("protocol") == "IGMP" else 0,
            ipv=1 if packet.get("ip_version") in [4, 6] else 0,
            mqtt=1 if packet.get("protocol") == "MQTT" else 0,
            coap=1 if packet.get("protocol") == "CoAP" else 0,
        )

    def _generate_flow_id(self, record: NetworkFeatureRecord) -> str:
        """Generate a canonical flow ID to make it direction-independent."""
        ip1, port1 = (record.src_ip, record.src_port)
        ip2, port2 = (record.dst_ip, record.dst_port)
        
        # Sort by IP and port to ensure consistency
        if (str(ip1), int(port1 or 0)) > (str(ip2), int(port2 or 0)):
            ip1, port1, ip2, port2 = ip2, port2, ip1, port1

        return f"{ip1}:{port1}-{ip2}:{port2}-{record.protocol_type}"

def main():
    """Example usage of TsharkFeatureExtractor."""
    # This main function is for demonstration.
    # It requires a collector to stream packets.
    #
    # Example with TsharkCollector (requires a pcap file):
    #
    # from ..collectors.tshark_collector import TsharkCollector
    # import logging
    #
    # logging.basicConfig(level=logging.INFO)
    # pcap_path = 'data/sample.pcap' # You need to provide a sample pcap
    #
    # try:
    #     collector = TsharkCollector(pcap_file=pcap_path)
    #     extractor = TsharkFeatureExtractor(flow_timeout_seconds=60)
    #
    #     for packet in collector.stream_packets():
    #         extractor.process_packet(packet)
    #
    #     print("--- Flushing all flows ---")
    #     flow_records = list(extractor.flush_all_flows())
    #
    #     if flow_records:
    #         print(f"Extracted {len(flow_records)} flows.")
    #         first_flow = flow_records[0].to_dict()
    #         print("\n--- First Flow Feature Record ---")
    #         for key, value in first_flow.items():
    #             print(f"  {key}: {value}")
    #
    # except FileNotFoundError:
    #     print(f"Error: Pcap file not found at '{pcap_path}'")
    # except Exception as e:
    #     print(f"An error occurred: {e}")
    pass

if __name__ == '__main__':
    main()