"""
Windowing and aggregation for network traffic and system events.

Implements flow-based aggregation matching online_files/Feature_extraction.py
summarization logic with configurable time/count windows.
"""

import logging
from typing import Dict, List, Optional, Generator, Tuple
from collections import defaultdict
from dataclasses import dataclass
import numpy as np
from scipy import stats

from .network_features import NetworkFeatureRecord, FlowAggregator

logger = logging.getLogger(__name__)


@dataclass
class WindowConfig:
    """Configuration for windowing strategy."""
    time_window_seconds: float = 10.0  # Time-based window size
    packet_count_window: int = 10  # Packet count-based window
    flow_timeout: float = 120.0  # Flow inactivity timeout
    mode: str = "packet_count"  # "time", "packet_count", or "hybrid"


class FlowWindowAggregator:
    """
    Aggregates network packets into flow-level summary statistics.
    
    Mimics the windowing/summarization logic from Feature_extraction.pcap_evaluation
    where packets are grouped into flows and then summarized over windows.
    """
    
    def __init__(self, config: WindowConfig = None):
        """
        Initialize aggregator.
        
        Args:
            config: WindowConfig instance, defaults to packet_count mode with 10 packets
        """
        self.config = config or WindowConfig()
        self.flows: Dict[str, FlowAggregator] = {}
        self.packet_buffer: List[NetworkFeatureRecord] = []
        self.summary_count = 0
        
    def add_packet(self, record: NetworkFeatureRecord) -> Optional[NetworkFeatureRecord]:
        """
        Add packet to aggregation buffers.
        
        Args:
            record: NetworkFeatureRecord from adapter
            
        Returns:
            Aggregated NetworkFeatureRecord if window is complete, None otherwise
        """
        if record.is_aggregated:
            logger.warning("Received already-aggregated record, skipping")
            return None
        
        # Add to packet buffer
        self.packet_buffer.append(record)
        
        # Add to flow tracking
        flow_id = record.flow_id
        if flow_id not in self.flows:
            self.flows[flow_id] = FlowAggregator(
                flow_id=flow_id,
                first_ts=record.ts,
                last_ts=record.ts,
                src_ip=record.src_ip or "0.0.0.0",
                dst_ip=record.dst_ip or "0.0.0.0",
                src_port=record.src_port,
                dst_port=record.dst_port,
                protocol=record.protocol_type or "Unknown"
            )
        
        # Determine if this is forward or backward direction
        flow = self.flows[flow_id]
        is_forward = (record.src_ip == flow.src_ip and record.dst_ip == flow.dst_ip)
        flow.add_packet(record, is_forward=is_forward)
        
        # Check if window is complete
        if self._should_emit_window():
            return self._create_summary()
        
        return None
    
    def _should_emit_window(self) -> bool:
        """Determine if current window should be emitted."""
        if self.config.mode == "packet_count":
            return len(self.packet_buffer) >= self.config.packet_count_window
        
        elif self.config.mode == "time":
            if len(self.packet_buffer) < 2:
                return False
            time_span = self.packet_buffer[-1].ts - self.packet_buffer[0].ts
            return time_span >= self.config.time_window_seconds
        
        elif self.config.mode == "hybrid":
            # Emit on either condition
            if len(self.packet_buffer) >= self.config.packet_count_window:
                return True
            if len(self.packet_buffer) >= 2:
                time_span = self.packet_buffer[-1].ts - self.packet_buffer[0].ts
                return time_span >= self.config.time_window_seconds
        
        return False
    
    def _create_summary(self) -> NetworkFeatureRecord:
        """
        Create summarized feature record from current window.
        
        Implements the summary logic from Feature_extraction (lines 485-520).
        """
        if not self.packet_buffer:
            return None
        
        # Extract protocol mode (most common)
        protocols = [p.protocol_type for p in self.packet_buffer if p.protocol_type]
        protocol_mode = max(set(protocols), key=protocols.count) if protocols else "Unknown"
        
        # Aggregate flag counts
        ack_count = sum(p.ack_flag_number for p in self.packet_buffer)
        syn_count = sum(p.syn_flag_number for p in self.packet_buffer)
        fin_count = sum(p.fin_flag_number for p in self.packet_buffer)
        rst_count = sum(p.rst_flag_number for p in self.packet_buffer)
        psh_count = sum(p.psh_flag_number for p in self.packet_buffer)
        urg_count = sum(p.urg_flag_number for p in self.packet_buffer)
        
        # Calculate size statistics
        sizes = np.array([p.tot_size for p in self.packet_buffer if p.tot_size > 0])
        if len(sizes) == 0:
            sizes = np.array([0])
        
        total_sum = float(np.sum(sizes))
        min_size = float(np.min(sizes))
        max_size = float(np.max(sizes))
        mean_size = float(np.mean(sizes))
        std_size = float(np.std(sizes)) if len(sizes) > 1 else 0.0
        variance_size = float(np.var(sizes)) if len(sizes) > 1 else 0.0
        
        # Calculate timing
        timestamps = [p.ts for p in self.packet_buffer]
        duration = timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0
        
        # Aggregate protocol flags (take max to indicate presence)
        http = max(p.http for p in self.packet_buffer)
        https = max(p.https for p in self.packet_buffer)
        dns = max(p.dns for p in self.packet_buffer)
        telnet = max(p.telnet for p in self.packet_buffer)
        smtp = max(p.smtp for p in self.packet_buffer)
        ssh = max(p.ssh for p in self.packet_buffer)
        tcp = max(p.tcp for p in self.packet_buffer)
        udp = max(p.udp for p in self.packet_buffer)
        icmp = max(p.icmp for p in self.packet_buffer)
        arp = max(p.arp for p in self.packet_buffer)
        
        # Calculate rate
        rate = total_sum / duration if duration > 0 else 0
        
        # Calculate mean IAT
        iats = [p.iat for p in self.packet_buffer if p.iat > 0]
        mean_iat = float(np.mean(iats)) if iats else 0.0
        
        # Get representative IPs/ports from first packet
        first = self.packet_buffer[0]
        
        # Create summary record
        summary = NetworkFeatureRecord(
            ts=first.ts,
            src_ip=first.src_ip,
            dst_ip=first.dst_ip,
            src_port=first.src_port,
            dst_port=first.dst_port,
            protocol_type=protocol_mode,
            time_to_live=first.time_to_live,
            
            # Aggregated flags
            ack_count=ack_count,
            syn_count=syn_count,
            fin_count=fin_count,
            rst_count=rst_count,
            psh_flag_number=psh_count,
            urg_count=urg_count,
            
            # Protocol indicators
            http=http,
            https=https,
            dns=dns,
            telnet=telnet,
            smtp=smtp,
            ssh=ssh,
            tcp=tcp,
            udp=udp,
            icmp=icmp,
            arp=arp,
            
            # Statistics
            tot_sum=total_sum,
            min=min_size,
            max=max_size,
            avg=mean_size,
            std=std_size,
            variance=variance_size,
            tot_size=int(total_sum),
            number=len(self.packet_buffer),
            iat=mean_iat,
            rate=rate,
            flow_duration=duration,
            
            # Metadata
            is_aggregated=True,
            packet_count_in_flow=len(self.packet_buffer)
        )
        
        # Clear buffer for next window
        self.packet_buffer.clear()
        self.summary_count += 1
        
        logger.debug(f"Created summary {self.summary_count} with {summary.number} packets")
        
        return summary
    
    def flush(self) -> Optional[NetworkFeatureRecord]:
        """
        Force creation of summary from remaining buffered packets.
        
        Returns:
            Summary record if buffer is non-empty, None otherwise
        """
        if self.packet_buffer:
            return self._create_summary()
        return None
    
    def get_active_flows(self) -> Dict[str, FlowAggregator]:
        """Get dictionary of active flows."""
        return self.flows.copy()
    
    def cleanup_old_flows(self, current_time: float):
        """Remove flows that haven't seen packets recently."""
        expired = [
            flow_id for flow_id, flow in self.flows.items()
            if current_time - flow.last_ts > self.config.flow_timeout
        ]
        for flow_id in expired:
            del self.flows[flow_id]
        
        if expired:
            logger.info(f"Cleaned up {len(expired)} expired flows")
    
    def get_stats(self) -> Dict:
        """Get aggregator statistics."""
        return {
            'active_flows': len(self.flows),
            'buffered_packets': len(self.packet_buffer),
            'summaries_created': self.summary_count
        }


class StreamingWindowAggregator:
    """
    Streaming aggregator that yields summaries as they become available.
    
    Use this for live network capture -> feature extraction pipeline.
    """
    
    def __init__(self, config: WindowConfig = None):
        """Initialize streaming aggregator."""
        self.aggregator = FlowWindowAggregator(config)
    
    def process_stream(
        self,
        packet_stream: Generator[NetworkFeatureRecord, None, None]
    ) -> Generator[NetworkFeatureRecord, None, None]:
        """
        Process a stream of packets and yield aggregated summaries.
        
        Args:
            packet_stream: Generator yielding NetworkFeatureRecord objects
            
        Yields:
            Aggregated NetworkFeatureRecord objects
        """
        for packet in packet_stream:
            summary = self.aggregator.add_packet(packet)
            if summary:
                yield summary
        
        # Flush remaining
        final_summary = self.aggregator.flush()
        if final_summary:
            yield final_summary


def create_windowing_aggregator(
    mode: str = "packet_count",
    time_window: float = 10.0,
    packet_window: int = 10,
    flow_timeout: float = 120.0
) -> FlowWindowAggregator:
    """
    Factory function to create configured aggregator.
    
    Args:
        mode: "time", "packet_count", or "hybrid"
        time_window: Time window in seconds
        packet_window: Packet count window
        flow_timeout: Flow inactivity timeout in seconds
        
    Returns:
        Configured FlowWindowAggregator
    """
    config = WindowConfig(
        time_window_seconds=time_window,
        packet_count_window=packet_window,
        flow_timeout=flow_timeout,
        mode=mode
    )
    return FlowWindowAggregator(config)


if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)
    
    # Create some example packets
    from .network_features import NetworkFeatureRecord
    
    packets = [
        NetworkFeatureRecord(
            ts=1000.0 + i*0.1,
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=12345,
            dst_port=443,
            protocol_type="TCP",
            tot_size=1400 + i*10,
            syn_flag_number=1 if i == 0 else 0,
            ack_flag_number=1 if i > 0 else 0,
            https=1,
            tcp=1
        )
        for i in range(15)
    ]
    
    # Create aggregator with 10-packet window
    aggregator = create_windowing_aggregator(mode="packet_count", packet_window=10)
    
    summaries = []
    for pkt in packets:
        summary = aggregator.add_packet(pkt)
        if summary:
            summaries.append(summary)
            print(f"Summary: {summary.number} packets, {summary.tot_sum} bytes, "
                  f"avg={summary.avg:.1f}, std={summary.std:.1f}")
    
    # Flush remaining
    final = aggregator.flush()
    if final:
        summaries.append(final)
        print(f"Final summary: {final.number} packets")
    
    print(f"\nTotal summaries created: {len(summaries)}")
