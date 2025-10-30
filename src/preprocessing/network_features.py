"""
Network feature data structures.

Defines feature schemas matching the CIC IoT research feature set from online_files.
"""

from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any
from datetime import datetime


@dataclass
class NetworkFeatureRecord:
    """
    Complete network feature record matching CIC IoT feature extraction.
    
    Based on Feature_extraction columns from online_files research.
    Represents either per-packet or aggregated flow-level features.
    """
    
    # Temporal features
    ts: float  # Epoch timestamp
    
    # Basic connectivity features (from Connectivity_features.py)
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol_type: Optional[str] = None  # Protocol Type from get_protocol_name
    header_length: Optional[int] = None  # Header_Length
    time_to_live: Optional[int] = None  # Time_To_Live
    
    # Rate features
    rate: float = 0.0  # Rate
    
    # TCP Flag counts (individual packet flags)
    fin_flag_number: int = 0
    syn_flag_number: int = 0
    rst_flag_number: int = 0
    psh_flag_number: int = 0
    ack_flag_number: int = 0
    ece_flag_number: int = 0
    cwr_flag_number: int = 0
    urg_flag_number: int = 0
    
    # Flow-level flag counts (aggregated)
    ack_count: int = 0
    syn_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    urg_count: int = 0
    
    # Layered protocol detection (from Layered_features.py)
    http: int = 0
    https: int = 0
    dns: int = 0
    telnet: int = 0
    smtp: int = 0
    ssh: int = 0
    irc: int = 0
    tcp: int = 0
    udp: int = 0
    dhcp: int = 0
    arp: int = 0
    icmp: int = 0
    igmp: int = 0
    ipv: int = 0
    llc: int = 0
    mqtt: int = 0
    coap: int = 0
    
    # Dynamic/statistical features (from Dynamic_features.py)
    tot_sum: float = 0.0  # Tot sum - total bytes
    min: float = 0.0  # Min packet size
    max: float = 0.0  # Max packet size
    avg: float = 0.0  # AVG packet size
    std: float = 0.0  # Std deviation
    tot_size: int = 0  # Tot size - packet length
    iat: float = 0.0  # IAT - inter-arrival time
    number: int = 0  # Number of packets in window
    variance: float = 0.0  # Variance
    
    # Flow-level features (from get_flow_info)
    flow_duration: float = 0.0
    idle_time: float = 0.0
    active_time: float = 0.0
    
    # Bidirectional flow features (from get_src_dst_packets)
    src_to_dst_packets: int = 0
    dst_to_src_packets: int = 0
    src_to_dst_bytes: int = 0
    dst_to_src_bytes: int = 0
    
    # Two-stream correlation features (from dynamic_two_streams)
    magnitude: float = 0.0
    radius: float = 0.0
    correlation: float = 0.0
    covariance: float = 0.0
    var_ratio: float = 0.0
    weight: float = 0.0
    
    # Metadata
    flow_id: Optional[str] = None  # Unique flow identifier (src_ip:src_port-dst_ip:dst_port-proto)
    is_aggregated: bool = False  # True if this is a flow summary, False if per-packet
    packet_count_in_flow: int = 1  # Number of packets represented
    
    # Raw data reference
    raw_data: Dict[str, Any] = field(default_factory=dict)  # Store original tshark JSON if needed
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary, excluding raw_data by default."""
        d = asdict(self)
        if not self.raw_data:
            d.pop('raw_data', None)
        return d
    
    def to_csv_row(self) -> Dict[str, Any]:
        """
        Convert to CSV row format matching Feature_extraction columns.
        
        Columns: ["ts","Header_Length","Protocol Type","Time_To_Live","Rate", 
                  "fin_flag_number","syn_flag_number","rst_flag_number",
                  "psh_flag_number","ack_flag_number","ece_flag_number","cwr_flag_number",
                  "ack_count", "syn_count", "fin_count","rst_count",           
                  "HTTP", "HTTPS", "DNS", "Telnet","SMTP", "SSH", "IRC", "TCP", "UDP", 
                  "DHCP","ARP", "ICMP", "IGMP", "IPv", "LLC",
                  "Tot sum", "Min", "Max", "AVG", "Std","Tot size", "IAT", "Number", "Variance"]
        """
        return {
            "ts": self.ts,
            "Header_Length": self.header_length or 0,
            "Protocol Type": self.protocol_type or "Unknown",
            "Time_To_Live": self.time_to_live or 0,
            "Rate": self.rate,
            "fin_flag_number": self.fin_flag_number,
            "syn_flag_number": self.syn_flag_number,
            "rst_flag_number": self.rst_flag_number,
            "psh_flag_number": self.psh_flag_number,
            "ack_flag_number": self.ack_flag_number,
            "ece_flag_number": self.ece_flag_number,
            "cwr_flag_number": self.cwr_flag_number,
            "ack_count": self.ack_count,
            "syn_count": self.syn_count,
            "fin_count": self.fin_count,
            "rst_count": self.rst_count,
            "HTTP": self.http,
            "HTTPS": self.https,
            "DNS": self.dns,
            "Telnet": self.telnet,
            "SMTP": self.smtp,
            "SSH": self.ssh,
            "IRC": self.irc,
            "TCP": self.tcp,
            "UDP": self.udp,
            "DHCP": self.dhcp,
            "ARP": self.arp,
            "ICMP": self.icmp,
            "IGMP": self.igmp,
            "IPv": self.ipv,
            "LLC": self.llc,
            "Tot sum": self.tot_sum,
            "Min": self.min,
            "Max": self.max,
            "AVG": self.avg,
            "Std": self.std,
            "Tot size": self.tot_size,
            "IAT": self.iat,
            "Number": self.number,
            "Variance": self.variance
        }
    
    @staticmethod
    def get_csv_columns() -> list:
        """Get CSV column names in correct order."""
        return [
            "ts", "Header_Length", "Protocol Type", "Time_To_Live", "Rate",
            "fin_flag_number", "syn_flag_number", "rst_flag_number",
            "psh_flag_number", "ack_flag_number", "ece_flag_number", "cwr_flag_number",
            "ack_count", "syn_count", "fin_count", "rst_count",
            "HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC", "TCP", "UDP",
            "DHCP", "ARP", "ICMP", "IGMP", "IPv", "LLC",
            "Tot sum", "Min", "Max", "AVG", "Std", "Tot size", "IAT", "Number", "Variance"
        ]
    
    def generate_flow_id(self) -> str:
        """Generate unique flow identifier."""
        if self.src_ip and self.dst_ip:
            return f"{self.src_ip}:{self.src_port or 0}-{self.dst_ip}:{self.dst_port or 0}-{self.protocol_type or 'UNKNOWN'}"
        return f"unknown-{self.ts}"
    
    def __post_init__(self):
        """Post-initialization processing."""
        if not self.flow_id:
            self.flow_id = self.generate_flow_id()


@dataclass
class FlowAggregator:
    """
    Aggregates packets into flow-level statistics.
    
    Maintains running statistics for a single flow (src_ip:src_port -> dst_ip:dst_port).
    """
    
    flow_id: str
    first_ts: float
    last_ts: float
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    
    # Accumulators
    packet_count: int = 0
    total_bytes: int = 0
    packet_sizes: list = field(default_factory=list)
    inter_arrival_times: list = field(default_factory=list)
    
    # Flag counters
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    urg_count: int = 0
    
    # Direction tracking
    forward_packets: int = 0
    backward_packets: int = 0
    forward_bytes: int = 0
    backward_bytes: int = 0
    
    def add_packet(self, record: NetworkFeatureRecord, is_forward: bool = True):
        """Add a packet to this flow's statistics."""
        self.packet_count += 1
        self.last_ts = record.ts
        
        if record.tot_size:
            self.total_bytes += record.tot_size
            self.packet_sizes.append(record.tot_size)
        
        # Calculate IAT
        if self.packet_count > 1 and self.inter_arrival_times:
            iat = record.ts - self.last_ts
            self.inter_arrival_times.append(iat)
        
        # Accumulate flags
        self.syn_count += record.syn_flag_number
        self.ack_count += record.ack_flag_number
        self.fin_count += record.fin_flag_number
        self.rst_count += record.rst_flag_number
        self.psh_count += record.psh_flag_number
        self.urg_count += record.urg_flag_number
        
        # Track direction
        if is_forward:
            self.forward_packets += 1
            self.forward_bytes += record.tot_size
        else:
            self.backward_packets += 1
            self.backward_bytes += record.tot_size
    
    def to_feature_record(self) -> NetworkFeatureRecord:
        """Convert aggregated flow to NetworkFeatureRecord."""
        import numpy as np
        
        # Calculate statistics
        sizes_array = np.array(self.packet_sizes) if self.packet_sizes else np.array([0])
        iat_array = np.array(self.inter_arrival_times) if self.inter_arrival_times else np.array([0])
        
        duration = self.last_ts - self.first_ts
        rate = self.total_bytes / duration if duration > 0 else 0
        
        return NetworkFeatureRecord(
            ts=self.first_ts,
            src_ip=self.src_ip,
            dst_ip=self.dst_ip,
            src_port=self.src_port,
            dst_port=self.dst_port,
            protocol_type=self.protocol,
            flow_id=self.flow_id,
            
            # Aggregated counts
            syn_count=self.syn_count,
            ack_count=self.ack_count,
            fin_count=self.fin_count,
            rst_count=self.rst_count,
            urg_count=self.urg_count,
            
            # Statistics
            tot_sum=float(np.sum(sizes_array)),
            min=float(np.min(sizes_array)),
            max=float(np.max(sizes_array)),
            avg=float(np.mean(sizes_array)),
            std=float(np.std(sizes_array)),
            variance=float(np.var(sizes_array)),
            tot_size=self.total_bytes,
            number=self.packet_count,
            
            # Timing
            iat=float(np.mean(iat_array)) if len(iat_array) > 0 else 0,
            flow_duration=duration,
            rate=rate,
            
            # Bidirectional
            src_to_dst_packets=self.forward_packets,
            dst_to_src_packets=self.backward_packets,
            src_to_dst_bytes=self.forward_bytes,
            dst_to_src_bytes=self.backward_bytes,
            
            is_aggregated=True,
            packet_count_in_flow=self.packet_count
        )
