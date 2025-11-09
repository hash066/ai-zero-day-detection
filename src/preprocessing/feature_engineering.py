"""
Advanced feature engineering for zero-day detection.

Implements entropy calculations, behavioral patterns, temporal features,
and anomaly indicators critical for detecting unknown threats.
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional
from collections import Counter
from scipy import stats
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EntropyFeatureExtractor:
    """Calculate entropy-based features for anomaly detection."""
    
    @staticmethod
    def shannon_entropy(data: List[Any]) -> float:
        """
        Calculate Shannon entropy of a sequence.
        High entropy indicates randomness (potential encryption/obfuscation).
        
        Args:
            data: List of values to calculate entropy from
            
        Returns:
            Shannon entropy value
        """
        if not data:
            return 0.0
        
        # Count occurrences
        counter = Counter(data)
        total = len(data)
        
        # Calculate entropy
        entropy = 0.0
        for count in counter.values():
            prob = count / total
            if prob > 0:
                entropy -= prob * np.log2(prob)
        
        return entropy
    
    @staticmethod
    def port_entropy(src_ports: List[int], dst_ports: List[int]) -> Dict[str, float]:
        """
        Calculate port usage entropy.
        Port scanning shows high entropy in destination ports.
        
        Args:
            src_ports: List of source ports
            dst_ports: List of destination ports
            
        Returns:
            Dictionary with src_port_entropy and dst_port_entropy
        """
        return {
            'src_port_entropy': EntropyFeatureExtractor.shannon_entropy(src_ports),
            'dst_port_entropy': EntropyFeatureExtractor.shannon_entropy(dst_ports),
        }
    
    @staticmethod
    def ip_entropy(src_ips: List[str], dst_ips: List[str]) -> Dict[str, float]:
        """
        Calculate IP address entropy.
        DDoS and scanning show high destination IP entropy.
        
        Args:
            src_ips: List of source IPs
            dst_ips: List of destination IPs
            
        Returns:
            Dictionary with src_ip_entropy and dst_ip_entropy
        """
        return {
            'src_ip_entropy': EntropyFeatureExtractor.shannon_entropy(src_ips),
            'dst_ip_entropy': EntropyFeatureExtractor.shannon_entropy(dst_ips),
        }
    
    @staticmethod
    def packet_size_entropy(sizes: List[int]) -> float:
        """
        Calculate packet size entropy.
        Tunneling/covert channels often show abnormal size patterns.
        """
        if not sizes:
            return 0.0
        
        # Bin sizes into ranges for entropy calculation
        bins = [0, 64, 128, 256, 512, 1024, 1500, 2048, 4096, float('inf')]
        binned = np.digitize(sizes, bins)
        
        return EntropyFeatureExtractor.shannon_entropy(binned.tolist())


class TemporalFeatureExtractor:
    """Extract time-based behavioral features."""
    
    @staticmethod
    def extract_temporal_features(timestamps: List[float]) -> Dict[str, float]:
        """
        Extract temporal patterns that indicate anomalies.
        
        Args:
            timestamps: List of event timestamps (epoch seconds)
            
        Returns:
            Dictionary of temporal features
        """
        if len(timestamps) < 2:
            return {
                'mean_inter_arrival': 0.0,
                'std_inter_arrival': 0.0,
                'cv_inter_arrival': 0.0,  # Coefficient of variation
                'burstiness': 0.0,
                'periodicity_score': 0.0,
            }
        
        # Calculate inter-arrival times
        sorted_ts = sorted(timestamps)
        iats = np.diff(sorted_ts)
        
        mean_iat = np.mean(iats)
        std_iat = np.std(iats)
        
        # Coefficient of variation (regularity measure)
        cv = std_iat / mean_iat if mean_iat > 0 else 0.0
        
        # Burstiness index: B = (std - mean) / (std + mean)
        # B → 1: bursty, B → 0: periodic, B → -1: regular
        burstiness = (std_iat - mean_iat) / (std_iat + mean_iat) if (std_iat + mean_iat) > 0 else 0.0
        
        # Detect periodicity using autocorrelation
        periodicity = 0.0
        if len(iats) > 10:
            try:
                # Normalize IATs
                normalized = (iats - np.mean(iats)) / (np.std(iats) + 1e-10)
                # Autocorrelation at lag 1
                autocorr = np.correlate(normalized[:-1], normalized[1:], mode='valid')
                periodicity = float(np.mean(autocorr))
            except Exception:
                periodicity = 0.0
        
        return {
            'mean_inter_arrival': float(mean_iat),
            'std_inter_arrival': float(std_iat),
            'cv_inter_arrival': float(cv),
            'burstiness': float(burstiness),
            'periodicity_score': float(periodicity),
        }
    
    @staticmethod
    def time_of_day_features(timestamps: List[float]) -> Dict[str, float]:
        """
        Extract time-of-day patterns.
        Attacks often occur at unusual hours.
        
        Args:
            timestamps: List of epoch timestamps
            
        Returns:
            Dictionary with hour distribution features
        """
        if not timestamps:
            return {
                'peak_hour': 0,
                'off_hours_ratio': 0.0,  # Ratio during 22:00-06:00
                'hour_entropy': 0.0,
            }
        
        # Convert to hours (0-23)
        hours = [int((ts % 86400) / 3600) for ts in timestamps]
        
        # Peak hour
        hour_counter = Counter(hours)
        peak_hour = hour_counter.most_common(1)[0][0] if hour_counter else 0
        
        # Off-hours ratio (10 PM to 6 AM)
        off_hours = sum(1 for h in hours if h >= 22 or h < 6)
        off_hours_ratio = off_hours / len(hours) if hours else 0.0
        
        # Hour entropy
        hour_entropy = EntropyFeatureExtractor.shannon_entropy(hours)
        
        return {
            'peak_hour': peak_hour,
            'off_hours_ratio': off_hours_ratio,
            'hour_entropy': hour_entropy,
        }


class BehavioralFeatureExtractor:
    """Extract behavioral patterns for anomaly detection."""
    
    @staticmethod
    def connection_patterns(df: pd.DataFrame) -> Dict[str, float]:
        """
        Analyze connection patterns for anomalies.
        
        Args:
            df: DataFrame with network events (must have src_ip, dst_ip, protocol columns)
            
        Returns:
            Dictionary of connection pattern features
        """
        if df.empty:
            return {
                'unique_src_ips': 0,
                'unique_dst_ips': 0,
                'unique_protocols': 0,
                'connection_diversity': 0.0,  # Ratio of unique connections
                'fan_out_ratio': 0.0,  # Avg destinations per source
                'fan_in_ratio': 0.0,   # Avg sources per destination
            }
        
        unique_src = df['src_ip'].nunique() if 'src_ip' in df.columns else 0
        unique_dst = df['dst_ip'].nunique() if 'dst_ip' in df.columns else 0
        unique_proto = df['protocol_type'].nunique() if 'protocol_type' in df.columns else 0
        
        # Connection diversity
        total_connections = len(df)
        try:
            unique_connections = len(df.drop_duplicates(subset=['src_ip', 'dst_ip']))
        except KeyError:
            unique_connections = total_connections
        diversity = unique_connections / total_connections if total_connections > 0 else 0.0
        
        # Fan-out/fan-in ratios (scanning indicators)
        fan_out = unique_dst / unique_src if unique_src > 0 else 0.0
        fan_in = unique_src / unique_dst if unique_dst > 0 else 0.0
        
        return {
            'unique_src_ips': unique_src,
            'unique_dst_ips': unique_dst,
            'unique_protocols': unique_proto,
            'connection_diversity': diversity,
            'fan_out_ratio': fan_out,
            'fan_in_ratio': fan_in,
        }
    
    @staticmethod
    def protocol_anomaly_score(df: pd.DataFrame) -> Dict[str, float]:
        """
        Calculate protocol usage anomaly scores.
        
        Args:
            df: DataFrame with protocol information
            
        Returns:
            Dictionary with protocol anomaly indicators
        """
        if df.empty or 'protocol_type' not in df.columns:
            return {
                'rare_protocol_ratio': 0.0,
                'protocol_switching_rate': 0.0,
            }
        
        # Rare protocol detection
        protocol_counts = df['protocol_type'].value_counts()
        total = len(df)
        rare_threshold = 0.05  # Less than 5% is considered rare
        
        rare_count = sum(1 for count in protocol_counts.values if count / total < rare_threshold)
        rare_ratio = rare_count / total if total > 0 else 0.0
        
        # Protocol switching rate (consecutive different protocols)
        if len(df) > 1 and 'protocol_type' in df.columns:
            protocols = df['protocol_type'].tolist()
            switches = sum(1 for i in range(len(protocols) - 1) 
                          if protocols[i] != protocols[i+1])
            switching_rate = switches / (len(df) - 1)
        else:
            switching_rate = 0.0
        
        return {
            'rare_protocol_ratio': rare_ratio,
            'protocol_switching_rate': switching_rate,
        }
    
    @staticmethod
    def payload_size_anomalies(sizes: List[int]) -> Dict[str, float]:
        """
        Detect payload size anomalies.
        
        Args:
            sizes: List of packet/payload sizes
            
        Returns:
            Dictionary with size anomaly features
        """
        if not sizes or len(sizes) < 2:
            return {
                'size_mean': 0.0,
                'size_std': 0.0,
                'size_skewness': 0.0,
                'size_kurtosis': 0.0,
                'small_packet_ratio': 0.0,  # < 60 bytes
                'large_packet_ratio': 0.0,  # > 1400 bytes
            }
        
        sizes_array = np.array(sizes)
        
        return {
            'size_mean': float(np.mean(sizes_array)),
            'size_std': float(np.std(sizes_array)),
            'size_skewness': float(stats.skew(sizes_array)),
            'size_kurtosis': float(stats.kurtosis(sizes_array)),
            'small_packet_ratio': float(np.sum(sizes_array < 60) / len(sizes_array)),
            'large_packet_ratio': float(np.sum(sizes_array > 1400) / len(sizes_array)),
        }


class SysmonBehavioralExtractor:
    """Extract behavioral features from Sysmon logs for process-level anomaly detection."""
    
    @staticmethod
    def process_features(df: pd.DataFrame) -> Dict[str, Any]:
        """
        Extract process behavior features from Sysmon data.
        
        Args:
            df: DataFrame with Sysmon events
            
        Returns:
            Dictionary of process-level features
        """
        if df.empty:
            return {
                'unique_processes': 0,
                'unique_users': 0,
                'suspicious_port_connections': 0,
                'external_connections': 0,
                'connection_rate': 0.0,
            }
        
        # Count unique processes and users
        unique_procs = df['image'].nunique() if 'image' in df.columns else 0
        unique_users = df['user'].nunique() if 'user' in df.columns else 0
        
        # Detect suspicious behavior
        suspicious_ports = 0
        external_connections = 0
        
        if 'destinationport' in df.columns:
            # Common malware ports
            malware_ports = {4444, 31337, 12345, 54321, 6666, 6667, 6668, 6669}
            suspicious_ports = df['destinationport'].isin(malware_ports).sum()
        
        if 'destinationip' in df.columns:
            # External (non-RFC1918) connections
            def is_external(ip):
                if pd.isna(ip):
                    return False
                ip_str = str(ip)
                return not (ip_str.startswith('192.168.') or 
                           ip_str.startswith('10.') or 
                           ip_str.startswith('172.'))
            
            external_connections = df['destinationip'].apply(is_external).sum()
        
        # Connection rate
        if 'timestamp' in df.columns and len(df) > 1:
            time_span = (df['timestamp'].max() - df['timestamp'].min()).total_seconds()
            connection_rate = len(df) / time_span if time_span > 0 else 0.0
        else:
            connection_rate = 0.0
        
        return {
            'unique_processes': unique_procs,
            'unique_users': unique_users,
            'suspicious_port_connections': int(suspicious_ports),
            'external_connections': int(external_connections),
            'connection_rate': float(connection_rate),
        }


def extract_all_features(network_df: pd.DataFrame, sysmon_df: Optional[pd.DataFrame] = None) -> pd.DataFrame:
    """
    Extract all engineered features for zero-day detection.
    
    Args:
        network_df: DataFrame with network features
        sysmon_df: Optional DataFrame with Sysmon events
        
    Returns:
        DataFrame with all engineered features added
    """
    logger.info("Starting comprehensive feature engineering...")
    
    result_df = network_df.copy()
    
    # Entropy features
    if 'src_port' in network_df.columns and 'dst_port' in network_df.columns:
        port_ent = EntropyFeatureExtractor.port_entropy(
            network_df['src_port'].dropna().tolist(),
            network_df['dst_port'].dropna().tolist()
        )
        result_df['src_port_entropy'] = port_ent['src_port_entropy']
        result_df['dst_port_entropy'] = port_ent['dst_port_entropy']
    
    if 'src_ip' in network_df.columns and 'dst_ip' in network_df.columns:
        ip_ent = EntropyFeatureExtractor.ip_entropy(
            network_df['src_ip'].dropna().tolist(),
            network_df['dst_ip'].dropna().tolist()
        )
        result_df['src_ip_entropy'] = ip_ent['src_ip_entropy']
        result_df['dst_ip_entropy'] = ip_ent['dst_ip_entropy']
    
    if 'tot_size' in network_df.columns:
        result_df['packet_size_entropy'] = EntropyFeatureExtractor.packet_size_entropy(
            network_df['tot_size'].dropna().tolist()
        )
    
    # Temporal features
    if 'ts' in network_df.columns:
        temporal = TemporalFeatureExtractor.extract_temporal_features(
            network_df['ts'].tolist()
        )
        for key, value in temporal.items():
            result_df[key] = value
        
        time_of_day = TemporalFeatureExtractor.time_of_day_features(
            network_df['ts'].tolist()
        )
        for key, value in time_of_day.items():
            result_df[key] = value
    
    # Behavioral features
    conn_patterns = BehavioralFeatureExtractor.connection_patterns(network_df)
    for key, value in conn_patterns.items():
        result_df[key] = value
    
    proto_anomaly = BehavioralFeatureExtractor.protocol_anomaly_score(network_df)
    for key, value in proto_anomaly.items():
        result_df[key] = value
    
    if 'tot_size' in network_df.columns:
        payload_anomalies = BehavioralFeatureExtractor.payload_size_anomalies(
            network_df['tot_size'].dropna().tolist()
        )
        for key, value in payload_anomalies.items():
            result_df[key] = value
    
    # Sysmon features (if provided)
    if sysmon_df is not None and not sysmon_df.empty:
        sysmon_features = SysmonBehavioralExtractor.process_features(sysmon_df)
        for key, value in sysmon_features.items():
            result_df[f'sysmon_{key}'] = value
    
    logger.info(f"Feature engineering complete. Added {len(result_df.columns) - len(network_df.columns)} new features.")
    
    return result_df


if __name__ == "__main__":
    # Example usage
    print("Feature Engineering Module for Zero-Day Detection")
    print("=" * 60)
    
    # Create sample data
    sample_data = pd.DataFrame({
        'ts': [1000.0 + i * 0.5 for i in range(100)],
        'src_ip': ['192.168.1.10'] * 50 + ['192.168.1.20'] * 50,
        'dst_ip': [f'10.0.0.{i % 10}' for i in range(100)],
        'src_port': [12345 + i for i in range(100)],
        'dst_port': [80] * 70 + [443] * 20 + [22] * 10,
        'protocol_type': ['TCP'] * 80 + ['UDP'] * 20,
        'tot_size': [1400 + np.random.randint(-200, 200) for i in range(100)],
    })
    
    complete_data = pd.read_csv("")
    
    # Extract features
    enriched = extract_all_features(sample_data)
    
    print(f"\nOriginal features: {len(sample_data.columns)}")
    print(f"Enriched features: {len(enriched.columns)}")
    print(f"\nNew features added:")
    new_features = set(enriched.columns) - set(sample_data.columns)
    for feat in sorted(new_features):
        print(f"  - {feat}")