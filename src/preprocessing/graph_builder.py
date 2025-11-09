"""
Graph builder for GNN-based zero-day detection.

Constructs network graphs from traffic and system logs for Graph Neural Network
analysis. Nodes represent hosts/processes, edges represent connections/communications.
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Optional, Any, Set
from collections import defaultdict
from dataclasses import dataclass
import logging
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class GraphNode:
    """Represents a node in the network graph (host/process)."""
    node_id: str
    node_type: str  # 'host', 'process', 'external'
    ip_address: Optional[str] = None
    process_name: Optional[str] = None
    features: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.features is None:
            self.features = {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'node_id': self.node_id,
            'node_type': self.node_type,
            'ip_address': self.ip_address,
            'process_name': self.process_name,
            'features': self.features
        }


@dataclass
class GraphEdge:
    """Represents an edge (connection) in the network graph."""
    source: str
    target: str
    edge_type: str  # 'network', 'process', 'parent_child'
    weight: float = 1.0
    features: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.features is None:
            self.features = {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'source': self.source,
            'target': self.target,
            'edge_type': self.edge_type,
            'weight': self.weight,
            'features': self.features
        }


class NetworkGraphBuilder:
    """
    Builds network communication graphs from traffic data.
    
    Nodes: IP addresses (hosts)
    Edges: Network flows between hosts with aggregated statistics
    """
    
    def __init__(self):
        """Initialize graph builder."""
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: Dict[Tuple[str, str], GraphEdge] = {}
        self.node_features = defaultdict(lambda: {
            'total_bytes_sent': 0,
            'total_bytes_received': 0,
            'unique_destinations': set(),
            'unique_sources': set(),
            'protocols_used': set(),
            'port_scan_score': 0.0,
            'connection_count': 0,
        })
    
    def add_network_flow(self, flow_record: Dict[str, Any]):
        """
        Add a network flow to the graph.
        
        Args:
            flow_record: Dictionary with src_ip, dst_ip, and flow features
        """
        src_ip = str(flow_record.get('src_ip', 'unknown'))
        dst_ip = str(flow_record.get('dst_ip', 'unknown'))
        
        if src_ip == 'unknown' or dst_ip == 'unknown':
            return
        
        # Create or update nodes
        self._ensure_node(src_ip, 'host')
        self._ensure_node(dst_ip, self._classify_node_type(dst_ip))
        
        # Update node features
        bytes_sent = flow_record.get('tot_size', 0) or flow_record.get('src_to_dst_bytes', 0)
        bytes_recv = flow_record.get('dst_to_src_bytes', 0)
        protocol = flow_record.get('protocol_type', 'unknown')
        dst_port = flow_record.get('dst_port')
        
        self.node_features[src_ip]['total_bytes_sent'] += bytes_sent
        self.node_features[src_ip]['unique_destinations'].add(dst_ip)
        self.node_features[src_ip]['protocols_used'].add(protocol)
        self.node_features[src_ip]['connection_count'] += 1
        
        self.node_features[dst_ip]['total_bytes_received'] += bytes_sent
        self.node_features[dst_ip]['unique_sources'].add(src_ip)
        self.node_features[dst_ip]['protocols_used'].add(protocol)
        
        # Calculate port scan score (many unique dst ports from same source)
        if dst_port:
            if 'dst_ports' not in self.node_features[src_ip]:
                self.node_features[src_ip]['dst_ports'] = set()
            self.node_features[src_ip]['dst_ports'].add(dst_port)
            
            # Port scan score: unique ports / unique destinations
            unique_ports = len(self.node_features[src_ip].get('dst_ports', set()))
            unique_dests = len(self.node_features[src_ip]['unique_destinations'])
            self.node_features[src_ip]['port_scan_score'] = unique_ports / max(unique_dests, 1)
        
        # Create or update edge
        edge_key = (src_ip, dst_ip)
        if edge_key in self.edges:
            edge = self.edges[edge_key]
            edge.weight += 1
            edge.features['total_bytes'] = edge.features.get('total_bytes', 0) + bytes_sent
            edge.features['packet_count'] = edge.features.get('packet_count', 0) + 1
            edge.features['protocols'].add(protocol)
        else:
            self.edges[edge_key] = GraphEdge(
                source=src_ip,
                target=dst_ip,
                edge_type='network',
                weight=1.0,
                features={
                    'total_bytes': bytes_sent,
                    'packet_count': 1,
                    'protocols': {protocol},
                    'first_seen': flow_record.get('ts', 0),
                    'last_seen': flow_record.get('ts', 0),
                    'dst_port': dst_port,
                }
            )
    
    def _ensure_node(self, node_id: str, node_type: str):
        """Ensure node exists in graph."""
        if node_id not in self.nodes:
            self.nodes[node_id] = GraphNode(
                node_id=node_id,
                node_type=node_type,
                ip_address=node_id if self._is_ip(node_id) else None
            )
    
    @staticmethod
    def _is_ip(addr: str) -> bool:
        """Check if string is an IP address."""
        parts = addr.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
    
    @staticmethod
    def _classify_node_type(ip: str) -> str:
        """Classify node as internal or external based on IP."""
        # RFC1918 private addresses
        if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
            return 'host'
        return 'external'
    
    def finalize_graph(self):
        """Finalize graph by computing aggregate features for all nodes."""
        logger.info(f"Finalizing graph with {len(self.nodes)} nodes and {len(self.edges)} edges")
        
        for node_id, node in self.nodes.items():
            feats = self.node_features[node_id]
            
            # Convert sets to counts
            node.features = {
                'total_bytes_sent': feats['total_bytes_sent'],
                'total_bytes_received': feats['total_bytes_received'],
                'unique_destinations': len(feats['unique_destinations']),
                'unique_sources': len(feats['unique_sources']),
                'protocols_used': len(feats['protocols_used']),
                'port_scan_score': feats['port_scan_score'],
                'connection_count': feats['connection_count'],
                'in_degree': 0,
                'out_degree': 0,
                'betweenness': 0.0,  # Placeholder for centrality metrics
            }
        
        # Calculate degrees
        for edge in self.edges.values():
            if edge.source in self.nodes:
                self.nodes[edge.source].features['out_degree'] += 1
            if edge.target in self.nodes:
                self.nodes[edge.target].features['in_degree'] += 1
        
        # Convert set features in edges to lists/counts
        for edge in self.edges.values():
            if 'protocols' in edge.features and isinstance(edge.features['protocols'], set):
                edge.features['protocol_count'] = len(edge.features['protocols'])
                edge.features['protocols'] = list(edge.features['protocols'])
    
    def to_adjacency_matrix(self) -> Tuple[np.ndarray, List[str]]:
        """
        Convert graph to adjacency matrix for GNN input.
        
        Returns:
            Tuple of (adjacency_matrix, node_id_list)
        """
        node_ids = sorted(self.nodes.keys())
        n = len(node_ids)
        node_idx = {nid: i for i, nid in enumerate(node_ids)}
        
        adj_matrix = np.zeros((n, n), dtype=np.float32)
        
        for edge in self.edges.values():
            if edge.source in node_idx and edge.target in node_idx:
                i = node_idx[edge.source]
                j = node_idx[edge.target]
                adj_matrix[i, j] = edge.weight
        
        return adj_matrix, node_ids
    
    def to_edge_index(self) -> Tuple[np.ndarray, np.ndarray, List[str]]:
        """
        Convert graph to edge index format (for PyTorch Geometric).
        
        Returns:
            Tuple of (edge_index, edge_weights, node_id_list)
        """
        node_ids = sorted(self.nodes.keys())
        node_idx = {nid: i for i, nid in enumerate(node_ids)}
        
        edge_list = []
        edge_weights = []
        
        for edge in self.edges.values():
            if edge.source in node_idx and edge.target in node_idx:
                src_idx = node_idx[edge.source]
                dst_idx = node_idx[edge.target]
                edge_list.append([src_idx, dst_idx])
                edge_weights.append(edge.weight)
        
        edge_index = np.array(edge_list, dtype=np.int64).T if edge_list else np.zeros((2, 0), dtype=np.int64)
        edge_weights = np.array(edge_weights, dtype=np.float32) if edge_weights else np.array([])
        
        return edge_index, edge_weights, node_ids
    
    def get_node_feature_matrix(self) -> Tuple[np.ndarray, List[str], List[str]]:
        """
        Extract node feature matrix for GNN.
        
        Returns:
            Tuple of (feature_matrix, node_id_list, feature_names)
        """
        node_ids = sorted(self.nodes.keys())
        
        if not node_ids:
            return np.array([]), [], []
        
        # Define feature order
        feature_names = [
            'total_bytes_sent', 'total_bytes_received',
            'unique_destinations', 'unique_sources',
            'protocols_used', 'port_scan_score',
            'connection_count', 'in_degree', 'out_degree'
        ]
        
        feature_matrix = []
        for nid in node_ids:
            node = self.nodes[nid]
            features = [node.features.get(fname, 0.0) for fname in feature_names]
            feature_matrix.append(features)
        
        return np.array(feature_matrix, dtype=np.float32), node_ids, feature_names
    
    def save_graph(self, output_path: str):
        """
        Save graph to JSON format.
        
        Args:
            output_path: Path to save JSON file
        """
        graph_data = {
            'nodes': [node.to_dict() for node in self.nodes.values()],
            'edges': [edge.to_dict() for edge in self.edges.values()],
            'metadata': {
                'num_nodes': len(self.nodes),
                'num_edges': len(self.edges),
            }
        }
        
        with open(output_path, 'w') as f:
            json.dump(graph_data, f, indent=2, default=str)
        
        logger.info(f"Graph saved to {output_path}")
    
    def get_anomaly_scores(self) -> Dict[str, float]:
        """
        Calculate simple anomaly scores for nodes based on graph features.
        
        Returns:
            Dictionary mapping node_id to anomaly_score
        """
        scores = {}
        
        if not self.nodes:
            return scores
        
        # Extract features for scoring
        all_out_degrees = [n.features.get('out_degree', 0) for n in self.nodes.values()]
        all_port_scans = [n.features.get('port_scan_score', 0) for n in self.nodes.values()]
        all_byte_sent = [n.features.get('total_bytes_sent', 0) for n in self.nodes.values()]
        
        # Calculate z-scores for anomaly detection
        mean_out = np.mean(all_out_degrees)
        std_out = np.std(all_out_degrees) + 1e-10
        
        mean_bytes = np.mean(all_byte_sent)
        std_bytes = np.std(all_byte_sent) + 1e-10
        
        for node_id, node in self.nodes.items():
            out_deg = node.features.get('out_degree', 0)
            port_scan = node.features.get('port_scan_score', 0)
            bytes_sent = node.features.get('total_bytes_sent', 0)
            
            # Z-score based anomaly
            z_out = abs((out_deg - mean_out) / std_out)
            z_bytes = abs((bytes_sent - mean_bytes) / std_bytes)
            
            # Combine scores
            anomaly_score = (z_out + z_bytes) / 2 + port_scan * 2
            scores[node_id] = float(anomaly_score)
        
        return scores


def build_graph_from_dataframe(df: pd.DataFrame, time_window: Optional[float] = None) -> NetworkGraphBuilder:
    """
    Build network graph from a pandas DataFrame.
    
    Args:
        df: DataFrame with network flow records
        time_window: Optional time window to limit data (in seconds from first timestamp)
        
    Returns:
        NetworkGraphBuilder instance with constructed graph
    """
    logger.info(f"Building graph from DataFrame with {len(df)} records")
    
    builder = NetworkGraphBuilder()
    
    # Filter by time window if specified
    if time_window and 'ts' in df.columns:
        min_ts = df['ts'].min()
        df = df[df['ts'] <= min_ts + time_window]
        logger.info(f"Filtered to {len(df)} records within {time_window}s window")
    
    # Add each flow to graph
    for idx, row in df.iterrows():
        builder.add_network_flow(row.to_dict())
    
    # Finalize graph features
    builder.finalize_graph()
    
    return builder


if __name__ == "__main__":
    # Example usage
    print("Network Graph Builder for GNN-based Zero-Day Detection")
    print("=" * 60)
    
    # Create sample network data
    sample_data = pd.DataFrame({
        'ts': [1000.0 + i for i in range(20)],
        'src_ip': ['192.168.1.10'] * 10 + ['192.168.1.20'] * 10,
        'dst_ip': [f'10.0.0.{i % 5}' for i in range(20)],
        'src_port': [12345 + i for i in range(20)],
        'dst_port': [80, 443, 22, 23, 8080] * 4,
        'protocol_type': ['TCP'] * 15 + ['UDP'] * 5,
        'tot_size': [1400] * 20,
        'src_to_dst_bytes': [1400] * 20,
        'dst_to_src_bytes': [500] * 20,
    })
    
    # Build graph
    builder = build_graph_from_dataframe(sample_data)
    
    print(f"\nGraph Statistics:")
    print(f"  Nodes: {len(builder.nodes)}")
    print(f"  Edges: {len(builder.edges)}")
    
    # Get GNN inputs
    edge_index, edge_weights, node_ids = builder.to_edge_index()
    feature_matrix, _, feature_names = builder.get_node_feature_matrix()
    
    print(f"\nGNN Inputs:")
    print(f"  Edge index shape: {edge_index.shape}")
    print(f"  Feature matrix shape: {feature_matrix.shape}")
    print(f"  Feature names: {feature_names}")
    
    # Get anomaly scores
    anomaly_scores = builder.get_anomaly_scores()
    print(f"\nTop 3 anomalous nodes:")
    for node_id, score in sorted(anomaly_scores.items(), key=lambda x: x[1], reverse=True)[:3]:
        print(f"  {node_id}: {score:.4f}")