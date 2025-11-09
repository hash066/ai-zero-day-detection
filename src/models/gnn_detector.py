"""
Enhanced Graph Neural Network for zero-day network anomaly detection.

Integrated with graph_builder.py outputs (9 node features, edge weights).
Uses Graph Attention Network (GAT) for focusing on anomalous connections.
Outputs anomaly probability scores with explainability via attention.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GATConv, global_mean_pool, global_max_pool
from torch_geometric.data import Data, Batch
from typing import Dict, List, Tuple, Optional
import numpy as np
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Node feature indices from graph_builder.py
NODE_FEATURE_NAMES = [
    'total_bytes_sent', 'total_bytes_received', 'total_packets_sent',
    'total_packets_received', 'unique_connections', 'avg_packet_size',
    'port_diversity', 'protocol_diversity', 'time_active'
]


class GraphTemporalAggregator(nn.Module):
    """
    Aggregates multiple temporal graph snapshots for temporal modeling.
    
    Combines features from past graph states to capture evolving attack patterns.
    """
    
    def __init__(self, node_dim: int, hidden_dim: int = 64):
        super(GraphTemporalAggregator, self).__init__()
        self.gru = nn.GRU(node_dim, hidden_dim, batch_first=True)
        self.projection = nn.Linear(hidden_dim, node_dim)
    
    def forward(self, graph_sequence: List[torch.Tensor]) -> torch.Tensor:
        """
        Args:
            graph_sequence: List of node embeddings [(num_nodes, node_dim), ...]
            
        Returns:
            aggregated: (num_nodes, node_dim) - temporally aggregated features
        """
        if len(graph_sequence) == 1:
            return graph_sequence[0]
        
        # Stack into sequence: (num_nodes, seq_len, node_dim)
        stacked = torch.stack(graph_sequence, dim=1)
        
        # Apply GRU to capture temporal evolution
        output, _ = self.gru(stacked)
        
        # Use final output and project back
        final_output = output[:, -1, :]  # (num_nodes, hidden_dim)
        aggregated = self.projection(final_output)
        
        return aggregated


class EnhancedGNNDetector(nn.Module):
    """
    Enhanced Graph Attention Network for zero-day attack detection.
    
    Key improvements over basic GCN:
    1. GAT (Graph Attention) instead of GCN for learning anomalous connections
    2. Anomaly scoring output (0-1 probability) instead of binary classification
    3. Integration with graph_builder's 9 node features
    4. Edge weight utilization from traffic volume
    5. Temporal graph aggregation for evolving patterns
    6. Graph-level pooling for network-wide anomaly scores
    7. Attention visualization for explainability
    
    Architecture:
    - 3 GAT layers with multi-head attention
    - Temporal aggregation across graph snapshots
    - Node-level anomaly scoring
    - Graph-level pooling for network anomaly score
    """

    def __init__(
        self,
        in_channels: int = 9,  # graph_builder outputs 9 features
        hidden_channels: int = 64,
        num_heads: int = 4,
        num_layers: int = 3,
        dropout: float = 0.3,
        use_temporal_aggregation: bool = True
    ):
        """
        Initialize Enhanced GNN Detector.

        Args:
            in_channels: Number of node features (9 from graph_builder)
            hidden_channels: Hidden dimension
            num_heads: Number of attention heads per GAT layer
            num_layers: Number of GAT layers
            dropout: Dropout probability
            use_temporal_aggregation: Whether to use temporal aggregation
        """
        super(EnhancedGNNDetector, self).__init__()
        
        self.in_channels = in_channels
        self.hidden_channels = hidden_channels
        self.num_heads = num_heads
        self.num_layers = num_layers
        self.use_temporal_aggregation = use_temporal_aggregation
        
        # Input projection to hidden dimension
        self.input_projection = nn.Linear(in_channels, hidden_channels)
        self.input_norm = nn.BatchNorm1d(hidden_channels)
        
        # --- Graph Attention Layers ---
        # GAT learns to focus on anomalous connections via attention
        self.gat_layers = nn.ModuleList()
        self.batch_norms = nn.ModuleList()
        
        for layer in range(num_layers):
            if layer == 0:
                # First layer: hidden_channels -> hidden_channels
                gat = GATConv(
                    hidden_channels,
                    hidden_channels // num_heads,
                    heads=num_heads,
                    dropout=dropout,
                    concat=True
                )
            else:
                # Subsequent layers
                gat = GATConv(
                    hidden_channels,
                    hidden_channels // num_heads,
                    heads=num_heads,
                    dropout=dropout,
                    concat=True if layer < num_layers - 1 else False
                )
            
            self.gat_layers.append(gat)
            self.batch_norms.append(nn.BatchNorm1d(hidden_channels))
        
        # Temporal aggregation (if enabled)
        if use_temporal_aggregation:
            self.temporal_aggregator = GraphTemporalAggregator(hidden_channels)
        
        # --- Node-level Anomaly Scoring ---
        self.node_anomaly_head = nn.Sequential(
            nn.Linear(hidden_channels, hidden_channels // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_channels // 2, 1),
            nn.Sigmoid()  # Output anomaly probability [0, 1]
        )
        
        # --- Graph-level Anomaly Scoring ---
        # Combines node scores into network-wide anomaly score
        self.graph_anomaly_head = nn.Sequential(
            nn.Linear(hidden_channels * 2, hidden_channels),  # *2 for mean+max pooling
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_channels, 1),
            nn.Sigmoid()
        )
        
        # Anomaly threshold (calibrated during training)
        self.register_buffer('node_threshold', torch.tensor(0.5))
        self.register_buffer('graph_threshold', torch.tensor(0.5))
        
        logger.info(f"Enhanced GNN Detector initialized: {in_channels} features, "
                   f"{hidden_channels} hidden, {num_heads} heads, {num_layers} layers")

    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        edge_weight: Optional[torch.Tensor] = None,
        batch: Optional[torch.Tensor] = None,
        return_attention: bool = False
    ) -> Tuple[torch.Tensor, torch.Tensor, Optional[List[torch.Tensor]]]:
        """
        Forward pass for GNN.

        Args:
            x: Node features (num_nodes, in_channels)
            edge_index: Graph connectivity (2, num_edges)
            edge_weight: Edge weights from traffic volume
            batch: Batch assignment for graph-level pooling
            return_attention: Whether to return attention weights

        Returns:
            node_scores: Node anomaly scores (num_nodes, 1)
            graph_score: Graph-level anomaly score (1,) or (batch_size,)
            attention_weights: List of attention matrices if return_attention=True
        """
        # --- Input Processing ---
        x = self.input_projection(x)
        x = self.input_norm(x)
        x = F.relu(x)
        
        # --- GAT Layers with Attention ---
        attention_weights = [] if return_attention else None
        
        for layer_idx, (gat_layer, batch_norm) in enumerate(zip(self.gat_layers, self.batch_norms)):
            if return_attention:
                # Get attention weights for explainability
                x_new, (edge_index_att, alpha) = gat_layer(
                    x, edge_index, edge_attr=edge_weight, return_attention_weights=True
                )
                attention_weights.append(alpha)
            else:
                x_new = gat_layer(x, edge_index, edge_attr=edge_weight)
            
            # Residual connection (if dimensions match)
            if x.shape == x_new.shape and layer_idx > 0:
                x = x + x_new
            else:
                x = x_new
            
            # Normalization and activation
            x = batch_norm(x)
            if layer_idx < self.num_layers - 1:
                x = F.relu(x)
                x = F.dropout(x, p=0.3, training=self.training)
        
        # --- Node-level Anomaly Scoring ---
        node_scores = self.node_anomaly_head(x)  # (num_nodes, 1)
        
        # --- Graph-level Anomaly Scoring ---
        if batch is None:
            # Single graph: pool all nodes
            graph_features = torch.cat([
                x.mean(dim=0, keepdim=True),  # Global mean pooling
                x.max(dim=0, keepdim=True)[0]  # Global max pooling
            ], dim=1)
            graph_score = self.graph_anomaly_head(graph_features).squeeze()
        else:
            # Multiple graphs: pool per graph
            mean_pool = global_mean_pool(x, batch)
            max_pool = global_max_pool(x, batch)
            graph_features = torch.cat([mean_pool, max_pool], dim=1)
            graph_score = self.graph_anomaly_head(graph_features).squeeze()
        
        return node_scores, graph_score, attention_weights

    def forward_temporal(
        self,
        graph_sequence: List[Data],
        return_attention: bool = False
    ) -> Dict[str, torch.Tensor]:
        """
        Forward pass for temporal graph sequence.

        Args:
            graph_sequence: List of PyG Data objects (temporal snapshots)
            return_attention: Whether to return attention weights

        Returns:
            Dictionary with node scores, graph score, and optional attention
        """
        if not self.use_temporal_aggregation or len(graph_sequence) == 1:
            # Single snapshot processing
            data = graph_sequence[0]
            node_scores, graph_score, attention = self.forward(
                data.x, data.edge_index, data.edge_attr,
                return_attention=return_attention
            )
            return {
                'node_scores': node_scores,
                'graph_score': graph_score,
                'attention_weights': attention
            }
        
        # Process each snapshot through GAT layers
        embeddings_sequence = []
        
        for data in graph_sequence:
            x = self.input_projection(data.x)
            x = self.input_norm(x)
            x = F.relu(x)
            
            for gat_layer, batch_norm in zip(self.gat_layers, self.batch_norms):
                x = gat_layer(x, data.edge_index, edge_attr=data.edge_attr)
                x = batch_norm(x)
                x = F.relu(x)
            
            embeddings_sequence.append(x)
        
        # Aggregate temporal information
        aggregated_embeddings = self.temporal_aggregator(embeddings_sequence)
        
        # Compute scores on aggregated embeddings
        node_scores = self.node_anomaly_head(aggregated_embeddings)
        
        graph_features = torch.cat([
            aggregated_embeddings.mean(dim=0, keepdim=True),
            aggregated_embeddings.max(dim=0, keepdim=True)[0]
        ], dim=1)
        graph_score = self.graph_anomaly_head(graph_features).squeeze()
        
        return {
            'node_scores': node_scores,
            'graph_score': graph_score,
            'attention_weights': None  # Not computed for temporal mode
        }

    def calibrate_threshold(
        self,
        normal_graphs: List[Data],
        percentile: float = 95.0
    ) -> Dict[str, float]:
        """
        Calibrate anomaly detection thresholds from normal network traffic.

        Args:
            normal_graphs: List of normal traffic graphs
            percentile: Percentile for threshold

        Returns:
            Dictionary with threshold statistics
        """
        logger.info(f"Calibrating GNN threshold on {len(normal_graphs)} normal graphs...")
        
        self.eval()
        node_scores_all = []
        graph_scores_all = []
        
        with torch.no_grad():
            for data in normal_graphs:
                node_scores, graph_score, _ = self.forward(
                    data.x, data.edge_index, data.edge_attr
                )
                node_scores_all.append(node_scores.cpu().numpy())
                graph_scores_all.append(graph_score.item())
        
        node_scores_all = np.concatenate(node_scores_all)
        graph_scores_all = np.array(graph_scores_all)
        
        # Set thresholds
        node_threshold = np.percentile(node_scores_all, percentile)
        graph_threshold = np.percentile(graph_scores_all, percentile)
        
        self.node_threshold = torch.tensor(node_threshold, dtype=torch.float32)
        self.graph_threshold = torch.tensor(graph_threshold, dtype=torch.float32)
        
        logger.info(f"Node threshold: {node_threshold:.4f}, Graph threshold: {graph_threshold:.4f}")
        
        return {
            'node_threshold': float(node_threshold),
            'graph_threshold': float(graph_threshold),
            'mean_node_score': float(node_scores_all.mean()),
            'mean_graph_score': float(graph_scores_all.mean()),
            'percentile': percentile
        }

    def detect_anomalies(
        self,
        data: Data,
        return_details: bool = False
    ) -> Dict[str, any]:
        """
        Detect anomalies in network graph.

        Args:
            data: PyG Data object with x, edge_index, edge_attr
            return_details: Whether to return detailed explanations

        Returns:
            Dictionary with anomaly detection results
        """
        self.eval()
        with torch.no_grad():
            node_scores, graph_score, attention = self.forward(
                data.x, data.edge_index, data.edge_attr,
                return_attention=return_details
            )
        
        node_scores_np = node_scores.squeeze().cpu().numpy()
        graph_score_np = graph_score.item()
        
        # Identify anomalous nodes
        anomalous_nodes = node_scores_np > self.node_threshold.item()
        is_graph_anomalous = graph_score_np > self.graph_threshold.item()
        
        results = {
            'node_scores': node_scores_np,
            'graph_score': graph_score_np,
            'anomalous_nodes': anomalous_nodes,
            'is_anomalous': is_graph_anomalous,
            'num_anomalous_nodes': int(anomalous_nodes.sum()),
            'node_threshold': self.node_threshold.item(),
            'graph_threshold': self.graph_threshold.item()
        }
        
        if return_details and attention is not None:
            # Find nodes with highest attention (most suspicious connections)
            attention_aggregated = torch.cat(attention, dim=0).mean(dim=0).cpu().numpy()
            top_k = min(10, len(node_scores_np))
            top_suspicious_nodes = np.argsort(node_scores_np)[-top_k:][::-1]
            
            results['attention_weights'] = attention
            results['top_suspicious_nodes'] = [
                {
                    'node_id': int(node_id),
                    'anomaly_score': float(node_scores_np[node_id]),
                    'features': data.x[node_id].cpu().numpy().tolist()
                }
                for node_id in top_suspicious_nodes
            ]
        
        return results

def main():
    """Example usage and model summary."""
    # --- Graph Configuration ---
    NUM_NODES = 100         # e.g., 100 devices in the network
    NUM_EDGES = 300         # e.g., 300 connections between devices
    NODE_FEATURES = 64      # Number of features per device (e.g., from network flow stats)
    HIDDEN_CHANNELS = 128   # GCN hidden layer size
    NUM_CLASSES = 2         # Anomaly vs. Normal

    # --- Create Model ---
    model = GNNNodeClassifier(
        in_channels=NODE_FEATURES,
        hidden_channels=HIDDEN_CHANNELS,
        out_channels=NUM_CLASSES
    )
    print("--- GNN Node Classifier Architecture ---")
    print(model)

    # --- Example Input ---
    # Simulate a graph with random node features and edges
    
    # Node features (e.g., aggregated stats for each IP)
    x = torch.randn(NUM_NODES, NODE_FEATURES)
    
    # Edge index (random connections)
    edge_index = torch.randint(0, NUM_NODES, (2, NUM_EDGES), dtype=torch.long)
    
    # Optional: Edge weights (e.g., number of connections or total bytes)
    edge_weight = torch.rand(NUM_EDGES)

    # --- Forward Pass ---
    try:
        output = model(x, edge_index, edge_weight)
        
        # --- Verify Shapes ---
        print("\n--- Tensor Shapes ---")
        print(f"Node feature shape: {x.shape}")
        print(f"Edge index shape:   {edge_index.shape}")
        print(f"Output shape:       {output.shape}")

        assert output.shape == (NUM_NODES, NUM_CLASSES)
        print("\nModel forward pass successful, and shapes match!")

    except Exception as e:
        print(f"\nAn error occurred during the forward pass: {e}")
        # Note: This might fail if torch_geometric is not installed.
        # This code is meant to be used in an environment where it is.
        print("Please ensure you have PyTorch and torch-geometric installed.")


if __name__ == '__main__':
    main()
