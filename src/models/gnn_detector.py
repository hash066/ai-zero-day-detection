"""
PyTorch implementation of a Graph Neural Network (GNN) for anomaly detection.

This model learns to classify nodes (e.g., devices) in a graph of network
connections as either normal or anomalous based on their features and connectivity.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GCNConv, GATConv

class GNNNodeClassifier(nn.Module):
    """
    Graph Neural Network for node classification.

    This model uses Graph Convolutional Network (GCN) layers to learn from the
    graph structure and node features. It's designed to predict if a node
    (e.g., an IP address) is part of an anomalous pattern.

    Architecture:
    - Two GCN layers for message passing and feature aggregation.
    - ReLU activation and Dropout for regularization.
    - A final linear layer to produce classification scores.
    """

    def __init__(self, in_channels: int, hidden_channels: int, out_channels: int = 2, dropout: float = 0.5):
        """
        Initialize the GNN Node Classifier.

        Args:
            in_channels (int): Number of features for each node in the graph.
            hidden_channels (int): Number of channels in the hidden GCN layer.
            out_channels (int): Number of output classes (e.g., 2 for normal/anomaly).
            dropout (float): Dropout probability.
        """
        super(GNNNodeClassifier, self).__init__()
        
        # --- Graph Convolutional Layers ---
        # GCNConv layers are suitable for semi-supervised learning on graphs.
        self.conv1 = GCNConv(in_channels, hidden_channels)
        self.conv2 = GCNConv(hidden_channels, hidden_channels)

        # --- Regularization ---
        self.dropout = nn.Dropout(p=dropout)

        # --- Output Layer ---
        # A linear layer to map final node embeddings to class scores.
        self.output_layer = nn.Linear(hidden_channels, out_channels)

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor, edge_weight: torch.Tensor = None) -> torch.Tensor:
        """
        Forward pass for the GNN model.

        Args:
            x (torch.Tensor): Node feature matrix of shape [num_nodes, in_channels].
            edge_index (torch.Tensor): Graph connectivity in COO format with shape [2, num_edges].
            edge_weight (torch.Tensor, optional): Edge weights. Defaults to None.

        Returns:
            torch.Tensor: Log-softmax probabilities for each node, shape [num_nodes, out_channels].
        """
        # --- First GCN Layer ---
        # Apply graph convolution, followed by activation and dropout.
        x = self.conv1(x, edge_index, edge_weight)
        x = F.relu(x)
        x = self.dropout(x)

        # --- Second GCN Layer ---
        x = self.conv2(x, edge_index, edge_weight)
        x = F.relu(x)

        # --- Output Layer ---
        # Produce the final classification scores.
        x = self.output_layer(x)
        
        # Apply log-softmax for use with NLLLoss during training
        return F.log_softmax(x, dim=1)

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
