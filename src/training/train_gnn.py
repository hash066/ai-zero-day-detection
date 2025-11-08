"""
Training script for the GNN-based anomaly detector.

This script loads network graph data (node features and edge list),
constructs a PyTorch Geometric graph, and trains the GNNNodeClassifier
to identify anomalous nodes.
"""

import argparse
import logging
import json
from pathlib import Path

import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim
from sklearn.preprocessing import StandardScaler
from torch_geometric.data import Data
from torch_geometric.loader import DataLoader

# Adjusting path to import from sibling directories
import sys
sys.path.append(str(Path(__file__).resolve().parent.parent))

from models.gnn_detector import GNNNodeClassifier

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_graph_data(node_features_path: str, edge_list_path: str):
    """
    Loads node features and edge list from files.

    Args:
        node_features_path (str): Path to the node features file (CSV or Parquet).
        edge_list_path (str): Path to the edge list file (CSV or Parquet).

    Returns:
        tuple: (DataFrame of node features, DataFrame of edge list)
    """
    logging.info(f"Loading node features from {node_features_path}...")
    if node_features_path.endswith('.parquet'):
        node_df = pd.read_parquet(node_features_path)
    else:
        node_df = pd.read_csv(node_features_path)

    logging.info(f"Loading edge list from {edge_list_path}...")
    if edge_list_path.endswith('.parquet'):
        edge_df = pd.read_parquet(edge_list_path)
    else:
        edge_df = pd.read_csv(edge_list_path)

    # Assuming node_df has a 'node_id' column and edge_df has 'source' and 'target'
    if 'node_id' not in node_df.columns:
        raise ValueError("Node features file must contain a 'node_id' column.")
    if not all(col in edge_df.columns for col in ['source', 'target']):
        raise ValueError("Edge list file must contain 'source' and 'target' columns.")

    return node_df, edge_df

def create_graph_object(node_df: pd.DataFrame, edge_df: pd.DataFrame, target_column: str):
    """
    Creates a PyTorch Geometric Data object from DataFrames.

    Args:
        node_df (pd.DataFrame): DataFrame with node features and IDs.
        edge_df (pd.DataFrame): DataFrame with source and target for edges.
        target_column (str): The name of the column containing node labels.

    Returns:
        torch_geometric.data.Data: A graph data object.
    """
    # Create a mapping from original node_id to a zero-indexed integer
    node_mapping = {node_id: i for i, node_id in enumerate(node_df['node_id'].unique())}
    
    # Extract features and scale them
    feature_cols = [col for col in node_df.columns if col not in ['node_id', target_column]]
    features = node_df[feature_cols].values
    scaler = StandardScaler()
    features_scaled = scaler.fit_transform(features)
    
    x = torch.tensor(features_scaled, dtype=torch.float32)

    # Map edges to the new integer indices
    source_nodes = edge_df['source'].map(node_mapping).values
    target_nodes = edge_df['target'].map(node_mapping).values
    edge_index = torch.tensor([source_nodes, target_nodes], dtype=torch.long)
    
    # Extract labels (targets)
    y = torch.tensor(node_df[target_column].values, dtype=torch.long)
    
    graph = Data(x=x, edge_index=edge_index, y=y)
    
    # Create train/val/test masks for semi-supervised learning
    num_nodes = len(node_df)
    train_mask = torch.zeros(num_nodes, dtype=torch.bool)
    val_mask = torch.zeros(num_nodes, dtype=torch.bool)
    
    # Example split: 60% train, 20% validation (rest is test)
    # This should be adapted based on real-world labeled data availability
    indices = torch.randperm(num_nodes)
    train_end = int(0.6 * num_nodes)
    val_end = int(0.8 * num_nodes)
    
    train_mask[indices[:train_end]] = True
    val_mask[indices[train_end:val_end]] = True
    
    graph.train_mask = train_mask
    graph.val_mask = val_mask

    return graph, scaler, node_mapping, feature_cols

def train_gnn_model(
    node_features_path: str,
    edge_list_path: str,
    model_dir: str,
    target_column: str,
    epochs: int,
    learning_rate: float,
    hidden_channels: int,
    dropout: float,
):
    """Main training function for the GNN model."""
    # --- 1. Setup and Device Configuration ---
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logging.info(f"Using device: {device}")
    
    output_path = Path(model_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # --- 2. Load and Prepare Graph Data ---
    node_df, edge_df = load_graph_data(node_features_path, edge_list_path)
    graph, scaler, node_mapping, feature_cols = create_graph_object(node_df, edge_df, target_column)
    graph = graph.to(device)

    # --- 3. Initialize Model and Optimizer ---
    model = GNNNodeClassifier(
        in_channels=graph.num_node_features,
        hidden_channels=hidden_channels,
        out_channels=2, # Assuming binary classification (normal/anomaly)
        dropout=dropout
    ).to(device)
    
    optimizer = optim.Adam(model.parameters(), lr=learning_rate)
    criterion = nn.NLLLoss() # Negative Log Likelihood Loss

    logging.info("GNN Model architecture:")
    logging.info(model)

    # --- 4. Training Loop ---
    best_val_loss = float('inf')
    for epoch in range(epochs):
        model.train()
        optimizer.zero_grad()
        
        out = model(graph.x, graph.edge_index)
        loss = criterion(out[graph.train_mask], graph.y[graph.train_mask])
        
        loss.backward()
        optimizer.step()

        # Validation
        model.eval()
        with torch.no_grad():
            val_out = model(graph.x, graph.edge_index)
            val_loss = criterion(val_out[graph.val_mask], graph.y[graph.val_mask])
            
            pred = val_out.argmax(dim=1)
            correct = (pred[graph.val_mask] == graph.y[graph.val_mask]).sum()
            acc = int(correct) / int(graph.val_mask.sum())
        
        logging.info(f"Epoch [{epoch+1}/{epochs}], Train Loss: {loss.item():.4f}, Val Loss: {val_loss.item():.4f}, Val Acc: {acc:.4f}")

        # Save the best model based on validation loss
        if val_loss < best_val_loss:
            best_val_loss = val_loss
            model_path = output_path / "gnn_detector_best.pth"
            torch.save(model.state_dict(), model_path)
            logging.info(f"Saved new best model to {model_path}")

    # --- 5. Save Final Artifacts ---
    final_model_path = output_path / "gnn_detector_final.pth"
    torch.save(model.state_dict(), final_model_path)
    
    import joblib
    joblib.dump(scaler, output_path / "scaler.pkl")
    joblib.dump(node_mapping, output_path / "node_mapping.pkl")

    config = {
        "in_channels": graph.num_node_features,
        "hidden_channels": hidden_channels,
        "out_channels": 2,
        "dropout": dropout,
        "feature_columns": feature_cols,
    }
    with open(output_path / "model_config.json", 'w') as f:
        json.dump(config, f, indent=4)
        
    logging.info(f"Training complete. Final model and artifacts saved to {output_path}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Train GNN for Network Anomaly Detection")
    parser.add_argument("--nodes", type=str, required=True, help="Path to node features file.")
    parser.add_argument("--edges", type=str, required=True, help="Path to edge list file.")
    parser.add_argument("--target", type=str, default="is_malicious", help="Name of the target/label column in the nodes file.")
    parser.add_argument("--model-dir", type=str, default="trained_models/gnn", help="Directory to save the trained model.")
    parser.add_argument("--epochs", type=int, default=100, help="Number of training epochs.")
    parser.add_argument("--lr", type=float, default=1e-2, help="Learning rate.")
    parser.add_argument("--hidden", type=int, default=128, help="Number of hidden channels in GNN.")
    parser.add_argument("--dropout", type=float, default=0.5, help="Dropout rate.")
    
    args = parser.parse_args()
    
    train_gnn_model(
        node_features_path=args.nodes,
        edge_list_path=args.edges,
        model_dir=args.model_dir,
        target_column=args.target,
        epochs=args.epochs,
        learning_rate=args.lr,
        hidden_channels=args.hidden,
        dropout=args.dropout
    )
