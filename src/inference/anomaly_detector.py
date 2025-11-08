"""
Real-time anomaly detection pipeline.

This module loads the trained LSTM and GNN models and performs inference
on incoming Sysmon and network data streams.
"""

import json
from pathlib import Path
import logging

import torch
import joblib
import pandas as pd
from torch_geometric.data import Data

# Adjusting path to import from sibling directories
import sys
sys.path.append(str(Path(__file__).resolve().parent.parent))

from models.lstm_autoencoder import LSTMAutoencoder
from models.gnn_detector import GNNNodeClassifier

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class AnomalyDetector:
    """
    Handles the loading of trained models and orchestration of the
    inference process for both system behavior and network traffic.
    """

    def __init__(self, lstm_model_dir: str, gnn_model_dir: str):
        """
        Initialize the AnomalyDetector and load all necessary artifacts.

        Args:
            lstm_model_dir (str): Path to the directory with LSTM model artifacts.
            gnn_model_dir (str): Path to the directory with GNN model artifacts.
        """
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        logging.info(f"Inference device set to: {self.device}")

        # --- Load LSTM Model and Artifacts ---
        self.lstm_model, self.lstm_scaler, self.lstm_config = self._load_lstm_artifacts(lstm_model_dir)
        
        # --- Load GNN Model and Artifacts ---
        self.gnn_model, self.gnn_scaler, self.gnn_node_mapping, self.gnn_config = self._load_gnn_artifacts(gnn_model_dir)

    def _load_lstm_artifacts(self, model_dir: str):
        """Loads the LSTM model, scaler, and configuration."""
        logging.info(f"Loading LSTM model from {model_dir}...")
        model_path = Path(model_dir)
        
        config_path = model_path / "model_config.json"
        with open(config_path, 'r') as f:
            config = json.load(f)

        model = LSTMAutoencoder(
            input_dim=config['input_dim'],
            latent_dim=config['latent_dim'],
            num_layers=config['num_layers'],
            dropout=config['dropout']
        ).to(self.device)
        model.load_state_dict(torch.load(model_path / "lstm_autoencoder_best.pth", map_location=self.device))
        model.eval()

        scaler = joblib.load(model_path / "scaler.pkl")
        
        return model, scaler, config

    def _load_gnn_artifacts(self, model_dir: str):
        """Loads the GNN model, scaler, node mapping, and configuration."""
        logging.info(f"Loading GNN model from {model_dir}...")
        model_path = Path(model_dir)

        config_path = model_path / "model_config.json"
        with open(config_path, 'r') as f:
            config = json.load(f)

        model = GNNNodeClassifier(
            in_channels=config['in_channels'],
            hidden_channels=config['hidden_channels'],
            out_channels=config['out_channels'],
            dropout=config['dropout']
        ).to(self.device)
        model.load_state_dict(torch.load(model_path / "gnn_detector_best.pth", map_location=self.device))
        model.eval()

        scaler = joblib.load(model_path / "scaler.pkl")
        node_mapping = joblib.load(model_path / "node_mapping.pkl")

        return model, scaler, node_mapping, config

    def detect_sysmon_anomaly(self, sequence_df: pd.DataFrame) -> float:
        """
        Calculates the reconstruction error for a sequence of Sysmon events.

        Args:
            sequence_df (pd.DataFrame): A DataFrame containing a sequence of events,
                                        with columns matching the trained features.

        Returns:
            float: The Mean Squared Error (MSE) reconstruction loss.
        """
        if len(sequence_df) != self.lstm_config['sequence_length']:
            raise ValueError(f"Input sequence must have length {self.lstm_config['sequence_length']}.")

        # Select and scale features
        features = sequence_df[self.lstm_config['feature_columns']]
        scaled_features = self.lstm_scaler.transform(features)
        
        sequence_tensor = torch.tensor([scaled_features], dtype=torch.float32).to(self.device)

        with torch.no_grad():
            reconstructed = self.lstm_model(sequence_tensor)
            loss = torch.nn.functional.mse_loss(reconstructed, sequence_tensor)
        
        return loss.item()

    def detect_network_anomaly(self, node_features_df: pd.DataFrame, edge_df: pd.DataFrame):
        """
        Performs inference on a network graph to get anomaly probabilities for each node.

        Args:
            node_features_df (pd.DataFrame): DataFrame of current node features.
            edge_df (pd.DataFrame): DataFrame of current network edges ('source', 'target').

        Returns:
            dict: A dictionary mapping node_id to its anomaly probability.
        """
        # --- Prepare graph data for inference ---
        # Map node IDs to the integer indices used during training
        node_ids = node_features_df['node_id'].tolist()
        mapped_indices = [self.gnn_node_mapping.get(nid) for nid in node_ids]

        # Filter out any nodes not seen during training
        valid_nodes_mask = [idx is not None for idx in mapped_indices]
        if not any(valid_nodes_mask):
            logging.warning("No known nodes in the provided graph data.")
            return {}
        
        # Scale features
        features = node_features_df[self.gnn_config['feature_columns']]
        scaled_features = self.gnn_scaler.transform(features)
        x = torch.tensor(scaled_features, dtype=torch.float32).to(self.device)

        # Map edges
        edge_df['source_mapped'] = edge_df['source'].map(self.gnn_node_mapping)
        edge_df['target_mapped'] = edge_df['target'].map(self.gnn_node_mapping)
        valid_edges = edge_df.dropna(subset=['source_mapped', 'target_mapped'])
        
        edge_index = torch.tensor([
            valid_edges['source_mapped'].values,
            valid_edges['target_mapped'].values
        ], dtype=torch.long).to(self.device)
        
        # --- Run GNN Inference ---
        with torch.no_grad():
            log_probs = self.gnn_model(x, edge_index)
            # Convert log probabilities to probabilities
            probs = torch.exp(log_probs)
            # Get the probability of the "anomaly" class (assuming class 1)
            anomaly_probs = probs[:, 1].cpu().numpy()

        # Map results back to original node IDs
        results = {node_id: float(prob) for node_id, prob in zip(node_ids, anomaly_probs)}
        
        return results

def main_demo():
    """Demonstration of loading models and running a mock inference."""
    # NOTE: This requires trained models to be present in the specified directories.
    # The paths should point to where train_lstm.py and train_gnn.py saved their outputs.
    LSTM_MODEL_PATH = "trained_models/lstm"
    GNN_MODEL_PATH = "trained_models/gnn"

    try:
        detector = AnomalyDetector(lstm_model_dir=LSTM_MODEL_PATH, gnn_model_dir=GNN_MODEL_PATH)
        logging.info("AnomalyDetector initialized successfully.")
    except FileNotFoundError:
        logging.error("Model artifacts not found. Please run the training scripts first.")
        return

    # --- Demo Sysmon Anomaly Detection ---
    logging.info("\n--- Running Sysmon Anomaly Detection Demo ---")
    try:
        # Create a dummy sequence DataFrame
        lstm_config = detector.lstm_config
        dummy_sysmon_data = pd.DataFrame(
            data=np.random.rand(lstm_config['sequence_length'], len(lstm_config['feature_columns'])),
            columns=lstm_config['feature_columns']
        )
        reconstruction_error = detector.detect_sysmon_anomaly(dummy_sysmon_data)
        logging.info(f"Sysmon sequence reconstruction error: {reconstruction_error:.6f}")
    except Exception as e:
        logging.error(f"Error during Sysmon detection demo: {e}")

    # --- Demo Network Anomaly Detection ---
    logging.info("\n--- Running Network Anomaly Detection Demo ---")
    try:
        # Create a dummy graph
        gnn_config = detector.gnn_config
        node_ids = list(detector.gnn_node_mapping.keys())[:5] # Use first 5 known nodes
        
        dummy_node_features = pd.DataFrame(
            data=np.random.rand(len(node_ids), len(gnn_config['feature_columns'])),
            columns=gnn_config['feature_columns']
        )
        dummy_node_features['node_id'] = node_ids
        
        dummy_edge_list = pd.DataFrame({
            'source': [node_ids[0], node_ids[1]],
            'target': [node_ids[2], node_ids[3]]
        })

        network_anomaly_scores = detector.detect_network_anomaly(dummy_node_features, dummy_edge_list)
        logging.info("Network node anomaly probabilities:")
        for node_id, score in network_anomaly_scores.items():
            logging.info(f"  Node {node_id}: {score:.4f}")
    except Exception as e:
        logging.error(f"Error during GNN detection demo: {e}")


if __name__ == '__main__':
    import numpy as np
    # This main function is for demonstration purposes.
    # To run it, you must first have trained models saved by the training scripts.
    main_demo()
