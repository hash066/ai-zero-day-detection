"""
Calculates the final zero-day threat score for an event or entity.

This module bridges the gap between the raw anomaly scores produced by the
AnomalyDetector and the final, interpretable threat score by using the
EnsembleScorer.
"""

from pathlib import Path
import logging

# Adjusting path to import from sibling directories
import sys
sys.path.append(str(Path(__file__).resolve().parent.parent))

from models.ensemble_scorer import EnsembleScorer
from inference.anomaly_detector import AnomalyDetector

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class ThreatScorer:
    """
    Orchestrates the calculation of a final threat score.

    This class takes anomaly scores for a specific entity (e.g., a process or a device)
    from different models and uses an ensemble method to combine them into a single score.
    """

    def __init__(self, lstm_weight: float = 0.6, gnn_weight: float = 0.4, max_lstm_error: float = 1.0):
        """
        Initialize the ThreatScorer.

        Args:
            lstm_weight (float): The weight for the LSTM model's score.
            gnn_weight (float): The weight for the GNN model's score.
            max_lstm_error (float): The maximum expected reconstruction error for
                                    the LSTM, used for normalization. This value
                                    should ideally be determined from a validation
                                    set of normal data.
        """
        self.ensemble_scorer = EnsembleScorer(lstm_weight=lstm_weight, gnn_weight=gnn_weight)
        self.max_lstm_error = max_lstm_error
        logging.info(f"ThreatScorer initialized with weights: LSTM={lstm_weight}, GNN={gnn_weight}")

    def score_event(
        self,
        lstm_score: float,
        gnn_score: float
    ) -> float:
        """
        Calculates the threat score for a given set of model outputs.

        Args:
            lstm_score (float): The reconstruction error from the LSTM autoencoder.
            gnn_score (float): The anomaly probability from the GNN classifier.

        Returns:
            float: The final, combined threat score between 0 and 1.
        """
        if lstm_score < 0:
            logging.warning(f"Received negative LSTM score ({lstm_score}), clamping to 0.")
            lstm_score = 0
        if not (0.0 <= gnn_score <= 1.0):
            logging.warning(f"Received GNN score outside [0, 1] ({gnn_score}), clamping.")
            gnn_score = max(0.0, min(1.0, gnn_score))

        final_score = self.ensemble_scorer.calculate_threat_score(
            lstm_reconstruction_error=lstm_score,
            gnn_anomaly_probability=gnn_score,
            max_expected_lstm_error=self.max_lstm_error
        )
        
        logging.debug(
            f"Scoring event: LSTM_err={lstm_score:.4f}, GNN_prob={gnn_score:.4f} -> Final Score={final_score:.4f}"
        )
        
        return final_score

def main_demo():
    """
    Demonstrates the full pipeline from AnomalyDetector to ThreatScorer.
    """
    # This demo requires trained models to be present.
    LSTM_MODEL_PATH = "trained_models/lstm"
    GNN_MODEL_PATH = "trained_models/gnn"

    logging.info("--- Threat Scoring Demo ---")

    # --- 1. Initialize Systems ---
    try:
        anomaly_detector = AnomalyDetector(lstm_model_dir=LSTM_MODEL_PATH, gnn_model_dir=GNN_MODEL_PATH)
        threat_scorer = ThreatScorer(lstm_weight=0.6, gnn_weight=0.4, max_lstm_error=0.8)
        logging.info("Systems initialized successfully.")
    except FileNotFoundError:
        logging.error("Model artifacts not found. Please run training scripts first.")
        return
    except Exception as e:
        logging.error(f"Initialization failed: {e}")
        return

    # --- 2. Simulate Incoming Data and Get Anomaly Scores ---
    # (Using dummy data as in the anomaly_detector demo)
    try:
        # Sysmon data for a process sequence
        lstm_config = anomaly_detector.lstm_config
        dummy_sysmon_data = pd.DataFrame(
            data=np.random.rand(lstm_config['sequence_length'], len(lstm_config['feature_columns'])),
            columns=lstm_config['feature_columns']
        )
        lstm_anomaly_score = anomaly_detector.detect_sysmon_anomaly(dummy_sysmon_data)
        logging.info(f"Detected LSTM reconstruction error: {lstm_anomaly_score:.4f}")

        # Network data for a specific device (node)
        gnn_config = anomaly_detector.gnn_config
        node_ids = list(anomaly_detector.gnn_node_mapping.keys())[:5]
        target_node = node_ids[0]
        
        dummy_node_features = pd.DataFrame(
            data=np.random.rand(len(node_ids), len(gnn_config['feature_columns'])),
            columns=gnn_config['feature_columns']
        )
        dummy_node_features['node_id'] = node_ids
        
        dummy_edge_list = pd.DataFrame({'source': [node_ids[1]], 'target': [target_node]})
        
        network_scores = anomaly_detector.detect_network_anomaly(dummy_node_features, dummy_edge_list)
        gnn_anomaly_score = network_scores.get(target_node, 0.0)
        logging.info(f"Detected GNN anomaly probability for node '{target_node}': {gnn_anomaly_score:.4f}")
        
    except Exception as e:
        logging.error(f"Error during anomaly detection phase: {e}")
        return

    # --- 3. Calculate Final Threat Score ---
    final_threat_score = threat_scorer.score_event(
        lstm_score=lstm_anomaly_score,
        gnn_score=gnn_anomaly_score
    )

    logging.info(f"\n--- Final Result ---")
    logging.info(f"Combined Threat Score for the event/entity: {final_threat_score:.4f}")

    if final_threat_score > 0.7:
        logging.warning("Threat score exceeds threshold! Alerting security team.")
    else:
        logging.info("Threat score is below threshold. Event considered normal.")

if __name__ == '__main__':
    import numpy as np
    import pandas as pd
    # This main function is for demonstration purposes.
    main_demo()
