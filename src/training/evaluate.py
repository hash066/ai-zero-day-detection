"""
Model evaluation script.

This script loads a labeled test dataset and the trained models to
evaluate their performance. It calculates metrics like precision, recall,
F1-score, and AUC-ROC for the combined detection system.
"""

import argparse
import logging
from pathlib import Path

import pandas as pd
import numpy as np
from sklearn.metrics import precision_recall_fscore_support, roc_auc_score, confusion_matrix
import json
import seaborn as sns
import matplotlib.pyplot as plt

# Adjusting path to import from sibling directories
import sys
sys.path.append(str(Path(__file__).resolve().parent.parent))

from inference.anomaly_detector import AnomalyDetector
from inference.threat_scorer import ThreatScorer

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def evaluate(
    lstm_model_dir: str,
    gnn_model_dir: str,
    test_data_path: str,
    results_dir: str,
    threat_threshold: float
):
    """
    Runs the full evaluation pipeline.

    Args:
        lstm_model_dir (str): Directory of the trained LSTM model.
        gnn_model_dir (str): Directory of the trained GNN model.
        test_data_path (str): Path to the labeled test dataset (e.g., CSV).
        results_dir (str): Directory to save evaluation results and plots.
        threat_threshold (float): The threshold to classify an event as an anomaly.
    """
    # --- 1. Setup ---
    results_path = Path(results_dir)
    results_path.mkdir(parents=True, exist_ok=True)
    
    logging.info("Initializing models for evaluation...")
    try:
        anomaly_detector = AnomalyDetector(lstm_model_dir, gnn_model_dir)
        threat_scorer = ThreatScorer()
    except Exception as e:
        logging.error(f"Failed to initialize models: {e}")
        return

    # --- 2. Load Test Data ---
    # This is a simplified example. A real implementation would need to handle
    # loading both sequence data and graph data for the test set.
    # For this script, we assume a CSV with pre-calculated anomaly scores
    # and ground truth labels.
    logging.info(f"Loading test data from {test_data_path}...")
    try:
        test_df = pd.read_csv(test_data_path)
    except FileNotFoundError:
        logging.error(f"Test data file not found at {test_data_path}.")
        return
    except pd.errors.EmptyDataError:
        logging.error(f"Test data file at {test_data_path} is empty.")
        return
    except Exception as e:
        logging.error(f"Failed to read test data from {test_data_path}: {e}")
        return

    # Required columns: 'lstm_score', 'gnn_score', 'is_anomaly' (0 or 1)
    required_cols = ['lstm_score', 'gnn_score', 'is_anomaly']
    if not all(c in test_df.columns for c in required_cols):
        logging.error(f"Test data must contain {required_cols} columns. Found: {list(test_df.columns)}")
        return

    if test_df.shape[0] == 0:
        logging.error("Test data is empty.")
        return

    # --- 3. Generate Predictions ---
    logging.info("Generating threat scores for the test set...")
    y_true = test_df['is_anomaly'].values
    # Ensure numpy array type for sklearn metrics
    y_true = np.asarray(y_true)
    
    # Calculate threat scores for each event in the test set
    # Safely compute threat scores, catching per-row scoring errors
    def _safe_score(row):
        try:
            return threat_scorer.score_event(row['lstm_score'], row['gnn_score'])
        except Exception as e:
            logging.warning(f"Failed to score row (index={row.name}): {e}")
            return float('nan')

    threat_scores = test_df.apply(_safe_score, axis=1).to_numpy()

    # Validate threat_scores
    if not (len(threat_scores) == len(test_df)):
        logging.error("Threat scores length does not match number of test samples.")
        return

    # Ensure we have finite numeric scores for ROC AUC and thresholding
    import math
    finite_mask = [not (isinstance(v, float) and math.isnan(v)) for v in threat_scores]
    if not any(finite_mask):
        logging.error("No valid threat scores could be computed from the test data.")
        return

    # Replace NaNs with a low score (so they are treated as normal)
    threat_scores = [ (v if (not (isinstance(v, float) and math.isnan(v))) else 0.0) for v in threat_scores ]
    # Convert to a plain list/array for downstream functions
    threat_scores = np.array(threat_scores)
    
    # Classify based on the threshold
    y_pred = (threat_scores >= threat_threshold).astype(int)

    # --- 4. Calculate and Log Metrics ---
    logging.info(f"\n--- Evaluation Results (Threshold = {threat_threshold}) ---")
    
    # Precision, Recall, F1-Score
    precision, recall, f1, _ = precision_recall_fscore_support(y_true, y_pred, average='binary')
    logging.info(f"Precision: {precision:.4f}")
    logging.info(f"Recall:    {recall:.4f}")
    logging.info(f"F1-Score:  {f1:.4f}")

    # ROC AUC Score
    # Note: roc_auc_score uses the raw scores, not the binary predictions
    try:
        roc_auc = roc_auc_score(y_true, threat_scores)
        logging.info(f"ROC AUC:   {roc_auc:.4f}")
    except ValueError as e:
        roc_auc = float('nan')
        logging.warning(f"Could not calculate ROC AUC: {e}")

    # Save metrics to a file
    metrics = {
        'threshold': threat_threshold,
        'precision': precision,
        'recall': recall,
        'f1_score': f1,
        'roc_auc': roc_auc,
    }
    with open(results_path / "evaluation_metrics.json", 'w') as f:
        json.dump(metrics, f, indent=4)
        
    # --- 5. Generate and Save Confusion Matrix ---
    logging.info("Generating confusion matrix plot...")
    cm = confusion_matrix(y_true, y_pred)
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=['Normal', 'Anomaly'],
                yticklabels=['Normal', 'Anomaly'])
    plt.title('Confusion Matrix')
    plt.xlabel('Predicted Label')
    plt.ylabel('True Label')
    
    cm_path = results_path / "confusion_matrix.png"
    plt.savefig(cm_path)
    plt.close()
    logging.info(f"Confusion matrix saved to {cm_path}")

    logging.info("\nEvaluation complete.")
    return metrics

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Evaluate the anomaly detection models.")
    parser.add_argument("--lstm-dir", type=str, required=True, help="Directory of the trained LSTM model.")
    parser.add_argument("--gnn-dir", type=str, required=True, help="Directory of the trained GNN model.")
    parser.add_argument("--test-data", type=str, required=True, help="Path to the labeled test data CSV file.")
    parser.add_argument("--results-dir", type=str, default="evaluation_results", help="Directory to save evaluation results.")
    parser.add_argument("--threshold", type=float, default=0.5, help="Threat score threshold for anomaly classification.")
    
    args = parser.parse_args()

    evaluate(
        lstm_model_dir=args.lstm_dir,
        gnn_model_dir=args.gnn_dir,
        test_data_path=args.test_data,
        results_dir=args.results_dir,
        threat_threshold=args.threshold
    )
