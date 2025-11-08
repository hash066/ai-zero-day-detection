"""
Ensemble model for combining anomaly scores.

This module provides a mechanism to combine the outputs from multiple
anomaly detection models (e.g., LSTM Autoencoder and GNN) into a
single, unified threat score.
"""

import numpy as np

class EnsembleScorer:
    """
    Combines anomaly scores from different models using a weighted average.

    The scorer normalizes the scores from each model to a common scale [0, 1]
    before combining them. This ensures that no single model's score range
    dominates the final output.
    """

    def __init__(self, lstm_weight: float = 0.6, gnn_weight: float = 0.4):
        """
        Initialize the EnsembleScorer.

        Args:
            lstm_weight (float): The weight to assign to the LSTM model's score.
            gnn_weight (float): The weight to assign to the GNN model's score.

        Raises:
            ValueError: If the weights do not sum to 1.
        """
        if not np.isclose(lstm_weight + gnn_weight, 1.0):
            raise ValueError("The sum of lstm_weight and gnn_weight must be 1.")

        self.lstm_weight = lstm_weight
        self.gnn_weight = gnn_weight

    def _normalize_lstm_score(self, lstm_recon_error: float, max_expected_error: float = 1.0) -> float:
        """
        Normalizes the LSTM reconstruction error to a [0, 1] range.

        A simple clipping and scaling approach is used here. In a production
        system, this could be replaced with a more sophisticated method, such
        as using the cumulative distribution function (CDF) of errors from a
        validation set.

        Args:
            lstm_recon_error (float): The raw reconstruction error (e.g., MSE).
            max_expected_error (float): The maximum error considered for scaling.
                                        Errors above this will be clipped to 1.0.

        Returns:
            float: The normalized score between 0 and 1.
        """
        # Clamp the error to prevent scores > 1
        normalized_score = min(lstm_recon_error / max_expected_error, 1.0)
        return normalized_score

    def calculate_threat_score(
        self,
        lstm_reconstruction_error: float,
        gnn_anomaly_probability: float,
        max_expected_lstm_error: float = 1.0
    ) -> float:
        """
        Calculates the final threat score based on model outputs.

        Args:
            lstm_reconstruction_error (float): The anomaly score from the LSTM
                                               (e.g., mean squared error).
            gnn_anomaly_probability (float): The anomaly probability [0, 1] for a
                                             node from the GNN.
            max_expected_lstm_error (float): The benchmark for normalizing the LSTM
                                             error. This should ideally be determined
                                             from a validation set of normal data.

        Returns:
            float: The final combined threat score, ranging from 0 to 1.
        """
        # Step 1: Normalize the LSTM score to be on the same scale as the GNN score.
        normalized_lstm_score = self._normalize_lstm_score(
            lstm_reconstruction_error,
            max_expected_error=max_expected_lstm_error
        )

        # Step 2: Ensure the GNN score is within the valid [0, 1] range.
        clamped_gnn_score = max(0.0, min(1.0, gnn_anomaly_probability))

        # Step 3: Compute the weighted average of the scores.
        threat_score = (
            self.lstm_weight * normalized_lstm_score +
            self.gnn_weight * clamped_gnn_score
        )
        
        return threat_score

def main():
    """Example usage of the EnsembleScorer."""
    print("--- Initializing Ensemble Scorer (60% LSTM, 40% GNN) ---")
    scorer = EnsembleScorer(lstm_weight=0.6, gnn_weight=0.4)

    # --- Scenario 1: Low anomaly scores from both models ---
    lstm_error_low = 0.1  # Low reconstruction error
    gnn_prob_low = 0.05   # Low anomaly probability
    score1 = scorer.calculate_threat_score(lstm_error_low, gnn_prob_low)
    print(f"\nScenario 1 (Low Anomaly):")
    print(f"  LSTM Error: {lstm_error_low}, GNN Prob: {gnn_prob_low}")
    print(f"  -> Final Threat Score: {score1:.4f}")

    # --- Scenario 2: High anomaly from LSTM, low from GNN ---
    lstm_error_high = 1.2 # High reconstruction error (will be clipped)
    gnn_prob_low = 0.1
    score2 = scorer.calculate_threat_score(lstm_error_high, gnn_prob_low)
    print(f"\nScenario 2 (High LSTM Anomaly):")
    print(f"  LSTM Error: {lstm_error_high}, GNN Prob: {gnn_prob_low}")
    print(f"  -> Final Threat Score: {score2:.4f}")

    # --- Scenario 3: Low anomaly from LSTM, high from GNN ---
    lstm_error_low = 0.2
    gnn_prob_high = 0.95  # High anomaly probability
    score3 = scorer.calculate_threat_score(lstm_error_low, gnn_prob_high)
    print(f"\nScenario 3 (High GNN Anomaly):")
    print(f"  LSTM Error: {lstm_error_low}, GNN Prob: {gnn_prob_high}")
    print(f"  -> Final Threat Score: {score3:.4f}")
    
    # --- Scenario 4: High anomaly from both models ---
    lstm_error_high = 0.9
    gnn_prob_high = 0.98
    score4 = scorer.calculate_threat_score(lstm_error_high, gnn_prob_high)
    print(f"\nScenario 4 (High Anomaly on Both):")
    print(f"  LSTM Error: {lstm_error_high}, GNN Prob: {gnn_prob_high}")
    print(f"  -> Final Threat Score: {score4:.4f}")

if __name__ == '__main__':
    main()
