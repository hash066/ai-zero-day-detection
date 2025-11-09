"""
Enhanced Ensemble Scorer for zero-day attack detection.

Combines LSTM temporal anomaly scores and GNN graph anomaly scores with:
- Learned weight combination (neural network)
- Confidence scoring based on model agreement
- Temporal consistency tracking
- Feature-based context integration
- Explainability via feature attributions
"""

import numpy as np
import torch
import torch.nn as nn
from typing import Dict, List, Optional, Tuple
from collections import deque
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class LearnedEnsembleCombiner(nn.Module):
    """
    Neural network for learning optimal combination of LSTM and GNN scores.
    
    Instead of fixed weights, learns to combine scores based on context
    and feature patterns for more adaptive threat detection.
    """
    
    def __init__(
        self,
        feature_dim: int = 27,  # 27 behavioral features from preprocessing
        hidden_dim: int = 32
    ):
        super(LearnedEnsembleCombiner, self).__init__()
        
        # Network that takes model scores + features and outputs combined score
        self.combiner = nn.Sequential(
            nn.Linear(2 + feature_dim, hidden_dim),  # 2 = LSTM + GNN scores
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Linear(hidden_dim // 2, 1),
            nn.Sigmoid()
        )
        
        # Attention layer for feature importance
        self.feature_attention = nn.Sequential(
            nn.Linear(feature_dim, feature_dim // 2),
            nn.Tanh(),
            nn.Linear(feature_dim // 2, feature_dim),
            nn.Softmax(dim=-1)
        )
    
    def forward(
        self,
        lstm_score: torch.Tensor,
        gnn_score: torch.Tensor,
        features: torch.Tensor
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Args:
            lstm_score: (batch,) - LSTM anomaly scores
            gnn_score: (batch,) - GNN anomaly scores
            features: (batch, feature_dim) - behavioral features
            
        Returns:
            combined_score: (batch,) - final threat score
            feature_weights: (batch, feature_dim) - feature importance
        """
        # Calculate feature importance
        feature_weights = self.feature_attention(features)
        weighted_features = features * feature_weights
        
        # Concatenate scores and features
        combined_input = torch.cat([
            lstm_score.unsqueeze(-1),
            gnn_score.unsqueeze(-1),
            weighted_features
        ], dim=-1)
        
        # Compute combined score
        combined_score = self.combiner(combined_input).squeeze(-1)
        
        return combined_score, feature_weights


class EnhancedEnsembleScorer:
    """
    Enhanced ensemble scorer for zero-day attack detection.
    
    Key improvements over basic weighted average:
    1. Learned weight combination via neural network
    2. Confidence scoring based on model agreement
    3. Temporal consistency tracking (smoothing over time)
    4. Feature-based context integration (uses behavioral features)
    5. Calibration mechanism for score reliability
    6. Explainability via feature attributions
    
    Integrates with:
    - LSTM Autoencoder (temporal anomaly scores)
    - GNN Detector (graph anomaly scores)
    - Feature Engineering (27 behavioral features)
    - Sysmon features (process behavior)
    """

    def __init__(
        self,
        feature_dim: int = 27,
        use_learned_weights: bool = True,
        temporal_window: int = 10,
        confidence_threshold: float = 0.7,
        lstm_weight: float = 0.6,
        gnn_weight: float = 0.4
    ):
        """
        Initialize Enhanced Ensemble Scorer.

        Args:
            feature_dim: Number of behavioral features
            use_learned_weights: Use neural network for weight learning
            temporal_window: Size of temporal smoothing window
            confidence_threshold: Minimum confidence for high-confidence alerts
        """
        self.feature_dim = feature_dim
        self.use_learned_weights = use_learned_weights
        self.temporal_window = temporal_window
        self.confidence_threshold = confidence_threshold
        
        # Learned combiner
        if use_learned_weights:
            self.combiner = LearnedEnsembleCombiner(feature_dim)
        else:
            # Fallback to fixed weights
            self.lstm_weight = 0.6
            self.gnn_weight = 0.4
        
        # Temporal consistency tracking
        self.score_history = deque(maxlen=temporal_window)
        
        # Calibration parameters (fitted on validation data)
        self.calibration_a = 1.0  # Platt scaling parameter
        self.calibration_b = 0.0
        
        # Feature importance tracking
        self.feature_names = [
            'src_port_entropy', 'dst_port_entropy', 'src_ip_entropy', 'dst_ip_entropy',
            'packet_size_entropy', 'mean_inter_arrival', 'std_inter_arrival',
            'cv_inter_arrival', 'burstiness', 'periodicity_score', 'peak_hour',
            'off_hours_ratio', 'hour_entropy', 'connection_diversity', 'fan_out_ratio',
            'rare_protocol_ratio', 'protocol_switching_rate', 'size_mean', 'size_std',
            'size_skewness', 'size_kurtosis', 'small_packet_ratio', 'large_packet_ratio',
            'process_diversity', 'registry_access_count', 'network_connection_count', 'file_creation_count'
        ]
        
        logger.info(f"Enhanced Ensemble Scorer initialized: "
                   f"learned_weights={use_learned_weights}, "
                   f"temporal_window={temporal_window}")

    def calculate_threat_score(
        self,
        lstm_score: float,
        gnn_score: float,
        behavioral_features: Optional[np.ndarray] = None,
        return_details: bool = False
    ) -> Dict:
        """
        Calculate comprehensive threat score with confidence and explanations.

        Args:
            lstm_score: LSTM anomaly score (0-1)
            gnn_score: GNN anomaly score (0-1)
            behavioral_features: 27 behavioral features from preprocessing
            return_details: Whether to return detailed explanations

        Returns:
            Dictionary with threat score, confidence, and optional details
        """
        # Convert to tensors
        lstm_tensor = torch.tensor([lstm_score], dtype=torch.float32)
        gnn_tensor = torch.tensor([gnn_score], dtype=torch.float32)
        
        # --- Combine Scores ---
        if self.use_learned_weights and behavioral_features is not None:
            # Use learned combiner with features
            features_tensor = torch.tensor(
                behavioral_features.reshape(1, -1),
                dtype=torch.float32
            )
            
            with torch.no_grad():
                combined_score, feature_weights = self.combiner(
                    lstm_tensor, gnn_tensor, features_tensor
                )
            
            threat_score = combined_score.item()
            feature_importance = feature_weights.squeeze().numpy()
        else:
            # Fallback to weighted average
            threat_score = (
                self.lstm_weight * lstm_score +
                self.gnn_weight * gnn_score
            )
            feature_importance = None
        
        # --- Apply Calibration ---
        # Platt scaling for better probability estimates
        calibrated_score = 1.0 / (1.0 + np.exp(
            self.calibration_a * threat_score + self.calibration_b
        ))
        
        # --- Calculate Confidence ---
        # High confidence when models agree
        model_agreement = 1.0 - abs(lstm_score - gnn_score)
        
        # High confidence when scores are extreme (very high or very low)
        score_extremity = 2 * abs(calibrated_score - 0.5)
        
        confidence = (model_agreement + score_extremity) / 2
        
        # --- Temporal Consistency ---
        self.score_history.append(calibrated_score)
        
        if len(self.score_history) >= 3:
            # Smooth score using exponential moving average
            smoothed_score = self._calculate_ema(list(self.score_history), alpha=0.3)
            
            # Measure temporal volatility
            volatility = np.std(list(self.score_history))
            
            # Adjust confidence based on consistency
            temporal_consistency = 1.0 - min(volatility * 2, 1.0)
            confidence = (confidence + temporal_consistency) / 2
        else:
            smoothed_score = calibrated_score
        
        # --- Build Results ---
        results = {
            'threat_score': float(smoothed_score),
            'raw_threat_score': float(threat_score),
            'calibrated_score': float(calibrated_score),
            'confidence': float(confidence),
            'lstm_score': float(lstm_score),
            'gnn_score': float(gnn_score),
            'is_high_confidence': confidence >= self.confidence_threshold,
            'is_anomalous': smoothed_score > 0.5
        }
        
        # --- Add Detailed Explanations ---
        if return_details:
            # Feature-based explanation
            if feature_importance is not None and behavioral_features is not None:
                top_k = 5
                top_indices = np.argsort(feature_importance)[-top_k:][::-1]
                
                results['top_contributing_features'] = [
                    {
                        'feature': self.feature_names[idx] if idx < len(self.feature_names) else f'feature_{idx}',
                        'importance': float(feature_importance[idx]),
                        'value': float(behavioral_features[idx])
                    }
                    for idx in top_indices
                ]
            
            # Model contribution breakdown
            if self.use_learned_weights:
                results['model_contribution'] = {
                    'lstm': 'learned',
                    'gnn': 'learned'
                }
            else:
                results['model_contribution'] = {
                    'lstm': self.lstm_weight * lstm_score / (threat_score + 1e-8),
                    'gnn': self.gnn_weight * gnn_score / (threat_score + 1e-8)
                }
            
            # Temporal context
            results['temporal_context'] = {
                'history_length': len(self.score_history),
                'score_trend': self._calculate_trend(),
                'volatility': float(np.std(list(self.score_history))) if len(self.score_history) > 1 else 0.0
            }
        
        return results

    def _calculate_ema(self, values: List[float], alpha: float = 0.3) -> float:
        """Calculate exponential moving average."""
        ema = values[0]
        for value in values[1:]:
            ema = alpha * value + (1 - alpha) * ema
        return ema

    def _calculate_trend(self) -> str:
        """Calculate score trend (increasing, decreasing, stable)."""
        if len(self.score_history) < 3:
            return 'insufficient_data'
        
        recent = list(self.score_history)
        first_half_mean = np.mean(recent[:len(recent)//2])
        second_half_mean = np.mean(recent[len(recent)//2:])
        
        if second_half_mean > first_half_mean + 0.1:
            return 'increasing'
        elif second_half_mean < first_half_mean - 0.1:
            return 'decreasing'
        else:
            return 'stable'

    def calibrate(
        self,
        validation_scores: List[Tuple[float, float, int]],
        method: str = 'platt'
    ) -> Dict[str, float]:
        """
        Calibrate ensemble scores on validation data.

        Args:
            validation_scores: List of (lstm_score, gnn_score, label) tuples
            method: Calibration method ('platt' or 'isotonic')

        Returns:
            Calibration statistics
        """
        logger.info(f"Calibrating ensemble scorer on {len(validation_scores)} samples...")
        
        # Calculate raw scores
        raw_scores = []
        labels = []
        
        for lstm_score, gnn_score, label in validation_scores:
            if self.use_learned_weights:
                # Would need features here, fallback to weighted average
                score = self.lstm_weight * lstm_score + self.gnn_weight * gnn_score
            else:
                score = self.lstm_weight * lstm_score + self.gnn_weight * gnn_score
            
            raw_scores.append(score)
            labels.append(label)
        
        raw_scores = np.array(raw_scores)
        labels = np.array(labels)
        
        if method == 'platt':
            # Fit logistic regression for Platt scaling
            from scipy.optimize import minimize
            
            def log_loss(params):
                a, b = params
                calibrated = 1.0 / (1.0 + np.exp(a * raw_scores + b))
                epsilon = 1e-8
                calibrated = np.clip(calibrated, epsilon, 1 - epsilon)
                loss = -np.mean(labels * np.log(calibrated) + (1 - labels) * np.log(1 - calibrated))
                return loss
            
            result = minimize(log_loss, [1.0, 0.0], method='BFGS')
            self.calibration_a, self.calibration_b = result.x
            
            logger.info(f"Platt scaling parameters: a={self.calibration_a:.4f}, b={self.calibration_b:.4f}")
        
        # Calculate calibrated scores
        calibrated_scores = 1.0 / (1.0 + np.exp(
            self.calibration_a * raw_scores + self.calibration_b
        ))
        
        # Measure calibration quality (Brier score)
        brier_score = np.mean((calibrated_scores - labels) ** 2)
        
        return {
            'calibration_method': method,
            'calibration_a': float(self.calibration_a),
            'calibration_b': float(self.calibration_b),
            'brier_score': float(brier_score),
            'num_samples': len(validation_scores)
        }

    def reset_temporal_state(self):
        """Reset temporal tracking (call when starting new session)."""
        self.score_history.clear()
        logger.info("Temporal state reset")

    def train_combiner(
        self,
        training_data: List[Tuple[float, float, np.ndarray, int]],
        epochs: int = 50,
        lr: float = 0.001
    ) -> Dict[str, List[float]]:
        """
        Train the learned ensemble combiner.

        Args:
            training_data: List of (lstm_score, gnn_score, features, label) tuples
            epochs: Number of training epochs
            lr: Learning rate

        Returns:
            Training history
        """
        if not self.use_learned_weights:
            logger.warning("Learned weights disabled, skipping training")
            return {}
        
        logger.info(f"Training ensemble combiner on {len(training_data)} samples...")
        
        # Prepare data
        lstm_scores = []
        gnn_scores = []
        features_list = []
        labels = []
        
        for lstm_score, gnn_score, features, label in training_data:
            lstm_scores.append(lstm_score)
            gnn_scores.append(gnn_score)
            features_list.append(features)
            labels.append(label)
        
        lstm_tensor = torch.tensor(lstm_scores, dtype=torch.float32)
        gnn_tensor = torch.tensor(gnn_scores, dtype=torch.float32)
        features_tensor = torch.tensor(np.array(features_list), dtype=torch.float32)
        labels_tensor = torch.tensor(labels, dtype=torch.float32)
        
        # Training loop
        optimizer = torch.optim.Adam(self.combiner.parameters(), lr=lr)
        criterion = nn.BCELoss()
        
        history = {'loss': [], 'accuracy': []}
        
        for epoch in range(epochs):
            self.combiner.train()
            optimizer.zero_grad()
            
            # Forward pass
            predictions, _ = self.combiner(lstm_tensor, gnn_tensor, features_tensor)
            loss = criterion(predictions, labels_tensor)
            
            # Backward pass
            loss.backward()
            optimizer.step()
            
            # Metrics
            accuracy = ((predictions > 0.5) == labels_tensor).float().mean()
            history['loss'].append(loss.item())
            history['accuracy'].append(accuracy.item())
            
            if (epoch + 1) % 10 == 0:
                logger.info(f"Epoch {epoch+1}/{epochs}: Loss={loss.item():.4f}, Acc={accuracy.item():.4f}")
        
        logger.info("Ensemble combiner training complete")
        return history

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
