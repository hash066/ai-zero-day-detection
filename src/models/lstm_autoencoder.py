"""
Enhanced LSTM Autoencoder for zero-day attack detection.

Integrated with preprocessing pipeline features (entropy, burstiness, temporal patterns).
Uses bidirectional LSTM with attention mechanism for superior anomaly detection.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
from typing import Dict, List, Tuple, Optional
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Temporal feature indices for the 27 engineered features
TEMPORAL_FEATURE_NAMES = [
    'src_port_entropy', 'dst_port_entropy', 'src_ip_entropy', 'dst_ip_entropy',
    'packet_size_entropy', 'mean_inter_arrival', 'std_inter_arrival',
    'cv_inter_arrival', 'burstiness', 'periodicity_score', 'peak_hour',
    'off_hours_ratio', 'hour_entropy', 'connection_diversity', 'fan_out_ratio',
    'rare_protocol_ratio', 'protocol_switching_rate', 'size_mean', 'size_std',
    'size_skewness', 'size_kurtosis', 'small_packet_ratio', 'large_packet_ratio'
]


class TemporalAttention(nn.Module):
    """
    Attention mechanism for focusing on anomalous time steps.
    
    Learns to assign higher weights to time steps with unusual patterns,
    improving reconstruction of normal sequences while highlighting anomalies.
    """
    
    def __init__(self, hidden_dim: int):
        super(TemporalAttention, self).__init__()
        self.attention = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.Tanh(),
            nn.Linear(hidden_dim // 2, 1)
        )
    
    def forward(self, lstm_output: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Args:
            lstm_output: (batch, seq_len, hidden_dim)
            
        Returns:
            context: (batch, hidden_dim) - weighted sum of lstm outputs
            attention_weights: (batch, seq_len) - attention scores for explainability
        """
        # Calculate attention scores for each time step
        attention_scores = self.attention(lstm_output)  # (batch, seq_len, 1)
        attention_weights = F.softmax(attention_scores.squeeze(-1), dim=1)  # (batch, seq_len)
        
        # Apply attention weights to create context vector
        context = torch.bmm(
            attention_weights.unsqueeze(1),  # (batch, 1, seq_len)
            lstm_output  # (batch, seq_len, hidden_dim)
        ).squeeze(1)  # (batch, hidden_dim)
        
        return context, attention_weights


class EnhancedLSTMAutoencoder(nn.Module):
    """
    Enhanced LSTM Autoencoder for zero-day attack detection.
    
    Key improvements:
    1. Bidirectional LSTM to capture both past and future context
    2. Temporal attention mechanism to focus on anomalous patterns
    3. Feature normalization built-in
    4. Integration with preprocessing pipeline features
    5. Threshold auto-calibration from normal traffic
    6. Per-timestep reconstruction errors for explainability
    
    Architecture:
    - Bidirectional Encoder LSTM
    - Temporal Attention Layer
    - Decoder LSTM with attention context
    - Feature-wise reconstruction layer
    """

    def __init__(
        self,
        input_dim: int,
        latent_dim: int = 64,
        num_layers: int = 2,
        dropout: float = 0.3,
        use_attention: bool = True,
        feature_names: Optional[List[str]] = None
    ):
        """
        Initialize Enhanced LSTM Autoencoder.

        Args:
            input_dim: Number of features per time step
            latent_dim: Dimensionality of latent space
            num_layers: Number of LSTM layers
            dropout: Dropout probability
            use_attention: Whether to use attention mechanism
            feature_names: Names of input features for feature importance tracking
        """
        super(EnhancedLSTMAutoencoder, self).__init__()

        self.input_dim = input_dim
        self.latent_dim = latent_dim
        self.num_layers = num_layers
        self.use_attention = use_attention
        self.feature_names = feature_names or [f'feature_{i}' for i in range(input_dim)]

        # Feature normalization layers (learned mean/std per feature)
        self.feature_norm = nn.BatchNorm1d(input_dim)
        
        # --- Bidirectional Encoder ---
        # Captures both past and future context in sequences
        self.encoder = nn.LSTM(
            input_size=input_dim,
            hidden_size=latent_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0,
            bidirectional=True
        )
        
        # Attention mechanism for focusing on important time steps
        if use_attention:
            self.attention = TemporalAttention(latent_dim * 2)  # *2 for bidirectional
        
        # Project bidirectional hidden state to decoder hidden size
        self.bridge = nn.Linear(latent_dim * 2, latent_dim)
        
        # --- Decoder ---
        self.decoder = nn.LSTM(
            input_size=latent_dim,
            hidden_size=latent_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0
        )
        
        # --- Feature-wise Reconstruction ---
        # Separate output heads for different feature types
        self.reconstruction_layer = nn.Sequential(
            nn.Linear(latent_dim, latent_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(latent_dim // 2, input_dim)
        )
        
        # Reconstruction error thresholds (calibrated during training)
        self.register_buffer('reconstruction_threshold', torch.tensor(0.0))
        self.register_buffer('feature_thresholds', torch.zeros(input_dim))
        
        logger.info(f"Enhanced LSTM Autoencoder initialized: "
                    f"{input_dim} features, {latent_dim} latent dim, "
                    f"bidirectional={'Yes' if True else 'No'}, "
                    f"attention={'Yes' if use_attention else 'No'}")

    def forward(
        self,
        x: torch.Tensor,
        return_attention: bool = False
    ) -> Tuple[torch.Tensor, Optional[torch.Tensor], Optional[torch.Tensor]]:
        """
        Forward pass with optional attention weights.

        Args:
            x: Input (batch, seq_len, input_dim)
            return_attention: Whether to return attention weights

        Returns:
            reconstructed: Reconstructed sequence (batch, seq_len, input_dim)
            attention_weights: Attention scores if return_attention=True
            latent_representation: Encoded representation
        """
        batch_size, seq_len, _ = x.shape
        
        # --- Normalize Features ---
        # Reshape for BatchNorm1d: (batch * seq_len, features)
        x_reshaped = x.reshape(-1, self.input_dim)
        x_normalized = self.feature_norm(x_reshaped)
        x_normalized = x_normalized.reshape(batch_size, seq_len, self.input_dim)
        
        # --- Encode ---
        encoder_output, (hidden, cell) = self.encoder(x_normalized)
        # encoder_output: (batch, seq_len, latent_dim * 2) for bidirectional
        
        # --- Apply Attention (if enabled) ---
        attention_weights = None
        if self.use_attention:
            context, attention_weights = self.attention(encoder_output)
            # Use attention context as initial decoder state
            latent_representation = context
        else:
            # Use final hidden state
            # Concatenate forward and backward hidden states
            hidden_concat = torch.cat([hidden[-2], hidden[-1]], dim=1)  # (batch, latent_dim * 2)
            latent_representation = hidden_concat
        
        # Bridge bidirectional encoder to unidirectional decoder
        decoder_hidden = self.bridge(latent_representation)  # (batch, latent_dim)
        
        # Prepare decoder initial state
        decoder_hidden = decoder_hidden.unsqueeze(0).repeat(self.num_layers, 1, 1)
        decoder_cell = torch.zeros_like(decoder_hidden)
        
        # --- Decode ---
        # Repeat latent representation for each time step
        decoder_input = latent_representation.unsqueeze(1).repeat(1, seq_len, 1)
        decoder_input = self.bridge(decoder_input)  # Project to decoder input size
        
        decoder_output, _ = self.decoder(decoder_input, (decoder_hidden, decoder_cell))
        
        # --- Reconstruct ---
        reconstructed = self.reconstruction_layer(decoder_output)
        
        if return_attention:
            return reconstructed, attention_weights, latent_representation
        else:
            return reconstructed, None, latent_representation

    def compute_reconstruction_error(
        self,
        x: torch.Tensor,
        reduction: str = 'mean'
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Compute reconstruction error for anomaly scoring.

        Args:
            x: Input sequence (batch, seq_len, input_dim)
            reduction: 'mean', 'sum', or 'none' (per-sample)

        Returns:
            total_error: Scalar or per-sample error
            feature_errors: Per-feature errors for explainability (batch, input_dim)
        """
        self.eval()
        with torch.no_grad():
            reconstructed, _, _ = self.forward(x)
            
            # MSE per feature per sample
            squared_errors = (x - reconstructed) ** 2  # (batch, seq_len, input_dim)
            
            # Average over time, keep feature dimension
            feature_errors = squared_errors.mean(dim=1)  # (batch, input_dim)
            
            # Total error per sample
            if reduction == 'mean':
                total_error = feature_errors.mean(dim=1)  # (batch,)
            elif reduction == 'sum':
                total_error = feature_errors.sum(dim=1)  # (batch,)
            elif reduction == 'none':
                total_error = feature_errors  # (batch, input_dim)
            else:
                raise ValueError(f"Unknown reduction: {reduction}")
        
        return total_error, feature_errors

    def calibrate_threshold(
        self,
        normal_data: torch.Tensor,
        percentile: float = 95.0
    ) -> Dict[str, float]:
        """
        Calibrate anomaly detection threshold from normal traffic.

        Args:
            normal_data: Normal traffic sequences (num_samples, seq_len, input_dim)
            percentile: Percentile for threshold (95 = 95th percentile)

        Returns:
            Dictionary with threshold statistics
        """
        logger.info(f"Calibrating threshold on {normal_data.shape[0]} normal samples...")
        
        self.eval()
        errors = []
        feature_errors_list = []
        
        # Process in batches to avoid memory issues
        batch_size = 64
        for i in range(0, normal_data.shape[0], batch_size):
            batch = normal_data[i:i+batch_size]
            error, feat_error = self.compute_reconstruction_error(batch, reduction='mean')
            errors.append(error.cpu().numpy())
            feature_errors_list.append(feat_error.cpu().numpy())
        
        errors = np.concatenate(errors)
        feature_errors_all = np.concatenate(feature_errors_list, axis=0)
        
        # Set global threshold
        threshold = np.percentile(errors, percentile)
        self.reconstruction_threshold = torch.tensor(threshold, dtype=torch.float32)
        
        # Set per-feature thresholds
        feature_thresholds = np.percentile(feature_errors_all, percentile, axis=0)
        self.feature_thresholds = torch.tensor(feature_thresholds, dtype=torch.float32)
        
        logger.info(f"Threshold set to {threshold:.6f} ({percentile}th percentile)")
        logger.info(f"Mean reconstruction error on normal data: {errors.mean():.6f}")
        logger.info(f"Std reconstruction error: {errors.std():.6f}")
        
        return {
            'threshold': float(threshold),
            'mean_error': float(errors.mean()),
            'std_error': float(errors.std()),
            'percentile': percentile,
            'num_samples': len(errors)
        }

    def detect_anomalies(
        self,
        x: torch.Tensor,
        return_details: bool = False
    ) -> Dict[str, any]:
        """
        Detect anomalies in input sequences.

        Args:
            x: Input sequences (batch, seq_len, input_dim)
            return_details: Whether to return detailed feature errors

        Returns:
            Dictionary with anomaly scores and details
        """
        total_error, feature_errors = self.compute_reconstruction_error(x)
        
        # Binary anomaly labels
        is_anomaly = (total_error > self.reconstruction_threshold.item()).cpu().numpy()
        
        # Normalized anomaly scores (0-1 range)
        anomaly_scores = torch.clamp(
            total_error / (self.reconstruction_threshold + 1e-8),
            0, 10  # Cap at 10x threshold
        ).cpu().numpy()
        
        results = {
            'anomaly_scores': anomaly_scores,
            'is_anomaly': is_anomaly,
            'reconstruction_errors': total_error.cpu().numpy(),
            'threshold': self.reconstruction_threshold.item()
        }
        
        if return_details:
            # Find top anomalous features for each sample
            top_k = 5
            top_features = []
            for i in range(feature_errors.shape[0]):
                feat_err = feature_errors[i].cpu().numpy()
                top_indices = np.argsort(feat_err)[-top_k:][::-1]
                top_features.append([
                    {
                        'feature': self.feature_names[idx],
                        'error': float(feat_err[idx]),
                        'threshold': float(self.feature_thresholds[idx])
                    }
                    for idx in top_indices
                ])
            results['top_anomalous_features'] = top_features
            results['feature_errors'] = feature_errors.cpu().numpy()
        
        return results

def main():
    """Example usage and model summary."""
    # --- Model Configuration ---
    INPUT_DIM = 42      # Number of features from SysmonFeatureRecord
    LATENT_DIM = 16     # Dimensionality of the compressed representation
    SEQUENCE_LENGTH = 20 # Number of events in a sequence
    BATCH_SIZE = 64     # Number of sequences processed at once
    NUM_LAYERS = 2      # Number of LSTM layers

    # --- Create Model ---
    model = EnhancedLSTMAutoencoder(input_dim=INPUT_DIM, latent_dim=LATENT_DIM, num_layers=NUM_LAYERS)
    print("--- LSTM Autoencoder Architecture ---")
    print(model)
    
    # --- Example Input ---
    # Create a random tensor to simulate a batch of sequences
    example_input = torch.randn(BATCH_SIZE, SEQUENCE_LENGTH, INPUT_DIM)
    
    # --- Forward Pass ---
    try:
        reconstructed_output = model(example_input)
        
        # --- Verify Shapes ---
        print("\n--- Tensor Shapes ---")
        print(f"Input shape:      {example_input.shape}")
        print(f"Reconstructed shape: {reconstructed_output.shape}")
        
        assert example_input.shape == reconstructed_output.shape
        print("\nModel forward pass successful, and shapes match!")

    except Exception as e:
        print(f"\nAn error occurred during the forward pass: {e}")

if __name__ == '__main__':
    main()
