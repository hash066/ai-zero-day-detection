"""
Training script for Enhanced LSTM Autoencoder.

Trains the bidirectional LSTM with attention mechanism on temporal behavioral features.
Integrates with preprocessing pipeline and model_utils for seamless data loading.

Features:
- Uses 27 temporal features from TemporalFeatureSelector
- Automatic threshold calibration on normal traffic
- Checkpoint saving with best model tracking
- Comprehensive metrics (loss, reconstruction error, anomaly detection)
- Integration with preprocessing pipeline outputs
"""

import argparse
import logging
import json
from pathlib import Path
from typing import Dict, List, Tuple
import sys

import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score

# Add parent directory for imports
sys.path.append(str(Path(__file__).parent.parent))

from models.lstm_autoencoder import EnhancedLSTMAutoencoder, TEMPORAL_FEATURE_NAMES
from preprocessing.feature_engineering import extract_all_features
from preprocessing.preprocess_tshark import preprocess_tshark_csv

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class TemporalFeatureSelector:
    """Selects 27 temporal features for LSTM Autoencoder."""
    
    TEMPORAL_FEATURES = TEMPORAL_FEATURE_NAMES
    
    @staticmethod
    def select_features(df: pd.DataFrame) -> pd.DataFrame:
        """Extract temporal features from preprocessed data."""
        available_features = [f for f in TemporalFeatureSelector.TEMPORAL_FEATURES if f in df.columns]
        
        if len(available_features) < len(TemporalFeatureSelector.TEMPORAL_FEATURES):
            missing = set(TemporalFeatureSelector.TEMPORAL_FEATURES) - set(available_features)
            logger.warning(f"Missing {len(missing)} temporal features: {missing}")
        
        return df[available_features].copy()


class TemporalDataset(torch.utils.data.Dataset):
    """PyTorch Dataset for LSTM sequences."""
    
    def __init__(
        self,
        data: pd.DataFrame,
        sequence_length: int = 10,
        stride: int = 1
    ):
        self.data = data.values.astype(np.float32)
        self.sequence_length = sequence_length
        self.stride = stride
        
        # Create sequences with sliding window
        self.sequences = []
        for i in range(0, len(self.data) - sequence_length + 1, stride):
            seq = self.data[i:i + sequence_length]
            self.sequences.append(seq)
        
        logger.info(f"Created {len(self.sequences)} sequences from {len(data)} samples")
    
    def __len__(self):
        return len(self.sequences)
    
    def __getitem__(self, idx):
        return torch.tensor(self.sequences[idx], dtype=torch.float32)

def load_and_preprocess_data(
    data_path: str,
    sequence_length: int = 10,
    stride: int = 1,
    test_size: float = 0.2
) -> Tuple[DataLoader, DataLoader, pd.DataFrame]:
    """
    Load and preprocess data for LSTM training.
    
    Args:
        data_path: Path to preprocessed CSV with features
        sequence_length: Length of temporal sequences
        stride: Stride for sequence creation
        test_size: Fraction for test set
        
    Returns:
        train_loader, test_loader, feature_df
    """
    logger.info(f"Loading data from {data_path}")
    
    # Load preprocessed data
    if data_path.endswith('.csv'):
        df = pd.read_csv(data_path)
    elif data_path.endswith('.parquet'):
        df = pd.read_parquet(data_path)
    else:
        raise ValueError(f"Unsupported file format: {data_path}")
    
    logger.info(f"Loaded {len(df)} samples with {len(df.columns)} columns")
    
    # Select temporal features
    selector = TemporalFeatureSelector()
    feature_df = selector.select_features(df)
    
    logger.info(f"Selected {len(feature_df.columns)} temporal features")
    
    # Handle missing values
    feature_df = feature_df.fillna(feature_df.mean())
    feature_df = feature_df.replace([np.inf, -np.inf], 0)
    
    # Normalize features
    from sklearn.preprocessing import StandardScaler
    scaler = StandardScaler()
    feature_df_scaled = pd.DataFrame(
        scaler.fit_transform(feature_df),
        columns=feature_df.columns
    )
    
    # Split train/test
    train_df, test_df = train_test_split(
        feature_df_scaled,
        test_size=test_size,
        random_state=42,
        shuffle=False  # Keep temporal order
    )
    
    logger.info(f"Train: {len(train_df)} samples, Test: {len(test_df)} samples")
    
    # Create datasets
    train_dataset = TemporalDataset(train_df, sequence_length, stride)
    test_dataset = TemporalDataset(test_df, sequence_length, stride)
    
    # Create dataloaders
    train_loader = DataLoader(
        train_dataset,
        batch_size=64,
        shuffle=True,
        num_workers=0
    )
    
    test_loader = DataLoader(
        test_dataset,
        batch_size=64,
        shuffle=False,
        num_workers=0
    )
    
    return train_loader, test_loader, feature_df_scaled


def train_epoch(
    model: EnhancedLSTMAutoencoder,
    dataloader: DataLoader,
    optimizer: torch.optim.Optimizer,
    device: torch.device
) -> Dict[str, float]:
    """Train for one epoch."""
    model.train()
    total_loss = 0.0
    total_samples = 0
    
    for batch_idx, sequences in enumerate(dataloader):
        sequences = sequences.to(device)
        
        optimizer.zero_grad()
        
        # Forward pass
        reconstructed, _, _ = model(sequences)
        
        # Compute reconstruction loss (MSE)
        loss = nn.MSELoss()(reconstructed, sequences)
        
        # Backward pass
        loss.backward()
        optimizer.step()
        
        total_loss += loss.item() * sequences.size(0)
        total_samples += sequences.size(0)
        
        if (batch_idx + 1) % 10 == 0:
            logger.info(
                f"Batch {batch_idx + 1}/{len(dataloader)}, "
                f"Loss: {loss.item():.6f}"
            )
    
    avg_loss = total_loss / total_samples
    return {'loss': avg_loss}


def evaluate_epoch(
    model: EnhancedLSTMAutoencoder,
    dataloader: DataLoader,
    device: torch.device
) -> Dict[str, float]:
    """Evaluate on validation/test set."""
    model.eval()
    total_loss = 0.0
    total_samples = 0
    all_errors = []
    
    with torch.no_grad():
        for sequences in dataloader:
            sequences = sequences.to(device)
            
            # Forward pass
            reconstructed, _, _ = model(sequences)
            
            # Compute loss
            loss = nn.MSELoss()(reconstructed, sequences)
            total_loss += loss.item() * sequences.size(0)
            total_samples += sequences.size(0)
            
            # Compute reconstruction errors
            sample_errors, _ = model.compute_reconstruction_error(sequences, reduction='none')
            all_errors.extend(sample_errors.cpu().numpy())
    
    avg_loss = total_loss / total_samples
    all_errors = np.array(all_errors)
    
    return {
        'loss': avg_loss,
        'mean_error': np.mean(all_errors),
        'std_error': np.std(all_errors),
        'max_error': np.max(all_errors),
        'percentile_95': np.percentile(all_errors, 95)
    }


def train_model(
    data_path: str,
    output_dir: str,
    sequence_length: int = 10,
    latent_dim: int = 64,
    num_layers: int = 2,
    dropout: float = 0.3,
    epochs: int = 50,
    learning_rate: float = 0.001,
    use_attention: bool = True,
    calibrate_threshold: bool = True
):
    """
    Main training function for LSTM Autoencoder.
    
    Args:
        data_path: Path to preprocessed data with features
        output_dir: Directory to save model and artifacts
        sequence_length: Length of temporal sequences
        latent_dim: LSTM hidden dimension
        num_layers: Number of LSTM layers
        dropout: Dropout rate
        epochs: Number of training epochs
        learning_rate: Learning rate
        use_attention: Use temporal attention mechanism
        calibrate_threshold: Calibrate threshold on normal data
    """
    # Setup
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    logger.info(f"Using device: {device}")
    
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Load data
    train_loader, test_loader, feature_df = load_and_preprocess_data(
        data_path,
        sequence_length=sequence_length,
        stride=1,
        test_size=0.2
    )
    
    input_dim = feature_df.shape[1]
    logger.info(f"Input dimension: {input_dim} features")
    
    # Create model
    model = EnhancedLSTMAutoencoder(
        input_dim=input_dim,
        latent_dim=latent_dim,
        num_layers=num_layers,
        dropout=dropout,
        use_attention=use_attention,
        feature_names=list(feature_df.columns)
    ).to(device)
    
    logger.info(f"Model created with {sum(p.numel() for p in model.parameters())} parameters")
    
    # Optimizer and scheduler
    optimizer = optim.Adam(model.parameters(), lr=learning_rate)
    scheduler = optim.lr_scheduler.ReduceLROnPlateau(
        optimizer,
        mode='min',
        factor=0.5,
        patience=5,
        verbose=True
    )
    
    # Training loop
    best_loss = float('inf')
    history = {'train_loss': [], 'test_loss': [], 'test_metrics': []}
    
    logger.info("Starting training...")
    
    for epoch in range(epochs):
        logger.info(f"\nEpoch {epoch + 1}/{epochs}")
        
        # Train
        train_metrics = train_epoch(model, train_loader, optimizer, device)
        history['train_loss'].append(train_metrics['loss'])
        
        # Evaluate
        test_metrics = evaluate_epoch(model, test_loader, device)
        history['test_loss'].append(test_metrics['loss'])
        history['test_metrics'].append(test_metrics)
        
        logger.info(
            f"Train Loss: {train_metrics['loss']:.6f}, "
            f"Test Loss: {test_metrics['loss']:.6f}, "
            f"Mean Error: {test_metrics['mean_error']:.6f}, "
            f"95th Percentile: {test_metrics['percentile_95']:.6f}"
        )
        
        # Learning rate scheduling
        scheduler.step(test_metrics['loss'])
        
        # Save best model
        if test_metrics['loss'] < best_loss:
            best_loss = test_metrics['loss']
            checkpoint = {
                'epoch': epoch,
                'model_state_dict': model.state_dict(),
                'optimizer_state_dict': optimizer.state_dict(),
                'loss': best_loss,
                'metrics': test_metrics,
                'config': {
                    'input_dim': input_dim,
                    'latent_dim': latent_dim,
                    'num_layers': num_layers,
                    'dropout': dropout,
                    'sequence_length': sequence_length,
                    'use_attention': use_attention
                }
            }
            torch.save(checkpoint, output_path / 'best_lstm_model.pth')
            logger.info(f"Saved best model with loss {best_loss:.6f}")
    
    # Calibrate threshold on normal data (training set)
    if calibrate_threshold:
        logger.info("\nCalibrating threshold on normal traffic...")
        
        # Collect all training sequences
        all_sequences = []
        for sequences in train_loader:
            all_sequences.append(sequences)
        all_sequences = torch.cat(all_sequences, dim=0).to(device)
        
        # Calibrate
        threshold_info = model.calibrate_threshold(
            all_sequences,
            percentile=95.0
        )
        
        logger.info(f"Calibrated thresholds:")
        logger.info(f"  Global: {threshold_info['global_threshold']:.6f}")
        logger.info(f"  Mean: {threshold_info['mean_error']:.6f}")
        logger.info(f"  Std: {threshold_info['std_error']:.6f}")
        
        # Save threshold info
        checkpoint['threshold_info'] = threshold_info
        torch.save(checkpoint, output_path / 'best_lstm_model.pth')
    
    # Save training history
    with open(output_path / 'training_history.json', 'w') as f:
        json.dump(history, f, indent=2, default=float)
    
    logger.info(f"\nTraining complete! Model saved to {output_path}")
    logger.info(f"Best test loss: {best_loss:.6f}")
    
    return model, history

def main():
    parser = argparse.ArgumentParser(
        description='Train Enhanced LSTM Autoencoder for zero-day detection'
    )
    
    parser.add_argument(
        '--data',
        type=str,
        required=True,
        help='Path to preprocessed data CSV/Parquet with features'
    )
    
    parser.add_argument(
        '--output',
        type=str,
        default='data/models',
        help='Output directory for model and artifacts'
    )
    
    parser.add_argument(
        '--sequence-length',
        type=int,
        default=10,
        help='Length of temporal sequences'
    )
    
    parser.add_argument(
        '--latent-dim',
        type=int,
        default=64,
        help='LSTM hidden dimension'
    )
    
    parser.add_argument(
        '--num-layers',
        type=int,
        default=2,
        help='Number of LSTM layers'
    )
    
    parser.add_argument(
        '--dropout',
        type=float,
        default=0.3,
        help='Dropout rate'
    )
    
    parser.add_argument(
        '--epochs',
        type=int,
        default=50,
        help='Number of training epochs'
    )
    
    parser.add_argument(
        '--lr',
        type=float,
        default=0.001,
        help='Learning rate'
    )
    
    parser.add_argument(
        '--no-attention',
        action='store_true',
        help='Disable attention mechanism'
    )
    
    parser.add_argument(
        '--no-calibrate',
        action='store_true',
        help='Skip threshold calibration'
    )
    
    args = parser.parse_args()
    
    # Train model
    train_model(
        data_path=args.data,
        output_dir=args.output,
        sequence_length=args.sequence_length,
        latent_dim=args.latent_dim,
        num_layers=args.num_layers,
        dropout=args.dropout,
        epochs=args.epochs,
        learning_rate=args.lr,
        use_attention=not args.no_attention,
        calibrate_threshold=not args.no_calibrate
    )


if __name__ == '__main__':
    main()
