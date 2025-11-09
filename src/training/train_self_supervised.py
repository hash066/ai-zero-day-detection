"""
Training script for Self-Supervised Pre-training.

Pre-trains encoders using SimCLR contrastive learning on unlabeled normal traffic.
Provides better initialization for downstream LSTM/GNN models.

Features:
- Behavioral encoder for 92 tabular features
- Temporal encoder for sequential data
- BehavioralAugmentation for positive pairs
- NT-Xent contrastive loss
- Transfer learning to LSTM/GNN
- Feature extraction utilities
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

# Add parent directory for imports
sys.path.append(str(Path(__file__).parent.parent))

from models.self_supervised_model import (
    BehavioralAugmentation,
    BehavioralEncoder,
    TemporalBehavioralEncoder,
    EnhancedSimCLRModel,
    BehavioralPretrainingDataset,
    SelfSupervisedTrainer,
    transfer_to_lstm,
    transfer_to_gnn
)
from models.lstm_autoencoder import EnhancedLSTMAutoencoder
from models.gnn_detector import EnhancedGNNDetector
from preprocessing.feature_engineering import extract_all_features

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def train_behavioral_encoder(
    data_path: str,
    output_dir: str,
    input_dim: int = 92,
    output_dim: int = 128,
    hidden_dims: List[int] = [256, 512, 256],
    dropout: float = 0.2,
    epochs: int = 100,
    batch_size: int = 256,
    learning_rate: float = 0.001,
    temperature: float = 0.5,
    noise_std: float = 0.1,
    mask_ratio: float = 0.15
):
    """
    Train behavioral encoder on tabular features.
    
    Args:
        data_path: Path to preprocessed CSV with 92 features
        output_dir: Directory to save model and artifacts
        input_dim: Number of input features (92)
        output_dim: Encoder output dimension
        hidden_dims: Hidden layer dimensions
        dropout: Dropout rate
        epochs: Number of training epochs
        batch_size: Batch size for training
        learning_rate: Learning rate
        temperature: Temperature for NT-Xent loss
        noise_std: Standard deviation for noise augmentation
        mask_ratio: Ratio of features to mask
    """
    # Setup
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    logger.info(f"Using device: {device}")
    
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Create augmentation strategy
    augmentation = BehavioralAugmentation(
        noise_std=noise_std,
        mask_ratio=mask_ratio
    )
    
    logger.info(f"Created augmentation: noise_std={noise_std}, mask_ratio={mask_ratio}")
    
    # Create dataset
    dataset = BehavioralPretrainingDataset(
        data_path=data_path,
        augmentation=augmentation,
        is_temporal=False
    )
    
    dataloader = DataLoader(
        dataset,
        batch_size=batch_size,
        shuffle=True,
        num_workers=0
    )
    
    logger.info(f"Created dataset with {len(dataset)} samples")
    
    # Create encoder
    encoder = BehavioralEncoder(
        input_dim=input_dim,
        hidden_dims=hidden_dims,
        output_dim=output_dim,
        dropout=dropout
    )
    
    # Create SimCLR model
    model = EnhancedSimCLRModel(
        base_encoder=encoder,
        projection_dim=output_dim
    ).to(device)
    
    logger.info(f"Model created with {sum(p.numel() for p in model.parameters())} parameters")
    
    # Create trainer
    trainer = SelfSupervisedTrainer(
        model=model,
        device=device,
        learning_rate=learning_rate,
        temperature=temperature
    )
    
    # Train
    logger.info("Starting training...")
    history = trainer.train(
        dataloader,
        epochs=epochs,
        save_path=str(output_path / 'behavioral_encoder.pth')
    )
    
    # Save training history
    with open(output_path / 'training_history.json', 'w') as f:
        json.dump(history, f, indent=2, default=float)
    
    # Save config
    config = {
        'encoder_type': 'behavioral',
        'input_dim': input_dim,
        'output_dim': output_dim,
        'hidden_dims': hidden_dims,
        'dropout': dropout,
        'temperature': temperature,
        'noise_std': noise_std,
        'mask_ratio': mask_ratio
    }
    
    with open(output_path / 'config.json', 'w') as f:
        json.dump(config, f, indent=2)
    
    logger.info(f"\nTraining complete! Model saved to {output_path}")
    logger.info(f"Final loss: {history['loss'][-1]:.6f}")
    
    return model, history


def train_temporal_encoder(
    data_path: str,
    output_dir: str,
    input_dim: int = 92,
    output_dim: int = 128,
    feature_hidden_dim: int = 256,
    lstm_hidden_dim: int = 128,
    num_lstm_layers: int = 2,
    dropout: float = 0.2,
    sequence_length: int = 10,
    epochs: int = 100,
    batch_size: int = 128,
    learning_rate: float = 0.001,
    temperature: float = 0.5,
    noise_std: float = 0.1,
    mask_ratio: float = 0.15,
    jitter_std: float = 0.05
):
    """
    Train temporal encoder on sequential features.
    
    Args:
        data_path: Path to preprocessed CSV with 92 features
        output_dir: Directory to save model and artifacts
        input_dim: Number of input features (92)
        output_dim: Encoder output dimension
        feature_hidden_dim: Hidden dimension for feature encoding
        lstm_hidden_dim: LSTM hidden dimension
        num_lstm_layers: Number of LSTM layers
        dropout: Dropout rate
        sequence_length: Length of sequences
        epochs: Number of training epochs
        batch_size: Batch size for training
        learning_rate: Learning rate
        temperature: Temperature for NT-Xent loss
        noise_std: Standard deviation for noise augmentation
        mask_ratio: Ratio of features to mask
        jitter_std: Standard deviation for temporal jitter
    """
    # Setup
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    logger.info(f"Using device: {device}")
    
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Create augmentation strategy
    augmentation = BehavioralAugmentation(
        noise_std=noise_std,
        mask_ratio=mask_ratio,
        jitter_std=jitter_std
    )
    
    logger.info(f"Created temporal augmentation: jitter_std={jitter_std}")
    
    # Create dataset
    dataset = BehavioralPretrainingDataset(
        data_path=data_path,
        augmentation=augmentation,
        is_temporal=True,
        sequence_length=sequence_length
    )
    
    dataloader = DataLoader(
        dataset,
        batch_size=batch_size,
        shuffle=True,
        num_workers=0
    )
    
    logger.info(f"Created temporal dataset with {len(dataset)} samples")
    
    # Create encoder
    encoder = TemporalBehavioralEncoder(
        input_dim=input_dim,
        feature_hidden_dim=feature_hidden_dim,
        lstm_hidden_dim=lstm_hidden_dim,
        output_dim=output_dim,
        num_lstm_layers=num_lstm_layers,
        dropout=dropout
    )
    
    # Create SimCLR model
    model = EnhancedSimCLRModel(
        base_encoder=encoder,
        encoder_output_dim=output_dim
    ).to(device)
    
    logger.info(f"Model created with {sum(p.numel() for p in model.parameters())} parameters")
    
    # Create trainer
    trainer = SelfSupervisedTrainer(
        model=model,
        device=device,
        learning_rate=learning_rate,
        temperature=temperature
    )
    
    # Train
    logger.info("Starting training...")
    history = trainer.train(
        dataloader,
        epochs=epochs,
        save_path=str(output_path / 'temporal_encoder.pth')
    )
    
    # Save training history
    with open(output_path / 'training_history.json', 'w') as f:
        json.dump(history, f, indent=2, default=float)
    
    # Save config
    config = {
        'encoder_type': 'temporal',
        'input_dim': input_dim,
        'output_dim': output_dim,
        'feature_hidden_dim': feature_hidden_dim,
        'lstm_hidden_dim': lstm_hidden_dim,
        'num_lstm_layers': num_lstm_layers,
        'sequence_length': sequence_length,
        'dropout': dropout,
        'temperature': temperature,
        'noise_std': noise_std,
        'mask_ratio': mask_ratio,
        'jitter_std': jitter_std
    }
    
    with open(output_path / 'config.json', 'w') as f:
        json.dump(config, f, indent=2)
    
    logger.info(f"\nTraining complete! Model saved to {output_path}")
    logger.info(f"Final loss: {history['loss'][-1]:.6f}")
    
    return model, history


def demo_transfer_learning(
    pretrained_model_path: str,
    encoder_type: str = 'behavioral'
):
    """
    Demonstrate transfer learning to LSTM/GNN models.
    
    Args:
        pretrained_model_path: Path to pre-trained SimCLR model
        encoder_type: 'behavioral' or 'temporal'
    """
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    
    # Load config
    config_path = Path(pretrained_model_path).parent / 'config.json'
    with open(config_path, 'r') as f:
        config = json.load(f)
    
    logger.info(f"Loaded config: {config}")
    
    # Create encoder
    if encoder_type == 'behavioral':
        encoder = BehavioralEncoder(
            input_dim=config['input_dim'],
            hidden_dims=config['hidden_dims'],
            output_dim=config['output_dim'],
            dropout=config['dropout']
        )
    else:
        encoder = TemporalBehavioralEncoder(
            input_dim=config['input_dim'],
            feature_hidden_dim=config['feature_hidden_dim'],
            lstm_hidden_dim=config['lstm_hidden_dim'],
            output_dim=config['output_dim'],
            num_lstm_layers=config['num_lstm_layers'],
            dropout=config['dropout']
        )
    
    # Create SimCLR model
    simclr_model = EnhancedSimCLRModel(
        base_encoder=encoder,
        projection_dim=config['output_dim']
    )
    
    # Load weights
    simclr_model.load_state_dict(torch.load(pretrained_model_path, map_location=device))
    logger.info(f"Loaded pre-trained weights from {pretrained_model_path}")
    
    # Transfer to LSTM
    if encoder_type == 'temporal':
        lstm_model = EnhancedLSTMAutoencoder(
            input_dim=27,  # 27 temporal features
            latent_dim=64
        )
        
        lstm_model = transfer_to_lstm(
            simclr_model,
            lstm_model,
            freeze_encoder=False
        )
        
        logger.info("✓ Transferred weights to LSTM Autoencoder")
        logger.info(f"  - Encoder weights initialized from pre-training")
        logger.info(f"  - Ready for fine-tuning on anomaly detection task")
    
    # Transfer to GNN
    else:
        gnn_model = EnhancedGNNDetector(
            in_channels=9,  # 9 node features
            hidden_channels=64
        )
        
        gnn_model = transfer_to_gnn(
            simclr_model,
            gnn_model,
            freeze_encoder=False
        )
        
        logger.info("✓ Transferred weights to GNN Detector")
        logger.info(f"  - Input projection initialized from pre-training")
        logger.info(f"  - Ready for fine-tuning on graph anomaly detection")
    
    logger.info("\n✅ Transfer learning demonstration complete!")
    logger.info("Next steps:")
    logger.info("  1. Load your labeled data for fine-tuning")
    logger.info("  2. Train LSTM/GNN with pre-trained weights")
    logger.info("  3. Evaluate on test set")
    logger.info("  4. Compare performance vs random initialization")


def main():
    parser = argparse.ArgumentParser(
        description='Train self-supervised encoders for zero-day detection'
    )
    
    parser.add_argument(
        '--data',
        type=str,
        required=True,
        help='Path to preprocessed CSV with unlabeled normal traffic'
    )
    
    parser.add_argument(
        '--output',
        type=str,
        default='data/models/pretrained',
        help='Output directory for model and artifacts'
    )
    
    parser.add_argument(
        '--encoder-type',
        type=str,
        choices=['behavioral', 'temporal'],
        default='behavioral',
        help='Type of encoder to train'
    )
    
    parser.add_argument(
        '--input-dim',
        type=int,
        default=92,
        help='Number of input features'
    )
    
    parser.add_argument(
        '--output-dim',
        type=int,
        default=128,
        help='Encoder output dimension'
    )
    
    parser.add_argument(
        '--sequence-length',
        type=int,
        default=10,
        help='Sequence length for temporal encoder'
    )
    
    parser.add_argument(
        '--epochs',
        type=int,
        default=100,
        help='Number of training epochs'
    )
    
    parser.add_argument(
        '--batch-size',
        type=int,
        default=256,
        help='Batch size for training'
    )
    
    parser.add_argument(
        '--lr',
        type=float,
        default=0.001,
        help='Learning rate'
    )
    
    parser.add_argument(
        '--temperature',
        type=float,
        default=0.5,
        help='Temperature for NT-Xent loss'
    )
    
    parser.add_argument(
        '--noise-std',
        type=float,
        default=0.1,
        help='Standard deviation for noise augmentation'
    )
    
    parser.add_argument(
        '--mask-ratio',
        type=float,
        default=0.15,
        help='Ratio of features to mask'
    )
    
    parser.add_argument(
        '--demo-transfer',
        type=str,
        help='Path to pre-trained model for transfer learning demo'
    )
    
    args = parser.parse_args()
    
    # Demo transfer learning
    if args.demo_transfer:
        demo_transfer_learning(args.demo_transfer, args.encoder_type)
        return
    
    # Train encoder
    if args.encoder_type == 'behavioral':
        logger.info("Training behavioral encoder for tabular features...")
        train_behavioral_encoder(
            data_path=args.data,
            output_dir=args.output,
            input_dim=args.input_dim,
            output_dim=args.output_dim,
            epochs=args.epochs,
            batch_size=args.batch_size,
            learning_rate=args.lr,
            temperature=args.temperature,
            noise_std=args.noise_std,
            mask_ratio=args.mask_ratio
        )
    else:
        logger.info("Training temporal encoder for sequential features...")
        train_temporal_encoder(
            data_path=args.data,
            output_dir=args.output,
            input_dim=args.input_dim,
            output_dim=args.output_dim,
            sequence_length=args.sequence_length,
            epochs=args.epochs,
            batch_size=args.batch_size,
            learning_rate=args.lr,
            temperature=args.temperature,
            noise_std=args.noise_std,
            mask_ratio=args.mask_ratio
        )
    
    logger.info("\n✅ Pre-training complete!")
    logger.info(f"Model saved to: {args.output}")
    logger.info("\nTo use the pre-trained model:")
    logger.info(f"  python src/training/train_self_supervised.py --demo-transfer {args.output}/{'behavioral_encoder.pth' if args.encoder_type == 'behavioral' else 'temporal_encoder.pth'}")


if __name__ == '__main__':
    main()
