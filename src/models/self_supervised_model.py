"""
Enhanced Self-Supervised Learning for Zero-Day Attack Detection.

Implements contrastive learning (SimCLR-style) for behavioral network/sysmon data.
Pre-trains encoders on unlabeled normal traffic to learn rich representations
for downstream anomaly detection tasks.

Key Features:
- Behavioral data augmentations (noise, masking, jitter)
- Temporal contrastive learning for sequences
- Integration with LSTM/GNN encoders
- Transfer learning utilities
- Domain-specific for network traffic and system logs
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
from typing import Dict, List, Tuple, Optional
from torch.utils.data import Dataset, DataLoader
import logging
from pathlib import Path
import sys

# Add parent directory for imports
sys.path.append(str(Path(__file__).parent.parent))

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ============================================================================
# DATA AUGMENTATIONS FOR BEHAVIORAL DATA
# ============================================================================

class BehavioralAugmentation:
    """
    Data augmentation strategies for network traffic and system log features.
    
    Creates positive pairs by applying semantically-preserving transformations:
    - Gaussian noise injection
    - Feature masking (dropout)
    - Temporal jittering
    - Value scaling
    """
    
    def __init__(
        self,
        noise_std: float = 0.1,
        mask_ratio: float = 0.15,
        jitter_std: float = 0.05,
        scale_range: Tuple[float, float] = (0.9, 1.1)
    ):
        """
        Initialize augmentation parameters.
        
        Args:
            noise_std: Standard deviation for Gaussian noise
            mask_ratio: Fraction of features to mask
            jitter_std: Standard deviation for temporal jitter
            scale_range: Range for random scaling
        """
        self.noise_std = noise_std
        self.mask_ratio = mask_ratio
        self.jitter_std = jitter_std
        self.scale_range = scale_range
    
    def apply(self, x: torch.Tensor, augmentation_type: str = 'combined') -> torch.Tensor:
        """
        Apply augmentation to input features.
        
        Args:
            x: Input tensor (batch, features) or (batch, seq_len, features)
            augmentation_type: 'noise', 'mask', 'jitter', 'scale', or 'combined'
            
        Returns:
            Augmented tensor
        """
        if augmentation_type == 'noise' or augmentation_type == 'combined':
            x = self._add_noise(x)
        
        if augmentation_type == 'mask' or augmentation_type == 'combined':
            x = self._mask_features(x)
        
        if augmentation_type == 'jitter' or augmentation_type == 'combined':
            x = self._temporal_jitter(x)
        
        if augmentation_type == 'scale' or augmentation_type == 'combined':
            x = self._random_scale(x)
        
        return x
    
    def _add_noise(self, x: torch.Tensor) -> torch.Tensor:
        """Add Gaussian noise to features."""
        noise = torch.randn_like(x) * self.noise_std
        return x + noise
    
    def _mask_features(self, x: torch.Tensor) -> torch.Tensor:
        """Randomly mask (zero out) features."""
        mask = torch.rand_like(x) > self.mask_ratio
        return x * mask.float()
    
    def _temporal_jitter(self, x: torch.Tensor) -> torch.Tensor:
        """Add temporal jitter to sequential data."""
        if len(x.shape) == 3:  # (batch, seq_len, features)
            # Randomly shift sequence in time
            jitter = torch.randn(x.shape[0], x.shape[1], 1, device=x.device) * self.jitter_std
            x = x + jitter
        return x
    
    def _random_scale(self, x: torch.Tensor) -> torch.Tensor:
        """Apply random scaling to features."""
        scale = torch.FloatTensor(1).uniform_(*self.scale_range).to(x.device)
        return x * scale
    
    def create_positive_pair(
        self,
        x: torch.Tensor
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Create two augmented views of the same sample (positive pair).
        
        Args:
            x: Input tensor
            
        Returns:
            (view1, view2): Two augmented versions
        """
        view1 = self.apply(x, 'combined')
        view2 = self.apply(x, 'combined')
        return view1, view2


# ============================================================================
# BEHAVIORAL ENCODER
# ============================================================================

class BehavioralEncoder(nn.Module):
    """
    Encoder for tabular behavioral features (network traffic, system logs).
    
    Designed for the 92 features from preprocessing pipeline:
    - 65 base features (network flows)
    - 27 engineered features (entropy, temporal, behavioral)
    
    Can be used as:
    - Standalone encoder for self-supervised pre-training
    - Base encoder for LSTM Autoencoder
    - Base encoder for GNN feature extraction
    """
    
    def __init__(
        self,
        input_dim: int = 92,  # 92 features from preprocessing
        hidden_dims: List[int] = [256, 512, 256],
        output_dim: int = 128,
        dropout: float = 0.2
    ):
        """
        Initialize behavioral encoder.
        
        Args:
            input_dim: Number of input features (92 from preprocessing)
            hidden_dims: Sizes of hidden layers
            output_dim: Size of encoded representation
            dropout: Dropout probability
        """
        super(BehavioralEncoder, self).__init__()
        
        self.input_dim = input_dim
        self.output_dim = output_dim
        
        # Build encoder layers
        layers = []
        prev_dim = input_dim
        
        for hidden_dim in hidden_dims:
            layers.extend([
                nn.Linear(prev_dim, hidden_dim),
                nn.BatchNorm1d(hidden_dim),
                nn.ReLU(),
                nn.Dropout(dropout)
            ])
            prev_dim = hidden_dim
        
        # Final projection
        layers.append(nn.Linear(prev_dim, output_dim))
        
        self.encoder = nn.Sequential(*layers)
        
        logger.info(f"BehavioralEncoder initialized: {input_dim} -> {hidden_dims} -> {output_dim}")
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Encode behavioral features.
        
        Args:
            x: Input features (batch, input_dim)
            
        Returns:
            Encoded representation (batch, output_dim)
        """
        return self.encoder(x)


class TemporalBehavioralEncoder(nn.Module):
    """
    Encoder for temporal sequences of behavioral features.
    
    Combines:
    - Behavioral feature encoding (MLP)
    - Temporal pattern encoding (LSTM)
    
    Suitable for pre-training LSTM Autoencoder.
    """
    
    def __init__(
        self,
        input_dim: int = 92,
        feature_hidden_dim: int = 256,
        lstm_hidden_dim: int = 128,
        output_dim: int = 128,
        num_lstm_layers: int = 2,
        dropout: float = 0.2
    ):
        """
        Initialize temporal behavioral encoder.
        
        Args:
            input_dim: Number of features per time step
            feature_hidden_dim: Hidden dimension for feature encoding
            lstm_hidden_dim: Hidden dimension for LSTM
            output_dim: Size of final representation
            num_lstm_layers: Number of LSTM layers
            dropout: Dropout probability
        """
        super(TemporalBehavioralEncoder, self).__init__()
        
        # Feature encoder (per time step)
        self.feature_encoder = nn.Sequential(
            nn.Linear(input_dim, feature_hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout)
        )
        
        # Temporal encoder (across time steps)
        self.temporal_encoder = nn.LSTM(
            input_size=feature_hidden_dim,
            hidden_size=lstm_hidden_dim,
            num_layers=num_lstm_layers,
            batch_first=True,
            dropout=dropout if num_lstm_layers > 1 else 0,
            bidirectional=True
        )
        
        # Final projection
        self.projection = nn.Linear(lstm_hidden_dim * 2, output_dim)  # *2 for bidirectional
        
        logger.info(f"TemporalBehavioralEncoder initialized: {input_dim} -> LSTM({lstm_hidden_dim}) -> {output_dim}")
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Encode temporal sequence.
        
        Args:
            x: Input sequence (batch, seq_len, input_dim)
            
        Returns:
            Encoded representation (batch, output_dim)
        """
        batch_size, seq_len, _ = x.shape
        
        # Encode features at each time step
        x_flat = x.reshape(-1, x.shape[-1])  # (batch * seq_len, input_dim)
        features = self.feature_encoder(x_flat)
        features = features.reshape(batch_size, seq_len, -1)  # (batch, seq_len, feature_hidden_dim)
        
        # Encode temporal patterns
        _, (hidden, _) = self.temporal_encoder(features)
        
        # Use final hidden state (concatenate forward and backward)
        hidden = torch.cat([hidden[-2], hidden[-1]], dim=1)  # (batch, lstm_hidden_dim * 2)
        
        # Project to output dimension
        output = self.projection(hidden)
        
        return output


# ============================================================================
# PROJECTION HEAD & SIMCLR MODEL
# ============================================================================

class ProjectionHead(nn.Module):
    """
    The projection head used in SimCLR.

    It projects the representations from the base encoder into a space
    where the contrastive loss is applied.
    """
    def __init__(self, in_features: int, hidden_features: int, out_features: int):
        super(ProjectionHead, self).__init__()
        self.fc1 = nn.Linear(in_features, hidden_features)
        self.bn = nn.BatchNorm1d(hidden_features)
        self.relu = nn.ReLU()
        self.fc2 = nn.Linear(hidden_features, out_features)

    def forward(self, x):
        x = self.fc1(x)
        x = self.bn(x)
        x = self.relu(x)
        x = self.fc2(x)
        return x

class EnhancedSimCLRModel(nn.Module):
    """
    Enhanced SimCLR model for behavioral data (network traffic, system logs).
    
    Improvements over basic SimCLR:
    - Works with tabular behavioral features (92D)
    - Supports temporal sequences for LSTM pre-training
    - Integrated with preprocessing pipeline
    - Domain-specific augmentations
    """
    
    def __init__(
        self,
        base_encoder: nn.Module,
        projection_dim: int = 128,
        encoder_output_dim: Optional[int] = None
    ):
        """
        Initialize Enhanced SimCLR model.

        Args:
            base_encoder: BehavioralEncoder or TemporalBehavioralEncoder
            projection_dim: Output dimension of projection head
            encoder_output_dim: Output dimension of base encoder (auto-detected if None)
        """
        super(EnhancedSimCLRModel, self).__init__()
        self.base_encoder = base_encoder
        
        # Determine encoder output dimension
        if encoder_output_dim is None:
            if hasattr(base_encoder, 'output_dim'):
                encoder_output_dim = base_encoder.output_dim
            else:
                # Auto-detect with dummy input
                dummy_input = torch.randn(2, 92) if not hasattr(base_encoder, 'temporal_encoder') else torch.randn(2, 10, 92)
                encoder_output_dim = self.base_encoder(dummy_input).shape[-1]
        
        self.encoder_output_dim = encoder_output_dim
            
        self.projection_head = ProjectionHead(
            in_features=encoder_output_dim,
            hidden_features=encoder_output_dim,
            out_features=projection_dim
        )
        
        logger.info(f"EnhancedSimCLRModel initialized: encoder_dim={encoder_output_dim}, projection_dim={projection_dim}")

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Forward pass for contrastive learning.

        Args:
            x: Input data (batch, features) or (batch, seq_len, features)

        Returns:
            Normalized projections (batch, projection_dim)
        """
        h = self.base_encoder(x)
        z = self.projection_head(h)
        return F.normalize(z, dim=1)
    
    def encode(self, x: torch.Tensor) -> torch.Tensor:
        """
        Get encoded representation without projection (for downstream tasks).
        
        Args:
            x: Input data
            
        Returns:
            Encoded features (batch, encoder_output_dim)
        """
        return self.base_encoder(x)

def nt_xent_loss(z1, z2, temperature=0.5):
    """
    Normalized Temperature-scaled Cross-Entropy loss for contrastive learning.

    Args:
        z1 (torch.Tensor): Projected features from the first augmented view.
        z2 (torch.Tensor): Projected features from the second augmented view.
        temperature (float): The temperature parameter to scale logits.

    Returns:
        torch.Tensor: The calculated contrastive loss.
    """
    batch_size = z1.shape[0]
    device = z1.device
    
    # Concatenate features from both views
    z = torch.cat([z1, z2], dim=0)
    
    # Calculate similarity matrix
    sim_matrix = F.cosine_similarity(z.unsqueeze(1), z.unsqueeze(0), dim=2)
    
    # Create masks to identify positive and negative pairs
    # Positive pairs are the augmented versions of the same sample
    sim_ij = torch.diag(sim_matrix, batch_size)
    sim_ji = torch.diag(sim_matrix, -batch_size)
    positive_samples = torch.cat([sim_ij, sim_ji], dim=0).reshape(2 * batch_size, 1)
    
    # Mask to remove self-similarity
    mask = torch.eye(2 * batch_size, device=device).bool()
    
    # Get negative samples (all pairs except positive ones)
    negative_samples = sim_matrix[~mask].reshape(2 * batch_size, -1)
    
    # Logits: similarity scores scaled by temperature
    logits = torch.cat([positive_samples, negative_samples], dim=1) / temperature
    
    # Labels: the first column (positive samples) is always the correct one
    labels = torch.zeros(2 * batch_size, dtype=torch.long, device=device)
    
    loss = F.cross_entropy(logits, labels, reduction='mean')
    
    return loss

# ============================================================================
# PRETRAINING DATASET
# ============================================================================

class BehavioralPretrainingDataset(Dataset):
    """
    Dataset for self-supervised pre-training on unlabeled behavioral data.
    
    Loads preprocessed network/sysmon data and creates augmented positive pairs.
    """
    
    def __init__(
        self,
        data_path: str,
        augmentation: BehavioralAugmentation,
        feature_cols: Optional[List[str]] = None,
        is_temporal: bool = False,
        sequence_length: int = 10
    ):
        """
        Initialize pretraining dataset.
        
        Args:
            data_path: Path to preprocessed CSV
            augmentation: Augmentation strategy
            feature_cols: List of feature column names (None = use all numeric)
            is_temporal: Whether to create sequences
            sequence_length: Length of sequences if is_temporal=True
        """
        import pandas as pd
        
        self.augmentation = augmentation
        self.is_temporal = is_temporal
        self.sequence_length = sequence_length
        
        # Load data
        df = pd.read_csv(data_path)
        
        # Select features
        if feature_cols is None:
            # Use all numeric columns except timestamp and label
            exclude_cols = ['timestamp', 'label', 'Unnamed: 0']
            feature_cols = [col for col in df.select_dtypes(include=[np.number]).columns 
                          if col not in exclude_cols]
        
        self.features = df[feature_cols].values.astype(np.float32)
        
        # Handle NaN/inf
        self.features = np.nan_to_num(self.features, nan=0.0, posinf=1e6, neginf=-1e6)
        
        # Create sequences if temporal
        if is_temporal:
            self.sequences = []
            for i in range(len(self.features) - sequence_length + 1):
                self.sequences.append(self.features[i:i+sequence_length])
            self.data = np.array(self.sequences)
        else:
            self.data = self.features
        
        logger.info(f"Loaded {len(self.data)} samples with {self.features.shape[1]} features")
        logger.info(f"Temporal: {is_temporal}, Shape: {self.data.shape}")
    
    def __len__(self) -> int:
        return len(self.data)
    
    def __getitem__(self, idx: int) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Get augmented positive pair.
        
        Returns:
            (view1, view2): Two augmented versions of the same sample
        """
        sample = torch.tensor(self.data[idx], dtype=torch.float32)
        view1, view2 = self.augmentation.create_positive_pair(sample)
        return view1, view2


# ============================================================================
# TRAINING UTILITIES
# ============================================================================

class SelfSupervisedTrainer:
    """
    Trainer for self-supervised contrastive learning.
    
    Handles:
    - Training loop with NT-Xent loss
    - Learning rate scheduling
    - Checkpoint saving
    - Linear evaluation protocol
    """
    
    def __init__(
        self,
        model: EnhancedSimCLRModel,
        device: str = 'cuda' if torch.cuda.is_available() else 'cpu',
        learning_rate: float = 0.001,
        temperature: float = 0.5,
        weight_decay: float = 1e-4
    ):
        """
        Initialize trainer.
        
        Args:
            model: SimCLR model to train
            device: Device for training
            learning_rate: Learning rate
            temperature: Temperature for NT-Xent loss
            weight_decay: Weight decay for optimizer
        """
        self.model = model.to(device)
        self.device = device
        self.temperature = temperature
        
        self.optimizer = torch.optim.Adam(
            model.parameters(),
            lr=learning_rate,
            weight_decay=weight_decay
        )
        
        self.scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(
            self.optimizer,
            T_max=100  # Will be updated based on epochs
        )
        
        logger.info(f"Trainer initialized on {device}")
    
    def train_epoch(self, dataloader: DataLoader) -> float:
        """
        Train for one epoch.
        
        Args:
            dataloader: DataLoader with positive pairs
            
        Returns:
            Average loss for epoch
        """
        self.model.train()
        total_loss = 0.0
        
        for view1, view2 in dataloader:
            view1 = view1.to(self.device)
            view2 = view2.to(self.device)
            
            # Forward pass
            z1 = self.model(view1)
            z2 = self.model(view2)
            
            # Compute contrastive loss
            loss = nt_xent_loss(z1, z2, temperature=self.temperature)
            
            # Backward pass
            self.optimizer.zero_grad()
            loss.backward()
            self.optimizer.step()
            
            total_loss += loss.item()
        
        avg_loss = total_loss / len(dataloader)
        return avg_loss
    
    def train(
        self,
        train_loader: DataLoader,
        epochs: int = 100,
        save_path: Optional[str] = None
    ) -> Dict[str, List[float]]:
        """
        Full training loop.
        
        Args:
            train_loader: Training data loader
            epochs: Number of epochs
            save_path: Path to save best model
            
        Returns:
            Training history
        """
        history = {'loss': []}
        best_loss = float('inf')
        
        logger.info(f"Starting training for {epochs} epochs")
        
        for epoch in range(epochs):
            loss = self.train_epoch(train_loader)
            history['loss'].append(loss)
            
            self.scheduler.step()
            
            if (epoch + 1) % 10 == 0:
                logger.info(f"Epoch {epoch+1}/{epochs}: Loss={loss:.4f}")
            
            # Save best model
            if save_path and loss < best_loss:
                best_loss = loss
                torch.save(self.model.state_dict(), save_path)
                logger.info(f"Saved best model with loss {loss:.4f}")
        
        logger.info("Training complete")
        return history
    
    def extract_features(
        self,
        dataloader: DataLoader,
        return_projections: bool = False
    ) -> np.ndarray:
        """
        Extract features from trained encoder for downstream tasks.
        
        Args:
            dataloader: Data loader
            return_projections: Return projections instead of encodings
            
        Returns:
            Feature matrix (num_samples, feature_dim)
        """
        self.model.eval()
        features = []
        
        with torch.no_grad():
            for batch in dataloader:
                if isinstance(batch, (tuple, list)):
                    batch = batch[0]  # Take first view
                
                batch = batch.to(self.device)
                
                if return_projections:
                    feat = self.model(batch)
                else:
                    feat = self.model.encode(batch)
                
                features.append(feat.cpu().numpy())
        
        return np.concatenate(features, axis=0)


# ============================================================================
# TRANSFER LEARNING UTILITIES
# ============================================================================

def transfer_to_lstm(
    pretrained_simclr: EnhancedSimCLRModel,
    lstm_model: nn.Module,
    freeze_encoder: bool = True
) -> nn.Module:
    """
    Transfer pre-trained encoder to LSTM Autoencoder.
    
    Args:
        pretrained_simclr: Pre-trained SimCLR model
        lstm_model: LSTM model to initialize
        freeze_encoder: Whether to freeze encoder weights
        
    Returns:
        LSTM model with transferred weights
    """
    # Transfer encoder weights
    if hasattr(pretrained_simclr.base_encoder, 'feature_encoder'):
        # TemporalBehavioralEncoder
        lstm_encoder_state = pretrained_simclr.base_encoder.state_dict()
        
        # Load compatible weights
        model_dict = lstm_model.state_dict()
        pretrained_dict = {k: v for k, v in lstm_encoder_state.items() if k in model_dict}
        model_dict.update(pretrained_dict)
        lstm_model.load_state_dict(model_dict, strict=False)
        
        logger.info(f"Transferred {len(pretrained_dict)} weight tensors to LSTM")
    
    # Freeze encoder if requested
    if freeze_encoder and hasattr(lstm_model, 'encoder'):
        for param in lstm_model.encoder.parameters():
            param.requires_grad = False
        logger.info("Froze encoder weights")
    
    return lstm_model


def transfer_to_gnn(
    pretrained_simclr: EnhancedSimCLRModel,
    gnn_model: nn.Module,
    freeze_encoder: bool = True
) -> nn.Module:
    """
    Transfer pre-trained encoder to GNN Detector.
    
    Args:
        pretrained_simclr: Pre-trained SimCLR model
        gnn_model: GNN model to initialize
        freeze_encoder: Whether to freeze encoder weights
        
    Returns:
        GNN model with transferred weights
    """
    # Transfer input projection weights
    if hasattr(pretrained_simclr.base_encoder, 'encoder'):
        # BehavioralEncoder
        encoder_first_layer = list(pretrained_simclr.base_encoder.encoder.children())[0]
        
        if hasattr(gnn_model, 'input_projection') and isinstance(encoder_first_layer, nn.Linear):
            gnn_model.input_projection.weight.data = encoder_first_layer.weight.data.clone()
            gnn_model.input_projection.bias.data = encoder_first_layer.bias.data.clone()
            logger.info("Transferred input projection to GNN")
    
    # Freeze projection if requested
    if freeze_encoder and hasattr(gnn_model, 'input_projection'):
        for param in gnn_model.input_projection.parameters():
            param.requires_grad = False
        logger.info("Froze input projection weights")
    
    return gnn_model


# ============================================================================
# EXAMPLE USAGE
# ============================================================================

def main():
    """Example: Pre-train encoder on unlabeled behavioral data."""
    
    print("=== Self-Supervised Learning for Zero-Day Detection ===\n")
    
    # 1. Setup augmentation
    print("1. Creating augmentation strategy...")
    augmentation = BehavioralAugmentation(
        noise_std=0.1,
        mask_ratio=0.15,
        jitter_std=0.05
    )
    
    # 2. Create encoder
    print("2. Creating behavioral encoder...")
    encoder = BehavioralEncoder(
        input_dim=92,  # 92 features from preprocessing
        hidden_dims=[256, 512, 256],
        output_dim=128
    )
    
    # 3. Create SimCLR model
    print("3. Creating SimCLR model...")
    model = EnhancedSimCLRModel(
        base_encoder=encoder,
        projection_dim=128
    )
    
    # 4. Create dummy data
    print("4. Creating dummy training data...")
    dummy_data = torch.randn(1000, 92)  # 1000 samples, 92 features
    
    # Test augmentation
    view1, view2 = augmentation.create_positive_pair(dummy_data[:10])
    print(f"   Augmented views: {view1.shape}, {view2.shape}")
    
    # 5. Forward pass test
    print("5. Testing forward pass...")
    z1 = model(view1)
    z2 = model(view2)
    print(f"   Projections: {z1.shape}, {z2.shape}")
    
    # 6. Loss calculation
    loss = nt_xent_loss(z1, z2, temperature=0.5)
    print(f"   Contrastive loss: {loss.item():.4f}")
    
    # 7. Temporal encoder test
    print("\n7. Testing temporal encoder...")
    temporal_encoder = TemporalBehavioralEncoder(
        input_dim=92,
        lstm_hidden_dim=128,
        output_dim=128
    )
    temporal_model = EnhancedSimCLRModel(
        base_encoder=temporal_encoder,
        encoder_output_dim=128
    )
    
    sequences = torch.randn(10, 10, 92)  # 10 sequences, 10 time steps, 92 features
    z_temporal = temporal_model(sequences)
    print(f"   Temporal projections: {z_temporal.shape}")
    
    print("\n=== Ready for pre-training on unlabeled data ===")
    print("Use BehavioralPretrainingDataset to load your data")
    print("Use SelfSupervisedTrainer.train() to pre-train")
    print("Use transfer_to_lstm() or transfer_to_gnn() for downstream tasks")


if __name__ == '__main__':
    main()
