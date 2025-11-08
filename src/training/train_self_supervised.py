"""
Training script for the self-supervised SimCLR model.

This script loads an unlabeled dataset, applies augmentations to create
positive pairs, and trains the SimCLRModel using a contrastive loss.
The goal is to learn a powerful feature representation (encoder) that can
be used for downstream tasks.
"""

import argparse
import logging
from pathlib import Path
import torch.nn as nn
import pandas as pd
import torch
import torch.optim as optim
from torch.utils.data import DataLoader, Dataset
from torchvision.transforms import v2 as transforms # Using v2 for modern transforms

# Adjusting path to import from sibling directories
import sys
sys.path.append(str(Path(__file__).resolve().parent.parent))

from models.self_supervised_model import SimCLRModel, nt_xent_loss, ProjectionHead

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class UnlabeledDataset(Dataset):
    """A custom dataset for loading unlabeled tabular data."""
    def __init__(self, data_path, transform=None):
        if data_path.endswith('.parquet'):
            self.data = pd.read_parquet(data_path).values
        else:
            self.data = pd.read_csv(data_path).values
        self.transform = transform

    def __len__(self):
        return len(self.data)

    def __getitem__(self, idx):
        sample = self.data[idx]
        sample = torch.tensor(sample, dtype=torch.float32)
        if self.transform:
            # For contrastive learning, we apply two different augmentations
            view1 = self.transform(sample)
            view2 = self.transform(sample)
            return view1, view2
        return sample, sample

class TabularAugmentation:
    """Simple augmentation for tabular data: jitter and masking."""
    def __init__(self, jitter_strength=0.1, mask_ratio=0.2):
        self.jitter_strength = jitter_strength
        self.mask_ratio = mask_ratio

    def __call__(self, x):
        # Add random jitter
        jitter = torch.randn_like(x) * self.jitter_strength
        x_jittered = x + jitter
        
        # Apply random masking
        mask = torch.rand_like(x) < self.mask_ratio
        x_masked = x_jittered.clone()
        x_masked[mask] = 0
        
        return x_masked

def train_self_supervised(
    data_path: str,
    model_dir: str,
    input_dim: int,
    epochs: int,
    batch_size: int,
    learning_rate: float,
    projection_dim: int,
    temperature: float
):
    """Main training function for the SimCLR model."""
    # --- 1. Setup and Device Configuration ---
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logging.info(f"Using device: {device}")

    output_path = Path(model_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # --- 2. Data Loading and Augmentations ---
    # Define augmentations for creating different "views" of the data
    transform = TabularAugmentation(jitter_strength=0.05, mask_ratio=0.15)
    
    try:
        dataset = UnlabeledDataset(data_path=data_path, transform=transform)
        train_loader = DataLoader(dataset, batch_size=batch_size, shuffle=True, num_workers=4, pin_memory=True)
        logging.info(f"Loaded {len(dataset)} samples for self-supervised training.")
    except FileNotFoundError:
        logging.error(f"Data file not found at {data_path}.")
        return

    # --- 3. Initialize Model and Optimizer ---
    # Using a simple MLP as the base encoder for tabular data
    class MLPEncoder(nn.Module):
        def __init__(self, in_dim, hidden_dim=512, out_dim=256):
            super().__init__()
            self.fc = nn.Sequential(
                nn.Linear(in_dim, hidden_dim),
                nn.ReLU(),
                nn.Linear(hidden_dim, out_dim)
            )
        def forward(self, x):
            return self.fc(x)
            
    base_encoder = MLPEncoder(in_dim=input_dim).to(device)
    
    # We need to adapt the SimCLRModel to get the output dim correctly for MLP
    class CustomSimCLR(SimCLRModel):
        def __init__(self, base_encoder, projection_dim=128):
            super().__init__(base_encoder, projection_dim)
            encoder_out_features = 256 # Manually specify for MLP
            self.projection_head = ProjectionHead(
                in_features=encoder_out_features,
                hidden_features=encoder_out_features,
                out_features=projection_dim
            )
            
    model = CustomSimCLR(base_encoder, projection_dim).to(device)
    
    optimizer = optim.Adam(model.parameters(), lr=learning_rate, weight_decay=1e-4)
    scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=len(train_loader)*epochs, eta_min=0, last_epoch=-1)

    logging.info("SimCLR Model architecture:")
    logging.info(model)

    # --- 4. Training Loop ---
    for epoch in range(epochs):
        total_loss = 0
        for view1, view2 in train_loader:
            view1, view2 = view1.to(device), view2.to(device)
            
            optimizer.zero_grad()
            
            # Get projected features for both views
            z1 = model(view1)
            z2 = model(view2)
            
            # Calculate contrastive loss
            loss = nt_xent_loss(z1, z2, temperature=temperature)
            
            loss.backward()
            optimizer.step()
            
            total_loss += loss.item()
            scheduler.step()

        avg_loss = total_loss / len(train_loader)
        logging.info(f"Epoch [{epoch+1}/{epochs}], Loss: {avg_loss:.4f}, LR: {scheduler.get_last_lr()[0]:.6f}")

    # --- 5. Save the Trained Base Encoder ---
    # For downstream tasks, we only need the base_encoder part of the model.
    encoder_path = output_path / "self_supervised_encoder.pth"
    torch.save(model.base_encoder.state_dict(), encoder_path)
    logging.info(f"Training complete. Saved the trained base encoder to {encoder_path}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Train a SimCLR model for self-supervised learning.")
    parser.add_argument("--data-path", type=str, required=True, help="Path to the unlabeled data file (CSV or Parquet).")
    parser.add_argument("--model-dir", type=str, default="trained_models/self_supervised", help="Directory to save the trained encoder.")
    parser.add_argument("--input-dim", type=int, required=True, help="The number of features in the input data.")
    parser.add_argument("--epochs", type=int, default=100, help="Number of training epochs.")
    parser.add_argument("--batch-size", type=int, default=256, help="Batch size for training.")
    parser.add_argument("--lr", type=float, default=3e-4, help="Learning rate.")
    parser.add_argument("--proj-dim", type=int, default=128, help="Dimension of the projection head.")
    parser.add_argument("--temp", type=float, default=0.07, help="Temperature for the NT-Xent loss.")

    args = parser.parse_args()

    train_self_supervised(
        data_path=args.data_path,
        model_dir=args.model_dir,
        input_dim=args.input_dim,
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.lr,
        projection_dim=args.proj_dim,
        temperature=args.temp
    )
