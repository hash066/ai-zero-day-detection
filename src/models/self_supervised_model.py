"""
PyTorch implementation of a self-supervised learning model.

This module implements a contrastive learning model (SimCLR-style) to learn
rich representations from unlabeled data. These representations can then be
used for downstream tasks like anomaly detection, either by fine-tuning or
as a feature extractor.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F

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

class SimCLRModel(nn.Module):
    """
    A SimCLR-style model for self-supervised contrastive learning.

    This model consists of a base encoder that learns the representations
    and a projection head that is used during contrastive training.
    """
    def __init__(self, base_encoder: nn.Module, projection_dim: int = 128):
        """
        Initialize the SimCLR model.

        Args:
            base_encoder (nn.Module): The backbone model that extracts features.
                                      This could be a ResNet, a simple MLP, etc.
            projection_dim (int): The output dimension of the projection head.
        """
        super(SimCLRModel, self).__init__()
        self.base_encoder = base_encoder
        
        # Determine the feature dimension from the base encoder
        # This is a heuristic and might need to be adjusted
        try:
            encoder_out_features = self.base_encoder.fc.in_features
        except AttributeError:
            # Fallback for models without a standard 'fc' layer
            dummy_input = torch.randn(2, 3, 224, 224) # Assuming image data for ResNet-like
            encoder_out_features = self.base_encoder(dummy_input).shape[-1]
            
        self.projection_head = ProjectionHead(
            in_features=encoder_out_features,
            hidden_features=encoder_out_features,
            out_features=projection_dim
        )

    def forward(self, x):
        """
        Forward pass through the model. During training, this should be called
        on two augmented views of the same batch.

        Args:
            x: A batch of input data.

        Returns:
            torch.Tensor: The output from the projection head, normalized.
        """
        h = self.base_encoder(x)
        z = self.projection_head(h)
        return F.normalize(z, dim=1)

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

def main():
    """Example of initializing the model and calculating loss."""
    # --- Example with a simple MLP as the base encoder ---
    class MLPEncoder(nn.Module):
        def __init__(self, in_dim=100, out_dim=512):
            super().__init__()
            self.fc = nn.Sequential(
                nn.Linear(in_dim, 256),
                nn.ReLU(),
                nn.Linear(256, out_dim)
            )
        def forward(self, x):
            return self.fc(x)

    base_encoder = MLPEncoder()
    # Manually set the feature dim for MLP
    base_encoder.fc.in_features = 100 
    
    # We need to adapt the SimCLRModel to get the output dim correctly for MLP
    class CustomSimCLR(SimCLRModel):
        def __init__(self, base_encoder, projection_dim=128):
            super().__init__(base_encoder, projection_dim)
            encoder_out_features = 512 # Manually specify for MLP
            self.projection_head = ProjectionHead(
                in_features=encoder_out_features,
                hidden_features=encoder_out_features,
                out_features=projection_dim
            )
            
    model = CustomSimCLR(base_encoder)

    print("--- SimCLR Model with MLP Encoder ---")
    print(model)

    # --- Dummy data for two augmented views ---
    batch_size = 64
    input_dim = 100
    x1 = torch.randn(batch_size, input_dim)
    x2 = torch.randn(batch_size, input_dim) # In reality, x2 is an augmentation of x1

    # --- Forward pass and loss calculation ---
    z1 = model(x1)
    z2 = model(x2)
    
    loss = nt_xent_loss(z1, z2)
    
    print(f"\nExample batch size: {batch_size}")
    print(f"Projected feature shape: {z1.shape}")
    print(f"Calculated contrastive loss: {loss.item():.4f}")

if __name__ == '__main__':
    main()
