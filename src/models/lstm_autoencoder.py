"""
PyTorch implementation of an LSTM Autoencoder for anomaly detection.

This model learns to reconstruct sequences of system behavior features.
Anomalies are detected when the reconstruction error exceeds a threshold.
"""

import torch
import torch.nn as nn

class LSTMAutoencoder(nn.Module):
    """
    LSTM Autoencoder for sequential anomaly detection.

    Architecture:
    - Encoder: Compresses a sequence of feature vectors into a latent representation.
    - Decoder: Reconstructs the original sequence from the latent vector.
    """

    def __init__(self, input_dim: int, latent_dim: int, num_layers: int = 1, dropout: float = 0.2):
        """
        Initialize the LSTM Autoencoder.

        Args:
            input_dim (int): The number of features in each time step of the input sequence.
            latent_dim (int): The dimensionality of the latent space (encoding).
            num_layers (int): The number of LSTM layers in the encoder and decoder.
            dropout (float): Dropout probability for regularization.
        """
        super(LSTMAutoencoder, self).__init__()

        self.input_dim = input_dim
        self.latent_dim = latent_dim
        self.num_layers = num_layers

        # --- Encoder ---
        # Takes input of shape (batch_size, seq_len, input_dim)
        self.encoder = nn.LSTM(
            input_size=input_dim,
            hidden_size=latent_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0
        )

        # --- Decoder ---
        # Takes the final hidden state of the encoder as input
        self.decoder = nn.LSTM(
            input_size=latent_dim,
            hidden_size=latent_dim, # The internal hidden state of the decoder
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0
        )
        
        # --- Reconstruction Layer ---
        # Maps the decoder's output back to the original input dimension
        self.reconstruction_layer = nn.Linear(latent_dim, input_dim)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Forward pass through the autoencoder.

        Args:
            x (torch.Tensor): Input tensor of shape (batch_size, seq_len, input_dim).

        Returns:
            torch.Tensor: Reconstructed output tensor of shape (batch_size, seq_len, input_dim).
        """
        # --- Encoding ---
        # The encoder outputs the encoded sequence and the final hidden/cell states.
        # We only need the final hidden and cell states to represent the entire sequence.
        _, (hidden_state, cell_state) = self.encoder(x)
        
        # The latent representation is the final hidden state of the encoder.
        # Shape: (num_layers, batch_size, latent_dim)

        # --- Decoding ---
        # The decoder needs an input sequence. We repeat the latent vector `seq_len` times.
        # This provides a consistent input to the decoder for each time step.
        seq_len = x.shape[1]
        
        # Create a decoder input of shape (batch_size, seq_len, latent_dim)
        decoder_input = hidden_state[-1].unsqueeze(1).repeat(1, seq_len, 1)

        # Initialize the decoder with the encoder's final hidden and cell states.
        decoder_output, _ = self.decoder(decoder_input, (hidden_state, cell_state))
        
        # --- Reconstruction ---
        # Apply the final linear layer to reconstruct the original feature dimension.
        reconstructed_x = self.reconstruction_layer(decoder_output)
        
        return reconstructed_x

def main():
    """Example usage and model summary."""
    # --- Model Configuration ---
    INPUT_DIM = 42      # Number of features from SysmonFeatureRecord
    LATENT_DIM = 16     # Dimensionality of the compressed representation
    SEQUENCE_LENGTH = 20 # Number of events in a sequence
    BATCH_SIZE = 64     # Number of sequences processed at once
    NUM_LAYERS = 2      # Number of LSTM layers

    # --- Create Model ---
    model = LSTMAutoencoder(input_dim=INPUT_DIM, latent_dim=LATENT_DIM, num_layers=NUM_LAYERS)
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
