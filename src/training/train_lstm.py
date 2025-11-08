"""
Training script for the LSTM Autoencoder model.

This script loads preprocessed Sysmon feature data, creates sequences,
and trains the LSTM Autoencoder to reconstruct normal behavior.
"""

import argparse
import logging
import json
from pathlib import Path

import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from torch.utils.data import DataLoader, TensorDataset

# Adjusting path to import from sibling directories
import sys
sys.path.append(str(Path(__file__).resolve().parent.parent))

from models.lstm_autoencoder import LSTMAutoencoder
from preprocessing.sysmon_features import SysmonFeatureRecord

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def create_sequences(data: pd.DataFrame, sequence_length: int):
    """
    Converts a DataFrame of features into sequences for LSTM training.

    Args:
        data (pd.DataFrame): DataFrame with scaled numerical features.
        sequence_length (int): The number of time steps in each sequence.

    Returns:
        torch.Tensor: A tensor of sequences with shape (num_sequences, sequence_length, num_features).
    """
    sequences = []
    for i in range(len(data) - sequence_length + 1):
        sequences.append(data.iloc[i:i + sequence_length].values)
    
    return torch.tensor(sequences, dtype=torch.float32)

def train_model(
    data_path: str,
    model_dir: str,
    epochs: int,
    batch_size: int,
    learning_rate: float,
    sequence_length: int,
    latent_dim: int,
    num_layers: int,
    dropout: float,
    validation_split: float
):
    """
    Main training function for the LSTM Autoencoder.

    Args:
        data_path (str): Path to the preprocessed Sysmon data (CSV or Parquet).
        model_dir (str): Directory to save the trained model and artifacts.
        epochs (int): Number of training epochs.
        batch_size (int): Batch size for training.
        learning_rate (float): Learning rate for the optimizer.
        sequence_length (int): Length of event sequences.
        latent_dim (int): Dimensionality of the model's latent space.
        num_layers (int): Number of LSTM layers.
        dropout (float): Dropout rate for regularization.
        validation_split (float): Fraction of data to use for validation.
    """
    # --- 1. Setup and Device Configuration ---
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logging.info(f"Using device: {device}")

    output_path = Path(model_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # --- 2. Load and Preprocess Data ---
    logging.info(f"Loading data from {data_path}...")
    try:
        if data_path.endswith('.parquet'):
            df = pd.read_parquet(data_path)
        else:
            df = pd.read_csv(data_path)
    except FileNotFoundError:
        logging.error(f"Data file not found at {data_path}. Please provide a valid path.")
        return

    # Use only the numerical feature columns for training
    feature_columns = SysmonFeatureRecord.get_feature_columns()
    # Ensure all feature columns exist in the dataframe
    df_features = df[[col for col in feature_columns if col in df.columns]]
    
    logging.info(f"Loaded {len(df)} records with {len(df_features.columns)} features.")

    # Scale the features
    scaler = StandardScaler()
    df_scaled = pd.DataFrame(scaler.fit_transform(df_features), columns=df_features.columns)

    # --- 3. Create Sequences and DataLoaders ---
    logging.info(f"Creating sequences of length {sequence_length}...")
    sequences = create_sequences(df_scaled, sequence_length)
    
    # Split data into training and validation sets
    train_sequences, val_sequences = train_test_split(
        sequences, test_size=validation_split, random_state=42
    )

    logging.info(f"Training sequences: {len(train_sequences)}, Validation sequences: {len(val_sequences)}")

    # Create TensorDatasets (input and target are the same for autoencoders)
    train_dataset = TensorDataset(train_sequences, train_sequences)
    val_dataset = TensorDataset(val_sequences, val_sequences)

    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False)

    # --- 4. Initialize Model, Loss, and Optimizer ---
    input_dim = len(df_features.columns)
    model = LSTMAutoencoder(
        input_dim=input_dim,
        latent_dim=latent_dim,
        num_layers=num_layers,
        dropout=dropout
    ).to(device)

    criterion = nn.MSELoss()
    optimizer = optim.Adam(model.parameters(), lr=learning_rate)
    
    logging.info("Model architecture:")
    logging.info(model)

    # --- 5. Training Loop ---
    best_val_loss = float('inf')
    for epoch in range(epochs):
        model.train()
        total_train_loss = 0
        for seq_in, seq_out in train_loader:
            seq_in = seq_in.to(device)
            seq_out = seq_out.to(device)

            optimizer.zero_grad()
            reconstructed = model(seq_in)
            loss = criterion(reconstructed, seq_out)
            loss.backward()
            optimizer.step()

            total_train_loss += loss.item()

        avg_train_loss = total_train_loss / len(train_loader)

        # Validation loop
        model.eval()
        total_val_loss = 0
        with torch.no_grad():
            for seq_in, seq_out in val_loader:
                seq_in = seq_in.to(device)
                seq_out = seq_out.to(device)
                reconstructed = model(seq_in)
                loss = criterion(reconstructed, seq_out)
                total_val_loss += loss.item()

        avg_val_loss = total_val_loss / len(val_loader)

        logging.info(f"Epoch [{epoch+1}/{epochs}], Train Loss: {avg_train_loss:.6f}, Val Loss: {avg_val_loss:.6f}")

        # Save the best model
        if avg_val_loss < best_val_loss:
            best_val_loss = avg_val_loss
            model_path = output_path / "lstm_autoencoder_best.pth"
            torch.save(model.state_dict(), model_path)
            logging.info(f"Saved new best model to {model_path}")

    # --- 6. Save Final Artifacts ---
    # Save the final model
    final_model_path = output_path / "lstm_autoencoder_final.pth"
    torch.save(model.state_dict(), final_model_path)
    
    # Save the scaler
    import joblib
    scaler_path = output_path / "scaler.pkl"
    joblib.dump(scaler, scaler_path)

    # Save training configuration
    config = {
        "input_dim": input_dim,
        "latent_dim": latent_dim,
        "sequence_length": sequence_length,
        "num_layers": num_layers,
        "dropout": dropout,
        "feature_columns": list(df_features.columns)
    }
    config_path = output_path / "model_config.json"
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=4)
        
    logging.info(f"Training complete. Final model and artifacts saved to {output_path}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Train LSTM Autoencoder for Anomaly Detection")
    parser.add_argument("--data-path", type=str, required=True, help="Path to preprocessed Sysmon data file (CSV or Parquet).")
    parser.add_argument("--model-dir", type=str, default="trained_models/lstm", help="Directory to save the trained model.")
    parser.add_argument("--epochs", type=int, default=50, help="Number of training epochs.")
    parser.add_argument("--batch-size", type=int, default=64, help="Batch size for training.")
    parser.add_argument("--lr", type=float, default=1e-3, help="Learning rate.")
    parser.add_argument("--seq-len", type=int, default=20, help="Sequence length for LSTM.")
    parser.add_argument("--latent-dim", type=int, default=16, help="Latent space dimensionality.")
    parser.add_argument("--num-layers", type=int, default=2, help="Number of LSTM layers.")
    parser.add_argument("--dropout", type=float, default=0.2, help="Dropout rate.")
    parser.add_argument("--val-split", type=float, default=0.2, help="Validation set split ratio.")
    
    args = parser.parse_args()

    train_model(
        data_path=args.data_path,
        model_dir=args.model_dir,
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.lr,
        sequence_length=args.seq_len,
        latent_dim=args.latent_dim,
        num_layers=args.num_layers,
        dropout=args.dropout,
        validation_split=args.val_split
    )
