"""
Model utilities for integration with preprocessing pipeline.

Provides data loaders, feature selectors, and standardization utilities
that connect preprocessing outputs to model inputs.
"""

import numpy as np
import pandas as pd
import torch
from torch.utils.data import Dataset, DataLoader
from torch_geometric.data import Data
from typing import Dict, List, Tuple, Optional
import logging
from pathlib import Path
import sys

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from preprocessing.feature_engineering import extract_all_features
from preprocessing.graph_builder import NetworkGraphBuilder
from preprocessing.windowing import create_sliding_windows

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TemporalFeatureSelector:
    """
    Selects temporal features for LSTM input from preprocessing output.
    
    Extracts the 27 temporal/behavioral features from feature_engineering.py:
    - Entropy features (5)
    - Inter-arrival time features (4)
    - Temporal pattern features (4)
    - Behavioral features (11)
    - Size distribution features (6)
    """
    
    # Feature indices from extract_all_features() output
    TEMPORAL_FEATURES = [
        'src_port_entropy', 'dst_port_entropy', 'src_ip_entropy', 'dst_ip_entropy',
        'packet_size_entropy', 'mean_inter_arrival', 'std_inter_arrival',
        'cv_inter_arrival', 'burstiness', 'periodicity_score', 'peak_hour',
        'off_hours_ratio', 'hour_entropy', 'connection_diversity', 'fan_out_ratio',
        'rare_protocol_ratio', 'protocol_switching_rate', 'size_mean', 'size_std',
        'size_skewness', 'size_kurtosis', 'small_packet_ratio', 'large_packet_ratio'
    ]
    
    # Sysmon behavioral features
    SYSMON_FEATURES = [
        'process_diversity', 'registry_access_count',
        'network_connection_count', 'file_creation_count'
    ]
    
    def __init__(self, include_sysmon: bool = True):
        self.include_sysmon = include_sysmon
        
        if include_sysmon:
            self.feature_names = self.TEMPORAL_FEATURES + self.SYSMON_FEATURES
        else:
            self.feature_names = self.TEMPORAL_FEATURES
        
        logger.info(f"Temporal feature selector initialized: {len(self.feature_names)} features")
    
    def select_features(self, df: pd.DataFrame) -> np.ndarray:
        """
        Select temporal features from preprocessed DataFrame.
        
        Args:
            df: DataFrame from extract_all_features()
            
        Returns:
            Array of shape (num_samples, num_features)
        """
        # Check which features exist in the DataFrame
        available_features = [f for f in self.feature_names if f in df.columns]
        missing_features = set(self.feature_names) - set(available_features)
        
        if missing_features:
            logger.warning(f"Missing {len(missing_features)} features: {missing_features}")
        
        if not available_features:
            raise ValueError("No temporal features found in DataFrame")
        
        # Extract features
        features = df[available_features].values
        
        # Handle NaN/inf values
        features = np.nan_to_num(features, nan=0.0, posinf=1e6, neginf=-1e6)
        
        return features


class SpatialFeatureSelector:
    """
    Selects spatial (graph) features for GNN input from graph_builder output.
    
    Extracts the 9 node features from NetworkGraphBuilder:
    - Traffic volume features (4)
    - Connection diversity features (3)
    - Protocol/port diversity (2)
    - Time-based features (1)
    """
    
    NODE_FEATURES = [
        'total_bytes_sent', 'total_bytes_received', 'total_packets_sent',
        'total_packets_received', 'unique_connections', 'avg_packet_size',
        'port_diversity', 'protocol_diversity', 'time_active'
    ]
    
    def __init__(self):
        logger.info(f"Spatial feature selector initialized: {len(self.NODE_FEATURES)} node features")
    
    def build_graph_from_flows(
        self,
        df: pd.DataFrame,
        window_start: Optional[float] = None,
        window_end: Optional[float] = None
    ) -> Data:
        """
        Build PyTorch Geometric graph from network flows.
        
        Args:
            df: DataFrame with network flows
            window_start: Start timestamp for filtering
            window_end: End timestamp for filtering
            
        Returns:
            PyG Data object with x (node features), edge_index, edge_attr
        """
        # Filter by time window if provided
        if window_start is not None and window_end is not None and 'timestamp' in df.columns:
            df = df[(df['timestamp'] >= window_start) & (df['timestamp'] < window_end)]
        
        # Build graph
        builder = NetworkGraphBuilder()
        
        # Add flows to graph
        for _, row in df.iterrows():
            builder.add_network_flow(
                src_ip=row.get('src_ip', '0.0.0.0'),
                dst_ip=row.get('dst_ip', '0.0.0.0'),
                src_port=int(row.get('src_port', 0)),
                dst_port=int(row.get('dst_port', 0)),
                protocol=row.get('protocol', 'TCP'),
                bytes_sent=int(row.get('bytes', 0)),
                bytes_received=int(row.get('response_bytes', 0)),
                timestamp=float(row.get('timestamp', 0))
            )
        
        # Finalize graph
        builder.finalize_graph()
        
        # Convert to PyTorch Geometric format
        edge_index = builder.to_edge_index()
        node_features = builder.get_node_feature_matrix()
        
        # Create edge weights from traffic volume
        edge_weights = []
        for src_id, dst_id in edge_index.T:
            src_node = builder.nodes[list(builder.nodes.keys())[src_id]]
            edge_weights.append(src_node.total_bytes_sent + src_node.total_bytes_received)
        
        edge_weights = torch.tensor(edge_weights, dtype=torch.float32)
        
        # Normalize edge weights
        if edge_weights.sum() > 0:
            edge_weights = edge_weights / edge_weights.max()
        
        # Create PyG Data object
        data = Data(
            x=torch.tensor(node_features, dtype=torch.float32),
            edge_index=edge_index,
            edge_attr=edge_weights
        )
        
        return data


class FeatureStandardizer:
    """
    Standardizes features to zero mean and unit variance.
    
    Fits on training data and transforms train/test consistently.
    """
    
    def __init__(self):
        self.mean = None
        self.std = None
        self.is_fitted = False
    
    def fit(self, X: np.ndarray):
        """
        Fit standardizer on training data.
        
        Args:
            X: Training data (num_samples, num_features)
        """
        self.mean = np.mean(X, axis=0)
        self.std = np.std(X, axis=0)
        
        # Prevent division by zero
        self.std[self.std == 0] = 1.0
        
        self.is_fitted = True
        logger.info(f"Standardizer fitted on {X.shape[0]} samples, {X.shape[1]} features")
    
    def transform(self, X: np.ndarray) -> np.ndarray:
        """
        Standardize data using fitted parameters.
        
        Args:
            X: Data to standardize
            
        Returns:
            Standardized data
        """
        if not self.is_fitted:
            raise ValueError("Standardizer must be fitted before transform")
        
        return (X - self.mean) / self.std
    
    def fit_transform(self, X: np.ndarray) -> np.ndarray:
        """Fit and transform in one step."""
        self.fit(X)
        return self.transform(X)
    
    def inverse_transform(self, X: np.ndarray) -> np.ndarray:
        """Reverse standardization."""
        if not self.is_fitted:
            raise ValueError("Standardizer must be fitted before inverse_transform")
        
        return X * self.std + self.mean


class TemporalDataset(Dataset):
    """
    PyTorch Dataset for LSTM temporal sequences.
    
    Integrates with preprocessing pipeline to create sequences from
    windowed network flows and engineered features.
    """
    
    def __init__(
        self,
        data_path: str,
        window_size: int = 10,
        stride: int = 1,
        include_sysmon: bool = True,
        standardize: bool = True
    ):
        """
        Initialize temporal dataset.
        
        Args:
            data_path: Path to preprocessed data CSV
            window_size: Number of time steps per sequence
            stride: Stride for sliding window
            include_sysmon: Include Sysmon features
            standardize: Standardize features
        """
        self.window_size = window_size
        self.stride = stride
        
        # Load and preprocess data
        df = pd.read_csv(data_path)
        logger.info(f"Loaded {len(df)} samples from {data_path}")
        
        # Extract features
        df_features = extract_all_features(df)
        
        # Select temporal features
        selector = TemporalFeatureSelector(include_sysmon=include_sysmon)
        features = selector.select_features(df_features)
        
        # Standardize
        if standardize:
            self.standardizer = FeatureStandardizer()
            features = self.standardizer.fit_transform(features)
        else:
            self.standardizer = None
        
        # Create sequences
        self.sequences = []
        self.labels = []  # For supervised training (if labels available)
        
        for i in range(0, len(features) - window_size + 1, stride):
            sequence = features[i:i+window_size]
            self.sequences.append(sequence)
            
            # If labels exist, take label of last time step
            if 'label' in df.columns:
                label = df.iloc[i+window_size-1]['label']
                self.labels.append(label)
        
        logger.info(f"Created {len(self.sequences)} sequences of length {window_size}")
    
    def __len__(self) -> int:
        return len(self.sequences)
    
    def __getitem__(self, idx: int) -> Tuple[torch.Tensor, Optional[torch.Tensor]]:
        sequence = torch.tensor(self.sequences[idx], dtype=torch.float32)
        
        if self.labels:
            label = torch.tensor(self.labels[idx], dtype=torch.float32)
            return sequence, label
        else:
            return sequence, None


class GraphDataset(Dataset):
    """
    PyTorch Dataset for GNN graph data.
    
    Creates graph snapshots from windowed network flows.
    """
    
    def __init__(
        self,
        data_path: str,
        window_duration: int = 60,  # seconds
        stride: int = 30
    ):
        """
        Initialize graph dataset.
        
        Args:
            data_path: Path to preprocessed data CSV
            window_duration: Duration of each graph snapshot (seconds)
            stride: Stride between snapshots (seconds)
        """
        self.window_duration = window_duration
        self.stride = stride
        
        # Load data
        df = pd.read_csv(data_path)
        logger.info(f"Loaded {len(df)} flows from {data_path}")
        
        # Ensure timestamp column exists
        if 'timestamp' not in df.columns:
            logger.warning("No timestamp column, using index as proxy")
            df['timestamp'] = range(len(df))
        
        # Create graph snapshots
        selector = SpatialFeatureSelector()
        self.graphs = []
        self.labels = []
        
        min_time = df['timestamp'].min()
        max_time = df['timestamp'].max()
        
        current_time = min_time
        while current_time + window_duration <= max_time:
            graph = selector.build_graph_from_flows(
                df,
                window_start=current_time,
                window_end=current_time + window_duration
            )
            
            self.graphs.append(graph)
            
            # If labels exist, check if any flow in window is anomalous
            if 'label' in df.columns:
                window_df = df[
                    (df['timestamp'] >= current_time) &
                    (df['timestamp'] < current_time + window_duration)
                ]
                label = 1 if window_df['label'].sum() > 0 else 0
                self.labels.append(label)
            
            current_time += stride
        
        logger.info(f"Created {len(self.graphs)} graph snapshots")
    
    def __len__(self) -> int:
        return len(self.graphs)
    
    def __getitem__(self, idx: int) -> Tuple[Data, Optional[int]]:
        graph = self.graphs[idx]
        
        if self.labels:
            label = self.labels[idx]
            return graph, label
        else:
            return graph, None


def create_dataloaders(
    data_path: str,
    model_type: str = 'lstm',
    batch_size: int = 32,
    train_split: float = 0.8,
    **kwargs
) -> Tuple[DataLoader, DataLoader]:
    """
    Create train/validation dataloaders for model training.
    
    Args:
        data_path: Path to preprocessed data
        model_type: 'lstm' or 'gnn'
        batch_size: Batch size
        train_split: Fraction of data for training
        **kwargs: Additional arguments for dataset
        
    Returns:
        train_loader, val_loader
    """
    # Create dataset
    if model_type == 'lstm':
        dataset = TemporalDataset(data_path, **kwargs)
    elif model_type == 'gnn':
        dataset = GraphDataset(data_path, **kwargs)
    else:
        raise ValueError(f"Unknown model type: {model_type}")
    
    # Split train/validation
    train_size = int(len(dataset) * train_split)
    val_size = len(dataset) - train_size
    
    train_dataset, val_dataset = torch.utils.data.random_split(
        dataset, [train_size, val_size]
    )
    
    # Create dataloaders
    train_loader = DataLoader(
        train_dataset,
        batch_size=batch_size,
        shuffle=True,
        num_workers=0  # Set to 0 for Windows compatibility
    )
    
    val_loader = DataLoader(
        val_dataset,
        batch_size=batch_size,
        shuffle=False,
        num_workers=0
    )
    
    logger.info(f"Created dataloaders: {len(train_dataset)} train, {len(val_dataset)} val")
    
    return train_loader, val_loader


if __name__ == "__main__":
    """Example usage of model utilities."""
    
    print("=== Model Utilities Demo ===\n")
    
    # Example 1: Feature Selection
    print("1. Temporal Feature Selector")
    selector = TemporalFeatureSelector(include_sysmon=True)
    print(f"   Selected {len(selector.feature_names)} temporal features")
    print(f"   Features: {selector.feature_names[:5]}...\n")
    
    # Example 2: Spatial Feature Selector
    print("2. Spatial Feature Selector")
    spatial_selector = SpatialFeatureSelector()
    print(f"   Node features: {spatial_selector.NODE_FEATURES}\n")
    
    # Example 3: Standardizer
    print("3. Feature Standardizer")
    X_train = np.random.randn(100, 10)
    standardizer = FeatureStandardizer()
    X_train_std = standardizer.fit_transform(X_train)
    print(f"   Original mean: {X_train.mean(axis=0)[:3]}")
    print(f"   Standardized mean: {X_train_std.mean(axis=0)[:3]}")
    print(f"   Standardized std: {X_train_std.std(axis=0)[:3]}\n")
    
    print("=== Model utilities ready for integration ===")
