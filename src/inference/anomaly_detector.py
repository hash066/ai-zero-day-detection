"""
Enhanced Real-time Anomaly Detection Pipeline.

Integrated with enhanced models for zero-day attack detection:
- EnhancedLSTMAutoencoder for temporal behavioral analysis
- EnhancedGNNDetector for network graph anomaly detection
- EnhancedEnsembleScorer for unified threat assessment
- Self-supervised pre-training support
- Feature engineering pipeline integration
- Attention-based explainability
- Calibrated threshold detection
- Temporal consistency tracking
"""

import logging
import torch
import json
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
import pandas as pd
import numpy as np
import joblib
from collections import deque
import sys

# Optional import for torch_geometric
try:
    from torch_geometric.data import Data
    TORCH_GEOMETRIC_AVAILABLE = True
except ImportError:
    TORCH_GEOMETRIC_AVAILABLE = False
    Data = None

# Adjusting path to import from sibling directories
sys.path.append(str(Path(__file__).resolve().parent.parent))

try:
    from models.lstm_autoencoder import EnhancedLSTMAutoencoder
    LSTM_AVAILABLE = True
except ImportError:
    LSTM_AVAILABLE = False

try:
    from models.gnn_detector import EnhancedGNNDetector
    GNN_AVAILABLE = True
except ImportError:
    GNN_AVAILABLE = False

try:
    from models.ensemble_scorer import EnhancedEnsembleScorer
    ENSEMBLE_AVAILABLE = True
except ImportError:
    ENSEMBLE_AVAILABLE = False

# Feature names for compatibility - aligned with trained model
TEMPORAL_FEATURE_NAMES = [
    'unique_src_ips', 'unique_dst_ips', 'src_port_entropy', 'dst_port_entropy'
]

NODE_FEATURE_NAMES = [
    'total_bytes_sent', 'total_bytes_received', 'total_packets_sent',
    'total_packets_received', 'unique_connections', 'avg_packet_size',
    'port_diversity', 'protocol_diversity', 'time_active'
]
from preprocessing.graph_builder import NetworkGraphBuilder
from preprocessing.feature_engineering import extract_all_features

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class EnhancedAnomalyDetector:
    """
    Enhanced anomaly detection pipeline for zero-day attack detection.
    
    Integrates:
    - LSTM Autoencoder for temporal behavioral patterns
    - GNN Detector for network graph anomalies
    - Ensemble Scorer for unified threat assessment
    - Feature engineering pipeline (92 features)
    - Attention mechanisms for explainability
    - Calibrated thresholds for accurate detection
    - Temporal consistency tracking
    """

    def __init__(
        self,
        lstm_model_path: str,
        gnn_model_path: str,
        ensemble_model_path: Optional[str] = None,
        use_pretrained_weights: bool = False,
        pretrained_lstm_path: Optional[str] = None,
        pretrained_gnn_path: Optional[str] = None
    ):
        """
        Initialize Enhanced Anomaly Detector.

        Args:
            lstm_model_path: Path to trained LSTM model directory
            gnn_model_path: Path to trained GNN model directory
            ensemble_model_path: Path to trained ensemble scorer (optional)
            use_pretrained_weights: Whether models use self-supervised pre-training
            pretrained_lstm_path: Path to pre-trained LSTM encoder weights
            pretrained_gnn_path: Path to pre-trained GNN encoder weights
        """
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        logger.info(f"Inference device: {self.device}")

        # Load models and artifacts
        self.lstm_model, self.lstm_config = self._load_lstm_model(lstm_model_path)
        self.gnn_model, self.gnn_config = self._load_gnn_model(gnn_model_path)

        # Initialize ensemble scorer
        if ensemble_model_path and Path(ensemble_model_path).exists():
            self.ensemble_scorer = self._load_ensemble_scorer(ensemble_model_path)
        else:
            # Create new ensemble scorer with default settings
            self.ensemble_scorer = EnhancedEnsembleScorer(
                feature_dim=27,  # 27 behavioral features
                use_learned_weights=True,
                temporal_window=10,
                confidence_threshold=0.7
            )
            logger.info("Created new ensemble scorer with default settings")

        # Graph builder for network data
        self.graph_builder = NetworkGraphBuilder()

        # Temporal tracking
        self.anomaly_history = deque(maxlen=100)

        logger.info("Enhanced Anomaly Detector initialized successfully")

    def _load_lstm_model(self, model_dir: str) -> Tuple[EnhancedLSTMAutoencoder, Dict]:
        """Load LSTM model with enhanced features."""
        logger.info(f"Loading Enhanced LSTM model from {model_dir}...")
        model_path = Path(model_dir)

        # Load configuration
        config_path = model_path / "config.json"
        with open(config_path, 'r') as f:
            config = json.load(f)

        # Create enhanced model
        model = EnhancedLSTMAutoencoder(
            input_dim=config.get('input_dim', 27),  # 27 temporal features
            latent_dim=config.get('latent_dim', 64),
            num_layers=config.get('num_layers', 2),
            dropout=config.get('dropout', 0.3),
            use_attention=config.get('use_attention', True),
            feature_names=TEMPORAL_FEATURE_NAMES
        ).to(self.device)

        # Load weights
        weights_path = model_path / "best_model.pth"
        if weights_path.exists():
            checkpoint = torch.load(weights_path, map_location=self.device)
            model.load_state_dict(checkpoint['model_state_dict'])
            logger.info(f"✓ Loaded LSTM weights from epoch {checkpoint.get('epoch', 'N/A')}")
        else:
            logger.warning(f"No trained weights found at {weights_path}, using random initialization")

        model.eval()

        return model, config

    def _load_gnn_model(self, model_dir: str):
        """Load GNN model with enhanced features."""
        if not GNN_AVAILABLE:
            logger.warning("GNN model not available (torch_geometric not installed)")
            return None, {}

        logger.info(f"Loading Enhanced GNN model from {model_dir}...")
        model_path = Path(model_dir)

        # Load configuration
        config_path = model_path / "config.json"
        config = {}
        if config_path.exists():
            with open(config_path, 'r') as f:
                config = json.load(f)

        # Create enhanced model
        model = EnhancedGNNDetector(
            in_channels=config.get('in_channels', 9),  # 9 node features
            hidden_channels=config.get('hidden_channels', 64),
            num_heads=config.get('num_heads', 4),
            num_layers=config.get('num_layers', 3),
            dropout=config.get('dropout', 0.3),
            use_temporal_aggregation=config.get('use_temporal_aggregation', True)
        ).to(self.device)

        # Load weights
        weights_path = model_path / "best_model.pth"
        if weights_path.exists():
            checkpoint = torch.load(weights_path, map_location=self.device)
            model.load_state_dict(checkpoint['model_state_dict'])
            logger.info(f"✓ Loaded GNN weights from epoch {checkpoint.get('epoch', 'N/A')}")
        else:
            logger.warning(f"No trained weights found at {weights_path}, using random initialization")

        model.eval()

        return model, config

    def _load_ensemble_scorer(self, model_path: str) -> EnhancedEnsembleScorer:
        """Load trained ensemble scorer."""
        logger.info(f"Loading ensemble scorer from {model_path}...")

        with open(Path(model_path) / "config.json", 'r') as f:
            config = json.load(f)

        scorer = EnhancedEnsembleScorer(
            feature_dim=config.get('feature_dim', 27),
            use_learned_weights=config.get('use_learned_weights', True),
            temporal_window=config.get('temporal_window', 10),
            confidence_threshold=config.get('confidence_threshold', 0.7)
        )

        # Load learned weights if available
        weights_path = Path(model_path) / "ensemble_weights.pth"
        if weights_path.exists() and scorer.use_learned_weights:
            scorer.combiner.load_state_dict(
                torch.load(weights_path, map_location=self.device)
            )
            logger.info("✓ Loaded ensemble combiner weights")

        return scorer

    def detect_temporal_anomaly(
        self,
        sequence_df: pd.DataFrame,
        return_details: bool = True
    ) -> Dict[str, Any]:
        """
        Detect anomalies in temporal behavioral sequences using LSTM.

        Args:
            sequence_df: DataFrame with temporal features (27 columns)
            return_details: Whether to return attention weights and feature importance
            
        Returns:
            Dictionary with:
                - anomaly_score: Reconstruction error (0-1)
                - is_anomaly: Boolean flag
                - confidence: Detection confidence
                - attention_weights: Time step importance (if return_details=True)
                - feature_errors: Per-feature reconstruction errors
        """
        # Ensure correct features
        if not all(feat in sequence_df.columns for feat in TEMPORAL_FEATURE_NAMES):
            # Extract features if raw data provided
            logger.info("Extracting temporal features from raw data...")
            sequence_df = self._extract_temporal_features(sequence_df)

        # Select temporal features
        feature_data = sequence_df[TEMPORAL_FEATURE_NAMES].values

        # Convert to tensor: (1, seq_len, num_features)
        sequence_tensor = torch.tensor(
            feature_data,
            dtype=torch.float32
        ).unsqueeze(0).to(self.device)

        # Run LSTM inference
        with torch.no_grad():
            result = self.lstm_model.detect_anomalies(
                sequence_tensor,
                return_details=return_details
            )

        # Convert tensors to Python types
        output = {
            'anomaly_score': float(result['anomaly_scores'][0]),  # Take first sample score
            'is_anomaly': bool(result['is_anomaly'][0]),  # Take first sample result
            'confidence': float(result.get('confidence', 0.0))
        }

        if return_details:
            # Handle optional attention weights
            if 'attention_weights' in result and result['attention_weights'] is not None:
                output['attention_weights'] = result['attention_weights'].cpu().numpy().tolist()
            else:
                output['attention_weights'] = []

            # Handle feature errors
            if 'feature_errors' in result:
                feature_errors_array = result['feature_errors']
                if hasattr(feature_errors_array, 'cpu'):
                    feature_errors_array = feature_errors_array.cpu().numpy()
                output['feature_errors'] = {
                    name: float(error)
                    for name, error in zip(TEMPORAL_FEATURE_NAMES, feature_errors_array.flatten())
                }
                output['top_anomalous_features'] = [
                    {'feature': name, 'error': float(error)}
                    for name, error in sorted(
                        output['feature_errors'].items(),
                        key=lambda x: x[1],
                        reverse=True
                    )[:5]
                ]
            else:
                output['feature_errors'] = {}
                output['top_anomalous_features'] = []

        return output

    def detect_network_anomaly(
        self,
        network_df: pd.DataFrame,
        return_details: bool = True
    ) -> Dict[str, Any]:
        """
        Detect anomalies in network traffic using GNN.

        Args:
            network_df: DataFrame with network flow data
            return_details: Whether to return attention and node scores
            
        Returns:
            Dictionary with:
                - graph_anomaly_score: Network-level anomaly score (0-1)
                - is_anomaly: Boolean flag
                - node_scores: Per-node anomaly scores
                - attention_weights: Graph attention patterns (if return_details=True)
                - anomalous_nodes: Top anomalous nodes
        """
        # Build graph from network data
        logger.debug("Building graph from network flows...")

        # Reset graph builder for fresh graph
        self.graph_builder = NetworkGraphBuilder()

        # Add flows to graph builder (vectorized approach)
        # Convert DataFrame to list of dicts efficiently
        flow_records = network_df.to_dict('records')
        for flow_dict in flow_records:  # Much faster than iterrows()
            self.graph_builder.add_network_flow(flow_dict)
        
        # Finalize graph features
        self.graph_builder.finalize_graph()

        # Convert to PyTorch Geometric Data
        edge_index, edge_weights, node_ids = self.graph_builder.to_edge_index()
        feature_matrix, _, feature_names = self.graph_builder.get_node_feature_matrix()

        # Create Data object
        data = Data(
            x=torch.tensor(feature_matrix, dtype=torch.float32).to(self.device),
            edge_index=torch.tensor(edge_index, dtype=torch.long).to(self.device)
        )

        # Run GNN inference
        with torch.no_grad():
            result = self.gnn_model.detect_anomalies(
                data,
                return_details=return_details
            )

        # Convert results
        output = {
            'graph_anomaly_score': float(result['graph_score']),
            'is_anomaly': bool(result['is_anomaly']),
            'confidence': float(result.get('confidence', 0.0)),
            'num_nodes': len(self.graph_builder.nodes),
            'num_edges': len(self.graph_builder.edges)
        }

        if return_details:
            # Map node indices to IPs
            node_list = node_ids
            node_scores_dict = {
                node_list[i]: float(score)
                for i, score in enumerate(result['node_scores'].cpu().numpy())
            }

            output['node_scores'] = node_scores_dict
            output['anomalous_nodes'] = [
                {'node': node, 'score': score}
                for node, score in sorted(
                    node_scores_dict.items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:10]  # Top 10 anomalous nodes
            ]

            if 'attention_weights' in result:
                output['attention_weights'] = [
                    attn.cpu().numpy().tolist()
                    for attn in result['attention_weights']
                ]

        return output

    def detect_comprehensive(
        self,
        temporal_df: pd.DataFrame,
        network_df: pd.DataFrame,
        behavioral_features: Optional[pd.DataFrame] = None,
        return_details: bool = True
    ) -> Dict[str, Any]:
        """
        Comprehensive anomaly detection using both LSTM and GNN with ensemble scoring.

        Args:
            temporal_df: DataFrame with temporal behavioral data
            network_df: DataFrame with network flow data
            behavioral_features: Optional pre-extracted 27 behavioral features
            return_details: Whether to return detailed explanations
            
        Returns:
            Comprehensive threat assessment with:
                - final_threat_score: Unified score (0-1)
                - severity: LOW/MEDIUM/HIGH/CRITICAL
                - confidence: Detection confidence
                - lstm_analysis: LSTM results
                - gnn_analysis: GNN results
                - ensemble_details: Scoring breakdown
                - explainability: Feature attributions and attention
        """
        logger.info("Running comprehensive anomaly detection...")

        # 1. LSTM Temporal Analysis
        lstm_result = self.detect_temporal_anomaly(temporal_df, return_details)
        lstm_score = lstm_result['anomaly_score']

        # 2. GNN Network Analysis
        gnn_result = self.detect_network_anomaly(network_df, return_details)
        gnn_score = gnn_result['graph_anomaly_score']

        # 3. Extract behavioral features for ensemble
        if behavioral_features is None:
            behavioral_features = self._extract_behavioral_features(temporal_df, network_df)

        behavioral_array = behavioral_features.values if isinstance(behavioral_features, pd.DataFrame) else behavioral_features

        # 4. Ensemble Scoring
        ensemble_result = self.ensemble_scorer.calculate_threat_score(
            lstm_score=lstm_score,
            gnn_score=gnn_score,
            behavioral_features=behavioral_array,
            return_details=True
        )

        # 5. Determine severity level
        final_score = ensemble_result['final_score']
        severity = self._calculate_severity(final_score, ensemble_result['confidence'])

        # 6. Track temporal consistency
        self.anomaly_history.append({
            'timestamp': pd.Timestamp.now(),
            'score': final_score,
            'lstm_score': lstm_score,
            'gnn_score': gnn_score
        })

        # 7. Build comprehensive output
        output = {
            'final_threat_score': final_score,
            'severity': severity,
            'confidence': ensemble_result['confidence'],
            'is_anomaly': ensemble_result['is_anomaly'],
            'lstm_analysis': lstm_result,
            'gnn_analysis': gnn_result,
            'ensemble_details': {
                'model_agreement': ensemble_result.get('model_agreement', 0.0),
                'temporal_consistency': ensemble_result.get('temporal_consistency', 0.0),
                'trend': ensemble_result.get('trend', 'stable')
            },
            'timestamp': pd.Timestamp.now().isoformat()
        }

        if return_details:
            output['explainability'] = {
                'top_temporal_features': lstm_result.get('top_anomalous_features', []),
                'anomalous_nodes': gnn_result.get('anomalous_nodes', []),
                'feature_importance': ensemble_result.get('feature_importance', {}),
                'attention_lstm': lstm_result.get('attention_weights', []),
                'attention_gnn': gnn_result.get('attention_weights', [])
            }

        logger.info(f"Detection complete: Score={final_score:.4f}, Severity={severity}")

        return output

    def _extract_temporal_features(self, raw_df: pd.DataFrame) -> pd.DataFrame:
        """Extract 27 temporal features from raw data."""
        # Use feature engineering pipeline
        features_df = extract_all_features(raw_df)
        # Return DataFrame with temporal features
        temporal_features = features_df[TEMPORAL_FEATURE_NAMES]
        if isinstance(temporal_features, pd.Series):
            return temporal_features.to_frame().T
        return temporal_features

    def _extract_behavioral_features(
        self,
        temporal_df: pd.DataFrame,
        network_df: pd.DataFrame
    ) -> np.ndarray:
        """Extract 27 behavioral features for ensemble."""
        # Combine temporal and network data, extract features
        combined_df = pd.concat([temporal_df, network_df], axis=0, ignore_index=True)
        features_df = extract_all_features(combined_df)

        # Select 27 behavioral features
        behavioral_cols = TEMPORAL_FEATURE_NAMES[:27]
        return features_df[behavioral_cols].iloc[-1].values

    def _calculate_severity(self, score: float, confidence: float) -> str:
        """
        Calculate threat severity based on score and confidence.
        
        Severity Levels:
        - CRITICAL: score > 0.9, high confidence
        - HIGH: score > 0.75
        - MEDIUM: score > 0.5
        - LOW: score <= 0.5
        """
        if score > 0.9 and confidence > 0.8:
            return 'CRITICAL'
        elif score > 0.75:
            return 'HIGH'
        elif score > 0.5:
            return 'MEDIUM'
        else:
            return 'LOW'

    def get_anomaly_trend(self, window: int = 10) -> Dict[str, Any]:
        """
        Get anomaly trend over recent detections.
        
        Args:
            window: Number of recent detections to analyze
            
        Returns:
            Trend analysis with statistics
        """
        if len(self.anomaly_history) < 2:
            return {'trend': 'insufficient_data', 'samples': len(self.anomaly_history)}

        recent = list(self.anomaly_history)[-window:]
        scores = [entry['score'] for entry in recent]

        # Calculate trend
        if len(scores) >= 3:
            recent_avg = np.mean(scores[-3:])
            older_avg = np.mean(scores[:-3]) if len(scores) > 3 else scores[0]

            if recent_avg > older_avg * 1.2:
                trend = 'increasing'
            elif recent_avg < older_avg * 0.8:
                trend = 'decreasing'
            else:
                trend = 'stable'
        else:
            trend = 'stable'

        return {
            'trend': trend,
            'mean_score': float(np.mean(scores)),
            'max_score': float(np.max(scores)),
            'min_score': float(np.min(scores)),
            'std_score': float(np.std(scores)),
            'samples': len(scores)
        }

    def reset(self):
        """Reset temporal tracking state."""
        self.anomaly_history.clear()
        self.ensemble_scorer.reset_temporal_state()
        logger.info("Detector state reset")


def main_demo():
    """Demonstration of enhanced anomaly detector."""
    logger.info("=== Enhanced Anomaly Detector Demo ===\n")

    # Paths to trained models
    LSTM_MODEL_PATH = "data/models/lstm_trained"
    GNN_MODEL_PATH = "data/models/gnn_trained"
    ENSEMBLE_MODEL_PATH = "data/models/ensemble_trained"

    try:
        # Initialize detector
        detector = EnhancedAnomalyDetector(
            lstm_model_path=LSTM_MODEL_PATH,
            gnn_model_path=GNN_MODEL_PATH,
            ensemble_model_path=ENSEMBLE_MODEL_PATH
        )
        logger.info("✓ Detector initialized\n")

        # Demo 1: Temporal Anomaly Detection
        logger.info("--- Demo 1: Temporal Anomaly Detection ---")
        temporal_data = pd.DataFrame(
            np.random.rand(20, 27),  # 20 timesteps, 27 features
            columns=TEMPORAL_FEATURE_NAMES
        )

        lstm_result = detector.detect_temporal_anomaly(temporal_data)
        logger.info(f"LSTM Score: {lstm_result['anomaly_score']:.4f}")
        logger.info(f"Is Anomaly: {lstm_result['is_anomaly']}")
        logger.info(f"Top Anomalous Features: {lstm_result['top_anomalous_features'][:3]}\n")

        # Demo 2: Network Anomaly Detection
        logger.info("--- Demo 2: Network Anomaly Detection ---")
        network_data = pd.DataFrame({
            'src_ip': ['192.168.1.1', '192.168.1.2', '192.168.1.1'],
            'dst_ip': ['10.0.0.1', '10.0.0.2', '10.0.0.2'],
            'src_port': [443, 80, 443],
            'dst_port': [12345, 54321, 12346],
            'protocol': ['TCP', 'TCP', 'TCP'],
            'bytes_sent': [1024, 2048, 512],
            'bytes_received': [512, 1024, 256],
            'packets_sent': [10, 20, 5],
            'packets_received': [5, 10, 3],
            'timestamp': pd.date_range('2024-01-01', periods=3, freq='1S')
        })

        gnn_result = detector.detect_network_anomaly(network_data)
        logger.info(f"GNN Score: {gnn_result['graph_anomaly_score']:.4f}")
        logger.info(f"Is Anomaly: {gnn_result['is_anomaly']}")
        logger.info(f"Anomalous Nodes: {gnn_result.get('anomalous_nodes', [])[:3]}\n")

        # Demo 3: Comprehensive Detection
        logger.info("--- Demo 3: Comprehensive Detection ---")
        comprehensive_result = detector.detect_comprehensive(
            temporal_df=temporal_data,
            network_df=network_data
        )

        logger.info(f"Final Threat Score: {comprehensive_result['final_threat_score']:.4f}")
        logger.info(f"Severity: {comprehensive_result['severity']}")
        logger.info(f"Confidence: {comprehensive_result['confidence']:.4f}")
        logger.info(f"Model Agreement: {comprehensive_result['ensemble_details']['model_agreement']:.4f}")

        logger.info("\n✅ Demo complete!")

    except FileNotFoundError as e:
        logger.error(f"Model files not found: {e}")
        logger.info("Please train models first using:")
        logger.info("  python src/training/train_lstm.py --data <data> --output data/models/lstm_trained")
        logger.info("  python src/training/train_gnn.py --data <data> --output data/models/gnn_trained")
    except Exception as e:
        logger.error(f"Error during demo: {e}", exc_info=True)


if __name__ == '__main__':
    main_demo()
