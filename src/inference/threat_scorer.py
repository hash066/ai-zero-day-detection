"""
Unified Threat Scorer - Simplified Inference Coordinator.

Provides a simple interface that coordinates:
- Enhanced Anomaly Detector (LSTM + GNN + Ensemble)
- Enhanced Response Engine (Alerting + Isolation)

This is the main entry point for real-time threat detection and response.
"""

import logging
from pathlib import Path
from typing import Dict, Any, Optional
import pandas as pd

from .anomaly_detector import EnhancedAnomalyDetector
from .response_engine import EnhancedResponseEngine

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ThreatScorer:
    """
    Unified threat scoring interface for zero-day attack detection.
    
    Coordinates:
    1. Enhanced Anomaly Detection (LSTM + GNN + Ensemble)
    2. Automated Response (Alerting + Isolation + Logging)
    
    Usage:
        # Initialize
        scorer = ThreatScorer(
            lstm_model_path="data/models/lstm_trained",
            gnn_model_path="data/models/gnn_trained",
            alert_webhook_url="https://hooks.slack.com/..."
        )
        
        # Score a threat
        result = scorer.score_threat(
            temporal_data=temporal_df,
            network_data=network_df,
            entity_id="192.168.1.100"
        )
        
        # Get threat score
        print(f"Threat Score: {result['final_threat_score']}")
        print(f"Severity: {result['severity']}")
    """

    def __init__(
        self,
        lstm_model_path: str,
        gnn_model_path: str,
        ensemble_model_path: Optional[str] = None,
        alert_webhook_url: Optional[str] = None,
        firewall_api_url: Optional[str] = None,
        isolation_api_key: Optional[str] = None,
        incident_log_path: str = "data/incidents/incident_log.jsonl",
        auto_respond: bool = True
    ):
        """
        Initialize Unified Threat Scorer.

        Args:
            lstm_model_path: Path to trained LSTM model
            gnn_model_path: Path to trained GNN model
            ensemble_model_path: Path to trained ensemble scorer (optional)
            alert_webhook_url: Webhook URL for alerts
            firewall_api_url: Firewall API for network isolation
            isolation_api_key: API key for isolation
            incident_log_path: Path to incident log
            auto_respond: Whether to automatically trigger responses
        """
        logger.info("Initializing Unified Threat Scorer...")
        
        # Initialize anomaly detector
        self.detector = EnhancedAnomalyDetector(
            lstm_model_path=lstm_model_path,
            gnn_model_path=gnn_model_path,
            ensemble_model_path=ensemble_model_path
        )
        
        # Initialize response engine
        self.response_engine = EnhancedResponseEngine(
            alert_webhook_url=alert_webhook_url,
            firewall_api_url=firewall_api_url,
            isolation_api_key=isolation_api_key,
            incident_log_path=incident_log_path
        )
        
        self.auto_respond = auto_respond
        
        logger.info("✓ Threat Scorer initialized successfully")

    def score_threat(
        self,
        temporal_data: pd.DataFrame,
        network_data: pd.DataFrame,
        entity_id: str,
        entity_type: str = 'ip',
        auto_respond: Optional[bool] = None,
        return_details: bool = True
    ) -> Dict[str, Any]:
        """
        Score a potential threat and optionally trigger response.
        
        Args:
            temporal_data: DataFrame with temporal behavioral data
            network_data: DataFrame with network flow data
            entity_id: Entity identifier (IP, process GUID, etc.)
            entity_type: Type of entity ('ip', 'process', 'device')
            auto_respond: Override auto_respond setting (optional)
            return_details: Whether to return detailed analysis
            
        Returns:
            Comprehensive threat assessment with:
                - final_threat_score: Score (0-1)
                - severity: LOW/MEDIUM/HIGH/CRITICAL
                - confidence: Detection confidence
                - is_anomaly: Boolean flag
                - actions_taken: List of response actions (if auto_respond=True)
                - explainability: Feature attributions and attention
        """
        logger.info(f"Scoring threat for entity: {entity_id}")
        
        # 1. Detect anomaly using enhanced models
        detection_result = self.detector.detect_comprehensive(
            temporal_df=temporal_data,
            network_df=network_data,
            return_details=return_details
        )
        
        # 2. Trigger automated response if enabled
        should_respond = auto_respond if auto_respond is not None else self.auto_respond
        
        if should_respond and detection_result['is_anomaly']:
            response_result = self.response_engine.process_detection(
                detection_result=detection_result,
                entity_id=entity_id,
                entity_type=entity_type,
                source_data={
                    'temporal_samples': len(temporal_data),
                    'network_flows': len(network_data)
                }
            )
            detection_result['response'] = response_result
        else:
            detection_result['response'] = {'actions_taken': [], 'reason': 'auto_respond_disabled'}
        
        logger.info(f"Threat scoring complete: Score={detection_result['final_threat_score']:.4f}, "
                   f"Severity={detection_result['severity']}")
        
        return detection_result

    def score_temporal_only(
        self,
        temporal_data: pd.DataFrame,
        entity_id: str,
        return_details: bool = True
    ) -> Dict[str, Any]:
        """
        Score threat using LSTM temporal analysis only.
        
        Useful when network data is unavailable.
        """
        logger.info(f"Scoring temporal threat for entity: {entity_id}")
        
        result = self.detector.detect_temporal_anomaly(
            sequence_df=temporal_data,
            return_details=return_details
        )
        
        result['entity_id'] = entity_id
        result['analysis_type'] = 'temporal_only'
        
        return result

    def score_network_only(
        self,
        network_data: pd.DataFrame,
        entity_id: str,
        return_details: bool = True
    ) -> Dict[str, Any]:
        """
        Score threat using GNN network analysis only.
        
        Useful when temporal data is unavailable.
        """
        logger.info(f"Scoring network threat for entity: {entity_id}")
        
        result = self.detector.detect_network_anomaly(
            network_df=network_data,
            return_details=return_details
        )
        
        result['entity_id'] = entity_id
        result['analysis_type'] = 'network_only'
        
        return result

    def mark_false_positive(
        self,
        entity_id: str,
        timestamp: str,
        reason: Optional[str] = None
    ):
        """
        Mark an alert as false positive for model improvement.
        
        Args:
            entity_id: Entity that was incorrectly flagged
            timestamp: Timestamp of the original alert
            reason: Reason for false positive (optional)
        """
        self.response_engine.mark_false_positive(entity_id, timestamp, reason)
        logger.info(f"Marked {entity_id} as false positive")

    def generate_report(
        self,
        start_time=None,
        end_time=None,
        min_severity='MEDIUM'
    ) -> Dict[str, Any]:
        """
        Generate comprehensive incident report.
        
        Args:
            start_time: Report start time (default: last 24 hours)
            end_time: Report end time (default: now)
            min_severity: Minimum severity to include
            
        Returns:
            Report with statistics and incident list
        """
        return self.response_engine.generate_incident_report(
            start_time=start_time,
            end_time=end_time,
            min_severity=min_severity
        )

    def get_statistics(self) -> Dict[str, Any]:
        """Get current threat scorer statistics."""
        detector_trend = self.detector.get_anomaly_trend()
        response_stats = self.response_engine.get_statistics()
        
        return {
            'detector': detector_trend,
            'response_engine': response_stats
        }

    def reset(self):
        """Reset scorer state."""
        self.detector.reset()
        logger.info("Threat scorer reset")


def main_demo():
    """Demonstration of Unified Threat Scorer."""
    import numpy as np
    from models.lstm_autoencoder import TEMPORAL_FEATURE_NAMES
    
    logger.info("=== Unified Threat Scorer Demo ===\n")
    
    try:
        # Initialize scorer
        scorer = ThreatScorer(
            lstm_model_path="data/models/lstm_trained",
            gnn_model_path="data/models/gnn_trained",
            incident_log_path="data/incidents/demo_threats.jsonl",
            auto_respond=True
        )
        
        # Create sample data
        logger.info("--- Creating Sample Data ---")
        temporal_data = pd.DataFrame(
            np.random.rand(20, 27),
            columns=TEMPORAL_FEATURE_NAMES
        )
        
        network_data = pd.DataFrame({
            'src_ip': ['192.168.1.50'] * 10,
            'dst_ip': [f'10.0.0.{i}' for i in range(10)],
            'src_port': [443] * 10,
            'dst_port': np.random.randint(10000, 60000, 10),
            'protocol': ['TCP'] * 10,
            'bytes_sent': np.random.randint(100, 5000, 10),
            'bytes_received': np.random.randint(100, 5000, 10),
            'packets_sent': np.random.randint(1, 50, 10),
            'packets_received': np.random.randint(1, 50, 10),
            'timestamp': pd.date_range('2024-01-01', periods=10, freq='1S')
        })
        
        # Score threat
        logger.info("\n--- Scoring Threat ---")
        result = scorer.score_threat(
            temporal_data=temporal_data,
            network_data=network_data,
            entity_id='192.168.1.50',
            entity_type='ip'
        )
        
        # Display results
        logger.info(f"\n📊 Threat Assessment Results:")
        logger.info(f"  Entity: {result.get('entity_id', '192.168.1.50')}")
        logger.info(f"  Final Score: {result['final_threat_score']:.4f}")
        logger.info(f"  Severity: {result['severity']}")
        logger.info(f"  Confidence: {result['confidence']:.2%}")
        logger.info(f"  Is Anomaly: {result['is_anomaly']}")
        
        if 'response' in result:
            logger.info(f"  Actions Taken: {result['response']['actions_taken']}")
        
        if 'explainability' in result:
            top_features = result['explainability'].get('top_temporal_features', [])[:3]
            if top_features:
                logger.info(f"\n  Top Anomalous Features:")
                for feat in top_features:
                    logger.info(f"    • {feat['feature']}: {feat['error']:.4f}")
        
        # Get statistics
        logger.info("\n--- Statistics ---")
        stats = scorer.get_statistics()
        logger.info(f"  Detection Trend: {stats['detector']['trend']}")
        logger.info(f"  Total Alerts: {stats['response_engine']['total_alerts']}")
        logger.info(f"  Critical Alerts: {stats['response_engine']['by_severity']['CRITICAL']}")
        
        logger.info("\n✅ Demo complete!")
        
    except FileNotFoundError as e:
        logger.error(f"Model files not found: {e}")
        logger.info("\nPlease train models first:")
        logger.info("  1. python src/training/train_lstm.py --data <data> --output data/models/lstm_trained")
        logger.info("  2. python src/training/train_gnn.py --data <data> --output data/models/gnn_trained")
    except Exception as e:
        logger.error(f"Error during demo: {e}", exc_info=True)


if __name__ == '__main__':
    main_demo()
