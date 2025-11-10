"""
Model management module for AI Zero-Day Detection System.

Handles ML model loading, inference, and lifecycle management.
"""

import logging
import asyncio
from typing import Dict, Any, Optional
from pathlib import Path
import torch

try:
    from inference.anomaly_detector import EnhancedAnomalyDetector
    ANOMALY_DETECTOR_AVAILABLE = True
except ImportError:
    ANOMALY_DETECTOR_AVAILABLE = False

try:
    from inference.response_engine import EnhancedResponseEngine
    RESPONSE_ENGINE_AVAILABLE = True
except ImportError:
    RESPONSE_ENGINE_AVAILABLE = False

logger = logging.getLogger(__name__)


class ModelManager:
    """
    Manages ML models for anomaly detection.

    Responsibilities:
    - Model loading and initialization
    - Inference execution
    - Model health monitoring
    - Response engine coordination
    """

    def __init__(self,
                 lstm_model_path: str = "trained_models/lstm",
                 gnn_model_path: str = "trained_models/gnn",
                 ensemble_config: Optional[Dict[str, Any]] = None):
        """
        Initialize model manager.

        Args:
            lstm_model_path: Path to LSTM model directory
            gnn_model_path: Path to GNN model directory
            ensemble_config: Configuration for ensemble scorer
        """
        self.lstm_model_path = lstm_model_path
        self.gnn_model_path = gnn_model_path
        self.ensemble_config = ensemble_config or {
            'lstm_weight': 0.6,
            'gnn_weight': 0.4,
            'temporal_window': 10,
            'confidence_threshold': 0.7
        }

        self.detector = None
        self.response_engine = None
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

        logger.info(f"Model manager initialized (device: {self.device})")

    def initialize_models(self) -> bool:
        """
        Initialize all ML models.

        Returns:
            True if initialization successful, False otherwise
        """
        logger.info("Initializing ML models...")

        try:
            # Initialize anomaly detector
            if ANOMALY_DETECTOR_AVAILABLE:
                self.detector = EnhancedAnomalyDetector(
                    lstm_model_path=self.lstm_model_path,
                    gnn_model_path=self.gnn_model_path
                )
                logger.info("Anomaly detector initialized")
            else:
                logger.error("Anomaly detector module not available")
                return False

            # Initialize response engine
            if RESPONSE_ENGINE_AVAILABLE:
                self.response_engine = EnhancedResponseEngine(
                    alert_webhook_url=self.ensemble_config.get('webhook_url', '')
                )
                logger.info("Response engine initialized")
            else:
                logger.warning("Response engine not available")

            logger.info("All models initialized successfully")
            return True

        except Exception as e:
            logger.error(f"Model initialization failed: {e}")
            return False

    def run_inference(self,
                     temporal_data,
                     network_data,
                     behavioral_features: Optional[Any] = None) -> Dict[str, Any]:
        """
        Run anomaly detection inference.

        Args:
            temporal_data: Temporal feature data
            network_data: Network flow data
            behavioral_features: Optional pre-extracted behavioral features

        Returns:
            Dictionary with detection results
        """
        if not self.detector:
            raise RuntimeError("Models not initialized. Call initialize_models() first.")

        logger.info("Running anomaly detection inference")

        try:
            # Run comprehensive detection
            detection_result = self.detector.detect_comprehensive(
                temporal_df=temporal_data,
                network_df=network_data,
                behavioral_features=behavioral_features,
                return_details=True
            )

            logger.info(f"Detection completed: Score={detection_result['final_threat_score']:.4f}, "
                       f"Severity={detection_result['severity']}")

            return detection_result

        except Exception as e:
            logger.error(f"Inference failed: {e}")
            raise

    def process_detection_result(self,
                               detection_result: Dict[str, Any],
                               entity_id: str = "unknown",
                               entity_type: str = "system") -> Dict[str, Any]:
        """
        Process detection results through response engine.

        Args:
            detection_result: Results from run_inference
            entity_id: Identifier for the entity being monitored
            entity_type: Type of entity (system, user, etc.)

        Returns:
            Response engine results
        """
        if not self.response_engine:
            logger.warning("Response engine not available, skipping response processing")
            return {'actions_taken': [], 'alerts_sent': []}

        try:
            # Process through response engine
            response_result = self.response_engine.process_detection(
                detection_result=detection_result,
                entity_id=entity_id,
                entity_type=entity_type,
                source_data={
                    'model_version': '1.0',
                    'inference_timestamp': detection_result.get('timestamp')
                }
            )

            logger.info(f"Response processing completed: {len(response_result.get('actions_taken', []))} actions taken")

            return response_result

        except Exception as e:
            logger.error(f"Response processing failed: {e}")
            return {'actions_taken': [], 'alerts_sent': [], 'error': str(e)}

    def run_detection_pipeline(self,
                             temporal_data,
                             network_data,
                             entity_id: str = "system",
                             entity_type: str = "system") -> Dict[str, Any]:
        """
        Run complete detection pipeline: inference + response.

        Args:
            temporal_data: Temporal feature data
            network_data: Network flow data
            entity_id: Entity identifier
            entity_type: Entity type

        Returns:
            Complete pipeline results
        """
        logger.info(f"Running complete detection pipeline for {entity_type}:{entity_id}")

        results = {
            'success': False,
            'detection_result': None,
            'response_result': None,
            'entity_id': entity_id,
            'entity_type': entity_type,
            'timestamp': None
        }

        try:
            # Step 1: Run inference
            detection_result = self.run_inference(temporal_data, network_data)
            results['detection_result'] = detection_result

            # Step 2: Process response
            response_result = self.process_detection_result(
                detection_result,
                entity_id,
                entity_type
            )
            results['response_result'] = response_result

            # Step 3: Finalize results
            results['success'] = True
            results['timestamp'] = detection_result.get('timestamp')

            logger.info("Detection pipeline completed successfully")

        except Exception as e:
            logger.error(f"Detection pipeline failed: {e}")
            results['error'] = str(e)

        return results

    def get_model_status(self) -> Dict[str, Any]:
        """
        Get status of all managed models.

        Returns:
            Dictionary with model status information
        """
        status = {
            'device': str(self.device),
            'models_loaded': False,
            'model_paths': {
                'lstm': self.lstm_model_path,
                'gnn': self.gnn_model_path
            },
            'response_engine_available': RESPONSE_ENGINE_AVAILABLE,
            'anomaly_detector_available': ANOMALY_DETECTOR_AVAILABLE
        }

        if self.detector:
            status['models_loaded'] = True
            status['detector_status'] = 'initialized'
        else:
            status['detector_status'] = 'not_initialized'

        if self.response_engine:
            status['response_engine_status'] = 'initialized'
        else:
            status['response_engine_status'] = 'not_available'

        return status

    def reload_models(self) -> bool:
        """
        Reload all models (useful for model updates).

        Returns:
            True if reload successful, False otherwise
        """
        logger.info("Reloading ML models...")

        try:
            # Reset models
            self.detector = None
            self.response_engine = None

            # Reinitialize
            success = self.initialize_models()

            if success:
                logger.info("Models reloaded successfully")
            else:
                logger.error("Model reload failed")

            return success

        except Exception as e:
            logger.error(f"Model reload error: {e}")
            return False

    async def run_inference_async(self,
                                 temporal_data,
                                 network_data,
                                 behavioral_features: Optional[Any] = None) -> Dict[str, Any]:
        """
        Run anomaly detection inference asynchronously.

        Args:
            temporal_data: Temporal feature data
            network_data: Network flow data
            behavioral_features: Optional pre-extracted behavioral features

        Returns:
            Dictionary with detection results
        """
        if not self.detector:
            raise RuntimeError("Models not initialized. Call initialize_models() first.")

        # Run inference in thread pool to avoid blocking event loop
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            self.run_inference,
            temporal_data,
            network_data,
            behavioral_features
        )

    async def run_detection_pipeline_async(self,
                                         temporal_data,
                                         network_data,
                                         entity_id: str = "system",
                                         entity_type: str = "system") -> Dict[str, Any]:
        """
        Run complete detection pipeline asynchronously: inference + response.

        Args:
            temporal_data: Temporal feature data
            network_data: Network flow data
            entity_id: Entity identifier
            entity_type: Entity type

        Returns:
            Complete pipeline results
        """
        logger.info(f"Running async detection pipeline for {entity_type}:{entity_id}")

        results = {
            'success': False,
            'detection_result': None,
            'response_result': None,
            'entity_id': entity_id,
            'entity_type': entity_type,
            'timestamp': None
        }

        try:
            # Step 1: Run inference asynchronously
            detection_result = await self.run_inference_async(temporal_data, network_data)
            results['detection_result'] = detection_result

            # Step 2: Process response (can be async if needed)
            response_result = self.process_detection_result(
                detection_result,
                entity_id,
                entity_type
            )
            results['response_result'] = response_result

            # Step 3: Finalize results
            results['success'] = True
            results['timestamp'] = detection_result.get('timestamp')

            logger.info("Async detection pipeline completed successfully")

        except Exception as e:
            logger.error(f"Async detection pipeline failed: {e}")
            results['error'] = str(e)

        return results

    async def batch_inference_async(self,
                                   inference_tasks: list) -> list:
        """
        Run multiple inference tasks concurrently.

        Args:
            inference_tasks: List of (temporal_data, network_data, entity_id, entity_type) tuples

        Returns:
            List of inference results
        """
        logger.info(f"Running batch inference for {len(inference_tasks)} tasks")

        # Create async tasks
        async def process_task(task):
            temporal_data, network_data, entity_id, entity_type = task
            return await self.run_detection_pipeline_async(
                temporal_data, network_data, entity_id, entity_type
            )

        # Run all tasks concurrently
        results = await asyncio.gather(*[
            process_task(task) for task in inference_tasks
        ], return_exceptions=True)

        # Handle any exceptions
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Task {i} failed: {result}")
                processed_results.append({
                    'success': False,
                    'error': str(result),
                    'task_index': i
                })
            else:
                processed_results.append(result)

        logger.info(f"Batch inference completed: {len(processed_results)} results")
        return processed_results

    def cleanup(self):
        """
        Cleanup resources and memory.
        """
        logger.info("Cleaning up model resources...")

        try:
            # Clear GPU memory if available
            if torch.cuda.is_available():
                torch.cuda.empty_cache()

            # Reset models
            self.detector = None
            self.response_engine = None

            logger.info("Model cleanup completed")

        except Exception as e:
            logger.error(f"Model cleanup error: {e}")
