"""
Pipeline orchestrator for AI Zero-Day Detection System.

Coordinates all pipeline components for end-to-end processing.
"""

import logging
import gc
from typing import Dict, Any, Optional
from pathlib import Path
import pandas as pd
import time
import psutil
import torch

from .data_collector import DataCollector
from .preprocessor import DataPreprocessor
from .model_manager import ModelManager
from .streaming_engine import StreamingEngine

logger = logging.getLogger(__name__)


class PipelineOrchestrator:
    """
    Orchestrates the complete AI Zero-Day Detection pipeline.

    Coordinates:
    - Data collection
    - Preprocessing
    - ML inference
    - Response generation
    - Streaming processing
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize pipeline orchestrator.

        Args:
            config: Pipeline configuration dictionary
        """
        self.config = config or self._get_default_config()

        # Initialize components
        self.data_collector = DataCollector(
            batch_size=self.config.get('collection', {}).get('batch_size', 1000)
        )

        self.preprocessor = DataPreprocessor(
            raw_dir=self.config.get('data', {}).get('raw_dir', 'data/raw'),
            processed_dir=self.config.get('data', {}).get('processed_dir', 'data/processed'),
            features_dir=self.config.get('data', {}).get('features_dir', 'data/features'),
            graphs_dir=self.config.get('data', {}).get('graphs_dir', 'data/graphs')
        )

        self.model_manager = ModelManager(
            lstm_model_path=self.config.get('models', {}).get('lstm_path', 'trained_models/lstm'),
            gnn_model_path=self.config.get('models', {}).get('gnn_path', 'trained_models/gnn'),
            ensemble_config=self.config.get('models', {}).get('ensemble', {})
        )

        self.streaming_engine = StreamingEngine(
            kafka_topic=self.config.get('streaming', {}).get('kafka_topic', 'sysmon-topic'),
            kafka_servers=self.config.get('streaming', {}).get('kafka_servers', 'localhost:9092'),
            buffer_size=self.config.get('streaming', {}).get('buffer_size', 50)
        )

        # Pipeline state
        self.models_initialized = False

        logger.info("Pipeline orchestrator initialized")

    def _get_default_config(self) -> Dict[str, Any]:
        """
        Get default pipeline configuration.

        Returns:
            Default configuration dictionary
        """
        return {
            'data': {
                'raw_dir': 'data/raw',
                'processed_dir': 'data/processed',
                'features_dir': 'data/features',
                'graphs_dir': 'data/graphs'
            },
            'collection': {
                'batch_size': 1000
            },
            'models': {
                'lstm_path': 'trained_models/lstm',
                'gnn_path': 'trained_models/gnn',
                'ensemble': {
                    'lstm_weight': 0.6,
                    'gnn_weight': 0.4,
                    'temporal_window': 10,
                    'confidence_threshold': 0.7
                }
            },
            'streaming': {
                'kafka_topic': 'sysmon-topic',
                'kafka_servers': 'localhost:9092',
                'buffer_size': 50
            },
            'inference': {
                'alert_threshold': 0.75,
                'webhook_url': ''
            }
        }

    def initialize_pipeline(self) -> bool:
        """
        Initialize all pipeline components.

        Returns:
            True if initialization successful, False otherwise
        """
        logger.info("Initializing complete pipeline...")

        try:
            # Initialize ML models
            self.models_initialized = self.model_manager.initialize_models()

            if not self.models_initialized:
                logger.warning("ML models not available - pipeline will run in basic mode")

            # Set up streaming callbacks
            self._setup_streaming_callbacks()

            logger.info("Pipeline initialization completed")
            return True

        except Exception as e:
            logger.error(f"Pipeline initialization failed: {e}")
            return False

    def _setup_streaming_callbacks(self):
        """
        Set up callbacks for streaming engine integration.
        """
        def on_batch_processed(batch_results):
            """Process streaming batch results through ML pipeline."""
            if not self.models_initialized:
                logger.warning("Models not initialized, skipping batch processing")
                return

            try:
                # Convert batch results to DataFrames for processing
                features_list = [r['features'] for r in batch_results]
                features_df = pd.DataFrame(features_list)

                # Create mock network data (would come from separate stream)
                network_df = pd.DataFrame({
                    'src_ip': ['192.168.1.1'] * len(features_df),
                    'dst_ip': ['10.0.0.1'] * len(features_df),
                    'src_port': [443] * len(features_df),
                    'dst_port': [80] * len(features_df),
                    'protocol': ['TCP'] * len(features_df),
                    'bytes_sent': [1024] * len(features_df),
                    'bytes_received': [512] * len(features_df),
                    'packets_sent': [10] * len(features_df),
                    'packets_received': [5] * len(features_df),
                    'timestamp': pd.date_range('now', periods=len(features_df), freq='1S')
                })

                # Run detection pipeline
                for i, result in enumerate(batch_results):
                    if result.get('is_anomaly', False):
                        detection_result = self.model_manager.run_detection_pipeline(
                            temporal_data=features_df.iloc[[i]],  # Single row as DataFrame
                            network_data=network_df.iloc[[i]],
                            entity_id=result['entity_id'],
                            entity_type='streaming'
                        )

                        logger.info(f"Streaming anomaly processed: {detection_result}")

            except Exception as e:
                logger.error(f"Error processing streaming batch: {e}")

        def on_anomaly_detected(anomaly):
            """Handle anomaly detection in streaming."""
            logger.warning(f"🚨 STREAMING ANOMALY: {anomaly}")

        self.streaming_engine.set_callbacks(
            on_batch_processed=on_batch_processed,
            on_anomaly_detected=on_anomaly_detected
        )

    def run_batch_pipeline(self,
                          source: str = 'sysmon',
                          entity_id: str = 'batch_system',
                          entity_type: str = 'system') -> Dict[str, Any]:
        """
        Run complete batch processing pipeline.

        Args:
            source: Data source ('sysmon', 'file', etc.)
            entity_id: Identifier for the entity being analyzed
            entity_type: Type of entity

        Returns:
            Complete pipeline results
        """
        logger.info(f"Running batch pipeline for {entity_type}:{entity_id}")

        results = {
            'success': False,
            'collection': None,
            'preprocessing': None,
            'detection': None,
            'entity_id': entity_id,
            'entity_type': entity_type,
            'timestamp': time.time()
        }

        try:
            # Step 1: Collect data
            collected_data = self.data_collector.collect_batch(source=source)
            results['collection'] = {
                'events_collected': len(collected_data.get('sysmon_events', [])),
                'source': source
            }

            if not collected_data.get('sysmon_events'):
                logger.warning("No data collected, skipping pipeline")
                return results

            # Step 2: Preprocess data
            preprocessing_results = self.preprocessor.run_full_preprocessing(collected_data)
            results['preprocessing'] = preprocessing_results

            if not preprocessing_results.get('success', False):
                logger.error("Preprocessing failed")
                return results

            # Step 3: Run detection (if models available)
            if self.models_initialized and preprocessing_results.get('feature_files'):
                # Load processed data for inference
                try:
                    # Load temporal features
                    temporal_csv = preprocessing_results['feature_files'].get('temporal_features')
                    if temporal_csv and Path(temporal_csv).exists():
                        temporal_df = pd.read_csv(temporal_csv)

                        # Create mock network data (would be from preprocessing)
                        network_df = pd.DataFrame({
                            'src_ip': ['192.168.1.1'] * len(temporal_df),
                            'dst_ip': ['10.0.0.1'] * len(temporal_df),
                            'src_port': [443] * len(temporal_df),
                            'dst_port': [80] * len(temporal_df),
                            'protocol': ['TCP'] * len(temporal_df),
                            'bytes_sent': [1024] * len(temporal_df),
                            'bytes_received': [512] * len(temporal_df),
                            'packets_sent': [10] * len(temporal_df),
                            'packets_received': [5] * len(temporal_df),
                            'timestamp': pd.date_range('now', periods=len(temporal_df), freq='1S')
                        })

                        # Run detection
                        detection_result = self.model_manager.run_detection_pipeline(
                            temporal_data=temporal_df,
                            network_data=network_df,
                            entity_id=entity_id,
                            entity_type=entity_type
                        )

                        results['detection'] = detection_result
                    else:
                        logger.warning("No temporal features available for detection")

                except Exception as e:
                    logger.error(f"Detection failed: {e}")
                    results['detection'] = {'error': str(e)}
            else:
                logger.info("Models not initialized or no features available")

            results['success'] = True
            logger.info("Batch pipeline completed successfully")

        except Exception as e:
            logger.error(f"Batch pipeline failed: {e}")
            results['error'] = str(e)

        return results

    def run_streaming_pipeline(self) -> bool:
        """
        Start the streaming pipeline.

        Returns:
            True if streaming started successfully, False otherwise
        """
        logger.info("Starting streaming pipeline")

        if not self.models_initialized:
            logger.warning("Models not initialized - streaming will use simulated processing")

        return self.streaming_engine.start_streaming()

    def stop_streaming_pipeline(self):
        """
        Stop the streaming pipeline.
        """
        logger.info("Stopping streaming pipeline")
        self.streaming_engine.stop_streaming()

    def run_file_pipeline(self,
                         file_path: str,
                         source_type: str = 'auto',
                         entity_id: str = 'file_system',
                         entity_type: str = 'system') -> Dict[str, Any]:
        """
        Run pipeline on data from file.

        Args:
            file_path: Path to data file
            source_type: Type of data in file
            entity_id: Entity identifier
            entity_type: Entity type

        Returns:
            Pipeline results
        """
        logger.info(f"Running file pipeline for {file_path}")

        try:
            # Load data from file
            collected_data = self.data_collector.load_from_file(file_path, source_type)

            if not collected_data.get('sysmon_events'):
                return {
                    'success': False,
                    'error': 'No data loaded from file',
                    'file_path': file_path
                }

            # Run batch pipeline on loaded data
            return self.run_batch_pipeline(
                entity_id=entity_id,
                entity_type=entity_type
            )

        except Exception as e:
            logger.error(f"File pipeline failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'file_path': file_path
            }

    def get_pipeline_status(self) -> Dict[str, Any]:
        """
        Get comprehensive pipeline status.

        Returns:
            Dictionary with status of all components
        """
        return {
            'timestamp': time.time(),
            'components': {
                'data_collector': self.data_collector.get_status(),
                'preprocessor': self.preprocessor.get_status(),
                'model_manager': self.model_manager.get_model_status(),
                'streaming_engine': self.streaming_engine.get_status()
            },
            'pipeline': {
                'models_initialized': self.models_initialized,
                'streaming_active': self.streaming_engine.streaming_active
            },
            'resources': self.get_resource_usage()
        }

    def get_resource_usage(self) -> Dict[str, Any]:
        """
        Get current resource usage statistics.

        Returns:
            Dictionary with memory, CPU, and GPU usage
        """
        try:
            # System memory
            memory = psutil.virtual_memory()
            memory_usage = {
                'total_gb': round(memory.total / (1024**3), 2),
                'available_gb': round(memory.available / (1024**3), 2),
                'used_gb': round(memory.used / (1024**3), 2),
                'percentage': memory.percent
            }

            # CPU usage
            cpu_usage = {
                'percentage': psutil.cpu_percent(interval=0.1),
                'cores': psutil.cpu_count(),
                'cores_logical': psutil.cpu_count(logical=True)
            }

            # GPU memory (if available)
            gpu_usage = {}
            if torch.cuda.is_available():
                gpu_memory = torch.cuda.get_device_properties(0)
                gpu_usage = {
                    'name': gpu_memory.name,
                    'total_memory_gb': round(gpu_memory.total_memory / (1024**3), 2),
                    'allocated_memory_gb': round(torch.cuda.memory_allocated(0) / (1024**3), 2),
                    'cached_memory_gb': round(torch.cuda.memory_reserved(0) / (1024**3), 2)
                }

            return {
                'memory': memory_usage,
                'cpu': cpu_usage,
                'gpu': gpu_usage if gpu_usage else None,
                'process_count': len(psutil.pids())
            }

        except Exception as e:
            logger.warning(f"Could not get resource usage: {e}")
            return {'error': str(e)}

    def optimize_memory(self) -> Dict[str, Any]:
        """
        Perform memory optimization and cleanup.

        Returns:
            Dictionary with optimization results
        """
        logger.info("Performing memory optimization...")

        results = {
            'before': self.get_resource_usage(),
            'actions_taken': [],
            'success': False
        }

        try:
            # Force garbage collection
            collected = gc.collect()
            results['actions_taken'].append(f"Garbage collected {collected} objects")

            # Clear GPU cache if available
            if torch.cuda.is_available():
                torch.cuda.empty_cache()
                results['actions_taken'].append("GPU cache cleared")

            # Clear any cached DataFrames
            if hasattr(pd, '_cache'):
                pd._cache.clear()
                results['actions_taken'].append("Pandas cache cleared")

            results['after'] = self.get_resource_usage()
            results['success'] = True

            logger.info("Memory optimization completed")

        except Exception as e:
            logger.error(f"Memory optimization failed: {e}")
            results['error'] = str(e)

        return results

    def monitor_performance(self, duration_seconds: int = 60) -> Dict[str, Any]:
        """
        Monitor pipeline performance over time.

        Args:
            duration_seconds: How long to monitor

        Returns:
            Performance statistics
        """
        logger.info(f"Monitoring performance for {duration_seconds} seconds")

        start_time = time.time()
        measurements = []

        try:
            while time.time() - start_time < duration_seconds:
                measurement = {
                    'timestamp': time.time(),
                    'resources': self.get_resource_usage(),
                    'pipeline_status': self.get_pipeline_status()
                }
                measurements.append(measurement)
                time.sleep(5)  # Sample every 5 seconds

            # Calculate statistics
            stats = self._calculate_performance_stats(measurements)

            logger.info("Performance monitoring completed")
            return stats

        except Exception as e:
            logger.error(f"Performance monitoring failed: {e}")
            return {'error': str(e)}

    def _calculate_performance_stats(self, measurements: list) -> Dict[str, Any]:
        """
        Calculate performance statistics from measurements.

        Args:
            measurements: List of performance measurements

        Returns:
            Statistics dictionary
        """
        if not measurements:
            return {}

        # Memory usage statistics
        memory_percentages = [m['resources']['memory']['percentage'] for m in measurements]
        cpu_percentages = [m['resources']['cpu']['percentage'] for m in measurements]

        stats = {
            'duration_seconds': len(measurements) * 5,
            'samples': len(measurements),
            'memory': {
                'avg_percentage': round(sum(memory_percentages) / len(memory_percentages), 2),
                'max_percentage': max(memory_percentages),
                'min_percentage': min(memory_percentages)
            },
            'cpu': {
                'avg_percentage': round(sum(cpu_percentages) / len(cpu_percentages), 2),
                'max_percentage': max(cpu_percentages),
                'min_percentage': min(cpu_percentages)
            },
            'streaming': {
                'active_samples': sum(1 for m in measurements
                                    if m['pipeline_status']['pipeline']['streaming_active']),
                'total_samples': len(measurements)
            }
        }

        return stats

    def cleanup(self):
        """
        Cleanup all pipeline resources.
        """
        logger.info("Cleaning up pipeline resources")

        try:
            # Stop streaming if active
            if self.streaming_engine.streaming_active:
                self.streaming_engine.stop_streaming()

            # Cleanup models
            self.model_manager.cleanup()

            logger.info("Pipeline cleanup completed")

        except Exception as e:
            logger.error(f"Pipeline cleanup error: {e}")

    def __enter__(self):
        """Context manager entry."""
        self.initialize_pipeline()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.cleanup()
