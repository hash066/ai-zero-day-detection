"""
Streaming engine module for AI Zero-Day Detection System.

Handles real-time data streaming from Kafka and live inference.
"""

import logging
import signal
import time
from typing import Dict, Any, Optional, Callable
from queue import Queue
import threading

try:
    from kafka import KafkaConsumer
    from online_files.Feature_extraction import extract_features
    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False

logger = logging.getLogger(__name__)


class StreamingEngine:
    """
    Handles real-time streaming data processing.

    Features:
    - Kafka consumer integration
    - Real-time feature extraction
    - Buffered inference processing
    - Graceful shutdown handling
    - Configurable processing parameters
    """

    def __init__(self,
                 kafka_topic: str = 'sysmon-topic',
                 kafka_servers: str = 'localhost:9092',
                 buffer_size: int = 50,
                 processing_interval: float = 5.0):
        """
        Initialize streaming engine.

        Args:
            kafka_topic: Kafka topic to consume from
            kafka_servers: Kafka bootstrap servers
            buffer_size: Number of messages to buffer before processing
            processing_interval: Seconds between buffer processing
        """
        self.kafka_topic = kafka_topic
        self.kafka_servers = kafka_servers
        self.buffer_size = buffer_size
        self.processing_interval = processing_interval

        # Streaming state
        self.consumer = None
        self.streaming_active = False
        self.feature_buffer = []
        self.processed_count = 0
        self.anomaly_count = 0

        # Callbacks
        self.on_message_processed: Optional[Callable] = None
        self.on_batch_processed: Optional[Callable] = None
        self.on_anomaly_detected: Optional[Callable] = None

        logger.info("Streaming engine initialized")

    def set_callbacks(self,
                     on_message_processed: Optional[Callable] = None,
                     on_batch_processed: Optional[Callable] = None,
                     on_anomaly_detected: Optional[Callable] = None):
        """
        Set callback functions for streaming events.

        Args:
            on_message_processed: Called when individual message processed
            on_batch_processed: Called when batch processing completes
            on_anomaly_detected: Called when anomaly detected
        """
        self.on_message_processed = on_message_processed
        self.on_batch_processed = on_batch_processed
        self.on_anomaly_detected = on_anomaly_detected

    def start_streaming(self) -> bool:
        """
        Start the streaming pipeline.

        Returns:
            True if streaming started successfully, False otherwise
        """
        if not KAFKA_AVAILABLE:
            logger.error("Kafka not available. Install kafka-python package.")
            return False

        if self.streaming_active:
            logger.warning("Streaming already active")
            return True

        logger.info(f"Starting streaming from topic: {self.kafka_topic}")

        try:
            # Initialize Kafka consumer
            self.consumer = KafkaConsumer(
                self.kafka_topic,
                bootstrap_servers=[self.kafka_servers],
                auto_offset_reset='latest',
                value_deserializer=lambda x: self._deserialize_message(x),
                consumer_timeout_ms=1000,
                enable_auto_commit=True
            )

            # Set up signal handlers for graceful shutdown
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)

            self.streaming_active = True

            # Start processing thread
            processing_thread = threading.Thread(target=self._processing_loop, daemon=True)
            processing_thread.start()

            logger.info("Streaming pipeline started successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to start streaming: {e}")
            return False

    def stop_streaming(self):
        """
        Stop the streaming pipeline gracefully.
        """
        logger.info("Stopping streaming pipeline...")

        self.streaming_active = False

        if self.consumer:
            self.consumer.close()
            self.consumer = None

        # Process remaining buffer
        if self.feature_buffer:
            logger.info(f"Processing remaining {len(self.feature_buffer)} messages in buffer")
            self._process_feature_buffer()

        logger.info(f"Streaming stopped. Total processed: {self.processed_count}, Anomalies: {self.anomaly_count}")

    def _processing_loop(self):
        """
        Main processing loop for streaming data.
        """
        logger.info("Processing loop started")

        last_batch_time = time.time()

        while self.streaming_active:
            try:
                # Poll for messages
                message_batch = self.consumer.poll(timeout_ms=100)

                # Process messages
                for topic_partition, messages in message_batch.items():
                    for message in messages:
                        self._process_message(message.value)

                # Periodic batch processing
                current_time = time.time()
                if (current_time - last_batch_time >= self.processing_interval or
                    len(self.feature_buffer) >= self.buffer_size):
                    self._process_feature_buffer()
                    last_batch_time = current_time

                # Small sleep to prevent busy waiting
                time.sleep(0.1)

            except Exception as e:
                logger.error(f"Error in processing loop: {e}")
                time.sleep(1)  # Back off on errors

        logger.info("Processing loop ended")

    def _process_message(self, message: Dict[str, Any]):
        """
        Process individual Kafka message.

        Args:
            message: Deserialized message from Kafka
        """
        try:
            self.processed_count += 1

            # Extract features
            features = extract_features(message)
            features['timestamp'] = time.time()
            features['kafka_offset'] = getattr(message, 'offset', None)
            features['kafka_partition'] = getattr(message, 'partition', None)

            # Add to buffer
            self.feature_buffer.append(features)

            # Callback
            if self.on_message_processed:
                self.on_message_processed(features)

            # Log progress
            if self.processed_count % 100 == 0:
                logger.info(f"Processed {self.processed_count} messages, buffered: {len(self.feature_buffer)}")

        except Exception as e:
            logger.error(f"Error processing message: {e}")

    def _process_feature_buffer(self):
        """
        Process accumulated features through ML pipeline.
        """
        if not self.feature_buffer:
            return

        try:
            logger.info(f"Processing batch of {len(self.feature_buffer)} messages")

            # Here we would integrate with ModelManager for inference
            # For now, just simulate processing
            batch_results = self._simulate_batch_processing(self.feature_buffer)

            # Count anomalies
            anomalies = [r for r in batch_results if r.get('is_anomaly', False)]
            self.anomaly_count += len(anomalies)

            # Callbacks
            if self.on_batch_processed:
                self.on_batch_processed(batch_results)

            if self.on_anomaly_detected and anomalies:
                for anomaly in anomalies:
                    self.on_anomaly_detected(anomaly)

            # Clear buffer
            self.feature_buffer.clear()

            logger.info(f"Batch processing completed. Anomalies detected: {len(anomalies)}")

        except Exception as e:
            logger.error(f"Error processing feature buffer: {e}")

    def _simulate_batch_processing(self, features_batch: list) -> list:
        """
        Simulate batch processing (replace with actual ML inference).

        Args:
            features_batch: List of feature dictionaries

        Returns:
            List of processing results
        """
        results = []

        for features in features_batch:
            # Simulate anomaly detection (random for demo)
            import random
            is_anomaly = random.random() < 0.05  # 5% anomaly rate

            result = {
                'entity_id': f"stream_{features.get('timestamp', 'unknown')}",
                'threat_score': random.uniform(0, 1) if is_anomaly else random.uniform(0, 0.3),
                'is_anomaly': is_anomaly,
                'severity': 'HIGH' if is_anomaly else 'LOW',
                'features': features,
                'timestamp': time.time()
            }

            results.append(result)

        return results

    def _deserialize_message(self, message_bytes):
        """
        Deserialize Kafka message.

        Args:
            message_bytes: Raw message bytes

        Returns:
            Deserialized message dictionary
        """
        try:
            import json
            message_str = message_bytes.decode('utf-8')
            return json.loads(message_str)
        except Exception as e:
            logger.error(f"Failed to deserialize message: {e}")
            return {}

    def _signal_handler(self, signum, frame):
        """
        Handle shutdown signals gracefully.
        """
        logger.info(f"Received signal {signum}, initiating shutdown...")
        self.stop_streaming()

    def get_status(self) -> Dict[str, Any]:
        """
        Get streaming engine status.

        Returns:
            Dictionary with status information
        """
        return {
            'streaming_active': self.streaming_active,
            'kafka_topic': self.kafka_topic,
            'kafka_servers': self.kafka_servers,
            'buffer_size': len(self.feature_buffer),
            'buffer_limit': self.buffer_size,
            'processed_count': self.processed_count,
            'anomaly_count': self.anomaly_count,
            'kafka_available': KAFKA_AVAILABLE,
            'consumer_connected': self.consumer is not None,
            'timestamp': time.time()
        }

    def reset_counters(self):
        """
        Reset processing counters.
        """
        self.processed_count = 0
        self.anomaly_count = 0
        logger.info("Counters reset")
