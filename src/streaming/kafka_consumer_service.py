#!/usr/bin/env python3
"""
Kafka Consumer Service for AI Zero-Day Detection.

Consumes streaming data from Kafka topics, processes events in real-time,
and integrates with anomaly detection and alerting systems.
"""

import asyncio
import json
import logging
import os
import signal
import sys
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional, Any, Callable
from concurrent.futures import ThreadPoolExecutor

# Optional Kafka import
try:
    from kafka import KafkaConsumer
    from kafka.errors import KafkaError
    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False

from ..inference.anomaly_detector import EnhancedAnomalyDetector
from ..preprocessing.feature_engineering import extract_all_features
from ..inference.response_engine import EnhancedResponseEngine

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class StreamingEventProcessor:
    """
    Processes streaming events from Kafka topics.

    Handles batching, feature extraction, and anomaly detection
    for real-time security monitoring.
    """

    def __init__(
        self,
        anomaly_detector: Optional[EnhancedAnomalyDetector] = None,
        response_engine: Optional[EnhancedResponseEngine] = None,
        alert_callback: Optional[Callable] = None,
        batch_size: int = 10,
        batch_timeout: float = 5.0
    ):
        """
        Initialize streaming event processor.

        Args:
            anomaly_detector: Anomaly detection model
            response_engine: Automated response engine
            alert_callback: Callback for alert notifications
            batch_size: Number of events to batch before processing
            batch_timeout: Maximum time to wait before processing batch
        """
        self.anomaly_detector = anomaly_detector
        self.response_engine = response_engine
        self.alert_callback = alert_callback

        self.batch_size = batch_size
        self.batch_timeout = batch_timeout

        # Event buffers for different data types
        self.sysmon_buffer = []
        self.network_buffer = []
        self.last_process_time = time.time()

        # Statistics
        self.stats = {
            'events_processed': 0,
            'anomalies_detected': 0,
            'alerts_generated': 0,
            'processing_errors': 0
        }

        logger.info(f"✓ Streaming Event Processor initialized (batch_size={batch_size}, timeout={batch_timeout}s)")

    def process_sysmon_event(self, event: Dict[str, Any]):
        """Process incoming Sysmon event."""
        try:
            self.sysmon_buffer.append(event)
            self.stats['events_processed'] += 1

            # Process if batch is ready
            if self._should_process_batch(self.sysmon_buffer):
                self._process_sysmon_batch()

        except Exception as e:
            logger.error(f"Error processing Sysmon event: {e}")
            self.stats['processing_errors'] += 1

    def process_network_event(self, event: Dict[str, Any]):
        """Process incoming network event."""
        try:
            self.network_buffer.append(event)
            self.stats['events_processed'] += 1

            # Process if batch is ready
            if self._should_process_batch(self.network_buffer):
                self._process_network_batch()

        except Exception as e:
            logger.error(f"Error processing network event: {e}")
            self.stats['processing_errors'] += 1

    def _should_process_batch(self, buffer: List) -> bool:
        """Check if batch should be processed."""
        current_time = time.time()
        return (len(buffer) >= self.batch_size or
                current_time - self.last_process_time >= self.batch_timeout)

    def _process_sysmon_batch(self):
        """Process batch of Sysmon events."""
        if not self.sysmon_buffer:
            return

        try:
            # Convert to DataFrame
            events_df = pd.DataFrame(self.sysmon_buffer)

            # Run anomaly detection
            if self.anomaly_detector and len(events_df) > 2:
                try:
                    result = self.anomaly_detector.detect_temporal_anomaly(events_df)

                    if result['is_anomaly']:
                        self.stats['anomalies_detected'] += 1
                        self._handle_anomaly('sysmon', result, events_df)

                except Exception as e:
                    logger.warning(f"Failed to run anomaly detection on Sysmon batch: {e}")

            # Clear buffer
            self.sysmon_buffer.clear()
            self.last_process_time = time.time()

        except Exception as e:
            logger.error(f"Error processing Sysmon batch: {e}")
            self.stats['processing_errors'] += 1

    def _process_network_batch(self):
        """Process batch of network events."""
        if not self.network_buffer:
            return

        try:
            # Convert to DataFrame
            events_df = pd.DataFrame(self.network_buffer)

            # Run anomaly detection
            if self.anomaly_detector and len(events_df) > 5:
                try:
                    result = self.anomaly_detector.detect_network_anomaly(events_df)

                    if result['is_anomaly']:
                        self.stats['anomalies_detected'] += 1
                        self._handle_anomaly('network', result, events_df)

                except Exception as e:
                    logger.warning(f"Failed to run anomaly detection on network batch: {e}")

            # Clear buffer
            self.network_buffer.clear()
            self.last_process_time = time.time()

        except Exception as e:
            logger.error(f"Error processing network batch: {e}")
            self.stats['processing_errors'] += 1

    def _handle_anomaly(self, event_type: str, result: Dict[str, Any], events_df):
        """Handle detected anomaly."""
        try:
            # Create alert data
            alert_data = {
                'type': f'{event_type}_anomaly',
                'threat_score': result.get('anomaly_score', result.get('graph_anomaly_score', 0.0)),
                'severity': self._calculate_severity(result.get('anomaly_score', result.get('graph_anomaly_score', 0.0))),
                'description': f"{event_type.upper()} anomaly detected",
                'timestamp': datetime.now().isoformat(),
                'source': f'streaming_{event_type}_processor',
                'event_count': len(events_df),
                'details': result
            }

            # Trigger automated response
            if self.response_engine:
                try:
                    response_actions = self.response_engine.generate_response(alert_data)
                    alert_data['response_actions'] = response_actions
                except Exception as e:
                    logger.warning(f"Failed to generate automated response: {e}")

            # Send alert
            if self.alert_callback:
                self.alert_callback(alert_data)
                self.stats['alerts_generated'] += 1

            logger.info(f"🚨 {event_type.upper()} ANOMALY DETECTED: Score={alert_data['threat_score']:.4f}, Severity={alert_data['severity']}")

        except Exception as e:
            logger.error(f"Error handling anomaly: {e}")

    def _calculate_severity(self, score: float) -> str:
        """Calculate severity level from threat score."""
        if score > 0.8:
            return "CRITICAL"
        elif score > 0.6:
            return "HIGH"
        elif score > 0.4:
            return "MEDIUM"
        else:
            return "LOW"

    def get_stats(self) -> Dict[str, Any]:
        """Get processing statistics."""
        return self.stats.copy()


class KafkaStreamingConsumer:
    """
    Kafka consumer for streaming security events.

    Consumes events from Kafka topics and processes them in real-time
    using the streaming event processor.
    """

    def __init__(
        self,
        bootstrap_servers: str = "localhost:9092",
        sysmon_topic: str = "sysmon_events",
        network_topic: str = "network_flows",
        alert_topic: str = "security_alerts",
        group_id: str = "ai_zero_day_detector",
        event_processor: Optional[StreamingEventProcessor] = None
    ):
        """
        Initialize Kafka streaming consumer.

        Args:
            bootstrap_servers: Kafka bootstrap servers
            sysmon_topic: Topic for Sysmon events
            network_topic: Topic for network events
            alert_topic: Topic for security alerts
            group_id: Consumer group ID
            event_processor: Event processor instance
        """
        self.bootstrap_servers = bootstrap_servers
        self.sysmon_topic = sysmon_topic
        self.network_topic = network_topic
        self.alert_topic = alert_topic
        self.group_id = group_id

        self.event_processor = event_processor or StreamingEventProcessor()

        self.consumer = None
        self.running = False
        self.consumer_thread = None

        # Initialize consumer if Kafka available
        if KAFKA_AVAILABLE:
            try:
                self.consumer = KafkaConsumer(
                    self.sysmon_topic,
                    self.network_topic,
                    bootstrap_servers=bootstrap_servers.split(','),
                    group_id=group_id,
                    value_deserializer=lambda v: json.loads(v.decode('utf-8')),
                    key_deserializer=lambda k: k.decode('utf-8') if k else None,
                    auto_offset_reset='latest',
                    enable_auto_commit=True,
                    consumer_timeout_ms=1000
                )
                logger.info("✓ Kafka consumer initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize Kafka consumer: {e}")
        else:
            logger.warning("Kafka not available. Install kafka-python for streaming.")

    def set_event_processor(self, processor: StreamingEventProcessor):
        """Set the event processor."""
        self.event_processor = processor

    def start_consuming(self):
        """Start consuming Kafka messages."""
        if not self.consumer:
            logger.error("Kafka consumer not available")
            return False

        if self.running:
            logger.warning("Consumer already running")
            return True

        self.running = True
        self.consumer_thread = threading.Thread(target=self._consume_loop, daemon=True)
        self.consumer_thread.start()

        logger.info("✓ Started Kafka streaming consumer")
        return True

    def stop_consuming(self):
        """Stop consuming Kafka messages."""
        if not self.running:
            return

        self.running = False
        if self.consumer_thread:
            self.consumer_thread.join(timeout=5.0)

        logger.info("✓ Stopped Kafka streaming consumer")

    def _consume_loop(self):
        """Main consumption loop."""
        logger.info("Starting Kafka message consumption...")

        try:
            while self.running:
                try:
                    # Poll for messages
                    message_batch = self.consumer.poll(timeout_ms=1000)

                    for topic_partition, messages in message_batch.items():
                        for message in messages:
                            if not self.running:
                                break

                            try:
                                self._process_message(message)
                            except Exception as e:
                                logger.error(f"Error processing message: {e}")

                except Exception as e:
                    logger.warning(f"Error in consume loop: {e}")
                    time.sleep(1.0)

        except Exception as e:
            logger.error(f"Fatal error in consumption loop: {e}")
        finally:
            if self.consumer:
                self.consumer.close()

    def _process_message(self, message):
        """Process individual Kafka message."""
        try:
            topic = message.topic
            value = message.value

            if not value:
                return

            # Route message based on topic
            if topic == self.sysmon_topic:
                self.event_processor.process_sysmon_event(value)
            elif topic == self.network_topic:
                self.event_processor.process_network_event(value)
            else:
                logger.warning(f"Unknown topic: {topic}")

        except Exception as e:
            logger.error(f"Error processing Kafka message: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """Get consumer statistics."""
        stats = {
            'consumer_active': self.running,
            'kafka_available': self.consumer is not None
        }

        if self.event_processor:
            stats.update(self.event_processor.get_stats())

        return stats


class StreamingAnalyticsService:
    """
    Complete streaming analytics service for AI Zero-Day Detection.

    Integrates Kafka consumers, event processing, anomaly detection,
    and automated response systems for real-time security monitoring.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize streaming analytics service.

        Args:
            config: Configuration dictionary
        """
        self.config = config or self._load_config()

        # Initialize components
        self.anomaly_detector = None
        self.response_engine = None
        self.alert_callback = None

        # Initialize event processor
        self.event_processor = StreamingEventProcessor(
            batch_size=self.config.get('batch_size', 10),
            batch_timeout=self.config.get('batch_timeout', 5.0)
        )

        # Initialize Kafka consumer
        self.kafka_consumer = KafkaStreamingConsumer(
            bootstrap_servers=self.config.get('kafka_servers', 'localhost:9092'),
            sysmon_topic=self.config.get('sysmon_topic', 'sysmon_events'),
            network_topic=self.config.get('network_topic', 'network_flows'),
            alert_topic=self.config.get('alert_topic', 'security_alerts'),
            event_processor=self.event_processor
        )

        self.running = False
        logger.info("✓ Streaming Analytics Service initialized")

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from environment variables."""
        return {
            'kafka_servers': os.getenv('KAFKA_BOOTSTRAP_SERVERS', 'localhost:9092'),
            'sysmon_topic': os.getenv('KAFKA_TOPIC_SYSMON', 'sysmon_events'),
            'network_topic': os.getenv('KAFKA_TOPIC_NETWORK', 'network_flows'),
            'alert_topic': os.getenv('KAFKA_TOPIC_ALERTS', 'security_alerts'),
            'batch_size': int(os.getenv('STREAMING_BATCH_SIZE', '10')),
            'batch_timeout': float(os.getenv('STREAMING_BATCH_TIMEOUT', '5.0'))
        }

    def set_anomaly_detector(self, detector: EnhancedAnomalyDetector):
        """Set anomaly detector for real-time analysis."""
        self.anomaly_detector = detector
        self.event_processor.anomaly_detector = detector
        logger.info("✓ Anomaly detector configured for streaming analytics")

    def set_response_engine(self, engine: EnhancedResponseEngine):
        """Set automated response engine."""
        self.response_engine = engine
        self.event_processor.response_engine = engine
        logger.info("✓ Response engine configured for streaming analytics")

    def set_alert_callback(self, callback: Callable):
        """Set callback for alert notifications."""
        self.alert_callback = callback
        self.event_processor.alert_callback = callback
        logger.info("✓ Alert callback configured for streaming analytics")

    def start_service(self):
        """Start the streaming analytics service."""
        if self.running:
            logger.warning("Streaming analytics service already running")
            return

        self.running = True

        # Start Kafka consumer
        consumer_started = self.kafka_consumer.start_consuming()

        if consumer_started:
            logger.info("✓ Streaming Analytics Service started")
            logger.info("  - Real-time Sysmon event processing: ACTIVE")
            logger.info("  - Real-time network flow analysis: ACTIVE")
            logger.info("  - Automated anomaly detection: ACTIVE")
        else:
            logger.error("Failed to start streaming analytics service")
            self.running = False

    def stop_service(self):
        """Stop the streaming analytics service."""
        if not self.running:
            return

        self.running = False

        # Stop Kafka consumer
        self.kafka_consumer.stop_consuming()

        logger.info("✓ Streaming Analytics Service stopped")

    def get_status(self) -> Dict[str, Any]:
        """Get service status and statistics."""
        return {
            'service_active': self.running,
            'anomaly_detector': self.anomaly_detector is not None,
            'response_engine': self.response_engine is not None,
            'alert_callback': self.alert_callback is not None,
            'kafka_consumer': self.kafka_consumer.get_stats(),
            'event_processor': self.event_processor.get_stats()
        }

    def get_health_check(self) -> Dict[str, Any]:
        """Comprehensive health check."""
        status = self.get_status()

        # Determine overall health
        critical_components = [
            status.get('anomaly_detector', False),
            status.get('kafka_consumer', {}).get('kafka_available', False)
        ]

        all_healthy = all(critical_components)
        status['health_status'] = 'healthy' if all_healthy else 'degraded'

        # Add recommendations
        if not status.get('anomaly_detector'):
            status['recommendations'] = status.get('recommendations', [])
            status['recommendations'].append("Configure anomaly detector for real-time analysis")

        if not status.get('kafka_consumer', {}).get('kafka_available'):
            status['recommendations'] = status.get('recommendations', [])
            status['recommendations'].append("Ensure Kafka is running and accessible")

        return status


# Import here to avoid circular imports
import pandas as pd
