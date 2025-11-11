#!/usr/bin/env python3
"""
Live Data Collector Service for AI Zero-Day Detection.

This module provides real-time data collection capabilities for:
- Live Sysmon event streaming
- Live network packet capture
- Kafka integration for data streaming
- Automatic anomaly detection triggering
"""

import asyncio
import logging
import os
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from pathlib import Path
import threading
import queue

# Optional imports for live collection
try:
    import win32evtlog
    import win32evtlogutil
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False

try:
    from kafka import KafkaProducer
    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False

try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from ..preprocessing.log_parser import SysmonLogParser
from ..inference.anomaly_detector import EnhancedAnomalyDetector

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class LiveSysmonCollector:
    """
    Live Sysmon event collector for Windows Event Logs.

    Continuously monitors Sysmon event logs and streams events
    for real-time anomaly detection.
    """

    def __init__(
        self,
        kafka_bootstrap_servers: str = "localhost:9092",
        kafka_topic: str = "sysmon_events",
        anomaly_detector: Optional[EnhancedAnomalyDetector] = None,
        alert_callback: Optional[Callable] = None
    ):
        """
        Initialize live Sysmon collector.

        Args:
            kafka_bootstrap_servers: Kafka bootstrap servers
            kafka_topic: Kafka topic for Sysmon events
            anomaly_detector: Optional anomaly detector for real-time analysis
            alert_callback: Optional callback for alert notifications
        """
        self.kafka_servers = kafka_bootstrap_servers
        self.kafka_topic = kafka_topic
        self.anomaly_detector = anomaly_detector
        self.alert_callback = alert_callback

        self.running = False
        self.thread = None
        self.last_event_time = datetime.now()

        # Kafka producer
        self.producer = None
        if KAFKA_AVAILABLE:
            try:
                self.producer = KafkaProducer(
                    bootstrap_servers=kafka_bootstrap_servers.split(','),
                    value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                    key_serializer=lambda k: k.encode('utf-8') if k else None
                )
                logger.info("✓ Kafka producer initialized for Sysmon events")
            except Exception as e:
                logger.warning(f"Failed to initialize Kafka producer: {e}")

        # Event buffer for batch processing
        self.event_buffer = []
        self.buffer_size = 10
        self.buffer_timeout = 5.0  # seconds

    def start_collection(self):
        """Start live Sysmon event collection."""
        if not WIN32_AVAILABLE:
            logger.error("Windows Event Log API not available. Install pywin32.")
            return False

        if self.running:
            logger.warning("Sysmon collector already running")
            return True

        self.running = True
        self.thread = threading.Thread(target=self._collection_loop, daemon=True)
        self.thread.start()

        logger.info("✓ Started live Sysmon event collection")
        return True

    def stop_collection(self):
        """Stop live Sysmon event collection."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5.0)
        logger.info("✓ Stopped live Sysmon event collection")

    def _collection_loop(self):
        """Main collection loop for Sysmon events."""
        try:
            # Open Sysmon event log
            log_handle = win32evtlog.OpenEventLog(None, "Microsoft-Windows-Sysmon/Operational")

            # Get total number of records
            total_records = win32evtlog.GetNumberOfEventLogRecords(log_handle)

            # Start from the most recent events
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(log_handle, flags, 0)

            processed_events = set()

            while self.running:
                try:
                    # Read new events
                    new_events = []
                    while True:
                        events = win32evtlog.ReadEventLog(log_handle, flags, 0)
                        if not events:
                            break

                        for event in events:
                            event_id = f"{event.TimeGenerated}_{event.RecordNumber}"
                            if event_id not in processed_events:
                                processed_events.add(event_id)
                                new_events.append(self._parse_event(event))

                    # Process new events
                    if new_events:
                        self._process_events(new_events)

                    # Sleep before next check
                    time.sleep(1.0)

                except Exception as e:
                    logger.error(f"Error in Sysmon collection loop: {e}")
                    time.sleep(5.0)  # Wait before retry

            win32evtlog.CloseEventLog(log_handle)

        except Exception as e:
            logger.error(f"Failed to start Sysmon collection: {e}")
            self.running = False

    def _parse_event(self, event) -> Dict[str, Any]:
        """Parse Windows Event Log event to dictionary."""
        try:
            # Extract basic event information
            event_data = {
                'timestamp': event.TimeGenerated.isoformat(),
                'source': event.SourceName,
                'event_id': event.EventID,
                'level': event.EventType,
                'computer': event.ComputerName,
                'record_number': event.RecordNumber,
                'raw_data': str(event.StringInserts) if event.StringInserts else ""
            }

            # Parse Sysmon-specific data if available
            if event.StringInserts and len(event.StringInserts) > 0:
                try:
                    # Sysmon events have structured data in StringInserts
                    event_data['message'] = ' '.join(str(s) for s in event.StringInserts)
                except:
                    event_data['message'] = str(event.StringInserts)

            return event_data

        except Exception as e:
            logger.warning(f"Failed to parse event: {e}")
            return {
                'timestamp': datetime.now().isoformat(),
                'error': str(e),
                'raw_event': str(event)
            }

    def _process_events(self, events: List[Dict[str, Any]]):
        """Process batch of Sysmon events."""
        try:
            # Send to Kafka if available
            if self.producer:
                for event in events:
                    try:
                        self.producer.send(
                            self.kafka_topic,
                            value=event,
                            key=f"sysmon_{event.get('record_number', 'unknown')}"
                        )
                    except Exception as e:
                        logger.warning(f"Failed to send event to Kafka: {e}")

            # Add to buffer for batch processing
            self.event_buffer.extend(events)

            # Process buffer if it's full or timeout reached
            if len(self.event_buffer) >= self.buffer_size:
                self._process_buffer()

        except Exception as e:
            logger.error(f"Error processing Sysmon events: {e}")

    def _process_buffer(self):
        """Process buffered events for anomaly detection."""
        if not self.event_buffer:
            return

        try:
            # Convert events to DataFrame for processing
            events_df = pd.DataFrame(self.event_buffer)

            # Run anomaly detection if detector available
            if self.anomaly_detector:
                try:
                    # Extract features and run detection
                    features_df = extract_all_features(events_df)
                    if len(features_df) > 0:
                        result = self.anomaly_detector.detect_temporal_anomaly(features_df)

                        # Trigger alert if anomaly detected
                        if result['is_anomaly'] and self.alert_callback:
                            alert_data = {
                                'type': 'sysmon_anomaly',
                                'threat_score': result['anomaly_score'],
                                'severity': self._calculate_severity(result['anomaly_score']),
                                'description': f"Sysmon anomaly detected: {result.get('top_anomalous_features', [])}",
                                'timestamp': datetime.now().isoformat(),
                                'source': 'live_sysmon_collector',
                                'details': result
                            }
                            self.alert_callback(alert_data)

                except Exception as e:
                    logger.warning(f"Failed to run anomaly detection on Sysmon events: {e}")

            # Clear buffer
            self.event_buffer.clear()

        except Exception as e:
            logger.error(f"Error processing event buffer: {e}")

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


class LiveNetworkCollector:
    """
    Live network packet collector using Scapy.

    Captures network packets in real-time and streams them
    for anomaly detection.
    """

    def __init__(
        self,
        interface: str = "Wi-Fi",
        kafka_bootstrap_servers: str = "localhost:9092",
        kafka_topic: str = "network_flows",
        anomaly_detector: Optional[EnhancedAnomalyDetector] = None,
        alert_callback: Optional[Callable] = None
    ):
        """
        Initialize live network collector.

        Args:
            interface: Network interface to capture on
            kafka_bootstrap_servers: Kafka bootstrap servers
            kafka_topic: Kafka topic for network flows
            anomaly_detector: Optional anomaly detector for real-time analysis
            alert_callback: Optional callback for alert notifications
        """
        self.interface = interface
        self.kafka_servers = kafka_bootstrap_servers
        self.kafka_topic = kafka_topic
        self.anomaly_detector = anomaly_detector
        self.alert_callback = alert_callback

        self.running = False
        self.capture_thread = None

        # Kafka producer
        self.producer = None
        if KAFKA_AVAILABLE:
            try:
                self.producer = KafkaProducer(
                    bootstrap_servers=kafka_bootstrap_servers.split(','),
                    value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                    key_serializer=lambda k: k.encode('utf-8') if k else None
                )
                logger.info("✓ Kafka producer initialized for network flows")
            except Exception as e:
                logger.warning(f"Failed to initialize Kafka producer: {e}")

        # Packet buffer for batch processing
        self.packet_buffer = []
        self.buffer_size = 50
        self.buffer_timeout = 10.0  # seconds
        self.last_process_time = time.time()

    def start_collection(self):
        """Start live network packet collection."""
        if not SCAPY_AVAILABLE:
            logger.error("Scapy not available. Install scapy for network collection.")
            return False

        if self.running:
            logger.warning("Network collector already running")
            return True

        self.running = True
        self.capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.capture_thread.start()

        logger.info(f"✓ Started live network packet collection on {self.interface}")
        return True

    def stop_collection(self):
        """Stop live network packet collection."""
        self.running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=5.0)
        logger.info("✓ Stopped live network packet collection")

    def _capture_loop(self):
        """Main packet capture loop."""
        def packet_handler(packet):
            """Handle individual packets."""
            if not self.running:
                return

            try:
                packet_data = self._parse_packet(packet)
                if packet_data:
                    self._process_packet(packet_data)
            except Exception as e:
                logger.warning(f"Failed to process packet: {e}")

        try:
            # Start packet capture
            scapy.sniff(
                iface=self.interface,
                prn=packet_handler,
                store=False,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            logger.error(f"Failed to start network capture: {e}")
            self.running = False

    def _parse_packet(self, packet) -> Optional[Dict[str, Any]]:
        """Parse Scapy packet to dictionary."""
        try:
            packet_data = {
                'timestamp': datetime.now().isoformat(),
                'length': len(packet),
                'interface': self.interface
            }

            # Extract IP layer information
            if packet.haslayer('IP'):
                ip = packet['IP']
                packet_data.update({
                    'src_ip': ip.src,
                    'dst_ip': ip.dst,
                    'protocol': ip.proto,
                    'ttl': ip.ttl,
                    'flags': str(ip.flags)
                })

            # Extract TCP/UDP information
            if packet.haslayer('TCP'):
                tcp = packet['TCP']
                packet_data.update({
                    'src_port': tcp.sport,
                    'dst_port': tcp.dport,
                    'tcp_flags': str(tcp.flags),
                    'seq': tcp.seq,
                    'ack': tcp.ack
                })
            elif packet.haslayer('UDP'):
                udp = packet['UDP']
                packet_data.update({
                    'src_port': udp.sport,
                    'dst_port': udp.dport
                })

            return packet_data

        except Exception as e:
            logger.warning(f"Failed to parse packet: {e}")
            return None

    def _process_packet(self, packet_data: Dict[str, Any]):
        """Process individual packet."""
        try:
            # Send to Kafka if available
            if self.producer:
                try:
                    self.producer.send(
                        self.kafka_topic,
                        value=packet_data,
                        key=f"packet_{packet_data.get('src_ip', 'unknown')}_{packet_data.get('dst_ip', 'unknown')}"
                    )
                except Exception as e:
                    logger.warning(f"Failed to send packet to Kafka: {e}")

            # Add to buffer for batch processing
            self.packet_buffer.append(packet_data)

            # Process buffer if conditions met
            current_time = time.time()
            if (len(self.packet_buffer) >= self.buffer_size or
                current_time - self.last_process_time >= self.buffer_timeout):
                self._process_buffer()
                self.last_process_time = current_time

        except Exception as e:
            logger.error(f"Error processing packet: {e}")

    def _process_buffer(self):
        """Process buffered packets for anomaly detection."""
        if not self.packet_buffer:
            return

        try:
            # Convert packets to DataFrame for processing
            packets_df = pd.DataFrame(self.packet_buffer)

            # Run anomaly detection if detector available
            if self.anomaly_detector and len(packets_df) > 5:
                try:
                    result = self.anomaly_detector.detect_network_anomaly(packets_df)

                    # Trigger alert if anomaly detected
                    if result['is_anomaly'] and self.alert_callback:
                        alert_data = {
                            'type': 'network_anomaly',
                            'threat_score': result['graph_anomaly_score'],
                            'severity': self._calculate_severity(result['graph_anomaly_score']),
                            'description': f"Network anomaly detected: {result.get('anomalous_nodes', [])}",
                            'timestamp': datetime.now().isoformat(),
                            'source': 'live_network_collector',
                            'details': result
                        }
                        self.alert_callback(alert_data)

                except Exception as e:
                    logger.warning(f"Failed to run anomaly detection on network packets: {e}")

            # Clear buffer
            self.packet_buffer.clear()

        except Exception as e:
            logger.error(f"Error processing packet buffer: {e}")

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


class LiveDataCollectionService:
    """
    Unified service for live data collection from multiple sources.

    Manages Sysmon and network collectors, coordinates with Kafka,
    and integrates with anomaly detection.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize live data collection service.

        Args:
            config: Configuration dictionary with collection settings
        """
        self.config = config or self._load_config()
        self.anomaly_detector = None
        self.alert_callback = None

        # Initialize collectors
        self.sysmon_collector = LiveSysmonCollector(
            kafka_bootstrap_servers=self.config.get('kafka_servers', 'localhost:9092'),
            kafka_topic=self.config.get('sysmon_topic', 'sysmon_events'),
            anomaly_detector=self.anomaly_detector,
            alert_callback=self.alert_callback
        )

        self.network_collector = LiveNetworkCollector(
            interface=self.config.get('network_interface', 'Wi-Fi'),
            kafka_bootstrap_servers=self.config.get('kafka_servers', 'localhost:9092'),
            kafka_topic=self.config.get('network_topic', 'network_flows'),
            anomaly_detector=self.anomaly_detector,
            alert_callback=self.alert_callback
        )

        self.running = False
        logger.info("✓ Live Data Collection Service initialized")

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from environment variables."""
        return {
            'kafka_servers': os.getenv('KAFKA_BOOTSTRAP_SERVERS', 'localhost:9092'),
            'sysmon_topic': os.getenv('KAFKA_TOPIC_SYSMON', 'sysmon_events'),
            'network_topic': os.getenv('KAFKA_TOPIC_NETWORK', 'network_flows'),
            'network_interface': os.getenv('TSHARK_INTERFACE', 'Wi-Fi'),
            'alert_threshold': float(os.getenv('ALERT_THRESHOLD', '0.75'))
        }

    def set_anomaly_detector(self, detector: EnhancedAnomalyDetector):
        """Set anomaly detector for real-time analysis."""
        self.anomaly_detector = detector
        self.sysmon_collector.anomaly_detector = detector
        self.network_collector.anomaly_detector = detector
        logger.info("✓ Anomaly detector configured for live collection")

    def set_alert_callback(self, callback: Callable):
        """Set callback for alert notifications."""
        self.alert_callback = callback
        self.sysmon_collector.alert_callback = callback
        self.network_collector.alert_callback = callback
        logger.info("✓ Alert callback configured")

    def start_collection(self):
        """Start all live data collection."""
        if self.running:
            logger.warning("Live collection already running")
            return

        self.running = True

        # Start collectors
        sysmon_started = self.sysmon_collector.start_collection()
        network_started = self.network_collector.start_collection()

        if sysmon_started or network_started:
            logger.info("✓ Live data collection started")
            if sysmon_started:
                logger.info("  - Sysmon event collection: ACTIVE")
            if network_started:
                logger.info("  - Network packet collection: ACTIVE")
        else:
            logger.error("Failed to start any data collection")
            self.running = False

    def stop_collection(self):
        """Stop all live data collection."""
        if not self.running:
            return

        self.running = False

        # Stop collectors
        self.sysmon_collector.stop_collection()
        self.network_collector.stop_collection()

        logger.info("✓ Live data collection stopped")

    def get_status(self) -> Dict[str, Any]:
        """Get current collection status."""
        return {
            'running': self.running,
            'sysmon_collector': {
                'active': self.sysmon_collector.running,
                'buffered_events': len(self.sysmon_collector.event_buffer)
            },
            'network_collector': {
                'active': self.network_collector.running,
                'buffered_packets': len(self.network_collector.packet_buffer)
            },
            'anomaly_detector': self.anomaly_detector is not None,
            'alert_callback': self.alert_callback is not None
        }


# Import here to avoid circular imports
from ..preprocessing.feature_engineering import extract_all_features
import pandas as pd
