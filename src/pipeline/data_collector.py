"""
Data collection module for AI Zero-Day Detection System.

Handles data ingestion from various sources:
- Sysmon event logs
- Network packet captures
- File-based data sources
"""

import logging
from typing import Dict, List, Any, Optional
from pathlib import Path
import time

try:
    from collectors.sysmon_collector import SysmonCollector
    COLLECTOR_AVAILABLE = True
except ImportError:
    COLLECTOR_AVAILABLE = False

logger = logging.getLogger(__name__)


class DataCollector:
    """
    Handles data collection from various sources.

    Supports:
    - Live Sysmon event streaming
    - Batch file processing
    - Network data collection
    """

    def __init__(self, batch_size: int = 1000):
        """
        Initialize data collector.

        Args:
            batch_size: Batch size for data processing
        """
        self.batch_size = batch_size
        self.collectors = {}

        # Initialize available collectors
        self._setup_collectors()

    def _setup_collectors(self):
        """Initialize available data collectors."""
        if COLLECTOR_AVAILABLE:
            try:
                self.collectors['sysmon'] = SysmonCollector(
                    batch_size=self.batch_size
                )
                logger.info("Sysmon collector initialized")
            except Exception as e:
                logger.warning(f"Could not initialize Sysmon collector: {e}")
        else:
            logger.warning("Sysmon collector not available")

    def collect_batch(self, source: str = 'sysmon') -> Dict[str, Any]:
        """
        Collect a batch of data from specified source.

        Args:
            source: Data source ('sysmon', 'network', etc.)

        Returns:
            Dictionary containing collected data
        """
        logger.info(f"Collecting batch from {source}")

        collected_data = {
            'sysmon_events': [],
            'network_packets': [],
            'metadata': {
                'source': source,
                'timestamp': time.time(),
                'batch_size': self.batch_size
            }
        }

        if source == 'sysmon' and 'sysmon' in self.collectors:
            try:
                batch = self.collectors['sysmon'].collect_batch()
                collected_data['sysmon_events'] = batch.events
                collected_data['metadata']['event_count'] = len(batch.events)
                logger.info(f"Collected {len(batch.events)} Sysmon events")
            except Exception as e:
                logger.error(f"Failed to collect Sysmon batch: {e}")
                raise

        return collected_data

    def collect_stream(self, source: str = 'sysmon', duration_seconds: Optional[int] = None) -> Dict[str, Any]:
        """
        Collect streaming data for specified duration.

        Args:
            source: Data source to stream from
            duration_seconds: How long to stream (None = until interrupted)

        Returns:
            Dictionary containing streamed data
        """
        logger.info(f"Starting stream collection from {source}")

        collected_data = {
            'sysmon_events': [],
            'network_packets': [],
            'metadata': {
                'source': source,
                'stream_mode': True,
                'start_time': time.time()
            }
        }

        if source == 'sysmon' and 'sysmon' in self.collectors:
            start_time = time.time()

            try:
                for event in self.collectors['sysmon'].stream_events():
                    collected_data['sysmon_events'].append(event)

                    # Check duration limit
                    if duration_seconds and (time.time() - start_time) > duration_seconds:
                        break

                collected_data['metadata']['end_time'] = time.time()
                collected_data['metadata']['duration'] = collected_data['metadata']['end_time'] - start_time
                collected_data['metadata']['event_count'] = len(collected_data['sysmon_events'])

                logger.info(f"Stream collection completed: {len(collected_data['sysmon_events'])} events")

            except Exception as e:
                logger.error(f"Stream collection failed: {e}")
                raise

        return collected_data

    def load_from_file(self, file_path: str, source_type: str = 'auto') -> Dict[str, Any]:
        """
        Load data from file.

        Args:
            file_path: Path to data file
            source_type: Type of data ('sysmon', 'network', 'auto')

        Returns:
            Dictionary containing loaded data
        """
        logger.info(f"Loading data from file: {file_path}")

        file_path_obj = Path(file_path)
        if not file_path_obj.exists():
            raise FileNotFoundError(f"Data file not found: {file_path}")

        collected_data = {
            'sysmon_events': [],
            'network_packets': [],
            'metadata': {
                'source': 'file',
                'file_path': str(file_path),
                'timestamp': time.time()
            }
        }

        # Auto-detect file type
        if source_type == 'auto':
            if 'sysmon' in file_path.lower():
                source_type = 'sysmon'
            elif 'network' in file_path.lower() or 'pcap' in file_path.lower():
                source_type = 'network'
            else:
                source_type = 'sysmon'  # Default

        # Load based on type
        if source_type == 'sysmon':
            try:
                import pandas as pd
                df = pd.read_csv(file_path)
                collected_data['sysmon_events'] = df.to_dict('records')
                collected_data['metadata']['event_count'] = len(collected_data['sysmon_events'])
                logger.info(f"Loaded {len(collected_data['sysmon_events'])} Sysmon events from file")
            except Exception as e:
                logger.error(f"Failed to load Sysmon data from file: {e}")
                raise
        elif source_type == 'network':
            # Placeholder for network data loading
            logger.warning("Network file loading not yet implemented")
            collected_data['metadata']['event_count'] = 0

        return collected_data

    def get_status(self) -> Dict[str, Any]:
        """
        Get collector status and health information.

        Returns:
            Dictionary with status information
        """
        status = {
            'collectors_available': list(self.collectors.keys()),
            'batch_size': self.batch_size,
            'timestamp': time.time()
        }

        # Check collector health
        for name, collector in self.collectors.items():
            try:
                # Basic health check - could be more sophisticated
                status[f'{name}_healthy'] = True
            except Exception:
                status[f'{name}_healthy'] = False

        return status
