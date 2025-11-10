"""
Data preprocessing module for AI Zero-Day Detection System.

Handles data cleaning, feature engineering, and graph construction.
"""

import logging
from typing import Dict, Any, Optional
from pathlib import Path
import pandas as pd

try:
    from preprocessing.log_parser import SysmonLogParser
    LOG_PARSER_AVAILABLE = True
except ImportError:
    LOG_PARSER_AVAILABLE = False

try:
    from preprocessing.feature_engineering import engineer_features
    FEATURE_ENG_AVAILABLE = True
except ImportError:
    FEATURE_ENG_AVAILABLE = False

try:
    from preprocessing.graph_builder import build_provenance_graphs
    GRAPH_BUILDER_AVAILABLE = True
except ImportError:
    GRAPH_BUILDER_AVAILABLE = False

logger = logging.getLogger(__name__)


class DataPreprocessor:
    """
    Handles data preprocessing pipeline.

    Responsibilities:
    - Data cleaning and validation
    - Feature engineering
    - Graph construction
    - Data persistence
    """

    def __init__(self,
                 raw_dir: str = "data/raw",
                 processed_dir: str = "data/processed",
                 features_dir: str = "data/features",
                 graphs_dir: str = "data/graphs"):
        """
        Initialize data preprocessor.

        Args:
            raw_dir: Directory for raw data
            processed_dir: Directory for processed data
            features_dir: Directory for engineered features
            graphs_dir: Directory for graph data
        """
        self.raw_dir = Path(raw_dir)
        self.processed_dir = Path(processed_dir)
        self.features_dir = Path(features_dir)
        self.graphs_dir = Path(graphs_dir)

        # Create directories
        for dir_path in [self.raw_dir, self.processed_dir, self.features_dir, self.graphs_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)

        logger.info("Data preprocessor initialized")

    def preprocess_sysmon_data(self, sysmon_events: list, output_prefix: str = "sysmon") -> Dict[str, str]:
        """
        Preprocess Sysmon event data.

        Args:
            sysmon_events: List of Sysmon events
            output_prefix: Prefix for output files

        Returns:
            Dictionary with paths to processed files
        """
        logger.info(f"Preprocessing {len(sysmon_events)} Sysmon events")

        if not sysmon_events:
            logger.warning("No Sysmon events to preprocess")
            return {}

        try:
            # Convert to DataFrame
            df = pd.DataFrame(sysmon_events)

            # Save raw events
            raw_path = self.processed_dir / f"{output_prefix}_raw_events.csv"
            df.to_csv(raw_path, index=False)
            logger.info(f"Saved raw Sysmon data to {raw_path}")

            # Parse and clean data
            if LOG_PARSER_AVAILABLE:
                clean_path = self.processed_dir / f"{output_prefix}_clean.csv"
                SysmonLogParser.parse_sysmon_csv(str(raw_path), str(clean_path))
                logger.info(f"Parsed Sysmon data saved to {clean_path}")
            else:
                clean_path = raw_path
                logger.warning("Log parser not available, using raw data")

            return {
                'raw_path': str(raw_path),
                'clean_path': str(clean_path)
            }

        except Exception as e:
            logger.error(f"Failed to preprocess Sysmon data: {e}")
            raise

    def engineer_features(self,
                         sysmon_path: str,
                         network_path: Optional[str] = None,
                         output_prefix: str = "features") -> Dict[str, str]:
        """
        Perform feature engineering on processed data.

        Args:
            sysmon_path: Path to processed Sysmon data
            network_path: Optional path to network data
            output_prefix: Prefix for output files

        Returns:
            Dictionary with paths to feature files
        """
        logger.info("Starting feature engineering")

        if not FEATURE_ENG_AVAILABLE:
            logger.error("Feature engineering module not available")
            raise ImportError("Feature engineering module not available")

        try:
            # Engineer features
            feature_paths = engineer_features(
                sysmon_csv=sysmon_path,
                network_csv=network_path,
                output_dir=str(self.features_dir)
            )

            logger.info("Feature engineering completed")
            return feature_paths

        except Exception as e:
            logger.error(f"Feature engineering failed: {e}")
            raise

    def build_graphs(self,
                    sysmon_path: str,
                    temporal_features_path: str,
                    structural_features_path: str,
                    semantic_features_path: str,
                    network_path: Optional[str] = None,
                    window_minutes: int = 5,
                    time_tolerance: int = 5) -> Dict[str, str]:
        """
        Build provenance graphs from feature data.

        Args:
            sysmon_path: Path to Sysmon data
            temporal_features_path: Path to temporal features
            structural_features_path: Path to structural features
            semantic_features_path: Path to semantic features
            network_path: Optional path to network data
            window_minutes: Time window for graph construction
            time_tolerance: Time tolerance for event correlation

        Returns:
            Dictionary with paths to graph files
        """
        logger.info("Starting graph construction")

        if not GRAPH_BUILDER_AVAILABLE:
            logger.error("Graph builder module not available")
            raise ImportError("Graph builder module not available")

        try:
            # Build graphs
            graph_paths = build_provenance_graphs(
                sysmon_csv=sysmon_path,
                temporal_csv=temporal_features_path,
                structural_csv=structural_features_path,
                semantic_csv=semantic_features_path,
                network_csv=network_path,
                output_dir=str(self.graphs_dir),
                window_minutes=window_minutes,
                time_tolerance=time_tolerance
            )

            logger.info("Graph construction completed")
            return graph_paths

        except Exception as e:
            logger.error(f"Graph construction failed: {e}")
            raise

    def run_full_preprocessing(self,
                              collected_data: Dict[str, Any],
                              output_prefix: str = "processed") -> Dict[str, Any]:
        """
        Run complete preprocessing pipeline.

        Args:
            collected_data: Data collected by DataCollector
            output_prefix: Prefix for output files

        Returns:
            Dictionary with all preprocessing results and file paths
        """
        logger.info("Starting full preprocessing pipeline")

        results = {
            'success': False,
            'processed_files': {},
            'feature_files': {},
            'graph_files': {},
            'metadata': {
                'timestamp': pd.Timestamp.now().isoformat(),
                'input_events': len(collected_data.get('sysmon_events', []))
            }
        }

        try:
            # Step 1: Preprocess Sysmon data
            if collected_data.get('sysmon_events'):
                processed_files = self.preprocess_sysmon_data(
                    collected_data['sysmon_events'],
                    output_prefix
                )
                results['processed_files'] = processed_files

                # Step 2: Feature engineering
                if processed_files.get('clean_path'):
                    feature_files = self.engineer_features(
                        sysmon_path=processed_files['clean_path'],
                        network_path=collected_data.get('network_csv'),
                        output_prefix=output_prefix
                    )
                    results['feature_files'] = feature_files

                    # Step 3: Graph construction (if features available)
                    temporal_csv = self.features_dir / f"{output_prefix}_temporal_features.csv"
                    structural_csv = self.features_dir / f"{output_prefix}_structural_features.csv"
                    semantic_csv = self.features_dir / f"{output_prefix}_semantic_features.csv"

                    if (temporal_csv.exists() and structural_csv.exists() and semantic_csv.exists()):
                        graph_files = self.build_graphs(
                            sysmon_path=processed_files['clean_path'],
                            temporal_features_path=str(temporal_csv),
                            structural_features_path=str(structural_csv),
                            semantic_features_path=str(semantic_csv),
                            network_path=collected_data.get('network_csv')
                        )
                        results['graph_files'] = graph_files

            results['success'] = True
            logger.info("Full preprocessing pipeline completed successfully")

        except Exception as e:
            logger.error(f"Preprocessing pipeline failed: {e}")
            results['error'] = str(e)
            raise

        return results

    def validate_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate input data quality and completeness.

        Args:
            data: Data to validate

        Returns:
            Validation results
        """
        validation_results = {
            'valid': True,
            'issues': [],
            'stats': {}
        }

        # Check Sysmon events
        sysmon_events = data.get('sysmon_events', [])
        if not sysmon_events:
            validation_results['issues'].append("No Sysmon events found")
            validation_results['valid'] = False
        else:
            validation_results['stats']['sysmon_events'] = len(sysmon_events)

            # Check for required fields
            if isinstance(sysmon_events[0], dict):
                required_fields = ['EventID', 'TimeGenerated']
                missing_fields = []
                for field in required_fields:
                    if field not in sysmon_events[0]:
                        missing_fields.append(field)

                if missing_fields:
                    validation_results['issues'].append(f"Missing required fields: {missing_fields}")
                    validation_results['valid'] = False

        # Check network data if present
        network_packets = data.get('network_packets', [])
        if network_packets:
            validation_results['stats']['network_packets'] = len(network_packets)

        return validation_results

    def get_status(self) -> Dict[str, Any]:
        """
        Get preprocessor status and capabilities.

        Returns:
            Dictionary with status information
        """
        return {
            'modules_available': {
                'log_parser': LOG_PARSER_AVAILABLE,
                'feature_engineering': FEATURE_ENG_AVAILABLE,
                'graph_builder': GRAPH_BUILDER_AVAILABLE
            },
            'directories': {
                'raw': str(self.raw_dir),
                'processed': str(self.processed_dir),
                'features': str(self.features_dir),
                'graphs': str(self.graphs_dir)
            },
            'timestamp': pd.Timestamp.now().isoformat()
        }
