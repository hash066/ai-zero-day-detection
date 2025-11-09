#!/usr/bin/env python3
"""
Main pipeline orchestrator for AI Zero-Day Detection System.

This script provides a simple interface to the modular pipeline components.
For advanced usage, use the PipelineOrchestrator class directly.

Usage:
    python main_pipeline.py --config config.yaml
    python main_pipeline.py --run-batch
    python main_pipeline.py --run-streaming
    python main_pipeline.py --run-file data/sample.csv
"""

import argparse
import logging
import yaml
import sys
from pathlib import Path
from typing import Dict, Any, Optional

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

# Import modular pipeline components
from pipeline import PipelineOrchestrator

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def main():
    """Main entry point using modular pipeline components."""
    parser = argparse.ArgumentParser(description="AI Zero-Day Detection Pipeline")
    parser.add_argument("--config", type=str, help="Path to configuration YAML file")

    # Pipeline execution modes
    parser.add_argument("--run-batch", action="store_true",
                       help="Run batch processing pipeline")
    parser.add_argument("--run-streaming", action="store_true",
                       help="Run real-time streaming pipeline")
    parser.add_argument("--run-file", type=str,
                       help="Run pipeline on data from file")

    # Pipeline options
    parser.add_argument("--entity-id", type=str, default="system",
                       help="Entity identifier for analysis")
    parser.add_argument("--entity-type", type=str, default="system",
                       help="Entity type (system, user, etc.)")

    # Legacy support (redirect to new interface)
    parser.add_argument("--full-pipeline", action="store_true",
                       help="Legacy: use --run-batch instead")
    parser.add_argument("--streaming-mode", action="store_true",
                       help="Legacy: use --run-streaming instead")

    args = parser.parse_args()

    # Load configuration if provided
    config = None
    if args.config:
        try:
            with open(args.config, 'r') as f:
                config = yaml.safe_load(f)
            logger.info(f"Loaded configuration from {args.config}")
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            return

    # Create pipeline orchestrator
    with PipelineOrchestrator(config) as orchestrator:
        try:
            if args.run_batch or args.full_pipeline:
                # Run batch processing pipeline
                logger.info("Starting batch pipeline...")
                results = orchestrator.run_batch_pipeline(
                    entity_id=args.entity_id,
                    entity_type=args.entity_type
                )

                if results['success']:
                    logger.info("✅ Batch pipeline completed successfully")
                    if results.get('detection'):
                        detection = results['detection']
                        logger.info(f"Final threat score: {detection.get('final_threat_score', 'N/A')}")
                else:
                    logger.error("❌ Batch pipeline failed")
                    if 'error' in results:
                        logger.error(f"Error: {results['error']}")

            elif args.run_streaming or args.streaming_mode:
                # Run streaming pipeline
                logger.info("Starting streaming pipeline...")
                success = orchestrator.run_streaming_pipeline()
                if success:
                    logger.info("✅ Streaming pipeline started")
                    # Keep running until interrupted
                    try:
                        while True:
                            import time
                            time.sleep(1)
                    except KeyboardInterrupt:
                        logger.info("Stopping streaming...")
                        orchestrator.stop_streaming_pipeline()
                else:
                    logger.error("❌ Failed to start streaming pipeline")

            elif args.run_file:
                # Run pipeline on file data
                logger.info(f"Processing file: {args.run_file}")
                results = orchestrator.run_file_pipeline(
                    file_path=args.run_file,
                    entity_id=args.entity_id,
                    entity_type=args.entity_type
                )

                if results['success']:
                    logger.info("✅ File pipeline completed successfully")
                else:
                    logger.error("❌ File pipeline failed")
                    if 'error' in results:
                        logger.error(f"Error: {results['error']}")

            else:
                # Show pipeline status
                logger.info("Pipeline Status:")
                status = orchestrator.get_pipeline_status()
                print(yaml.dump(status, default_flow_style=False))

                # Show usage
                parser.print_help()

        except KeyboardInterrupt:
            logger.info("Pipeline interrupted by user")
        except Exception as e:
            logger.error(f"Pipeline execution failed: {e}")
            raise


if __name__ == '__main__':
    main()
