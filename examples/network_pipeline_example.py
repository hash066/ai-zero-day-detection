"""
Example end-to-end network traffic collection and feature extraction pipeline.

Demonstrates:
1. TsharkCollector: capture packets (live or pcap)
2. NetworkAdapter: convert to NetworkFeatureRecord
3. FlowWindowAggregator: aggregate into flow summaries
4. Export to CSV (compatible with online_files format)

Usage:
    # Live capture
    python examples/network_pipeline_example.py --interface Wi-Fi --duration 30
    
    # Offline pcap
    python examples/network_pipeline_example.py --pcap sample.pcap
"""

import sys
import argparse
import logging
import time
import csv
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.collectors.tshark_collector import TsharkCollector, list_interfaces
from src.collectors.network_adapter import NetworkAdapter
from src.preprocessing.windowing import create_windowing_aggregator
from src.preprocessing.network_features import NetworkFeatureRecord

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def run_pipeline(
    interface: str = None,
    pcap_file: str = None,
    output_csv: str = "network_features.csv",
    duration: int = 60,
    packet_window: int = 10
):
    """
    Run the complete network feature extraction pipeline.
    
    Args:
        interface: Network interface for live capture
        pcap_file: Path to pcap file for offline processing
        output_csv: Output CSV file path
        duration: Capture duration in seconds (live mode only)
        packet_window: Number of packets per aggregation window
    """
    logger.info("=" * 60)
    logger.info("Network Feature Extraction Pipeline")
    logger.info("=" * 60)
    
    # Initialize components
    logger.info("Initializing pipeline components...")
    
    # 1. Collector
    if interface:
        logger.info(f"Live capture mode: interface={interface}, duration={duration}s")
        collector = TsharkCollector(interface=interface)
    elif pcap_file:
        logger.info(f"Offline mode: pcap_file={pcap_file}")
        collector = TsharkCollector(pcap_file=pcap_file)
    else:
        raise ValueError("Must provide either interface or pcap_file")
    
    # 2. Adapter
    adapter = NetworkAdapter()
    
    # 3. Aggregator
    aggregator = create_windowing_aggregator(
        mode="packet_count",
        packet_window=packet_window
    )
    
    # 4. CSV writer
    csv_file = open(output_csv, 'w', newline='')
    csv_writer = csv.DictWriter(csv_file, fieldnames=NetworkFeatureRecord.get_csv_columns())
    csv_writer.writeheader()
    
    # Processing statistics
    stats = {
        'packets_processed': 0,
        'summaries_created': 0,
        'errors': 0
    }
    
    start_time = time.time()
    
    try:
        logger.info("Starting packet capture...")
        
        # Process packet stream
        for tshark_packet in collector.stream_packets():
            # Check timeout for live capture
            if interface and (time.time() - start_time) > duration:
                logger.info(f"Duration limit ({duration}s) reached")
                break
            
            # Convert packet to feature record
            try:
                feature_record = adapter.adapt_packet(tshark_packet)
                if not feature_record:
                    continue
                
                stats['packets_processed'] += 1
                
                # Aggregate into flow window
                summary = aggregator.add_packet(feature_record)
                
                if summary:
                    # Write summary to CSV
                    csv_writer.writerow(summary.to_csv_row())
                    stats['summaries_created'] += 1
                    
                    if stats['summaries_created'] % 10 == 0:
                        logger.info(
                            f"Progress: {stats['packets_processed']} packets, "
                            f"{stats['summaries_created']} summaries"
                        )
            
            except Exception as e:
                logger.error(f"Error processing packet: {e}")
                stats['errors'] += 1
        
        # Flush remaining packets
        logger.info("Flushing remaining packets...")
        final_summary = aggregator.flush()
        if final_summary:
            csv_writer.writerow(final_summary.to_csv_row())
            stats['summaries_created'] += 1
        
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    
    finally:
        collector.stop()
        csv_file.close()
    
    # Report statistics
    elapsed_time = time.time() - start_time
    logger.info("=" * 60)
    logger.info("Pipeline Statistics")
    logger.info("=" * 60)
    logger.info(f"Elapsed time: {elapsed_time:.2f}s")
    logger.info(f"Packets processed: {stats['packets_processed']}")
    logger.info(f"Flow summaries created: {stats['summaries_created']}")
    logger.info(f"Errors: {stats['errors']}")
    logger.info(f"Output written to: {output_csv}")
    logger.info("=" * 60)
    
    return stats


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Network traffic feature extraction pipeline"
    )
    
    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        '--interface',
        help='Network interface for live capture'
    )
    input_group.add_argument(
        '--pcap',
        help='Path to pcap file for offline processing'
    )
    input_group.add_argument(
        '--list-interfaces',
        action='store_true',
        help='List available network interfaces and exit'
    )
    
    # Options
    parser.add_argument(
        '--output',
        default='network_features.csv',
        help='Output CSV file path (default: network_features.csv)'
    )
    parser.add_argument(
        '--duration',
        type=int,
        default=60,
        help='Capture duration in seconds for live mode (default: 60)'
    )
    parser.add_argument(
        '--window',
        type=int,
        default=10,
        help='Packet window size for aggregation (default: 10)'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # List interfaces mode
    if args.list_interfaces:
        print("Available network interfaces:")
        interfaces = list_interfaces()
        if interfaces:
            for iface in interfaces:
                print(f"  - {iface}")
        else:
            print("  No interfaces found or tshark not available")
        return 0
    
    # Run pipeline
    try:
        stats = run_pipeline(
            interface=args.interface,
            pcap_file=args.pcap,
            output_csv=args.output,
            duration=args.duration,
            packet_window=args.window
        )
        
        return 0 if stats['errors'] == 0 else 1
    
    except Exception as e:
        logger.error(f"Pipeline failed: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
