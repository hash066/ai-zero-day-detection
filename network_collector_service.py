import time
import csv
import logging
from pathlib import Path
from datetime import datetime
from src.collectors.tshark_collector import TsharkCollector
from src.collectors.network_adapter import NetworkAdapter

# Setup logging
log_dir = Path("D:/NetworkCollectorLogs")
log_dir.mkdir(exist_ok=True)

logging.basicConfig(
    filename=log_dir / "service.log",
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def main():
    logging.info("Network Collector Service Starting...")
    
    collector = TsharkCollector(
        interface="Wi-Fi",  # Your interface name
        capture_filter="ip",
        buffer_size=1000
    )
    
    adapter = NetworkAdapter()
    
    # Create CSV with timestamp in filename
    csv_file = log_dir / f"network_data_{datetime.now():%Y%m%d_%H%M%S}.csv"
    
    try:
        with open(csv_file, 'w', newline='') as f:
            writer = None
            
            for packet in collector.stream_packets():
                record = adapter.adapt_packet(packet)
                if record:
                    if writer is None:
                        # Initialize writer with field names
                        writer = csv.DictWriter(f, fieldnames=record.__dict__.keys())
                        writer.writeheader()
                    
                    writer.writerow(record.__dict__)
                    f.flush()  # Write immediately
                    
    except KeyboardInterrupt:
        logging.info("Service stopped by user")
    except Exception as e:
        logging.error(f"Error in collector: {e}", exc_info=True)
    finally:
        collector.stop()
        logging.info("Network Collector Service Stopped")

if __name__ == "__main__":
    main()
