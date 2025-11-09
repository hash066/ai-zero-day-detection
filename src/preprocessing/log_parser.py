"""
Log parser for various input formats.

Converts XML, JSON, and PCAP formats into tabular/structured format
for downstream processing.
"""

import json
import pandas as pd
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
import logging
import xml.etree.ElementTree as ET

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SysmonLogParser:
    """Specialized parser for Sysmon event logs with parent process tracking."""

    @staticmethod
    def parse_sysmon_event(event_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse a single Sysmon event with proper parent process extraction.

        Args:
            event_data: Raw Sysmon event data

        Returns:
            Parsed event with parent_process_guid field
        """
        parsed = event_data.copy()

        # Extract parent process GUID from EventData
        event_data_section = event_data.get('EventData', {})
        if isinstance(event_data_section, dict):
            parsed['parent_process_guid'] = event_data_section.get('ParentProcessGuid', '')
            parsed['parent_process_id'] = event_data_section.get('ParentProcessId', '')
            parsed['parent_image'] = event_data_section.get('ParentImage', '')
        else:
            # Handle string format or other formats
            parsed['parent_process_guid'] = ''
            parsed['parent_process_id'] = ''
            parsed['parent_image'] = ''

        return parsed

    @staticmethod
    def parse_sysmon_csv(input_path: str, output_path: str):
        """
        Parse Sysmon CSV with proper parent process tracking.

        Args:
            input_path: Path to raw Sysmon CSV
            output_path: Path to save parsed CSV
        """
        logger.info(f"Parsing Sysmon CSV: {input_path}")

        try:
            df = pd.read_csv(input_path)

            # Parse each event to extract parent process info
            parsed_events = []
            for _, row in df.iterrows():
                event_dict = row.to_dict()
                parsed_event = SysmonLogParser.parse_sysmon_event(event_dict)
                parsed_events.append(parsed_event)

            parsed_df = pd.DataFrame(parsed_events)
            parsed_df.to_csv(output_path, index=False)

            logger.info(f"Parsed {len(parsed_df)} Sysmon events with parent process tracking")
            logger.info(f"Saved to: {output_path}")

        except Exception as e:
            logger.error(f"Failed to parse Sysmon CSV: {e}")
            raise


class JSONLogParser:
    """Parse JSON-formatted logs (Sysmon, network data, etc.)."""

    @staticmethod
    def parse_file(file_path: str) -> pd.DataFrame:
        """
        Parse JSON log file to DataFrame.
        
        Args:
            file_path: Path to JSON file
            
        Returns:
            DataFrame with parsed log entries
        """
        logger.info(f"Parsing JSON file: {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                # Try to load as JSON array
                try:
                    data = json.load(f)
                    if isinstance(data, list):
                        return pd.DataFrame(data)
                    elif isinstance(data, dict):
                        return pd.DataFrame([data])
                except json.JSONDecodeError:
                    # Try line-delimited JSON (NDJSON)
                    f.seek(0)
                    records = []
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                records.append(json.loads(line))
                            except json.JSONDecodeError as e:
                                logger.warning(f"Skipping malformed JSON line: {e}")
                    
                    if records:
                        return pd.DataFrame(records)
                    else:
                        logger.error("No valid JSON records found")
                        return pd.DataFrame()
        
        except FileNotFoundError:
            logger.error(f"File not found: {file_path}")
            return pd.DataFrame()
        except Exception as e:
            logger.error(f"Error parsing JSON file: {e}")
            return pd.DataFrame()
    
    @staticmethod
    def parse_nested_json(file_path: str, record_path: Optional[str] = None) -> pd.DataFrame:
        """
        Parse nested JSON with specific record path.
        
        Args:
            file_path: Path to JSON file
            record_path: Dot-separated path to records (e.g., 'data.events')
            
        Returns:
            DataFrame with flattened records
        """
        logger.info(f"Parsing nested JSON: {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Navigate to record path if specified
            if record_path:
                for key in record_path.split('.'):
                    data = data[key]
            
            # Normalize nested structures
            return pd.json_normalize(data)
        
        except FileNotFoundError:
            logger.error(f"File not found: {file_path}")
            return pd.DataFrame()
        except Exception as e:
            logger.error(f"Error parsing nested JSON: {e}")
            return pd.DataFrame()


class XMLLogParser:
    """Parse XML-formatted logs (Windows Event Logs, etc.)."""
    
    @staticmethod
    def parse_file(file_path: str, record_tag: str = 'Event') -> pd.DataFrame:
        """
        Parse XML log file to DataFrame.
        
        Args:
            file_path: Path to XML file
            record_tag: XML tag name for individual records
            
        Returns:
            DataFrame with parsed log entries
        """
        logger.info(f"Parsing XML file: {file_path}")
        
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            records = []
            for event in root.findall(f'.//{record_tag}'):
                record = XMLLogParser._xml_to_dict(event)
                records.append(record)
            
            if records:
                return pd.DataFrame(records)
            else:
                logger.warning("No records found in XML file")
                return pd.DataFrame()
        
        except FileNotFoundError:
            logger.error(f"File not found: {file_path}")
            return pd.DataFrame()
        except ET.ParseError as e:
            logger.error(f"XML parsing error: {e}")
            return pd.DataFrame()
        except Exception as e:
            logger.error(f"Error parsing XML file: {e}")
            return pd.DataFrame()
    
    @staticmethod
    def _xml_to_dict(element: ET.Element) -> Dict[str, Any]:
        """
        Recursively convert XML element to dictionary.
        
        Args:
            element: XML element
            
        Returns:
            Dictionary representation
        """
        result = {}
        
        # Add attributes
        if element.attrib:
            result.update(element.attrib)
        
        # Add text content
        if element.text and element.text.strip():
            result['_text'] = element.text.strip()
        
        # Add child elements
        for child in element:
            child_data = XMLLogParser._xml_to_dict(child)
            tag = child.tag.split('}')[-1]  # Remove namespace
            
            if tag in result:
                # Convert to list if multiple elements with same tag
                if not isinstance(result[tag], list):
                    result[tag] = [result[tag]]
                result[tag].append(child_data)
            else:
                result[tag] = child_data
        
        return result


class PCAPParser:
    """
    Parser for PCAP files using tshark.
    
    Note: This requires tshark to be installed and in PATH.
    """
    
    @staticmethod
    def is_tshark_available() -> bool:
        """Check if tshark is available in PATH."""
        import shutil
        return shutil.which('tshark') is not None
    
    @staticmethod
    def parse_pcap_to_json(pcap_path: str, output_json_path: Optional[str] = None) -> pd.DataFrame:
        """
        Parse PCAP file to JSON using tshark, then to DataFrame.
        
        Args:
            pcap_path: Path to PCAP file
            output_json_path: Optional path to save intermediate JSON
            
        Returns:
            DataFrame with packet data
        """
        if not PCAPParser.is_tshark_available():
            logger.error("tshark not found. Please install Wireshark/tshark.")
            return pd.DataFrame()
        
        logger.info(f"Parsing PCAP file: {pcap_path}")
        
        import subprocess
        import tempfile
        
        # Create temp file if output path not specified
        if output_json_path is None:
            temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
            output_json_path = temp_file.name
            temp_file.close()
        
        try:
            # Run tshark to extract JSON
            cmd = [
                'tshark',
                '-r', pcap_path,
                '-T', 'json',
                '-e', 'frame.time_epoch',
                '-e', 'ip.src',
                '-e', 'ip.dst',
                '-e', 'tcp.srcport',
                '-e', 'tcp.dstport',
                '-e', 'udp.srcport',
                '-e', 'udp.dstport',
                '-e', 'ip.proto',
                '-e', 'frame.len',
                '-e', 'tcp.flags',
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode != 0:
                logger.error(f"tshark error: {result.stderr}")
                return pd.DataFrame()
            
            # Parse JSON output
            packets = json.loads(result.stdout)
            
            # Convert to DataFrame
            records = []
            for pkt in packets:
                layers = pkt.get('_source', {}).get('layers', {})
                record = {
                    'ts': float(layers.get('frame.time_epoch', [0])[0]),
                    'src_ip': layers.get('ip.src', [None])[0],
                    'dst_ip': layers.get('ip.dst', [None])[0],
                    'src_port': layers.get('tcp.srcport', layers.get('udp.srcport', [None]))[0],
                    'dst_port': layers.get('tcp.dstport', layers.get('udp.dstport', [None]))[0],
                    'protocol': layers.get('ip.proto', [None])[0],
                    'length': layers.get('frame.len', [0])[0],
                    'tcp_flags': layers.get('tcp.flags', [None])[0],
                }
                records.append(record)
            
            df = pd.DataFrame(records)
            logger.info(f"Parsed {len(df)} packets from PCAP")
            
            return df
        
        except subprocess.TimeoutExpired:
            logger.error("tshark command timed out")
            return pd.DataFrame()
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse tshark JSON output: {e}")
            return pd.DataFrame()
        except Exception as e:
            logger.error(f"Error parsing PCAP: {e}")
            return pd.DataFrame()


class UniversalLogParser:
    """Universal log parser that auto-detects format."""
    
    @staticmethod
    def parse_file(file_path: str, format_hint: Optional[str] = None) -> pd.DataFrame:
        """
        Parse log file with automatic format detection.
        
        Args:
            file_path: Path to log file
            format_hint: Optional format hint ('json', 'xml', 'pcap', 'csv')
            
        Returns:
            DataFrame with parsed data
        """
        path = Path(file_path)
        
        if not path.exists():
            logger.error(f"File not found: {file_path}")
            return pd.DataFrame()
        
        # Determine format
        if format_hint:
            file_format = format_hint.lower()
        else:
            file_format = path.suffix.lower().lstrip('.')
        
        # Parse based on format
        if file_format in ['json', 'jsonl', 'ndjson']:
            return JSONLogParser.parse_file(file_path)
        
        elif file_format == 'xml':
            return XMLLogParser.parse_file(file_path)
        
        elif file_format in ['pcap', 'pcapng']:
            return PCAPParser.parse_pcap_to_json(file_path)
        
        elif file_format == 'csv':
            try:
                return pd.read_csv(file_path)
            except Exception as e:
                logger.error(f"Error reading CSV: {e}")
                return pd.DataFrame()
        
        else:
            logger.warning(f"Unknown format: {file_format}. Attempting JSON parse...")
            return JSONLogParser.parse_file(file_path)


def parse_log_directory(directory: str, pattern: str = '*', format_hint: Optional[str] = None) -> pd.DataFrame:
    """
    Parse all log files in a directory matching a pattern.
    
    Args:
        directory: Directory containing log files
        pattern: Glob pattern for files (default: '*')
        format_hint: Optional format hint
        
    Returns:
        Combined DataFrame from all files
    """
    path = Path(directory)
    
    if not path.is_dir():
        logger.error(f"Directory not found: {directory}")
        return pd.DataFrame()
    
    files = list(path.glob(pattern))
    logger.info(f"Found {len(files)} files matching pattern '{pattern}'")
    
    all_data = []
    for file in files:
        logger.info(f"Parsing {file.name}...")
        df = UniversalLogParser.parse_file(str(file), format_hint)
        if not df.empty:
            df['source_file'] = file.name
            all_data.append(df)
    
    if all_data:
        combined = pd.concat(all_data, ignore_index=True)
        logger.info(f"Combined {len(combined)} records from {len(all_data)} files")
        return combined
    else:
        logger.warning("No data parsed from any files")
        return pd.DataFrame()


if __name__ == "__main__":
    # Example usage
    print("Universal Log Parser for Zero-Day Detection System")
    print("=" * 60)
    
    # Test JSON parsing
    sample_json = {
        "events": [
            {"ts": 1000.0, "src_ip": "192.168.1.10", "dst_ip": "10.0.0.1", "protocol": "TCP"},
            {"ts": 1001.0, "src_ip": "192.168.1.11", "dst_ip": "10.0.0.2", "protocol": "UDP"},
        ]
    }
    
    # Save sample JSON
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(sample_json, f)
        temp_path = f.name
    
    # Parse it
    df = JSONLogParser.parse_nested_json(temp_path, 'events')
    print(f"\nParsed {len(df)} records from JSON")
    print(df.head())
    
    # Clean up
    import os
    os.unlink(temp_path)
