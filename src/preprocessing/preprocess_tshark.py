"""
Preprocesses raw tshark/PCAP data into structured format.

This script converts tshark output (CSV or JSON) into a clean, standardized
format ready for feature extraction. It handles both live capture output
and stored PCAP file processing.
"""

import argparse
import logging
import pandas as pd
import numpy as np
from pathlib import Path
from typing import Optional, Dict, Any
import json

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def preprocess_tshark_csv(input_path: str, output_path: str):
    """
    Preprocesses tshark CSV output into standardized format.
    
    Handles the CSV output from tshark, normalizing column names and
    extracting protocol-specific features.
    
    Args:
        input_path (str): Path to raw tshark CSV file.
        output_path (str): Path to save processed CSV file.
    """
    logging.info(f"Reading raw tshark CSV data from {input_path}...")
    
    try:
        # Read CSV with flexible parsing
        df = pd.read_csv(input_path, low_memory=False)
    except FileNotFoundError:
        logging.error(f"Input file not found: {input_path}")
        return
    except pd.errors.EmptyDataError:
        logging.error(f"Input file is empty: {input_path}")
        return
    except Exception as e:
        logging.error(f"Error reading CSV: {e}")
        return
    
    logging.info(f"Loaded {len(df)} records with {len(df.columns)} columns")
    
    # --- Column Standardization ---
    # Map common tshark column names to standardized names
    column_mapping = {
        'frame.time_epoch': 'ts',
        'frame.time': 'timestamp',
        'ip.src': 'src_ip',
        'ip.dst': 'dst_ip',
        'ipv6.src': 'src_ip',
        'ipv6.dst': 'dst_ip',
        'tcp.srcport': 'src_port',
        'tcp.dstport': 'dst_port',
        'udp.srcport': 'src_port',
        'udp.dstport': 'dst_port',
        'frame.len': 'tot_size',
        'frame.protocols': 'protocols',
        'ip.proto': 'protocol_number',
        'tcp.flags': 'tcp_flags',
        'tcp.flags.syn': 'syn_flag',
        'tcp.flags.ack': 'ack_flag',
        'tcp.flags.fin': 'fin_flag',
        'tcp.flags.rst': 'rst_flag',
        'tcp.flags.psh': 'psh_flag',
        'tcp.flags.urg': 'urg_flag',
        'tcp.window_size': 'window_size',
        'tcp.len': 'tcp_payload_len',
        'udp.length': 'udp_length',
    }
    
    # Rename columns if they exist
    rename_dict = {old: new for old, new in column_mapping.items() if old in df.columns}
    df.rename(columns=rename_dict, inplace=True)
    
    # --- Protocol Detection ---
    if 'protocols' in df.columns:
        # Extract protocol type from frame.protocols (e.g., "eth:ethertype:ip:tcp:tls")
        def extract_protocol_type(protocols_str):
            if pd.isna(protocols_str):
                return 'UNKNOWN'
            protocols = str(protocols_str).lower().split(':')
            
            # Priority: application layer > transport > network
            if 'tls' in protocols or 'ssl' in protocols:
                return 'TLS'
            elif 'http' in protocols:
                return 'HTTP'
            elif 'https' in protocols:
                return 'HTTPS'
            elif 'dns' in protocols:
                return 'DNS'
            elif 'ssh' in protocols:
                return 'SSH'
            elif 'smtp' in protocols:
                return 'SMTP'
            elif 'ftp' in protocols:
                return 'FTP'
            elif 'telnet' in protocols:
                return 'TELNET'
            elif 'tcp' in protocols:
                return 'TCP'
            elif 'udp' in protocols:
                return 'UDP'
            elif 'icmp' in protocols:
                return 'ICMP'
            else:
                return protocols[-1].upper() if protocols else 'UNKNOWN'
        
        df['protocol_type'] = df['protocols'].apply(extract_protocol_type)
    
    # --- TCP Flag Parsing ---
    # Convert TCP flags from hex or individual flag columns to binary indicators
    flag_cols = ['syn_flag', 'ack_flag', 'fin_flag', 'rst_flag', 'psh_flag', 'urg_flag']
    
    for flag_col in flag_cols:
        if flag_col in df.columns:
            # Convert to binary (1/0)
            df[flag_col + '_number'] = df[flag_col].apply(lambda x: 1 if x in [1, '1', True, 'True'] else 0)
        else:
            # Create empty column
            df[flag_col + '_number'] = 0
    
    # --- Data Type Conversions ---
    # Ensure timestamp is numeric
    if 'ts' not in df.columns and 'timestamp' in df.columns:
        # Try to convert timestamp to epoch
        try:
            df['ts'] = pd.to_datetime(df['timestamp']).astype(np.int64) / 1e9
        except Exception:
            logging.warning("Could not convert timestamp to epoch seconds")
    
    # Ensure numeric columns are numeric
    numeric_cols = ['src_port', 'dst_port', 'tot_size', 'window_size', 'tcp_payload_len', 'udp_length']
    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce')
    
    # --- Fill Missing Values ---
    df['src_ip'] = df['src_ip'].fillna('0.0.0.0')
    df['dst_ip'] = df['dst_ip'].fillna('0.0.0.0')
    df['src_port'] = df['src_port'].fillna(0).astype(int)
    df['dst_port'] = df['dst_port'].fillna(0).astype(int)
    df['tot_size'] = df['tot_size'].fillna(0).astype(int)
    
    if 'protocol_type' not in df.columns:
        df['protocol_type'] = 'UNKNOWN'
    
    # --- Generate Flow ID ---
    df['flow_id'] = df.apply(
        lambda row: f"{row['src_ip']}:{row['src_port']}-{row['dst_ip']}:{row['dst_port']}-{row.get('protocol_type', 'UNKNOWN')}",
        axis=1
    )
    
    # --- Sort by Timestamp ---
    if 'ts' in df.columns:
        df = df.sort_values('ts').reset_index(drop=True)
    
    # --- Save Processed Data ---
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_file, index=False)
    
    logging.info(f"Successfully preprocessed {len(df)} packets.")
    logging.info(f"Processed data saved to {output_path}")
    logging.info(f"Columns in output: {list(df.columns)}")


def preprocess_tshark_json(input_path: str, output_path: str):
    """
    Preprocesses tshark JSON output into standardized CSV format.
    
    Args:
        input_path (str): Path to raw tshark JSON file.
        output_path (str): Path to save processed CSV file.
    """
    logging.info(f"Reading raw tshark JSON data from {input_path}...")
    
    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        logging.error(f"Input file not found: {input_path}")
        return
    except json.JSONDecodeError as e:
        logging.error(f"Invalid JSON format: {e}")
        return
    
    # Extract packets
    records = []
    for packet in data:
        layers = packet.get('_source', {}).get('layers', {})
        
        # Extract basic fields
        record = {
            'ts': float(layers.get('frame.time_epoch', [0])[0]) if 'frame.time_epoch' in layers else 0,
            'src_ip': layers.get('ip.src', [None])[0],
            'dst_ip': layers.get('ip.dst', [None])[0],
            'src_port': layers.get('tcp.srcport', layers.get('udp.srcport', [0]))[0],
            'dst_port': layers.get('tcp.dstport', layers.get('udp.dstport', [0]))[0],
            'tot_size': int(layers.get('frame.len', [0])[0]),
            'protocol_type': 'TCP' if 'tcp' in layers else ('UDP' if 'udp' in layers else 'OTHER'),
        }
        
        records.append(record)
    
    # Convert to DataFrame and save
    df = pd.DataFrame(records)
    
    # Apply same standardization as CSV processing
    df['flow_id'] = df.apply(
        lambda row: f"{row['src_ip']}:{row['src_port']}-{row['dst_ip']}:{row['dst_port']}-{row['protocol_type']}",
        axis=1
    )
    
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_file, index=False)
    
    logging.info(f"Successfully preprocessed {len(df)} packets from JSON.")
    logging.info(f"Processed data saved to {output_path}")


def auto_detect_and_preprocess(input_path: str, output_path: str):
    """
    Auto-detect input format and preprocess accordingly.
    
    Args:
        input_path (str): Path to input file.
        output_path (str): Path to save output file.
    """
    path = Path(input_path)
    suffix = path.suffix.lower()
    
    if suffix == '.json':
        preprocess_tshark_json(input_path, output_path)
    elif suffix in ['.csv', '.txt']:
        preprocess_tshark_csv(input_path, output_path)
    else:
        logging.warning(f"Unknown file extension '{suffix}', attempting CSV parsing...")
        preprocess_tshark_csv(input_path, output_path)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Preprocess raw tshark/PCAP data.")
    parser.add_argument(
        "--input", 
        type=str, 
        required=True, 
        help="Path to the raw tshark output file (CSV or JSON)."
    )
    parser.add_argument(
        "--output", 
        type=str, 
        required=True, 
        help="Path to save the processed, structured CSV file."
    )
    parser.add_argument(
        "--format",
        type=str,
        choices=['csv', 'json', 'auto'],
        default='auto',
        help="Input format (csv, json, or auto-detect)."
    )
    
    args = parser.parse_args()
    
    if args.format == 'auto':
        auto_detect_and_preprocess(args.input, args.output)
    elif args.format == 'csv':
        preprocess_tshark_csv(args.input, args.output)
    elif args.format == 'json':
        preprocess_tshark_json(args.input, args.output)
