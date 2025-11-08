"""
Preprocesses raw Sysmon CSV logs into a structured format.

This script reads the complex, multi-line format of raw Sysmon logs
(as exported from Windows Event Viewer) and flattens them into a clean,
one-row-per-event CSV file. This structured output is the required input
for the `sysmon_features.py` feature engineering script.
"""

import argparse
import logging
import pandas as pd
import re
from pathlib import Path
from typing import Dict, Any

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def parse_sysmon_details(details: str) -> Dict[str, Any]:
    """
    Parses the detailed, multi-line string from a Sysmon log entry.

    Args:
        details (str): The string containing the event details.

    Returns:
        A dictionary with the parsed key-value pairs.
    """
    parsed_data = {}
    # Regex to capture key-value pairs, handling various formats
    # It looks for a key (alphanumeric, no spaces) followed by a colon,
    # and then captures the rest of the line as the value.
    pattern = re.compile(r'^\s*([a-zA-Z0-9\s_]+):\s*(.*)')
    
    for line in details.splitlines():
        match = pattern.match(line)
        if match:
            key, value = match.groups()
            # Clean up the key: remove spaces and make it snake_case
            key = key.strip().replace(' ', '_').lower()
            parsed_data[key] = value.strip()
            
    return parsed_data

def preprocess_sysmon_logs(input_path: str, output_path: str):
    """
    Reads a raw Sysmon CSV, parses it, and saves a structured CSV.

    Args:
        input_path (str): The path to the raw Sysmon CSV file.
        output_path (str): The path to save the processed CSV file.
    """
    logging.info(f"Reading raw Sysmon data from {input_path}...")
    try:
        # Use a less common separator to handle commas within the details
        df = pd.read_csv(input_path, sep=',', quotechar='"', engine='python')
    except FileNotFoundError:
        logging.error(f"Input file not found: {input_path}")
        return
        
    # The last column is assumed to contain the detailed event data
    details_column = df.columns[-1]
    
    logging.info("Parsing Sysmon event details...")
    # Apply the parsing function to each row's detail string
    parsed_details_list = df[details_column].dropna().apply(parse_sysmon_details)
    
    # Convert the list of dictionaries into a DataFrame
    details_df = pd.DataFrame(parsed_details_list.tolist())
    
    # Combine the initial columns (like Level, Event ID) with the new parsed columns
    # Drop the original details column as it's now redundant
    processed_df = pd.concat([df.drop(columns=[details_column]), details_df], axis=1)
    
    # --- Data Cleaning and Standardization ---
    # Rename columns to match expected formats for feature engineering
    column_renames = {
        'date_and_time': 'timestamp',
        'event_id': 'event_id',
        'task_category': 'task_category',
        # Add other renames if necessary based on parsed keys
    }
    processed_df.rename(columns=lambda c: column_renames.get(c.lower().replace(' ', '_'), c), inplace=True)
    
    # Convert timestamp to a more standard format if needed
    if 'timestamp' in processed_df.columns:
        processed_df['timestamp'] = pd.to_datetime(processed_df['timestamp'], errors='coerce')

    # Save the processed data
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    processed_df.to_csv(output_file, index=False)
    
    logging.info(f"Successfully preprocessed {len(processed_df)} events.")
    logging.info(f"Cleaned Sysmon data saved to {output_path}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Preprocess raw Sysmon CSV logs.")
    parser.add_argument(
        "--input", 
        type=str, 
        required=True, 
        help="Path to the raw Sysmon CSV file."
    )
    parser.add_argument(
        "--output", 
        type=str, 
        required=True, 
        help="Path to save the processed, structured CSV file."
    )
    
    args = parser.parse_args()
    
    preprocess_sysmon_logs(args.input, args.output)
