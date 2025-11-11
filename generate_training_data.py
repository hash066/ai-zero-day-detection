#!/usr/bin/env python3
"""
Generate training data for ML models from sample Sysmon logs.

This script processes the sample Sysmon data through the preprocessing pipeline
to create feature-rich training data for LSTM and GNN models.
"""

import sys
import pandas as pd
from pathlib import Path
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from preprocessing.log_parser import SysmonLogParser
from preprocessing.feature_engineering import extract_all_features

def main():
    print("🔧 Generating Training Data for ML Models")
    print("=" * 50)

    # Load sample Sysmon data
    csv_path = "kafka_pipeline/sample_logs/sysmon_logs.csv"
    print(f"📊 Loading sample data from: {csv_path}")

    try:
        # Load a subset for training (first 10,000 rows)
        df = pd.read_csv(csv_path, nrows=10000)
        print(f"✅ Loaded {len(df)} Sysmon events")

        # Parse the Sysmon data
        print("\n🔄 Parsing Sysmon data...")
        import tempfile
        import os

        # Create temporary output file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as temp_file:
            temp_output_path = temp_file.name

        try:
            # Parse using the correct method
            SysmonLogParser.parse_sysmon_csv(csv_path, temp_output_path)
            parsed_df = pd.read_csv(temp_output_path)
            print(f"✅ Parsed {len(parsed_df)} events with parent-child relationships")
        finally:
            # Clean up temp file
            if os.path.exists(temp_output_path):
                os.unlink(temp_output_path)

        # Engineer features
        print("\n⚙️ Engineering features...")
        features_df = extract_all_features(parsed_df)
        print(f"✅ Generated {len(features_df)} feature vectors with {len(features_df.columns)} features")

        # Save training data
        output_dir = Path("data/processed")
        output_dir.mkdir(parents=True, exist_ok=True)

        training_data_path = output_dir / "training_features.csv"
        features_df.to_csv(training_data_path, index=False)
        print(f"💾 Saved training data to: {training_data_path}")

        # Show feature summary
        print("\n📊 Feature Summary:")
        print(f"   - Total samples: {len(features_df)}")
        print(f"   - Feature columns: {len(features_df.columns)}")
        print(f"   - Sample features: {list(features_df.columns[:10])}...")

        # Check for temporal features needed by LSTM
        temporal_features = [
            'process_count_per_minute', 'network_connections_per_minute',
            'file_operations_per_minute', 'registry_operations_per_minute',
            'memory_usage_trend', 'cpu_usage_trend', 'entropy_trend',
            'process_lifetime_avg', 'parent_child_ratio', 'sibling_count'
        ]

        available_temporal = [f for f in temporal_features if f in features_df.columns]
        print(f"   - Temporal features available: {len(available_temporal)}/{len(temporal_features)}")

        if len(available_temporal) < len(temporal_features):
            missing = set(temporal_features) - set(available_temporal)
            print(f"   ⚠️  Missing temporal features: {missing}")

        print("\n🎉 Training data generation complete!")
        print(f"   Ready to train ML models with: {training_data_path}")

        return str(training_data_path)

    except Exception as e:
        print(f"❌ Error generating training data: {e}")
        return None

if __name__ == "__main__":
    training_data_path = main()
    if training_data_path:
        print(f"\n🚀 Next step: Train LSTM model")
        print(f"   python src/training/train_lstm.py --data {training_data_path}")
    else:
        print("\n❌ Failed to generate training data")
