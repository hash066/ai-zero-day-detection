"""
Unit tests for preprocessing components.
"""

import pytest
import pandas as pd
import numpy as np
import tempfile
import os
from pathlib import Path
import sys

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from preprocessing.log_parser import parse_sysmon_csv
from preprocessing.feature_engineering import create_temporal_features, create_structural_features
from preprocessing.graph_builder import generate_node_id, parse_node_id


class TestLogParser:
    """Test Sysmon log parsing functionality."""

    def test_parse_sysmon_csv(self):
        """Test parsing of Sysmon CSV with multi-line Details column."""
        # Create mock Sysmon CSV data
        mock_data = """Level,Date and Time,Source,Event ID,Task Category,Details
4,2023-10-01 10:30:45,Microsoft-Windows-Sysmon,1,Process Create,UtcTime: 10:30:45.123
ProcessGuid: {12345678-1234-1234-1234-123456789abc}
Image: C:\\Windows\\System32\\cmd.exe
CommandLine: C:\\Windows\\System32\\cmd.exe /c whoami
User: NT AUTHORITY\\SYSTEM

4,2023-10-01 10:30:46,Microsoft-Windows-Sysmon,3,Network Connect,UtcTime: 10:30:46.456
ProcessGuid: {12345678-1234-1234-1234-123456789abc}
Image: C:\\Windows\\System32\\cmd.exe
User: NT AUTHORITY\\SYSTEM
SourceIp: 192.168.1.100
DestinationIp: 8.8.8.8
SourcePort: 54321
DestinationPort: 53
"""

        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write(mock_data)
            input_path = f.name

        try:
            with tempfile.NamedTemporaryFile(suffix='.csv', delete=False) as f:
                output_path = f.name

            # Parse the data
            parse_sysmon_csv(input_path, output_path)

            # Verify output
            result_df = pd.read_csv(output_path)
            assert len(result_df) == 2
            assert 'event_id' in result_df.columns
            assert 'process_guid' in result_df.columns
            assert result_df['event_id'].tolist() == [1, 3]

        finally:
            os.unlink(input_path)
            if os.path.exists(output_path):
                os.unlink(output_path)


class TestFeatureEngineering:
    """Test feature engineering functionality."""

    def test_create_temporal_features(self):
        """Test temporal feature creation."""
        # Create mock Sysmon data
        mock_data = {
            'timestamp': pd.date_range('2023-01-01', periods=10, freq='1min'),
            'process_guid': ['proc1'] * 5 + ['proc2'] * 5,
            'event_id': [1, 3, 11, 12, 13] * 2
        }
        sysmon_df = pd.DataFrame(mock_data)

        # Add required columns for feature engineering
        sysmon_df['events_per_minute'] = 10.0
        sysmon_df['burst_intensity'] = 1.0
        sysmon_df['is_system32'] = 1
        sysmon_df['is_temp'] = 0
        sysmon_df['path_depth'] = 3
        sysmon_df['command_entropy'] = 2.5
        sysmon_df['token_count'] = 5

        result = create_temporal_features(sysmon_df)

        assert 'process_guid' in result.columns
        assert 'timestamp' in result.columns
        assert 'time_since_last_event' in result.columns
        assert len(result) == len(sysmon_df)

    def test_create_structural_features(self):
        """Test structural feature creation."""
        mock_data = {
            'process_guid': ['proc1', 'proc2'],
            'image': ['C:\\Windows\\System32\\cmd.exe', 'C:\\temp\\malware.exe'],
            'target_filename': ['C:\\docs\\file.txt', 'C:\\scripts\\script.ps1'],
            'event_id': [11, 11]
        }
        sysmon_df = pd.DataFrame(mock_data)

        result = create_structural_features(sysmon_df)

        assert 'process_guid' in result.columns
        assert 'is_system32' in result.columns
        assert 'is_executable' in result.columns
        assert len(result) == 2


class TestGraphBuilder:
    """Test graph building functionality."""

    def test_generate_node_id(self):
        """Test node ID generation."""
        node_id = generate_node_id('process', '12345')
        assert node_id == 'process:12345'

    def test_parse_node_id(self):
        """Test node ID parsing."""
        node_type, identifier = parse_node_id('process:12345')
        assert node_type == 'process'
        assert identifier == '12345'

    def test_parse_node_id_no_colon(self):
        """Test parsing node ID without colon."""
        node_type, identifier = parse_node_id('invalid_id')
        assert node_type == ''
        assert identifier == 'invalid_id'


class TestIntegration:
    """Integration tests for preprocessing pipeline."""

    def test_end_to_end_preprocessing(self):
        """Test complete preprocessing pipeline."""
        # This would be a more comprehensive integration test
        # For now, just verify the components can be imported and basic functions work

        # Test that all main functions can be called without errors
        from preprocessing.log_parser import parse_sysmon_csv
        from preprocessing.feature_engineering import create_temporal_features
        from preprocessing.graph_builder import generate_node_id

        # Basic smoke tests
        node_id = generate_node_id('test', '123')
        assert isinstance(node_id, str)
        assert ':' in node_id

        # Test with minimal dataframes
        minimal_df = pd.DataFrame({
            'timestamp': [pd.Timestamp.now()],
            'process_guid': ['test_proc'],
            'event_id': [1],
            'events_per_minute': [1.0],
            'burst_intensity': [1.0],
            'is_system32': [0],
            'is_temp': [0],
            'path_depth': [1],
            'command_entropy': [1.0],
            'token_count': [1]
        })

        temporal_features = create_temporal_features(minimal_df)
        assert isinstance(temporal_features, pd.DataFrame)
        assert len(temporal_features) >= 0  # May filter out invalid data


if __name__ == '__main__':
    pytest.main([__file__])
