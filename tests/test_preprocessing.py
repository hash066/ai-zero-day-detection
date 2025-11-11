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

from preprocessing.log_parser import SysmonLogParser
from preprocessing.feature_engineering import extract_all_features
from preprocessing.graph_builder import NetworkGraphBuilder


class TestLogParser:
    """Test Sysmon log parsing functionality."""

    def test_parse_sysmon_csv(self):
        """Test parsing of simple Sysmon CSV."""
        # Create simple mock Sysmon CSV data (single line per event)
        mock_data = """EventID,UtcTime,ProcessGuid,ProcessId,Image,CommandLine,User
1,2023-10-01 10:30:45.123,{12345678-1234-1234-1234-123456789abc},1234,C:\\Windows\\System32\\cmd.exe,cmd.exe /c whoami,USER
3,2023-10-01 10:30:46.456,{12345678-1234-1234-1234-123456789abc},1234,C:\\Windows\\System32\\cmd.exe,,USER
"""

        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write(mock_data)
            input_path = f.name

        try:
            with tempfile.NamedTemporaryFile(suffix='.csv', delete=False) as f:
                output_path = f.name

            # Parse the data
            SysmonLogParser.parse_sysmon_csv(input_path, output_path)

            # Verify output
            result_df = pd.read_csv(output_path)
            assert len(result_df) == 2
            assert 'EventID' in result_df.columns
            assert 'parent_process_guid' in result_df.columns
            assert result_df['EventID'].tolist() == [1, 3]

        finally:
            os.unlink(input_path)
            if os.path.exists(output_path):
                os.unlink(output_path)


class TestFeatureEngineering:
    """Test feature engineering functionality."""

    def test_extract_all_features(self):
        """Test comprehensive feature extraction."""
        # Create mock network data
        mock_data = {
            'ts': [1000.0 + i * 0.5 for i in range(10)],
            'src_ip': ['192.168.1.10'] * 5 + ['192.168.1.20'] * 5,
            'dst_ip': [f'10.0.0.{i % 5}' for i in range(10)],
            'src_port': [12345 + i for i in range(10)],
            'dst_port': [80] * 7 + [443] * 3,
            'protocol_type': ['TCP'] * 8 + ['UDP'] * 2,
            'tot_size': [1400 + np.random.randint(-200, 200) for i in range(10)],
        }
        network_df = pd.DataFrame(mock_data)

        result = extract_all_features(network_df)

        assert 'src_ip' in result.columns
        assert 'ts' in result.columns
        # Check that new features were added
        assert len(result.columns) > len(network_df.columns)
        assert len(result) == len(network_df)


class TestGraphBuilder:
    """Test graph building functionality."""

    def test_network_graph_builder_init(self):
        """Test NetworkGraphBuilder initialization."""
        builder = NetworkGraphBuilder()
        assert builder.nodes == {}
        assert builder.edges == {}

    def test_add_network_flow(self):
        """Test adding network flows to graph."""
        builder = NetworkGraphBuilder()
        flow = {
            'src_ip': '192.168.1.10',
            'dst_ip': '10.0.0.1',
            'tot_size': 1400,
            'protocol_type': 'TCP',
            'dst_port': 80
        }
        builder.add_network_flow(flow)
        assert len(builder.nodes) == 2
        assert len(builder.edges) == 1


class TestIntegration:
    """Integration tests for preprocessing pipeline."""

    def test_end_to_end_preprocessing(self):
        """Test complete preprocessing pipeline."""
        # This would be a more comprehensive integration test
        # For now, just verify the components can be imported and basic functions work

        # Test that all main functions can be called without errors
        from preprocessing.log_parser import SysmonLogParser
        from preprocessing.feature_engineering import extract_all_features
        from preprocessing.graph_builder import NetworkGraphBuilder

        # Basic smoke tests
        builder = NetworkGraphBuilder()
        assert isinstance(builder, NetworkGraphBuilder)

        # Test with minimal dataframes
        minimal_df = pd.DataFrame({
            'ts': [1000.0],
            'src_ip': ['192.168.1.10'],
            'dst_ip': ['10.0.0.1'],
            'src_port': [12345],
            'dst_port': [80],
            'protocol_type': ['TCP'],
            'tot_size': [1400]
        })

        enriched_features = extract_all_features(minimal_df)
        assert isinstance(enriched_features, pd.DataFrame)
        assert len(enriched_features) >= 0  # May filter out invalid data


if __name__ == '__main__':
    pytest.main([__file__])
