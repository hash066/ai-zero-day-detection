"""
Data validation schemas for AI Zero-Day Detection System.

Uses Pydantic for robust input validation and type safety.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator, model_validator
import pandas as pd
import numpy as np
from datetime import datetime
import ipaddress


class NetworkFlow(BaseModel):
    """Schema for network flow data validation."""

    src_ip: str = Field(..., description="Source IP address")
    dst_ip: str = Field(..., description="Destination IP address")
    src_port: int = Field(..., ge=0, le=65535, description="Source port")
    dst_port: int = Field(..., ge=0, le=65535, description="Destination port")
    protocol: str = Field(..., description="Protocol (TCP, UDP, etc.)")
    bytes_sent: int = Field(default=0, ge=0, description="Bytes sent")
    bytes_received: int = Field(default=0, ge=0, description="Bytes received")
    packets_sent: int = Field(default=0, ge=0, description="Packets sent")
    packets_received: int = Field(default=0, ge=0, description="Packets received")
    timestamp: datetime = Field(..., description="Flow timestamp")

    @field_validator('src_ip', 'dst_ip')
    @classmethod
    def validate_ip_address(cls, v):
        """Validate IP address format."""
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            raise ValueError(f'Invalid IP address: {v}')

    @field_validator('protocol')
    @classmethod
    def validate_protocol(cls, v):
        """Validate protocol is known."""
        valid_protocols = {'TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'FTP', 'SSH', 'DNS'}
        if v.upper() not in valid_protocols:
            # Allow unknown protocols but log warning
            pass
        return v.upper()


class SysmonEvent(BaseModel):
    """Schema for Sysmon event data validation."""

    EventID: int = Field(..., description="Sysmon event ID")
    TimeGenerated: datetime = Field(..., description="Event generation time")
    Computer: str = Field(..., description="Computer name")
    User: Optional[str] = Field(None, description="User associated with event")

    # Process events (EventID 1, 5)
    ProcessId: Optional[int] = Field(None, ge=0, description="Process ID")
    ParentProcessId: Optional[int] = Field(None, ge=0, description="Parent process ID")
    Image: Optional[str] = Field(None, description="Process image path")
    CommandLine: Optional[str] = Field(None, description="Process command line")

    # Network events (EventID 3)
    SourceIp: Optional[str] = Field(None, description="Source IP")
    SourcePort: Optional[int] = Field(None, ge=0, le=65535, description="Source port")
    DestinationIp: Optional[str] = Field(None, description="Destination IP")
    DestinationPort: Optional[int] = Field(None, ge=0, le=65535, description="Destination port")

    @field_validator('SourceIp', 'DestinationIp')
    @classmethod
    def validate_ip_address(cls, v):
        """Validate IP address if present."""
        if v is not None:
            try:
                ipaddress.ip_address(v)
            except ValueError:
                raise ValueError(f'Invalid IP address: {v}')
        return v


class TemporalFeatures(BaseModel):
    """Schema for temporal behavioral features."""

    src_port_entropy: float = Field(..., ge=0, le=10, description="Source port entropy")
    dst_port_entropy: float = Field(..., ge=0, le=10, description="Destination port entropy")
    src_ip_entropy: float = Field(..., ge=0, le=10, description="Source IP entropy")
    dst_ip_entropy: float = Field(..., ge=0, le=10, description="Destination IP entropy")
    packet_size_entropy: float = Field(..., ge=0, le=10, description="Packet size entropy")
    mean_inter_arrival: float = Field(..., ge=0, description="Mean inter-arrival time")
    std_inter_arrival: float = Field(..., ge=0, description="Std inter-arrival time")
    cv_inter_arrival: float = Field(..., ge=0, description="Coefficient of variation")
    burstiness: float = Field(-1, le=1, description="Burstiness index")
    periodicity_score: float = Field(0, le=1, description="Periodicity score")
    peak_hour: int = Field(0, ge=0, le=23, description="Peak activity hour")
    off_hours_ratio: float = Field(0, le=1, description="Off-hours activity ratio")
    hour_entropy: float = Field(0, le=5, description="Hour distribution entropy")
    connection_diversity: float = Field(0, le=1, description="Connection diversity")
    fan_out_ratio: float = Field(0, description="Fan-out ratio")
    fan_in_ratio: float = Field(0, description="Fan-in ratio")
    rare_protocol_ratio: float = Field(0, le=1, description="Rare protocol ratio")
    protocol_switching_rate: float = Field(0, le=1, description="Protocol switching rate")
    size_mean: float = Field(0, description="Mean packet size")
    size_std: float = Field(0, description="Std packet size")
    size_skewness: float = Field(description="Size distribution skewness")
    size_kurtosis: float = Field(description="Size distribution kurtosis")
    small_packet_ratio: float = Field(0, le=1, description="Small packet ratio")
    large_packet_ratio: float = Field(0, le=1, description="Large packet ratio")


class DetectionRequest(BaseModel):
    """Schema for anomaly detection requests."""

    temporal_data: List[TemporalFeatures] = Field(..., description="Temporal features")
    network_data: List[NetworkFlow] = Field(..., description="Network flow data")
    entity_id: str = Field(..., description="Entity identifier")
    entity_type: str = Field("system", description="Entity type")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional metadata")

    @model_validator(mode='after')
    def validate_data_consistency(self):
        """Validate that temporal and network data have same length."""
        if len(self.temporal_data) != len(self.network_data):
            raise ValueError(
                f"Temporal data ({len(self.temporal_data)}) and network data "
                f"({len(self.network_data)}) must have same length"
            )

        return self


class PipelineConfig(BaseModel):
    """Schema for pipeline configuration validation."""

    data: Dict[str, str] = Field(..., description="Data directory paths")
    collection: Dict[str, Any] = Field(..., description="Data collection settings")
    models: Dict[str, Any] = Field(..., description="ML model settings")
    streaming: Dict[str, Any] = Field(..., description="Streaming settings")
    inference: Dict[str, Any] = Field(..., description="Inference settings")

    @field_validator('data')
    @classmethod
    def validate_data_paths(cls, v):
        """Validate data directory paths exist or can be created."""
        required_keys = ['raw_dir', 'processed_dir', 'features_dir', 'graphs_dir']
        for key in required_keys:
            if key not in v:
                raise ValueError(f"Missing required data path: {key}")
        return v


class DataValidator:
    """Utility class for data validation operations."""

    @staticmethod
    def validate_network_dataframe(df: pd.DataFrame) -> Dict[str, Any]:
        """
        Validate pandas DataFrame containing network data.

        Args:
            df: DataFrame to validate

        Returns:
            Validation results
        """
        results = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'stats': {}
        }

        # Check required columns
        required_columns = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol']
        missing_columns = [col for col in required_columns if col not in df.columns]

        if missing_columns:
            results['valid'] = False
            results['errors'].append(f"Missing required columns: {missing_columns}")

        # Validate data types and ranges
        if 'src_port' in df.columns:
            invalid_ports = df[~df['src_port'].between(0, 65535)]
            if not invalid_ports.empty:
                results['errors'].append(f"Invalid source ports found: {len(invalid_ports)}")

        # Check for missing values
        missing_data = df.isnull().sum()
        if missing_data.any():
            results['warnings'].append(f"Missing values found: {missing_data[missing_data > 0].to_dict()}")

        # Basic statistics
        results['stats'] = {
            'rows': len(df),
            'columns': len(df.columns),
            'unique_src_ips': df['src_ip'].nunique() if 'src_ip' in df.columns else 0,
            'unique_dst_ips': df['dst_ip'].nunique() if 'dst_ip' in df.columns else 0,
            'protocols': df['protocol'].value_counts().to_dict() if 'protocol' in df.columns else {}
        }

        return results

    @staticmethod
    def validate_temporal_dataframe(df: pd.DataFrame) -> Dict[str, Any]:
        """
        Validate pandas DataFrame containing temporal features.

        Args:
            df: DataFrame to validate

        Returns:
            Validation results
        """
        results = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'stats': {}
        }

        # Check for expected feature columns
        expected_features = [
            'src_port_entropy', 'dst_port_entropy', 'src_ip_entropy', 'dst_ip_entropy',
            'packet_size_entropy', 'mean_inter_arrival', 'std_inter_arrival'
        ]

        missing_features = [feat for feat in expected_features if feat not in df.columns]
        if missing_features:
            results['warnings'].append(f"Missing expected features: {missing_features}")

        # Check for NaN/inf values
        if df.isnull().any().any():
            results['errors'].append("NaN values found in temporal features")

        if np.isinf(df.select_dtypes(include=[np.number])).any().any():
            results['errors'].append("Infinite values found in temporal features")

        # Validate ranges
        if 'src_port_entropy' in df.columns:
            invalid_entropy = df[~df['src_port_entropy'].between(0, 10)]
            if not invalid_entropy.empty:
                results['errors'].append("Invalid entropy values found")

        results['stats'] = {
            'rows': len(df),
            'columns': len(df.columns),
            'features': list(df.columns),
            'has_nan': df.isnull().any().any(),
            'has_inf': np.isinf(df.select_dtypes(include=[np.number])).any().any()
        }

        return results

    @staticmethod
    def sanitize_dataframe(df: pd.DataFrame) -> pd.DataFrame:
        """
        Sanitize DataFrame by handling missing values and outliers.

        Args:
            df: DataFrame to sanitize

        Returns:
            Sanitized DataFrame
        """
        # Create a copy to avoid modifying original
        sanitized = df.copy()

        # Fill missing numeric values with median
        numeric_columns = sanitized.select_dtypes(include=[np.number]).columns
        for col in numeric_columns:
            if sanitized[col].isnull().any():
                median_val = sanitized[col].median()
                sanitized[col].fillna(median_val, inplace=True)

        # Fill missing categorical values with mode
        categorical_columns = sanitized.select_dtypes(include=['object']).columns
        for col in categorical_columns:
            if sanitized[col].isnull().any():
                mode_val = sanitized[col].mode()
                if not mode_val.empty:
                    sanitized[col].fillna(mode_val[0], inplace=True)

        # Replace infinite values with large finite values
        sanitized.replace([np.inf, -np.inf], [1e10, -1e10], inplace=True)

        return sanitized
