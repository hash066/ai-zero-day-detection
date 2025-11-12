"""
Pydantic models for the Dashboard API.

These models define the data structures for request and response bodies,
ensuring type safety and providing automatic validation and documentation.
"""

from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from datetime import datetime

class Alert(BaseModel):
    """
    Represents a security alert record.
    """
    id: str = Field(default_factory=lambda: __import__('uuid').uuid4().hex, alias="_id", description="Unique identifier for the alert")
    entity_id: str = Field(..., description="The entity that triggered the alert (e.g., IP address, process GUID)")
    threat_score: float = Field(..., ge=0.0, le=1.0, description="The threat score [0, 1] that triggered the alert")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Timestamp of when the alert was generated")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional context about the alert")

    class Config:
        populate_by_name = True # Allows using both `id` and `_id`
        json_schema_extra = {
            "example": {
                "id": "654a7b9b3e6c1d7e8d5e8f6a",
                "entity_id": "192.168.1.105",
                "threat_score": 0.92,
                "timestamp": "2025-11-05T14:30:00Z",
                "metadata": {
                    "process_name": "powershell.exe",
                    "reason": "High reconstruction error and GNN anomaly score"
                }
            }
        }
