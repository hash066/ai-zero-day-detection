"""
API routes for device management.

This module defines endpoints for retrieving and managing monitored devices,
including device isolation capabilities.
"""

from fastapi import APIRouter, Depends, HTTPException
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import random

from ..utils.db import get_database, Database

router = APIRouter()

# Mock device data (in production, this would come from a device collection)
MOCK_DEVICES = [
    {
        "id": "device-001",
        "name": "WS-USER-145",
        "ip": "192.168.1.145",
        "status": "compromised",
        "riskScore": 9.2,
        "lastSeen": (datetime.utcnow() - timedelta(minutes=5)).isoformat() + "Z",
        "os": "Windows 11",
        "macAddress": "00:11:22:33:44:55",
        "location": "Office A",
        "cpuUsage": 78.5,
        "memoryUsage": 82.3,
        "networkActivity": "High"
    },
    {
        "id": "device-002",
        "name": "SRV-DB-01",
        "ip": "10.0.0.5",
        "status": "isolated",
        "riskScore": 8.7,
        "lastSeen": (datetime.utcnow() - timedelta(minutes=15)).isoformat() + "Z",
        "os": "Ubuntu 22.04 LTS",
        "macAddress": "AA:BB:CC:DD:EE:FF",
        "location": "Server Room",
        "cpuUsage": 45.2,
        "memoryUsage": 67.8,
        "networkActivity": "Isolated"
    },
    {
        "id": "device-003",
        "name": "WS-USER-067",
        "ip": "192.168.1.67",
        "status": "online",
        "riskScore": 7.5,
        "lastSeen": datetime.utcnow().isoformat() + "Z",
        "os": "Windows 11",
        "macAddress": "11:22:33:44:55:66",
        "location": "Office B",
        "cpuUsage": 23.1,
        "memoryUsage": 45.6,
        "networkActivity": "Normal"
    },
    {
        "id": "device-004",
        "name": "WS-USER-089",
        "ip": "192.168.1.89",
        "status": "online",
        "riskScore": 5.8,
        "lastSeen": datetime.utcnow().isoformat() + "Z",
        "os": "macOS 14",
        "macAddress": "77:88:99:AA:BB:CC",
        "location": "Office C",
        "cpuUsage": 12.3,
        "memoryUsage": 34.5,
        "networkActivity": "Low"
    },
    {
        "id": "device-005",
        "name": "SRV-WEB-02",
        "ip": "10.0.0.12",
        "status": "online",
        "riskScore": 3.2,
        "lastSeen": datetime.utcnow().isoformat() + "Z",
        "os": "CentOS 8",
        "macAddress": "DD:EE:FF:11:22:33",
        "location": "DMZ",
        "cpuUsage": 67.8,
        "memoryUsage": 78.9,
        "networkActivity": "High"
    }
]

@router.get("/devices", response_model=List[Dict[str, Any]], description="Get list of all monitored devices")
async def get_devices(
    status: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
) -> List[Dict[str, Any]]:
    """
    Returns a list of all monitored devices with optional filtering.
    """
    devices = MOCK_DEVICES.copy()

    # Apply status filter if provided
    if status:
        devices = [d for d in devices if d["status"] == status]

    # Apply pagination
    start_idx = offset
    end_idx = start_idx + limit
    paginated_devices = devices[start_idx:end_idx]

    # Update last seen times to be more realistic
    for device in paginated_devices:
        if device["status"] != "isolated":
            # Add some randomization to last seen times
            minutes_ago = random.randint(0, 30)
            device["lastSeen"] = (datetime.utcnow() - timedelta(minutes=minutes_ago)).isoformat() + "Z"

    return paginated_devices

@router.get("/devices/{device_id}", response_model=Dict[str, Any], description="Get detailed device information")
async def get_device_by_id(device_id: str) -> Dict[str, Any]:
    """
    Returns detailed information for a specific device.
    """
    device = next((d for d in MOCK_DEVICES if d["id"] == device_id), None)

    if not device:
        raise HTTPException(status_code=404, detail=f"Device with ID '{device_id}' not found")

    # Add more detailed information for individual device view
    detailed_device = device.copy()
    detailed_device.update({
        "processes": [
            {"name": "chrome.exe", "cpu": 15.2, "memory": 234},
            {"name": "explorer.exe", "cpu": 2.1, "memory": 89},
            {"name": "python.exe", "cpu": 8.7, "memory": 156}
        ],
        "networkConnections": [
            {"remoteIp": "8.8.8.8", "port": 53, "protocol": "UDP"},
            {"remoteIp": "13.107.21.200", "port": 443, "protocol": "TCP"}
        ],
        "securityEvents": [
            {
                "timestamp": (datetime.utcnow() - timedelta(hours=2)).isoformat() + "Z",
                "type": "Login Attempt",
                "severity": "low"
            }
        ],
        "uptime": "2 days, 4 hours",
        "diskUsage": 68.5
    })

    return detailed_device

@router.post("/devices/{device_id}/isolate", response_model=Dict[str, Any], description="Isolate a compromised device")
async def isolate_device(device_id: str) -> Dict[str, Any]:
    """
    Isolates a device from the network to prevent threat spread.
    """
    device = next((d for d in MOCK_DEVICES if d["id"] == device_id), None)

    if not device:
        raise HTTPException(status_code=404, detail=f"Device with ID '{device_id}' not found")

    # In a real implementation, this would trigger network isolation
    # For now, just update the device status
    device["status"] = "isolated"
    device["networkActivity"] = "Isolated"

    return {
        "id": device_id,
        "name": device["name"],
        "status": "isolated",
        "isolationTime": datetime.utcnow().isoformat() + "Z",
        "message": f"Device {device['name']} successfully isolated from network"
    }
