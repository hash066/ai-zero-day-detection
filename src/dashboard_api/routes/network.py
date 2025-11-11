"""
API routes for network monitoring and flow data.

This module defines endpoints for retrieving network flow information
and anomaly detection data.
"""

from fastapi import APIRouter
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import random

router = APIRouter()

# Mock network flow data
PROTOCOLS = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS']
THREAT_LEVELS = ['low', 'medium', 'high', 'critical']

def generate_mock_network_flows(limit: int = 100) -> List[Dict[str, Any]]:
    """
    Generate mock network flow data for demonstration.
    """
    flows = []

    for i in range(limit):
        # Generate realistic IP addresses
        src_ip = f"192.168.{random.randint(1, 5)}.{random.randint(1, 254)}"
        dst_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"

        # Generate ports
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 53, 22, 3389, 21, 25, 110, 143, 993])

        protocol = random.choice(PROTOCOLS)

        # Generate traffic data
        bytes_count = random.randint(64, 150000)
        packets = random.randint(1, 1000)

        # Generate timestamp (last hour)
        minutes_ago = random.randint(0, 60)
        timestamp = (datetime.utcnow() - timedelta(minutes=minutes_ago)).isoformat() + "Z"

        # Generate anomaly score (0-10, higher = more anomalous)
        anomaly_score = round(random.random() * 10, 2)

        # Determine threat level based on anomaly score
        if anomaly_score >= 8:
            threat_level = "critical"
        elif anomaly_score >= 6:
            threat_level = "high"
        elif anomaly_score >= 4:
            threat_level = "medium"
        else:
            threat_level = "low"

        # Add description for high-threat flows
        description = ""
        if threat_level in ["high", "critical"]:
            descriptions = [
                "Suspicious outbound connection to known malicious IP",
                "Unusual port scanning activity detected",
                "Abnormal traffic pattern from internal host",
                "Potential data exfiltration attempt",
                "Connection to command and control server"
            ]
            description = random.choice(descriptions)

        flow = {
            "id": f"flow-{i+1:04d}",
            "srcIp": src_ip,
            "dstIp": dst_ip,
            "srcPort": src_port,
            "dstPort": dst_port,
            "protocol": protocol,
            "bytes": bytes_count,
            "packets": packets,
            "timestamp": timestamp,
            "anomalyScore": anomaly_score,
            "threatLevel": threat_level,
            "description": description,
            "direction": "outbound" if random.random() > 0.5 else "inbound",
            "duration": random.randint(1, 3600),  # seconds
            "flags": ["SYN", "ACK"] if protocol == "TCP" else []
        }

        flows.append(flow)

    # Sort by timestamp (most recent first)
    flows.sort(key=lambda x: x["timestamp"], reverse=True)

    return flows

@router.get("/network/flows", response_model=List[Dict[str, Any]], description="Get network flow data with anomaly detection")
async def get_network_flows(
    limit: int = 100,
    startTime: Optional[str] = None,
    endTime: Optional[str] = None,
    anomalyOnly: bool = False,
    threatLevel: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Returns network flow data with anomaly detection scores.
    """
    # Generate mock data
    flows = generate_mock_network_flows(limit * 2)  # Generate more than needed for filtering

    # Apply time filters if provided
    if startTime:
        start_dt = datetime.fromisoformat(startTime.replace('Z', '+00:00'))
        flows = [f for f in flows if datetime.fromisoformat(f["timestamp"].replace('Z', '+00:00')) >= start_dt]

    if endTime:
        end_dt = datetime.fromisoformat(endTime.replace('Z', '+00:00'))
        flows = [f for f in flows if datetime.fromisoformat(f["timestamp"].replace('Z', '+00:00')) <= end_dt]

    # Filter for high anomaly scores only
    if anomalyOnly:
        flows = [f for f in flows if f["anomalyScore"] >= 6.0]

    # Filter by threat level
    if threatLevel:
        flows = [f for f in flows if f["threatLevel"] == threatLevel]

    # Apply final limit
    return flows[:limit]

@router.get("/network/flows/{flow_id}", response_model=Dict[str, Any], description="Get detailed network flow information")
async def get_network_flow_by_id(flow_id: str) -> Dict[str, Any]:
    """
    Returns detailed information for a specific network flow.
    """
    # Generate a single detailed flow
    flows = generate_mock_network_flows(1)
    flow = flows[0].copy()
    flow["id"] = flow_id

    # Add more detailed information
    flow.update({
        "detailedAnalysis": {
            "entropy": round(random.random(), 3),
            "packetSizeDistribution": {
                "small": random.randint(10, 50),
                "medium": random.randint(20, 100),
                "large": random.randint(5, 30)
            },
            "timingAnalysis": {
                "interPacketDelay": round(random.random() * 100, 2),
                "burstRate": random.randint(1, 20)
            }
        },
        "geoLocation": {
            "srcCountry": random.choice(["United States", "Germany", "China", "Russia", "Japan"]),
            "dstCountry": random.choice(["United States", "Germany", "China", "Russia", "Japan"]),
            "srcASN": f"AS{random.randint(1000, 9999)}",
            "dstASN": f"AS{random.randint(1000, 9999)}"
        },
        "threatIntelligence": {
            "srcIpReputation": random.choice(["clean", "suspicious", "malicious"]),
            "dstIpReputation": random.choice(["clean", "suspicious", "malicious"]),
            "knownVulnerabilities": random.randint(0, 5),
            "blacklistHits": random.randint(0, 3)
        },
        "packetCapture": {
            "available": random.choice([True, False]),
            "size": f"{random.randint(1, 100)} MB" if random.random() > 0.5 else None
        }
    })

    return flow

@router.get("/network/stats", response_model=Dict[str, Any], description="Get network monitoring statistics")
async def get_network_stats() -> Dict[str, Any]:
    """
    Returns network monitoring overview statistics.
    """
    return {
        "totalFlows": random.randint(10000, 50000),
        "activeConnections": random.randint(500, 2000),
        "bytesPerSecond": random.randint(1000000, 50000000),
        "packetsPerSecond": random.randint(1000, 10000),
        "anomalousFlows": random.randint(10, 100),
        "blockedConnections": random.randint(0, 50),
        "topProtocols": {
            "TCP": random.randint(60, 80),
            "UDP": random.randint(15, 25),
            "ICMP": random.randint(3, 8),
            "Other": random.randint(2, 7)
        },
        "threatLevels": {
            "low": random.randint(50, 200),
            "medium": random.randint(10, 50),
            "high": random.randint(5, 20),
            "critical": random.randint(0, 5)
        }
    }
