"""
API routes for system metrics and dashboard statistics.

This module defines endpoints for retrieving system performance metrics
and dashboard overview statistics.
"""

from fastapi import APIRouter, Depends
from typing import Dict, Any
from datetime import datetime, timedelta
import random

from ..utils.db import get_database, Database

# Create routers for different metric categories
router = APIRouter()

# --- Dashboard Statistics ---
@router.get("/dashboard/stats", response_model=Dict[str, Any], description="Get dashboard overview statistics")
async def get_dashboard_stats(db: Database = Depends(get_database)) -> Dict[str, Any]:
    """
    Returns dashboard overview statistics including alerts, threats, devices, and trends.
    """
    alerts_collection = db.get_alert_collection()

    # Get alert counts
    total_alerts = alerts_collection.count_documents({})
    active_threats = alerts_collection.count_documents({"threat_score": {"$gte": 0.7}})

    # Generate time series data for trends (last 24 hours)
    trends_data = generate_trends_data()

    # Mock device count and risk score (would come from device collection in real implementation)
    devices_monitored = 45
    avg_risk_score = 6.3

    return {
        "totalAlerts": total_alerts,
        "activeThreats": active_threats,
        "devicesMonitored": devices_monitored,
        "avgRiskScore": avg_risk_score,
        "trendsData": trends_data
    }

# --- System Metrics ---
@router.get("/metrics/system", response_model=Dict[str, Any], description="Get real-time system performance metrics")
async def get_system_metrics() -> Dict[str, Any]:
    """
    Returns current system performance metrics.
    """
    # In a real implementation, these would come from system monitoring tools
    # For now, return mock data with some randomization
    return {
        "cpuUsage": round(60 + random.random() * 20, 1),  # 60-80%
        "memoryUsage": round(65 + random.random() * 20, 1),  # 65-85%
        "networkTraffic": round(200 + random.random() * 100, 1),  # 200-300 MB/s
        "activeConnections": 1200 + int(random.random() * 200),  # 1200-1400 connections
        "anomalyScore": round(5.5 + random.random() * 2, 2),  # 5.5-7.5
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }

def generate_trends_data() -> Dict[str, Any]:
    """
    Generate mock time series data for dashboard trends.
    """
    now = datetime.utcnow()
    alerts_trend = []
    anomaly_trend = []
    network_trend = []

    # Generate data points for last 24 hours (every hour)
    for i in range(24):
        timestamp = (now - timedelta(hours=23-i)).isoformat() + "Z"

        # Alerts trend (0-20 alerts per hour)
        alerts_trend.append({
            "timestamp": timestamp,
            "value": int(random.random() * 20)
        })

        # Anomaly score trend (0-10)
        anomaly_trend.append({
            "timestamp": timestamp,
            "value": round(random.random() * 10, 1)
        })

        # Network traffic trend (50-300 MB/s)
        network_trend.append({
            "timestamp": timestamp,
            "value": round(50 + random.random() * 250, 1)
        })

    return {
        "alerts": alerts_trend,
        "anomalyScore": anomaly_trend,
        "networkTraffic": network_trend
    }
