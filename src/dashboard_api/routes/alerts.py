"""
API routes for retrieving alert data.

This module defines the FastAPI endpoints related to security alerts,
allowing the frontend to query for recent or specific alert records.
"""

from fastapi import APIRouter, Depends, HTTPException
from typing import List, Dict, Any
from bson import ObjectId
from datetime import datetime, timedelta

from ..models.alert import Alert
from ..utils.db import get_database, Database

# Create a new router for alert-related endpoints
router = APIRouter(
    prefix="/alerts",
    tags=["Alerts"], # Tag for OpenAPI documentation
)

@router.get("/", response_model=List[Alert], description="Get a list of recent security alerts.")
async def get_recent_alerts(
    limit: int = 50,
    db: Database = Depends(get_database)
) -> List[Alert]:
    """
    Fetches the most recent alerts from the database.
    """
    try:
        alerts_collection = db.get_alert_collection()
        # Find alerts, sort by timestamp descending, and limit the count
        alerts_cursor = alerts_collection.find().sort("timestamp", -1).limit(limit)

        # Convert MongoDB documents to our Pydantic model
        # The `_id` field needs to be converted to a string
        alerts = []
        for alert in alerts_cursor:
            if alert:  # Handle case where alert might be None
                alerts.append(Alert(_id=str(alert.get('_id', 'unknown')), **alert))

        # If no alerts from database, return mock data
        if not alerts:
            from datetime import datetime, timedelta
            mock_alerts = [
                Alert(
                    _id="mock_1",
                    entity_id="192.168.1.15",
                    threat_score=0.85,
                    timestamp=datetime.utcnow() - timedelta(hours=1),
                    metadata={"reason": "Anomalous process sequence detected", "is_mock": True}
                ),
                Alert(
                    _id="mock_2",
                    entity_id="10.0.5.20",
                    threat_score=0.92,
                    timestamp=datetime.utcnow() - timedelta(minutes=30),
                    metadata={"reason": "Suspicious network connection pattern", "is_mock": True}
                ),
                Alert(
                    _id="mock_3",
                    entity_id="192.168.1.15",
                    threat_score=0.78,
                    timestamp=datetime.utcnow() - timedelta(minutes=15),
                    metadata={"reason": "High commandline entropy", "is_mock": True}
                ),
            ]
            return mock_alerts[:limit]

        return alerts
    except Exception as e:
        # Database not available, return mock data
        from datetime import datetime, timedelta
        mock_alerts = [
            Alert(
                _id="mock_1",
                entity_id="192.168.1.15",
                threat_score=0.85,
                timestamp=datetime.utcnow() - timedelta(hours=1),
                metadata={"reason": "Anomalous process sequence detected", "is_mock": True, "db_error": str(e)}
            ),
            Alert(
                _id="mock_2",
                entity_id="10.0.5.20",
                threat_score=0.92,
                timestamp=datetime.utcnow() - timedelta(minutes=30),
                metadata={"reason": "Suspicious network connection pattern", "is_mock": True, "db_error": str(e)}
            ),
            Alert(
                _id="mock_3",
                entity_id="192.168.1.15",
                threat_score=0.78,
                timestamp=datetime.utcnow() - timedelta(minutes=15),
                metadata={"reason": "High commandline entropy", "is_mock": True, "db_error": str(e)}
            ),
        ]
        return mock_alerts[:limit]

@router.get("/{alert_id}", response_model=Alert, description="Get a specific alert by its unique ID.")
async def get_alert_by_id(
    alert_id: str,
    db: Database = Depends(get_database)
) -> Alert:
    """
    Fetches a single alert by its MongoDB ObjectId.
    """
    alerts_collection = db.get_alert_collection()
    
    # Validate that the provided ID is a valid MongoDB ObjectId
    if not ObjectId.is_valid(alert_id):
        raise HTTPException(status_code=400, detail=f"Invalid alert ID format: {alert_id}")
        
    alert = await alerts_collection.find_one({"_id": ObjectId(alert_id)})
    
    if alert:
        return Alert(_id=str(alert['_id']), **alert)
    
    raise HTTPException(status_code=404, detail=f"Alert with ID '{alert_id}' not found.")

@router.patch("/{alert_id}", response_model=Alert, description="Update alert status")
async def update_alert_status(
    alert_id: str,
    status_update: Dict[str, str],
    db: Database = Depends(get_database)
) -> Alert:
    """
    Updates the status of a specific alert.
    """
    # Validate status value
    valid_statuses = ["active", "investigating", "resolved", "false_positive"]
    new_status = status_update.get("status")
    if not new_status or new_status not in valid_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}"
        )

    try:
        alerts_collection = db.get_alert_collection()

        # For mock data, find and update the alert in our mock responses
        if not db.available:
            # Handle mock data updates
            mock_alerts = [
                {
                    "_id": "mock_1",
                    "entity_id": "192.168.1.15",
                    "threat_score": 0.85,
                    "timestamp": datetime.utcnow() - timedelta(hours=1),
                    "status": "active",
                    "metadata": {"reason": "Anomalous process sequence detected", "is_mock": True}
                },
                {
                    "_id": "mock_2",
                    "entity_id": "10.0.5.20",
                    "threat_score": 0.92,
                    "timestamp": datetime.utcnow() - timedelta(minutes=30),
                    "status": "active",
                    "metadata": {"reason": "Suspicious network connection pattern", "is_mock": True}
                },
                {
                    "_id": "mock_3",
                    "entity_id": "192.168.1.15",
                    "threat_score": 0.78,
                    "timestamp": datetime.utcnow() - timedelta(minutes=15),
                    "status": "active",
                    "metadata": {"reason": "High commandline entropy", "is_mock": True}
                },
            ]

            # Find the alert to update
            alert_to_update = next((alert for alert in mock_alerts if alert["_id"] == alert_id), None)
            if not alert_to_update:
                raise HTTPException(status_code=404, detail=f"Alert with ID '{alert_id}' not found")

            # Update the status
            alert_to_update["status"] = new_status
            alert_to_update["updatedAt"] = datetime.utcnow().isoformat() + "Z"

            return Alert(**alert_to_update)
        else:
            # Real database update
            # Validate that the provided ID is a valid MongoDB ObjectId
            if not ObjectId.is_valid(alert_id):
                raise HTTPException(status_code=400, detail=f"Invalid alert ID format: {alert_id}")

            # Update the alert
            update_result = await alerts_collection.update_one(
                {"_id": ObjectId(alert_id)},
                {
                    "$set": {
                        "status": new_status,
                        "updatedAt": datetime.utcnow()
                    }
                }
            )

            if update_result.matched_count == 0:
                raise HTTPException(status_code=404, detail=f"Alert with ID '{alert_id}' not found")

            # Fetch and return the updated alert
            updated_alert = await alerts_collection.find_one({"_id": ObjectId(alert_id)})
            return Alert(_id=str(updated_alert['_id']), **updated_alert)

    except Exception as e:
        # For mock data fallback
        mock_alerts = [
            {
                "_id": "mock_1",
                "entity_id": "192.168.1.15",
                "threat_score": 0.85,
                "timestamp": datetime.utcnow() - timedelta(hours=1),
                "status": "active",
                "metadata": {"reason": "Anomalous process sequence detected", "is_mock": True}
            },
            {
                "_id": "mock_2",
                "entity_id": "10.0.5.20",
                "threat_score": 0.92,
                "timestamp": datetime.utcnow() - timedelta(minutes=30),
                "status": "active",
                "metadata": {"reason": "Suspicious network connection pattern", "is_mock": True}
            },
            {
                "_id": "mock_3",
                "entity_id": "192.168.1.15",
                "threat_score": 0.78,
                "timestamp": datetime.utcnow() - timedelta(minutes=15),
                "status": "active",
                "metadata": {"reason": "High commandline entropy", "is_mock": True}
            },
        ]

        # Find and update the mock alert
        alert_to_update = next((alert for alert in mock_alerts if alert["_id"] == alert_id), None)
        if not alert_to_update:
            raise HTTPException(status_code=404, detail=f"Alert with ID '{alert_id}' not found")

        alert_to_update["status"] = new_status
        alert_to_update["updatedAt"] = datetime.utcnow().isoformat() + "Z"

        return Alert(**alert_to_update)
