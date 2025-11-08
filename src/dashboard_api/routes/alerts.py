"""
API routes for retrieving alert data.

This module defines the FastAPI endpoints related to security alerts,
allowing the frontend to query for recent or specific alert records.
"""

from fastapi import APIRouter, Depends, HTTPException
from typing import List
from bson import ObjectId

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
    alerts_collection = db.get_alert_collection()
    # Find alerts, sort by timestamp descending, and limit the count
    alerts_cursor = alerts_collection.find().sort("timestamp", -1).limit(limit)
    
    # Convert MongoDB documents to our Pydantic model
    # The `_id` field needs to be converted to a string
    return [Alert(_id=str(alert['_id']), **alert) for alert in alerts_cursor]

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
