"""
Main entrypoint for the FastAPI Dashboard API.

This application serves the backend API for the zero-day threat detection
dashboard. It provides endpoints for querying threat intelligence data,
such as recent alerts and device risk scores.
"""

from fastapi import FastAPI
from .routes import alerts

# --- FastAPI App Initialization ---
app = FastAPI(
    title="Zero-Day Threat Detector API",
    description="API for visualizing security alerts and threat intelligence.",
    version="1.0.0",
)

# --- Include API Routers ---
# Include the routes for alert data from the `alerts.py` module.
# This keeps the main application file clean and modular.
app.include_router(alerts.router)

# --- Root Endpoint ---
@app.get("/", tags=["Root"])
async def read_root():
    """
    Root endpoint providing a welcome message.
    """
    return {"message": "Welcome to the Zero-Day Threat Detector API"}

# --- Health Check Endpoint ---
@app.get("/health", tags=["Health"])
async def health_check():
    """
    A simple health check endpoint to confirm the API is running.
    """
    return {"status": "ok"}

# --- (Optional) Add dummy data for demonstration ---
# This part is useful for frontend development without a live database.
# In a production environment, this would be removed.
@app.on_event("startup")
async def add_dummy_data_on_startup():
    from .utils.db import get_database
    from .models.alert import Alert
    from datetime import datetime, timedelta
    
    db = get_database()
    alerts_collection = db.get_alert_collection()
    
    # Clear existing dummy data to avoid duplicates on reload
    alerts_collection.delete_many({"metadata.is_dummy": True})
    
    # Add a few sample alerts if the collection is empty
    if alerts_collection.count_documents({}) == 0:
        dummy_alerts = [
            {
                "entity_id": "192.168.1.15",
                "threat_score": 0.85,
                "timestamp": datetime.utcnow() - timedelta(hours=1),
                "metadata": {"reason": "Anomalous process sequence detected", "is_dummy": True}
            },
            {
                "entity_id": "10.0.5.20",
                "threat_score": 0.92,
                "timestamp": datetime.utcnow() - timedelta(minutes=30),
                "metadata": {"reason": "Suspicious network connection pattern", "is_dummy": True}
            },
            {
                "entity_id": "192.168.1.15",
                "threat_score": 0.78,
                "timestamp": datetime.utcnow() - timedelta(minutes=15),
                "metadata": {"reason": "High commandline entropy", "is_dummy": True}
            },
        ]
        
        # Pydantic model doesn't have `_id`, so we convert to dict
        alerts_to_insert = [Alert(**alert, _id=None).model_dump(exclude={'id'}) for alert in dummy_alerts]
        
        alerts_collection.insert_many(alerts_to_insert)
        print("INFO:     Added dummy alert data to the database.")

