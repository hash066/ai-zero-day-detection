"""
Database connection utility.

Provides a centralized way to connect to the MongoDB database and
access collections. This helps in managing the database connection
pool and makes it easy to mock the database during testing.
"""

from pymongo import MongoClient
from pymongo.collection import Collection

# --- Database Configuration ---
# In a real application, these would come from environment variables.
MONGO_CONNECTION_STRING = "mongodb://localhost:27017/"
DATABASE_NAME = "zero_day_detector"
ALERT_COLLECTION_NAME = "alerts"

class Database:
    """
    Manages the connection to the MongoDB database.
    """
    def __init__(self):
        self.client = MongoClient(MONGO_CONNECTION_STRING)
        self.db = self.client[DATABASE_NAME]

    def get_alert_collection(self) -> Collection:
        """
        Provides access to the alerts collection.

        Returns:
            The PyMongo Collection object for alerts.
        """
        return self.db[ALERT_COLLECTION_NAME]

# --- Singleton Database Instance ---
# This instance will be shared across the application to avoid creating
# multiple connection pools.
db_instance = Database()

def get_database() -> Database:
    """
    Dependency injector for the database instance.
    FastAPI will call this function to provide a database
    connection to the route handlers.
    """
    return db_instance
