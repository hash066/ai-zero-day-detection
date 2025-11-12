"""
Database connection utility.

Provides a centralized way to connect to the MongoDB database and
access collections. This helps in managing the database connection
pool and makes it easy to mock the database during testing.
"""

from pymongo import MongoClient
from pymongo.collection import Collection
from typing import Optional

# --- Database Configuration ---
# In a real application, these would come from environment variables.
import os
MONGO_CONNECTION_STRING = os.getenv("MONGO_CONNECTION_STRING", "mongodb://localhost:27017/")
DATABASE_NAME = os.getenv("DATABASE_NAME", "zero_day_detector")
ALERT_COLLECTION_NAME = "alerts"

class MockCursor:
    """Mock cursor for when database is not available."""
    def __init__(self, data):
        self.data = data

    def sort(self, *args, **kwargs):
        return self

    def limit(self, *args, **kwargs):
        return self

    def __iter__(self):
        return iter(self.data)

class MockCollection:
    """Mock collection for when database is not available."""
    def find(self, *args, **kwargs):
        return MockCursor([])

    def find_one(self, *args, **kwargs):
        return None

    def update_one(self, *args, **kwargs):
        class MockResult:
            matched_count = 0
        return MockResult()

    def delete_many(self, *args, **kwargs):
        class MockResult:
            deleted_count = 0
        return MockResult()

    def count_documents(self, *args, **kwargs):
        return 0

    def insert_many(self, *args, **kwargs):
        return None

class MockDatabase:
    """Mock database for when MongoDB is not available."""
    def get_alert_collection(self):
        return MockCollection()

class Database:
    """
    Manages the connection to the MongoDB database.
    """
    def __init__(self):
        try:
            self.client = MongoClient(MONGO_CONNECTION_STRING, serverSelectionTimeoutMS=5000)
            # Test the connection
            self.client.admin.command('ping')
            self.db = self.client[DATABASE_NAME]
            self.available = True
        except Exception as e:
            print(f"WARNING: Database connection failed: {e}")
            self.available = False
            self.mock_db = MockDatabase()

    def get_alert_collection(self) -> Collection:
        """
        Provides access to the alerts collection.

        Returns:
            The PyMongo Collection object for alerts.
        """
        if not self.available:
            return self.mock_db.get_alert_collection()
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
