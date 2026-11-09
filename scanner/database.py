"""
Database module for Analyzer2.
Handles MongoDB connection and scan data persistence.
MongoDB is optional — the scanner works without it.
"""

import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# MongoDB client and collections (lazy-initialized)
_client = None
_db = None
_scans_collection = None
_connected = False


def _get_mongo_client():
    """Lazy-initialize the MongoDB connection."""
    global _client, _db, _scans_collection, _connected

    if _connected:
        return _scans_collection

    try:
        from pymongo import MongoClient
        from pymongo.server_api import ServerApi
        from scanner.config import MONGODB_URI, DB_NAME, SCANS_COLLECTION

        _client = MongoClient(MONGODB_URI, server_api=ServerApi("1"), serverSelectionTimeoutMS=5000)
        # Test the connection
        _client.admin.command("ping")
        _db = _client[DB_NAME]
        _scans_collection = _db[SCANS_COLLECTION]
        _connected = True
        logger.info("Connected to MongoDB successfully.")
        return _scans_collection
    except ImportError:
        logger.warning("pymongo not installed. Database features disabled.")
        return None
    except Exception as e:
        logger.warning(f"Could not connect to MongoDB: {e}. Database features disabled.")
        return None


def is_connected():
    """Check if the database connection is active."""
    _get_mongo_client()
    return _connected


def save_scan_data(scan_results):
    """Save scan results to MongoDB. Returns True on success, False otherwise."""
    collection = _get_mongo_client()
    if collection is None:
        logger.debug("Database not available — scan results not persisted.")
        return False

    try:
        data = {
            "timestamp": datetime.now().isoformat(),
            "results": scan_results,
        }
        collection.insert_one(data)
        logger.info("Scan data saved to database.")
        return True
    except Exception as e:
        logger.warning(f"Error saving scan data: {e}")
        return False


def fetch_scan_history(limit=10):
    """Fetch recent scan results from MongoDB."""
    collection = _get_mongo_client()
    if collection is None:
        return []

    try:
        results = list(
            collection.find({}, {"_id": 0})
            .sort("timestamp", -1)
            .limit(limit)
        )
        return results
    except Exception as e:
        logger.warning(f"Error fetching scan history: {e}")
        return []
