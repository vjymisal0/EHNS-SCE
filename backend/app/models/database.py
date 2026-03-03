"""
MongoDB connection and collection access via Motor (async driver).

Uses Motor for non-blocking async I/O with MongoDB.
Collections are created lazily by MongoDB on first insert.
"""

from __future__ import annotations

import logging
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase, AsyncIOMotorCollection

from app.core.config import MONGO_URL, MONGO_DB_NAME

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# Client & database singleton
# ──────────────────────────────────────────────
_client: AsyncIOMotorClient | None = None
_db: AsyncIOMotorDatabase | None = None


async def connect_db() -> None:
    """Initialise the MongoDB connection (call once at startup)."""
    global _client, _db
    logger.info("Connecting to MongoDB at %s ...", MONGO_URL)
    _client = AsyncIOMotorClient(MONGO_URL)
    _db = _client[MONGO_DB_NAME]

    # Create indexes for common queries
    analyses: AsyncIOMotorCollection = _db["analyses"]
    await analyses.create_index("sha256")
    await analyses.create_index("created_at", unique=False)

    logger.info("MongoDB connected – database: %s", MONGO_DB_NAME)


async def close_db() -> None:
    """Gracefully close the MongoDB connection."""
    global _client
    if _client:
        _client.close()
        logger.info("MongoDB connection closed.")


def get_db() -> AsyncIOMotorDatabase:
    """Return the active database handle."""
    if _db is None:
        raise RuntimeError("Database not initialised. Call connect_db() first.")
    return _db


def get_analyses_collection() -> AsyncIOMotorCollection:
    """Return the 'analyses' collection."""
    return get_db()["analyses"]
