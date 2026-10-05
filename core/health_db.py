# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

import sqlite3
import os
from datetime import datetime, timedelta, timezone
import logging

logger = logging.getLogger(__name__)

# Resolve the DB path dynamically relative to the core directory or set via environment variable
DB_PATH = os.environ.get("HEALTH_DB_PATH", os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "health.db"))

def get_connection():
    """Returns a new SQLite connection."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

_db_initialized = False
_last_cleanup_time = None

def init_db():
    """Initializes the database schema."""
    global _db_initialized
    if _db_initialized:
        return
        
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS health_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_type TEXT NOT NULL,
                    name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    error_details TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            # Create an index to speed up lookups by entity and cleanup by timestamp
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_entity_timestamp ON health_events (entity_type, name, timestamp)
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_timestamp ON health_events (timestamp)
            ''')
            conn.commit()
            _db_initialized = True
    except Exception as e:
        logger.error(f"Failed to initialize health db: {e}")

def log_event(entity_type: str, name: str, status: str, error_details: str = None):
    """Logs a new health event."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO health_events (entity_type, name, status, error_details, timestamp)
                VALUES (?, ?, ?, ?, ?)
            ''', (entity_type, name, status, error_details, datetime.now(timezone.utc).isoformat()))
            conn.commit()
    except Exception as e:
        logger.error(f"Failed to log health event for {entity_type}/{name}: {e}")

def get_events_for_entity(entity_type: str, name: str, days: int = 30):
    """Fetches the last N days of events for a given entity, ordered by timestamp."""
    try:
        cutoff_date = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM health_events 
                WHERE entity_type = ? AND name = ? AND timestamp >= ?
                ORDER BY timestamp ASC
            ''', (entity_type, name, cutoff_date))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    except Exception as e:
        logger.error(f"Failed to fetch health events for {entity_type}/{name}: {e}")
        return []

def cleanup_old_events(days=30):
    """Deletes events older than the specified number of days."""
    global _last_cleanup_time
    now = datetime.now(timezone.utc)
    
    # Throttle cleanup to run at most once a day
    if _last_cleanup_time and (now - _last_cleanup_time).total_seconds() < 86400:
        return
        
    try:
        cutoff_date = (now - timedelta(days=days)).isoformat()
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                DELETE FROM health_events WHERE timestamp < ?
            ''', (cutoff_date,))
            deleted_count = cursor.rowcount
            conn.commit()
            if deleted_count > 0:
                logger.debug(f"Cleaned up {deleted_count} old health events.")
        _last_cleanup_time = now
    except Exception as e:
        logger.error(f"Failed to cleanup old health events: {e}")
