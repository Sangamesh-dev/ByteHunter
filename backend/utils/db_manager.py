"""
ByteHunter Persistence Layer.
Manages scan history and result caching using SQLite.
"""
import os
import json
import sqlite3
import aiosqlite
import logging
import numpy as np
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

def make_json_serializable(obj):
    """Convert NumPy types to native Python types for JSON serialization."""
    if isinstance(obj, dict):
        return {k: make_json_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [make_json_serializable(v) for v in obj]
    elif isinstance(obj, (np.bool_,)):
        return bool(obj)
    elif isinstance(obj, (np.integer,)):
        return int(obj)
    elif isinstance(obj, (np.floating,)):
        return float(obj)
    else:
        return obj

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scan_history.db")

class DBManager:
    def __init__(self):
        self.db_path = DB_PATH

    async def init_db(self):
        """Initialize SQLite database and create tables."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    filename TEXT,
                    sha256 TEXT NOT NULL,
                    threat_score REAL,
                    verdict TEXT,
                    risk_level TEXT,
                    malware_type TEXT,
                    file_type TEXT,
                    cached BOOLEAN,
                    result_json TEXT,
                    timestamp TEXT
                )
            """)
            await db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_sha256 ON scans (sha256)")
            await db.commit()
            logger.info(f"Database initialized at {self.db_path}")

    async def get_cached_result(self, sha256: str):
        """Check if a scan for this hash already exists."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM scans WHERE sha256 = ?", (sha256,)) as cursor:
                row = await cursor.fetchone()
                if row:
                    data = dict(row)
                    # Parse result_json back to dict
                    result = json.loads(data["result_json"])
                    
                    # Merge DB fields into result if missing (Fix for PDF metadata loss)
                    result["file_type"] = result.get("file_type") or data.get("file_type")
                    result["sha256"] = result.get("sha256") or data.get("sha256")
                    result["file_size"] = result.get("file_size") or 0
                    result["md5"] = result.get("md5") or "N/A"
                    
                    result["cached"] = True
                    return result
        return None

    async def save_scan_result(self, scan_id: str, filename: str, result: dict):
        """Persist analysis result to DB."""
        # Clean up result dict for JSON serialization (handle NumPy types)
        clean_result = make_json_serializable(result)
        result_str = json.dumps(clean_result)
        
        async with aiosqlite.connect(self.db_path) as db:
            try:
                await db.execute("""
                    INSERT INTO scans (
                        scan_id, filename, sha256, threat_score, verdict,
                        risk_level, malware_type, file_type, cached,
                        result_json, timestamp
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    scan_id,
                    filename,
                    clean_result.get("sha256"),
                    clean_result.get("threat_score"),
                    clean_result.get("verdict"),
                    clean_result.get("risk_level"),
                    clean_result.get("malware_type"),
                    clean_result.get("file_type"),
                    False,  # This entry itself is not 'cached', it's the original
                    result_str,
                    clean_result.get("timestamp", datetime.now(timezone.utc).isoformat())
                ))
                await db.commit()
            except sqlite3.IntegrityError:
                # If sha256 already exists, we skip saving or update timestamp?
                # The user said: "If duplicate file uploaded: return cached result, do not recompute"
                # This logic is handled in the endpoint by calling get_cached_result first.
                pass

    async def get_history(self, verdict=None, risk_level=None):
        """Fetch scan history with optional filters."""
        query = "SELECT scan_id, filename, sha256, threat_score, verdict, risk_level, timestamp FROM scans WHERE 1=1"
        params = []
        if verdict:
            query += " AND verdict = ?"
            params.append(verdict)
        if risk_level:
            query += " AND risk_level = ?"
            params.append(risk_level)
        
        query += " ORDER BY timestamp DESC"
        
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(query, params) as cursor:
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]

    async def get_scan_by_id(self, scan_id: str):
        """Fetch full scan result by ID with metadata restoration."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)) as cursor:
                row = await cursor.fetchone()
                if row:
                    data = dict(row)
                    result = json.loads(data["result_json"])

                    # Merge DB fields into result if missing
                    result["file_type"] = result.get("file_type") or data.get("file_type")
                    result["sha256"] = result.get("sha256") or data.get("sha256")
                    result["file_size"] = result.get("file_size") or 0
                    result["md5"] = result.get("md5") or "N/A"

                    return result
        return None
