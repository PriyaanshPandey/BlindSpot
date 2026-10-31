import logging
from typing import Optional, Dict, Any, List
import asyncio
from pymongo.errors import OperationFailure

logger = logging.getLogger("hdx.db")

class DatabaseClient:
    def __init__(self):
        # In-memory storage for offline / testing / fallback
        self.in_memory_scans: Dict[str, Dict[str, Any]] = {}
        self.in_memory_graphs: Dict[str, Dict[str, Any]] = {}
        self.in_memory_findings: Dict[str, List[Dict[str, Any]]] = {}
        self.in_memory_scenarios: Dict[str, List[Dict[str, Any]]] = {}
        self.in_memory_evidence: Dict[str, List[Dict[str, Any]]] = {}

        # Async Motor MongoDB connection
        self.client = None
        self.motor_db = None
        self.is_connected: bool = False
        self.storage_mode: str = "in_memory"
        self.db_name: str = "blindspot"
        self.uri: str = "mongodb://localhost:27017"

    async def connect(self, uri: Optional[str] = None, db_name: Optional[str] = None):
        """
        Connects to MongoDB using the configured URI and database name.
        Verifies connectivity with an explicit ping.
        """
        from app.core.config import settings
        target_uri = uri or settings.MONGODB_URI
        target_db = db_name or settings.MONGODB_DB_NAME
        self.uri = target_uri
        self.db_name = target_db

        try:
            from motor.motor_asyncio import AsyncIOMotorClient
            self.client = AsyncIOMotorClient(target_uri, serverSelectionTimeoutMS=2000)
            # Explicit ping to verify server is active and reachable
            await self.client.admin.command("ping")
            self.motor_db = self.client[target_db]
            self.is_connected = True
            self.storage_mode = "mongodb"
            logger.info(f"HDX Database successfully connected to MongoDB at {target_uri} [Database: '{target_db}']")
        except Exception as exc:
            self.is_connected = False
            self.storage_mode = "in_memory"
            self.motor_db = None
            if self.client:
                self.client.close()
                self.client = None
            logger.warning(
                f"MongoDB connection to {target_uri} failed ({exc}). "
                f"Active storage mode: IN_MEMORY (local state only)."
            )
            return

        # Create required unique and lookup indexes (failures must be visible to caller)
        await self._ensure_indexes()

    async def _ensure_indexes(self):
        """
        Ensures indexes exist across all core collections.
        Index creation failures are NOT silently swallowed.
        """
        if not self.is_connected or self.motor_db is None:
            return

        # Safely drop legacy single-field id indexes if they exist
        for coll_name in ("findings", "evidence"):
            try:
                await self.motor_db[coll_name].drop_index("id_1")
            except OperationFailure as exc:
                # Ignore only the specific error indicating the index is absent (IndexNotFound / code 27)
                is_index_not_found = (
                    getattr(exc, "code", None) == 27
                    or (exc.details and exc.details.get("codeName") == "IndexNotFound")
                    or "index not found" in str(exc).lower()
                )
                if not is_index_not_found:
                    raise

        # Required indexes: allow exceptions to propagate so caller is notified
        await self.motor_db.scans.create_index("scan_id", unique=True)
        await self.motor_db.graphs.create_index("scan_id", unique=True)
        await self.motor_db.scenarios.create_index("scenario_id", unique=True)
        await self.motor_db.scenarios.create_index("scan_id")
        await self.motor_db.findings.create_index("scan_id")
        await self.motor_db.findings.create_index([("scan_id", 1), ("id", 1)], unique=True)
        await self.motor_db.evidence.create_index("scan_id")
        await self.motor_db.evidence.create_index([("scan_id", 1), ("id", 1)], unique=True)
        logger.info("MongoDB indexes verified for scans, graphs, findings, scenarios, and evidence.")

    async def close(self):
        if self.client:
            self.client.close()
            self.is_connected = False
            logger.info("MongoDB client closed cleanly.")

db = DatabaseClient()
