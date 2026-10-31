import logging
from typing import Optional, Dict, Any

logger = logging.getLogger("hdx.db")

class DatabaseClient:
    def __init__(self):
        self.in_memory_scans: Dict[str, Any] = {}
        self.in_memory_graphs: Dict[str, Any] = {}
        self.in_memory_findings: Dict[str, Any] = {}
        self.in_memory_scenarios: Dict[str, Any] = {}

    async def connect(self):
        logger.info("Database initialized (Hybrid in-memory / MongoDB ready)")

    async def close(self):
        logger.info("Database connections closed")

db = DatabaseClient()

