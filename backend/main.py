from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging

from app.core.config import settings
from app.db import db
from app.api.router import api_router

logging.basicConfig(level=settings.LOG_LEVEL.upper())
logger = logging.getLogger("blindspot")

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing Blindspot Dependency Intelligence Backend...")
    await db.connect()
    yield
    await db.close()
    logger.info("Blindspot Backend shutdown cleanly.")

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Privacy-First Dependency Intelligence and Resilience Platform",
    lifespan=lifespan
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/v1/health")
async def health_check():
    return {
        "status": "healthy",
        "version": settings.VERSION,
        "operating_mode": settings.BLINDSPOT_OPERATING_MODE,
        "storage_mode": db.storage_mode,
        "database": db.db_name if db.is_connected else None
    }

app.include_router(api_router, prefix="/api/v1")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=settings.HOST, port=settings.PORT, reload=True)
