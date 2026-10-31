import os
from pydantic_settings import BaseSettings
from typing import List

class Settings(BaseSettings):
    PROJECT_NAME: str = "Hidden Dependency X-Ray"
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "info")

    # Server
    HOST: str = os.getenv("BACKEND_HOST", "0.0.0.0")
    PORT: int = int(os.getenv("BACKEND_PORT", "8000"))
    CORS_ORIGINS: List[str] = ["http://localhost:5173", "http://localhost:3000"]

    # Database
    MONGODB_URI: str = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
    MONGODB_DB_NAME: str = os.getenv("MONGODB_DB_NAME", "hdx_dependency_db")

    # Operating Mode
    HDX_OPERATING_MODE: str = os.getenv("HDX_OPERATING_MODE", "hybrid")
    KNOWLEDGE_PLANE_API_URL: str = os.getenv("KNOWLEDGE_PLANE_API_URL", "https://knowledge.hdx-defense.io/v1")
    KNOWLEDGE_BUNDLE_PUBLIC_KEY: str = os.getenv("KNOWLEDGE_BUNDLE_PUBLIC_KEY", "")

    # Integrations
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    SOLANA_RPC_URL: str = os.getenv("SOLANA_RPC_URL", "https://api.devnet.solana.com")

    class Config:
        env_file = ".env"
        extra = "allow"

settings = Settings()

