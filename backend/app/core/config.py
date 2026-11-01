import os
from pathlib import Path
from dotenv import load_dotenv

# Resolve .env relative to the backend project root, independent of process cwd
BACKEND_ROOT = Path(__file__).resolve().parent.parent.parent
env_file_path = BACKEND_ROOT / ".env"
if env_file_path.exists():
    # override=False ensures that valid existing process/system environment variables are never overwritten with empty values
    load_dotenv(dotenv_path=env_file_path, override=False)

try:
    from pydantic_settings import BaseSettings
except ImportError:
    from pydantic import BaseModel as BaseSettings
from typing import List


class Settings(BaseSettings):
    PROJECT_NAME: str = "Hidden Dependency X-Ray"
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "info")

    # Server
    HOST: str = os.getenv("BACKEND_HOST", "0.0.0.0")
    PORT: int = int(os.getenv("BACKEND_PORT", "8000"))
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "*"
    ]

    # Database
    MONGODB_URI: str = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
    MONGODB_DB_NAME: str = os.getenv("MONGODB_DB_NAME") or os.getenv("MONGODB_DATABASE") or "blindspot"

    # Operating Mode
    HDX_OPERATING_MODE: str = os.getenv("HDX_OPERATING_MODE", "hybrid")
    KNOWLEDGE_PLANE_API_URL: str = os.getenv("KNOWLEDGE_PLANE_API_URL", "https://knowledge.hdx-defense.io/v1")
    KNOWLEDGE_BUNDLE_PUBLIC_KEY: str = os.getenv("KNOWLEDGE_BUNDLE_PUBLIC_KEY", "")

    # Integrations
    GEMINI_API_KEY: str = (os.getenv("GEMINI_API_KEY") or "").strip()
    GEMINI_MODEL: str = (os.getenv("GEMINI_MODEL") or "gemini-3.6-flash").strip() or "gemini-3.6-flash"
    SOLANA_RPC_URL: str = os.getenv("SOLANA_RPC_URL", "https://api.devnet.solana.com")

    class Config:
        env_file = str(env_file_path)
        extra = "allow"


settings = Settings()
