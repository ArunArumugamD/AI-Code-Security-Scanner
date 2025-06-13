# config.py - Central configuration management
import os
from pathlib import Path
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # Project paths
    BASE_DIR: Path = Path(__file__).parent.parent
    DATA_DIR: Path = BASE_DIR / "data"
    MODEL_DIR: Path = DATA_DIR / "models"
    
    # API Configuration
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    API_PREFIX: str = "/api/v1"
    
    # Database
    DATABASE_URL: str = "postgresql://secscanner:secpass@localhost/aisec_scanner"
    REDIS_URL: str = "redis://localhost:6379"
    
    # AI Model Settings
    CODEBERT_MODEL: str = "microsoft/codebert-base"
    CONFIDENCE_THRESHOLD: float = 0.7
    MAX_FILE_SIZE_MB: int = 10
    
    # Security
    SECRET_KEY: str = "your-secret-key-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # CVE Feed
    NVD_API_KEY: str = ""  # Get from https://nvd.nist.gov/developers/request-an-api-key
    CVE_UPDATE_INTERVAL_HOURS: int = 24
    
    # WebSocket
    WS_HEARTBEAT_INTERVAL: int = 30
    
    class Config:
        env_file = ".env"

settings = Settings()
