"""
Configuration settings for User Service
"""
from pydantic_settings import BaseSettings
from pydantic import Field
from typing import List, Optional
import os


class Settings(BaseSettings):
    """
    User Service Configuration
    """
    
    # Application settings
    APP_NAME: str = "User Service"
    VERSION: str = "1.0.0"
    DEBUG: bool = Field(default=False, env="DEBUG")
    ENVIRONMENT: str = Field(default="production", env="ENVIRONMENT")
    
    # Service identification for event bus
    SERVICE_NAME: str = Field(default="user-service", env="SERVICE_NAME")
    SERVICE_ROLE: str = Field(default="user", env="SERVICE_ROLE")
    
    # API settings
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "User Service"
    
    # Database
    DATABASE_URL: str = Field(default="postgresql://localhost/users", env="DATABASE_URL")
    
    # Redis
    REDIS_URL: str = Field(default="redis://localhost:6379", env="REDIS_URL")
    
    # CORS settings
    BACKEND_CORS_ORIGINS: List[str] = Field(
        default_factory=lambda: ["http://localhost:5173"],
        env="CORS_ORIGINS"
    )
    
    # JWT settings
    JWT_SECRET_KEY: str = Field(default="your-secret-key", env="JWT_SECRET_KEY")
    JWT_ALGORITHM: str = "HS256"
    
    # Event bus configuration
    EVENT_BUS_TYPE: str = Field(default="in_memory", env="EVENT_BUS_TYPE")
    
    class Config:
        case_sensitive = True
        env_file = ".env"


# Create settings instance
settings = Settings()