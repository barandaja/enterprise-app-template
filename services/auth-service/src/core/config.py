from pydantic_settings import BaseSettings
from pydantic import Field, validator, ValidationError
from typing import List, Optional, Dict, Any
import os
import sys
import secrets
from functools import lru_cache
import structlog

logger = structlog.get_logger()


class Settings(BaseSettings):
    """
    Enterprise Auth Service Configuration
    
    All sensitive values MUST be provided via environment variables.
    The service will fail fast if required security configurations are missing.
    """
    
    # Application settings
    APP_NAME: str = "Auth Service"
    VERSION: str = "1.0.0"
    DEBUG: bool = Field(default=False, env="DEBUG")
    ENVIRONMENT: str = Field(default="production", env="ENVIRONMENT")
    
    # API settings
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "Enterprise Auth Service"
    
    # Security settings - REQUIRED, NO DEFAULTS
    SECRET_KEY: str = Field(..., env="SECRET_KEY", min_length=32)
    ENCRYPTION_KEY: str = Field(..., env="ENCRYPTION_KEY", min_length=32)
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=15, ge=5, le=60)  # 15 min default, max 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(default=7, ge=1, le=30)  # 7 days default, max 30
    
    # Password policy
    PASSWORD_MIN_LENGTH: int = Field(default=12, ge=12, le=128)
    PASSWORD_REQUIRE_UPPERCASE: bool = True
    PASSWORD_REQUIRE_LOWERCASE: bool = True
    PASSWORD_REQUIRE_NUMBERS: bool = True
    PASSWORD_REQUIRE_SPECIAL: bool = True
    PASSWORD_HISTORY_COUNT: int = Field(default=5, ge=3, le=24)  # Remember last N passwords
    PASSWORD_MAX_AGE_DAYS: int = Field(default=90, ge=30, le=365)  # Force rotation
    
    # Database - REQUIRED
    DATABASE_URL: str = Field(..., env="DATABASE_URL")
    
    # Connection pool configuration based on expected load
    # Formula: pool_size = (expected_concurrent_requests / avg_request_db_time)
    # For 1000 concurrent users with 50ms avg db time: 1000 / 20 = 50
    DATABASE_POOL_SIZE: int = Field(default=50, ge=10, le=200)
    DATABASE_MAX_OVERFLOW: int = Field(default=100, ge=0, le=200)  # 2x pool size for burst traffic
    DATABASE_POOL_TIMEOUT: int = Field(default=30, ge=10, le=60)
    DATABASE_POOL_RECYCLE: int = Field(default=1800, ge=300, le=3600)  # Recycle connections every 30 min
    DATABASE_POOL_PRE_PING: bool = True  # Test connections before use
    
    # Redis - REQUIRED for session management and rate limiting
    REDIS_URL: str = Field(..., env="REDIS_URL")
    REDIS_PASSWORD: Optional[str] = Field(None, env="REDIS_PASSWORD")
    REDIS_SSL: bool = Field(default=True, env="REDIS_SSL")
    REDIS_POOL_SIZE: int = Field(default=50, ge=10, le=100)  # Match DB pool size
    REDIS_DECODE_RESPONSES: bool = False  # Keep as bytes for encryption
    
    # CORS settings - should be environment-specific
    BACKEND_CORS_ORIGINS: List[str] = Field(
        default_factory=list,
        env="BACKEND_CORS_ORIGINS"
    )
    
    # Enterprise Rate Limiting Configuration
    RATE_LIMIT_ENABLED: bool = True
    
    # Authentication endpoints (stricter)
    RATE_LIMIT_LOGIN_PER_MINUTE: int = Field(default=5, ge=3, le=10)
    RATE_LIMIT_LOGIN_PER_HOUR: int = Field(default=20, ge=10, le=50)
    RATE_LIMIT_LOGIN_PER_DAY: int = Field(default=100, ge=50, le=200)
    
    # API endpoints (per authenticated user)
    RATE_LIMIT_API_PER_MINUTE: int = Field(default=100, ge=60, le=300)
    RATE_LIMIT_API_PER_HOUR: int = Field(default=3000, ge=1000, le=10000)
    
    # Admin endpoints (more permissive)
    RATE_LIMIT_ADMIN_PER_MINUTE: int = Field(default=200, ge=100, le=500)
    RATE_LIMIT_ADMIN_PER_HOUR: int = Field(default=6000, ge=3000, le=20000)
    
    # Global rate limits (per IP)
    RATE_LIMIT_GLOBAL_PER_MINUTE: int = Field(default=300, ge=100, le=1000)
    RATE_LIMIT_GLOBAL_PER_HOUR: int = Field(default=10000, ge=5000, le=50000)
    
    # Session settings
    SESSION_LIFETIME_SECONDS: int = Field(default=3600, ge=900, le=86400)  # 1 hour default, max 24
    SESSION_IDLE_TIMEOUT_SECONDS: int = Field(default=1800, ge=300, le=7200)  # 30 min idle timeout
    SESSION_COOKIE_NAME: str = "__Host-session"  # Use __Host- prefix for security
    SESSION_COOKIE_SECURE: bool = True
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = "strict"  # Strict for enterprise
    
    # Compliance settings
    ENABLE_AUDIT_LOGGING: bool = True
    ENABLE_DATA_ENCRYPTION: bool = True
    GDPR_DATA_RETENTION_DAYS: int = Field(default=730, ge=365, le=2555)  # 2 years default
    HIPAA_COMPLIANT_MODE: bool = True
    SOC2_COMPLIANT_MODE: bool = True
    
    # Email settings - Required for password reset
    SMTP_HOST: str = Field(..., env="SMTP_HOST")
    SMTP_PORT: int = Field(default=587, env="SMTP_PORT")
    SMTP_USER: str = Field(..., env="SMTP_USER")
    SMTP_PASSWORD: str = Field(..., env="SMTP_PASSWORD")
    SMTP_TLS: bool = Field(default=True, env="SMTP_TLS")
    EMAILS_FROM_EMAIL: str = Field(..., env="EMAILS_FROM_EMAIL")
    EMAILS_FROM_NAME: str = Field(default="Enterprise Auth Service", env="EMAILS_FROM_NAME")
    
    # OAuth2 providers (optional but validated if provided)
    GOOGLE_CLIENT_ID: Optional[str] = Field(None, env="GOOGLE_CLIENT_ID")
    GOOGLE_CLIENT_SECRET: Optional[str] = Field(None, env="GOOGLE_CLIENT_SECRET")
    
    # Monitoring - Required for production
    SENTRY_DSN: Optional[str] = Field(None, env="SENTRY_DSN")
    ENABLE_OPENTELEMETRY: bool = True
    OTEL_EXPORTER_OTLP_ENDPOINT: str = Field(
        default="http://localhost:4317",
        env="OTEL_EXPORTER_OTLP_ENDPOINT"
    )
    
    # Cloud provider settings
    GCP_PROJECT_ID: Optional[str] = Field(None, env="GCP_PROJECT_ID")
    GCP_SERVICE_ACCOUNT_KEY: Optional[str] = Field(None, env="GCP_SERVICE_ACCOUNT_KEY")
    
    # Security Headers
    SECURITY_HEADERS: Dict[str, str] = Field(default_factory=lambda: {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), accelerometer=(), gyroscope=()"
    })
    
    @validator("SECRET_KEY", "ENCRYPTION_KEY")
    def validate_keys(cls, v: str, field) -> str:
        """Validate that security keys are strong enough"""
        if len(v) < 32:
            raise ValueError(f"{field.name} must be at least 32 characters long")
        
        # Check for obvious bad values
        bad_values = ["your-secret-key", "change-me", "secret", "password", "12345"]
        if any(bad in v.lower() for bad in bad_values):
            raise ValueError(f"{field.name} contains weak or default values")
        
        return v
    
    @validator("DATABASE_URL")
    def validate_database_url(cls, v: str) -> str:
        """Ensure database URL doesn't contain default credentials"""
        if "user:password@" in v or "postgres:postgres@" in v:
            raise ValueError("DATABASE_URL contains default credentials")
        return v
    
    @validator("BACKEND_CORS_ORIGINS", pre=True)
    def parse_cors_origins(cls, v: Any) -> List[str]:
        """Parse CORS origins from comma-separated string or list"""
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        elif isinstance(v, list):
            return v
        return []
    
    @validator("ENVIRONMENT")
    def validate_environment(cls, v: str) -> str:
        """Validate environment and adjust settings accordingly"""
        valid_envs = ["development", "staging", "production"]
        if v not in valid_envs:
            raise ValueError(f"ENVIRONMENT must be one of: {valid_envs}")
        return v
    
    class Config:
        case_sensitive = True
        env_file = ".env"
        
        # Additional validation
        validate_assignment = True
        use_enum_values = True
        
        # Schema for documentation
        schema_extra = {
            "example": {
                "SECRET_KEY": secrets.token_urlsafe(32),
                "ENCRYPTION_KEY": secrets.token_urlsafe(32),
                "DATABASE_URL": "postgresql+asyncpg://authuser:strongpass@db.example.com:5432/authdb?sslmode=require",
                "REDIS_URL": "rediss://default:strongpass@redis.example.com:6380/0",
            }
        }


def validate_required_settings(settings: Settings) -> None:
    """
    Validate that all required settings are properly configured.
    Fail fast if critical settings are missing or invalid.
    """
    errors = []
    
    # Check production-specific requirements
    if settings.ENVIRONMENT == "production":
        if settings.DEBUG:
            errors.append("DEBUG must be False in production")
        
        if not settings.SENTRY_DSN:
            errors.append("SENTRY_DSN is required in production for error monitoring")
        
        if not settings.BACKEND_CORS_ORIGINS:
            errors.append("BACKEND_CORS_ORIGINS must be explicitly set in production")
        
        if "localhost" in str(settings.DATABASE_URL).lower():
            errors.append("DATABASE_URL cannot use localhost in production")
        
        if "localhost" in str(settings.REDIS_URL).lower():
            errors.append("REDIS_URL cannot use localhost in production")
        
        if not settings.REDIS_SSL:
            errors.append("REDIS_SSL must be enabled in production")
    
    # OAuth validation
    if settings.GOOGLE_CLIENT_ID and not settings.GOOGLE_CLIENT_SECRET:
        errors.append("GOOGLE_CLIENT_SECRET required when GOOGLE_CLIENT_ID is set")
    
    if errors:
        error_msg = "Configuration validation failed:\n" + "\n".join(f"  - {e}" for e in errors)
        logger.error(error_msg)
        raise ValueError(error_msg)
    
    logger.info(
        "Configuration validated successfully",
        environment=settings.ENVIRONMENT,
        debug=settings.DEBUG,
        cors_origins_count=len(settings.BACKEND_CORS_ORIGINS),
        rate_limiting_enabled=settings.RATE_LIMIT_ENABLED,
        audit_logging_enabled=settings.ENABLE_AUDIT_LOGGING,
        data_encryption_enabled=settings.ENABLE_DATA_ENCRYPTION,
    )


@lru_cache()
def get_settings() -> Settings:
    """
    Get cached settings instance.
    Fails fast if required environment variables are missing.
    """
    try:
        settings = Settings()
        validate_required_settings(settings)
        return settings
    except ValidationError as e:
        logger.error("Failed to load settings", errors=e.errors())
        print("\n" + "="*60)
        print("CONFIGURATION ERROR")
        print("="*60)
        print("\nRequired environment variables are missing or invalid:")
        for error in e.errors():
            field = error.get("loc", ["unknown"])[0]
            msg = error.get("msg", "Invalid value")
            print(f"  - {field}: {msg}")
        print("\nPlease check your environment variables and .env file")
        print("="*60 + "\n")
        sys.exit(1)
    except Exception as e:
        logger.error("Unexpected error loading settings", error=str(e))
        sys.exit(1)


# Initialize settings on module import
settings = get_settings()