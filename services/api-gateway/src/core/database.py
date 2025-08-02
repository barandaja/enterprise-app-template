"""
Database configuration and connection management for API Gateway.
Primarily used for caching, rate limiting, and gateway-specific data.
"""
import asyncio
from typing import AsyncGenerator, Optional
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, AsyncEngine, async_sessionmaker
from sqlalchemy.orm import declarative_base
from sqlalchemy.pool import NullPool
import structlog

from .config import get_settings

logger = structlog.get_logger()
settings = get_settings()

# Database engine and session
engine: Optional[AsyncEngine] = None
async_session_maker: Optional[async_sessionmaker] = None
Base = declarative_base()


async def init_db() -> None:
    """Initialize database engine and session factory."""
    global engine, async_session_maker
    
    try:
        # Create async engine
        engine = create_async_engine(
            settings.database_url,
            pool_size=settings.database_pool_size,
            max_overflow=settings.database_max_overflow,
            pool_timeout=settings.database_pool_timeout,
            pool_pre_ping=True,
            poolclass=NullPool if settings.environment == "test" else None,
            echo=settings.debug and settings.environment == "development"
        )
        
        # Create session factory
        async_session_maker = async_sessionmaker(
            engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=True,
            autocommit=False
        )
        
        logger.info("Database initialized successfully")
        
    except Exception as e:
        logger.error("Failed to initialize database", error=str(e))
        raise


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Get database session."""
    if not async_session_maker:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    
    async with async_session_maker() as session:
        try:
            yield session
        except Exception as e:
            await session.rollback()
            logger.error("Database session error", error=str(e))
            raise
        finally:
            await session.close()


async def close_db() -> None:
    """Close database connections."""
    global engine
    
    if engine:
        await engine.dispose()
        logger.info("Database connections closed")


class DatabaseManager:
    """Database connection manager with health checks."""
    
    def __init__(self):
        self.engine = engine
        self.session_maker = async_session_maker
    
    async def health_check(self) -> bool:
        """Check database connectivity."""
        try:
            if not self.engine:
                return False
            
            async with self.engine.begin() as conn:
                await conn.execute("SELECT 1")
            
            return True
            
        except Exception as e:
            logger.error("Database health check failed", error=str(e))
            return False
    
    async def get_connection_stats(self) -> dict:
        """Get database connection pool statistics."""
        try:
            if not self.engine or not self.engine.pool:
                return {}
            
            pool = self.engine.pool
            return {
                "pool_size": pool.size(),
                "checkedin": pool.checkedin(),
                "checkedout": pool.checkedout(),
                "overflow": pool.overflow(),
                "invalid": pool.invalid()
            }
            
        except Exception as e:
            logger.error("Failed to get connection stats", error=str(e))
            return {}