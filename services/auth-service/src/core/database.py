"""
Database configuration and connection management for the auth service.
Implements async SQLAlchemy with connection pooling and performance optimizations.
"""
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.pool import QueuePool
import structlog
from .config import settings

logger = structlog.get_logger()

# Create async engine with connection pooling
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    poolclass=QueuePool,
    pool_size=settings.DATABASE_POOL_SIZE,
    max_overflow=settings.DATABASE_MAX_OVERFLOW,
    pool_timeout=settings.DATABASE_POOL_TIMEOUT,
    pool_pre_ping=True,  # Validate connections before use
    pool_recycle=settings.DATABASE_POOL_RECYCLE,   # Recycle connections based on config
    connect_args={
        "server_settings": {
            "application_name": f"{settings.APP_NAME}-{settings.ENVIRONMENT}",
            "tcp_keepalives_idle": "600",
            "tcp_keepalives_interval": "30",
            "tcp_keepalives_count": "3",
        }
    }
)

# Create async session factory
AsyncSessionLocal = async_sessionmaker(
    engine, 
    class_=AsyncSession, 
    expire_on_commit=False,
    autoflush=False
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Database dependency that provides async session.
    Handles connection cleanup and error management.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception as e:
            await session.rollback()
            logger.error("Database session error", error=str(e))
            raise
        finally:
            await session.close()


class DatabaseHealthCheck:
    """Health check utilities for database connections."""
    
    @staticmethod
    async def check_connection() -> bool:
        """Check if database connection is healthy."""
        try:
            async with AsyncSessionLocal() as session:
                result = await session.execute("SELECT 1")
                return result.scalar() == 1
        except Exception as e:
            logger.error("Database health check failed", error=str(e))
            return False
    
    @staticmethod
    async def get_pool_status() -> dict:
        """Get connection pool status information."""
        pool = engine.pool
        return {
            "size": pool.size(),
            "checked_in": pool.checkedin(),
            "checked_out": pool.checkedout(),
            "overflow": pool.overflow(),
            "invalid": pool.invalid()
        }


async def close_db_connections():
    """Close all database connections on shutdown."""
    await engine.dispose()
    logger.info("Database connections closed")