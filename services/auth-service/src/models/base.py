"""
Base model class with common fields and functionality.
"""
from datetime import datetime
from typing import Any, Dict, Optional, Type, TypeVar
from sqlalchemy import Column, Integer, DateTime, Boolean, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import declared_attr
import structlog

logger = structlog.get_logger()

T = TypeVar('T', bound='Base')

Base = declarative_base()


class TimestampMixin:
    """Mixin for created_at and updated_at timestamps."""
    
    created_at = Column(
        DateTime(timezone=True), 
        server_default=func.now(),
        nullable=False,
        index=True
    )
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
        index=True
    )


class SoftDeleteMixin:
    """Mixin for soft delete functionality."""
    
    is_deleted = Column(Boolean, default=False, nullable=False, index=True)
    deleted_at = Column(DateTime(timezone=True), nullable=True)
    
    def soft_delete(self) -> None:
        """Mark record as deleted."""
        self.is_deleted = True
        self.deleted_at = datetime.utcnow()
    
    def restore(self) -> None:
        """Restore soft-deleted record."""
        self.is_deleted = False
        self.deleted_at = None


class BaseModel(Base, TimestampMixin, SoftDeleteMixin):
    """Base model with common functionality for all models."""
    
    __abstract__ = True
    
    id = Column(Integer, primary_key=True, index=True)
    
    @declared_attr
    def __tablename__(cls) -> str:
        """Generate table name from class name."""
        return cls.__name__.lower()
    
    def to_dict(self, exclude: Optional[set] = None) -> Dict[str, Any]:
        """Convert model instance to dictionary."""
        exclude = exclude or set()
        return {
            column.name: getattr(self, column.name)
            for column in self.__table__.columns
            if column.name not in exclude
        }
    
    @classmethod
    async def get_by_id(
        cls: Type[T], 
        db: AsyncSession, 
        id: int,
        include_deleted: bool = False
    ) -> Optional[T]:
        """Get record by ID."""
        query = select(cls).where(cls.id == id)
        
        if not include_deleted:
            query = query.where(cls.is_deleted == False)
        
        result = await db.execute(query)
        return result.scalar_one_or_none()
    
    @classmethod
    async def get_all(
        cls: Type[T],
        db: AsyncSession,
        skip: int = 0,
        limit: int = 100,
        include_deleted: bool = False
    ) -> list[T]:
        """Get all records with pagination."""
        query = select(cls)
        
        if not include_deleted:
            query = query.where(cls.is_deleted == False)
        
        query = query.offset(skip).limit(limit)
        result = await db.execute(query)
        return result.scalars().all()
    
    @classmethod
    async def count(
        cls: Type[T],
        db: AsyncSession,
        include_deleted: bool = False
    ) -> int:
        """Count total records."""
        query = select(func.count(cls.id))
        
        if not include_deleted:
            query = query.where(cls.is_deleted == False)
        
        result = await db.execute(query)
        return result.scalar()
    
    async def save(self, db: AsyncSession) -> T:
        """Save instance to database."""
        try:
            db.add(self)
            await db.flush()
            await db.refresh(self)
            return self
        except Exception as e:
            await db.rollback()
            logger.error(
                "Failed to save model instance",
                model=self.__class__.__name__,
                error=str(e)
            )
            raise
    
    async def delete(self, db: AsyncSession, hard_delete: bool = False) -> None:
        """Delete instance (soft delete by default)."""
        try:
            if hard_delete:
                await db.delete(self)
            else:
                self.soft_delete()
                db.add(self)
            
            await db.flush()
        except Exception as e:
            await db.rollback()
            logger.error(
                "Failed to delete model instance",
                model=self.__class__.__name__,
                id=self.id,
                error=str(e)
            )
            raise
    
    def __repr__(self) -> str:
        """String representation of model."""
        return f"<{self.__class__.__name__}(id={self.id})>"