"""
Repository implementations following the Repository pattern.
Provides data access layer abstraction with encryption handling.
"""

from .user_repository import UserRepository

__all__ = [
    "UserRepository"
]