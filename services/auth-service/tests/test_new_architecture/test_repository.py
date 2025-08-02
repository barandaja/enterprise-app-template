"""
Tests for the UserRepository implementation.
Tests the repository pattern with encryption handling.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import HTTPException, status

from src.repositories.user_repository import UserRepository
from src.models.user import User
from src.interfaces.encryption_interface import IEncryptionService
from src.interfaces.cache_interface import ICacheService


class MockEncryptionService:
    """Mock encryption service for testing."""
    
    def encrypt(self, plaintext: str) -> str:
        return f"encrypted_{plaintext}"
    
    def decrypt(self, ciphertext: str) -> str:
        if ciphertext.startswith("encrypted_"):
            return ciphertext[10:]  # Remove "encrypted_" prefix
        return ciphertext
    
    def hash_data(self, data: str) -> str:
        return f"hash_{data.lower()}"
    
    def verify_hash(self, data: str, hash_value: str) -> bool:
        return self.hash_data(data) == hash_value


class MockCacheService:
    """Mock cache service for testing."""
    
    def __init__(self):
        self.cache = {}
    
    async def get(self, key: str):
        return self.cache.get(key)
    
    async def set(self, key: str, value, ttl: int = None):
        self.cache[key] = value
        return True
    
    async def delete(self, key: str):
        if key in self.cache:
            del self.cache[key]
            return True
        return False
    
    async def delete_pattern(self, pattern: str):
        keys_to_delete = [k for k in self.cache.keys() if pattern.replace("*", "") in k]
        for key in keys_to_delete:
            del self.cache[key]
        return len(keys_to_delete)


class TestUserRepository:
    """Test cases for UserRepository."""
    
    @pytest.fixture
    def mock_encryption_service(self):
        """Create mock encryption service."""
        return MockEncryptionService()
    
    @pytest.fixture
    def mock_cache_service(self):
        """Create mock cache service."""
        return MockCacheService()
    
    @pytest.fixture
    def user_repository(self, mock_encryption_service, mock_cache_service):
        """Create UserRepository instance with mocked dependencies."""
        return UserRepository(
            encryption_service=mock_encryption_service,
            cache_service=mock_cache_service
        )
    
    @pytest.fixture
    def mock_db(self):
        """Create mock database session."""
        db = AsyncMock()
        db.add = MagicMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock()
        db.rollback = AsyncMock()
        db.execute = AsyncMock()
        db.delete = AsyncMock()
        db.utcnow = MagicMock(return_value="2023-01-01T00:00:00")
        return db
    
    @pytest.fixture
    def mock_user(self):
        """Create a mock user for testing."""
        user = MagicMock(spec=User)
        user.id = 1
        user.email = "encrypted_test@example.com"
        user.email_hash = "hash_test@example.com"
        user.first_name = "encrypted_John"
        user.last_name = "encrypted_Doe"
        user.is_active = True
        user.is_deleted = False
        return user
    
    @pytest.mark.asyncio
    async def test_create_user_success(self, user_repository, mock_db):
        """Test successful user creation with encryption."""
        # Arrange
        email = "test@example.com"
        password = "password123"
        first_name = "John"
        last_name = "Doe"
        
        with patch('src.repositories.user_repository.User') as MockUser, \
             patch('src.repositories.user_repository.SecurityService') as MockSecurity:
            
            MockSecurity.get_password_hash.return_value = "hashed_password"
            mock_user_instance = MagicMock()
            mock_user_instance.id = 1
            MockUser.return_value = mock_user_instance
            
            # Mock database query for existing user check
            mock_result = AsyncMock()
            mock_result.scalar_one_or_none.return_value = None  # No existing user
            mock_db.execute.return_value = mock_result
            
            # Act
            result = await user_repository.create(
                db=mock_db,
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name
            )
            
            # Assert
            assert result == mock_user_instance
            mock_db.add.assert_called_once_with(mock_user_instance)
            mock_db.commit.assert_called_once()
            mock_db.refresh.assert_called_once_with(mock_user_instance)
            MockSecurity.get_password_hash.assert_called_once_with(password)
            
            # Verify User was created with encrypted data
            MockUser.assert_called_once()
            call_args = MockUser.call_args[1]
            assert call_args["email"] == "encrypted_test@example.com"
            assert call_args["email_hash"] == "hash_test@example.com"
            assert call_args["first_name"] == "encrypted_John"
            assert call_args["last_name"] == "encrypted_Doe"
            assert call_args["password_hash"] == "hashed_password"
    
    @pytest.mark.asyncio
    async def test_create_user_already_exists(self, user_repository, mock_db, mock_user):
        """Test user creation when user already exists."""
        # Arrange
        email = "test@example.com"
        password = "password123"
        
        # Mock database query to return existing user
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        mock_db.execute.return_value = mock_result
        
        # Act & Assert
        with pytest.raises(HTTPException) as exc_info:
            await user_repository.create(
                db=mock_db,
                email=email,
                password=password
            )
        
        assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
        assert "User with this email already exists" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_get_by_id_success(self, user_repository, mock_db, mock_user):
        """Test successful user retrieval by ID."""
        # Arrange
        user_id = 1
        
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        mock_db.execute.return_value = mock_result
        
        # Act
        result = await user_repository.get_by_id(mock_db, user_id)
        
        # Assert
        assert result is not None
        assert result.email == "test@example.com"  # Should be decrypted
        assert result.first_name == "John"  # Should be decrypted
        assert result.last_name == "Doe"  # Should be decrypted
        
        # Verify database query was made
        mock_db.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_by_id_not_found(self, user_repository, mock_db):
        """Test user retrieval when user doesn't exist."""
        # Arrange
        user_id = 999
        
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute.return_value = mock_result
        
        # Act
        result = await user_repository.get_by_id(mock_db, user_id)
        
        # Assert
        assert result is None
    
    @pytest.mark.asyncio
    async def test_get_by_email_success(self, user_repository, mock_db, mock_user):
        """Test successful user retrieval by email."""
        # Arrange
        email = "test@example.com"
        
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        mock_db.execute.return_value = mock_result
        
        # Act
        result = await user_repository.get_by_email(mock_db, email)
        
        # Assert
        assert result is not None
        assert result.email == "test@example.com"  # Should be decrypted
        
        # Verify query used email hash
        mock_db.execute.assert_called_once()
        call_args = mock_db.execute.call_args[0][0]
        # The query should contain the email hash
        assert "hash_test@example.com" in str(call_args)
    
    @pytest.mark.asyncio
    async def test_update_user_success(self, user_repository, mock_db, mock_user):
        """Test successful user update with encryption."""
        # Arrange
        user_id = 1
        update_data = {
            "first_name": "Jane",
            "last_name": "Smith",
            "is_active": True
        }
        
        # Mock get_by_id to return user
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        mock_db.execute.return_value = mock_result
        
        # Act
        result = await user_repository.update(mock_db, user_id, update_data)
        
        # Assert
        assert result is not None
        mock_db.commit.assert_called_once()
        mock_db.refresh.assert_called_once_with(mock_user)
        
        # Verify sensitive fields were encrypted
        assert mock_user.first_name == "encrypted_Jane"
        assert mock_user.last_name == "encrypted_Smith"
        assert mock_user.is_active == True
    
    @pytest.mark.asyncio
    async def test_delete_user_soft_delete(self, user_repository, mock_db, mock_user):
        """Test soft user deletion."""
        # Arrange
        user_id = 1
        
        # Mock get_by_id to return user
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        mock_db.execute.return_value = mock_result
        
        # Act
        result = await user_repository.delete(mock_db, user_id, hard_delete=False)
        
        # Assert
        assert result is True
        assert mock_user.is_deleted is True
        assert mock_user.deleted_at == "2023-01-01T00:00:00"
        mock_db.commit.assert_called_once()
        mock_db.delete.assert_not_called()  # Should not hard delete
    
    @pytest.mark.asyncio
    async def test_delete_user_hard_delete(self, user_repository, mock_db, mock_user):
        """Test hard user deletion."""
        # Arrange
        user_id = 1
        
        # Mock get_by_id to return user
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        mock_db.execute.return_value = mock_result
        
        # Act
        result = await user_repository.delete(mock_db, user_id, hard_delete=True)
        
        # Assert
        assert result is True
        mock_db.delete.assert_called_once_with(mock_user)
        mock_db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_exists_by_email_true(self, user_repository, mock_db):
        """Test email existence check when user exists."""
        # Arrange
        email = "test@example.com"
        
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = 1  # User ID
        mock_db.execute.return_value = mock_result
        
        # Act
        result = await user_repository.exists_by_email(mock_db, email)
        
        # Assert
        assert result is True
        mock_db.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_exists_by_email_false(self, user_repository, mock_db):
        """Test email existence check when user doesn't exist."""
        # Arrange
        email = "nonexistent@example.com"
        
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute.return_value = mock_result
        
        # Act
        result = await user_repository.exists_by_email(mock_db, email)
        
        # Assert
        assert result is False
    
    @pytest.mark.asyncio
    async def test_update_password_success(self, user_repository, mock_db, mock_user):
        """Test successful password update."""
        # Arrange
        user_id = 1
        new_password = "newpassword123"
        
        # Mock get_by_id to return user
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        mock_db.execute.return_value = mock_result
        
        with patch('src.repositories.user_repository.SecurityService') as MockSecurity:
            MockSecurity.get_password_hash.return_value = "new_hashed_password"
            
            # Act
            result = await user_repository.update_password(mock_db, user_id, new_password)
            
            # Assert
            assert result is True
            assert mock_user.password_hash == "new_hashed_password"
            assert mock_user.password_changed_at == "2023-01-01T00:00:00"
            mock_db.commit.assert_called_once()
            MockSecurity.get_password_hash.assert_called_once_with(new_password)
    
    @pytest.mark.asyncio
    async def test_verify_password_success(self, user_repository, mock_db):
        """Test successful password verification."""
        # Arrange
        user_id = 1
        password = "password123"
        stored_hash = "hashed_password"
        
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = stored_hash
        mock_db.execute.return_value = mock_result
        
        with patch('src.repositories.user_repository.SecurityService') as MockSecurity:
            MockSecurity.verify_password.return_value = True
            
            # Act
            result = await user_repository.verify_password(mock_db, user_id, password)
            
            # Assert
            assert result is True
            MockSecurity.verify_password.assert_called_once_with(password, stored_hash)
    
    @pytest.mark.asyncio
    async def test_verify_password_failure(self, user_repository, mock_db):
        """Test password verification failure."""
        # Arrange
        user_id = 1
        password = "wrongpassword"
        stored_hash = "hashed_password"
        
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = stored_hash
        mock_db.execute.return_value = mock_result
        
        with patch('src.repositories.user_repository.SecurityService') as MockSecurity:
            MockSecurity.verify_password.return_value = False
            
            # Act
            result = await user_repository.verify_password(mock_db, user_id, password)
            
            # Assert
            assert result is False
    
    @pytest.mark.asyncio
    async def test_get_all_users(self, user_repository, mock_db):
        """Test retrieving all users with pagination."""
        # Arrange
        mock_users = [mock_user for _ in range(3)]
        mock_result = AsyncMock()
        mock_result.scalars.return_value.all.return_value = mock_users
        mock_db.execute.return_value = mock_result
        
        # Act
        result = await user_repository.get_all(mock_db, skip=0, limit=10)
        
        # Assert
        assert len(result) == 3
        for user in result:
            assert user.email == "test@example.com"  # Should be decrypted
        mock_db.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_search_users(self, user_repository, mock_db):
        """Test user search functionality."""
        # Arrange
        query = "john"
        mock_users = [mock_user for _ in range(2)]
        mock_result = AsyncMock()
        mock_result.scalars.return_value.all.return_value = mock_users
        mock_db.execute.return_value = mock_result
        
        # Act
        result = await user_repository.search(mock_db, query, skip=0, limit=10)
        
        # Assert
        assert len(result) <= 2
        # Since we're filtering by decrypted name, verify the logic
        for user in result:
            assert "john" in user.first_name.lower() or "john" in user.last_name.lower()
    
    def test_serialize_user_for_cache(self, user_repository, mock_user):
        """Test user serialization for caching."""
        # Arrange
        mock_user.created_at = "2023-01-01T00:00:00"
        mock_user.updated_at = "2023-01-01T01:00:00"
        
        # Act
        result = user_repository._serialize_user_for_cache(mock_user)
        
        # Assert
        expected_fields = {"id", "email", "first_name", "last_name", "is_active", "is_verified", "created_at", "updated_at"}
        assert set(result.keys()) == expected_fields
        assert result["id"] == 1
        assert result["email"] == "encrypted_test@example.com"  # Should remain encrypted
        assert result["first_name"] == "encrypted_John"  # Should remain encrypted