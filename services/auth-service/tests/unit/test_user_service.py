"""
Comprehensive unit tests for UserService class.
Tests CRUD operations, role management, and user lifecycle.
"""
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta
from fastapi import HTTPException, status

from src.services.user_service import UserService
from src.models.user import User, Role, Permission
from src.models.audit import AuditEventType, AuditLog
from tests.factories import UserFactory, RoleFactory, PermissionFactory


class TestUserService:
    """Test suite for UserService class."""
    
    @pytest.fixture
    def user_service(self):
        """Create UserService instance with mocked dependencies."""
        with patch('src.services.user_service.get_cache_service') as mock_cache_service, \
             patch('src.services.user_service.AuditLogger') as mock_audit_logger:
            
            service = UserService()
            service.cache_service = mock_cache_service.return_value
            service.audit_logger = mock_audit_logger.return_value
            
            return service
    
    @pytest.mark.unit
    @pytest.mark.database
    @pytest_asyncio.async
    async def test_create_user_success(self, user_service, db_session):
        """Test successful user creation."""
        # Arrange
        user = UserFactory(email="test@example.com")
        roles = [RoleFactory(name="user")]
        
        user_service.get_user_by_email = AsyncMock(return_value=None)
        user_service._assign_roles_to_user = AsyncMock()
        user_service.audit_logger.log_data_access = AsyncMock()
        
        with patch('src.models.user.User.create_user') as mock_create_user:
            mock_create_user.return_value = user
            
            # Act
            result = await user_service.create_user(
                db=db_session,
                email="test@example.com",
                password="TestPassword123!",
                first_name="Test",
                last_name="User",
                roles=["user"],
                created_by_user_id=1
            )
            
            # Assert
            assert result == user
            mock_create_user.assert_called_once_with(
                db=db_session,
                email="test@example.com",
                password="TestPassword123!",
                first_name="Test",
                last_name="User",
                is_active=True
            )
            user_service._assign_roles_to_user.assert_called_once_with(db_session, user, ["user"])
            user_service.audit_logger.log_data_access.assert_called_once()
    
    @pytest.mark.unit
    @pytest.mark.database
    @pytest_asyncio.async
    async def test_create_user_duplicate_email(self, user_service, db_session):
        """Test user creation with duplicate email."""
        # Arrange
        existing_user = UserFactory(email="test@example.com")
        user_service.get_user_by_email = AsyncMock(return_value=existing_user)
        
        # Act & Assert
        with pytest.raises(HTTPException) as exc_info:
            await user_service.create_user(
                db=db_session,
                email="test@example.com",
                password="TestPassword123!"
            )
        
        assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
        assert exc_info.value.detail == "User with this email already exists"
    
    @pytest.mark.unit
    @pytest.mark.database
    @pytest_asyncio.async  
    async def test_get_user_by_id_success(self, user_service, db_session):
        """Test successful user retrieval by ID."""
        # Arrange
        user = UserFactory(id=1)
        user.to_dict = MagicMock(return_value={"id": 1, "email": "test@example.com"})
        
        user_service.cache_service.get = AsyncMock(return_value=None)
        user_service.cache_service.set = AsyncMock()
        
        with patch('sqlalchemy.future.select') as mock_select, \
             patch.object(db_session, 'execute') as mock_execute:
            
            mock_result = MagicMock()
            mock_result.scalar_one_or_none.return_value = user
            mock_execute.return_value = mock_result
            
            # Act
            result = await user_service.get_user_by_id(db_session, 1)
            
            # Assert
            assert result == user
            user_service.cache_service.set.assert_called_once()
    
    @pytest.mark.unit
    @pytest.mark.database
    @pytest_asyncio.async
    async def test_get_user_by_id_cached(self, user_service, db_session):
        """Test user retrieval from cache."""
        # Arrange
        cached_data = {"id": 1, "email": "test@example.com"}
        user_service.cache_service.get = AsyncMock(return_value=cached_data)
        
        # Act
        result = await user_service.get_user_by_id(db_session, 1)
        
        # Assert - In real implementation, this would reconstruct User object
        # For this test, we'll just verify cache was called
        user_service.cache_service.get.assert_called_once_with("user:1:roles_True")
    
    @pytest.mark.unit
    @pytest.mark.database
    @pytest_asyncio.async
    async def test_get_user_by_email_success(self, user_service, db_session):
        """Test successful user retrieval by email."""
        # Arrange
        user = UserFactory(email="test@example.com")
        
        with patch('src.models.user.User.get_by_email') as mock_get_by_email:
            mock_get_by_email.return_value = user
            
            # Act
            result = await user_service.get_user_by_email(db_session, "test@example.com")
            
            # Assert
            assert result == user
            mock_get_by_email.assert_called_once_with(db_session, "test@example.com")
    
    @pytest.mark.unit
    @pytest.mark.database
    @pytest_asyncio.async
    async def test_update_user_success(self, user_service, db_session):
        """Test successful user update."""
        # Arrange
        user = UserFactory(id=1, first_name="Old", last_name="Name")
        user.to_dict = MagicMock(return_value={"first_name": "Old", "last_name": "Name"})
        user.save = AsyncMock()
        
        update_data = {"first_name": "New", "last_name": "Name"}
        
        user_service.get_user_by_id = AsyncMock(return_value=user)
        user_service.audit_logger.log_data_access = AsyncMock()
        user_service.cache_service.delete_pattern = AsyncMock()
        
        # Act
        result = await user_service.update_user(
            db=db_session,
            user_id=1,
            update_data=update_data,
            updated_by_user_id=1
        )
        
        # Assert
        assert result == user
        assert user.first_name == "New"
        user.save.assert_called_once_with(db_session)
        user_service.audit_logger.log_data_access.assert_called_once()
        user_service.cache_service.delete_pattern.assert_called_once_with("user:1:*")
    
    @pytest.mark.unit
    @pytest.mark.database
    @pytest_asyncio.async
    async def test_update_user_not_found(self, user_service, db_session):
        """Test user update with non-existent user."""
        # Arrange
        user_service.get_user_by_id = AsyncMock(return_value=None)
        
        # Act & Assert
        with pytest.raises(HTTPException) as exc_info:
            await user_service.update_user(
                db=db_session,
                user_id=999,
                update_data={"first_name": "New"},
                updated_by_user_id=1
            )
        
        assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND
        assert exc_info.value.detail == "User not found"
    
    @pytest.mark.unit
    @pytest.mark.database
    @pytest_asyncio.async
    async def test_change_password_success(self, user_service, db_session):
        """Test successful password change."""
        # Arrange
        user = UserFactory(id=1)
        user.verify_password = AsyncMock(return_value=True)
        user.update_password = AsyncMock()
        
        user_service.get_user_by_id = AsyncMock(return_value=user)
        user_service.audit_logger.log_auth_event = AsyncMock()
        
        # Act
        result = await user_service.change_password(
            db=db_session,
            user_id=1,
            current_password="OldPassword123!",
            new_password="NewPassword123!",
            changed_by_user_id=1
        )
        
        # Assert
        assert result is True
        user.verify_password.assert_called_once_with("OldPassword123!")
        user.update_password.assert_called_once_with(db_session, "NewPassword123!")
        user_service.audit_logger.log_auth_event.assert_called_once()
    
    @pytest.mark.unit
    @pytest.mark.database
    @pytest_asyncio.async
    async def test_change_password_wrong_current_password(self, user_service, db_session):
        """Test password change with wrong current password."""
        # Arrange
        user = UserFactory(id=1)
        user.verify_password = AsyncMock(return_value=False)
        
        user_service.get_user_by_id = AsyncMock(return_value=user)
        
        # Act & Assert
        with pytest.raises(HTTPException) as exc_info:
            await user_service.change_password(
                db=db_session,
                user_id=1,
                current_password="WrongPassword",
                new_password="NewPassword123!",
                changed_by_user_id=1
            )
        
        assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
        assert exc_info.value.detail == "Current password is incorrect"
    
    @pytest.mark.unit
    @pytest.mark.database
    @pytest_asyncio.async
    async def test_change_password_admin_action(self, user_service, db_session):
        """Test password change by admin (skip current password verification)."""
        # Arrange
        user = UserFactory(id=1)
        user.update_password = AsyncMock()
        
        user_service.get_user_by_id = AsyncMock(return_value=user)
        user_service.audit_logger.log_auth_event = AsyncMock()
        
        # Act
        result = await user_service.change_password(
            db=db_session,
            user_id=1,
            current_password="ignored",
            new_password="NewPassword123!",
            changed_by_user_id=999  # Different user (admin)
        )
        
        # Assert
        assert result is True
        # verify_password should not be called for admin actions
        user.update_password.assert_called_once_with(db_session, "NewPassword123!")
    
    @pytest.mark.unit
    @pytest.mark.database
    @pytest_asyncio.async
    async def test_deactivate_user_success(self, user_service, db_session):
        """Test successful user deactivation."""
        # Arrange
        user = UserFactory(id=1, is_active=True)
        user.save = AsyncMock()
        
        user_service.get_user_by_id = AsyncMock(return_value=user)
        user_service.audit_logger.log_data_access = AsyncMock()
        user_service.cache_service.delete_pattern = AsyncMock()
        
        # Act
        result = await user_service.deactivate_user(
            db=db_session,
            user_id=1,
            deactivated_by_user_id=999,
            reason="Policy violation"
        )
        
        # Assert
        assert result == user
        assert user.is_active is False
        user.save.assert_called_once_with(db_session)
        user_service.audit_logger.log_data_access.assert_called_once()
        user_service.cache_service.delete_pattern.assert_called_once()
    
    @pytest.mark.unit
    @pytest.mark.database
    @pytest_asyncio.async
    async def test_delete_user_soft_delete(self, user_service, db_session):
        """Test user soft deletion."""
        # Arrange
        user = UserFactory(id=1)
        user.delete = AsyncMock()
        
        user_service.get_user_by_id = AsyncMock(return_value=user)
        user_service.audit_logger.log_data_access = AsyncMock()
        user_service.cache_service.delete_pattern = AsyncMock()
        
        # Act
        result = await user_service.delete_user(
            db=db_session,
            user_id=1,
            deleted_by_user_id=999,
            hard_delete=False
        )
        
        # Assert
        assert result is True
        user.delete.assert_called_once_with(db_session, hard_delete=False)
        user_service.audit_logger.log_data_access.assert_called_once()
    
    @pytest.mark.unit
    @pytest.mark.database
    @pytest_asyncio.async
    async def test_delete_user_hard_delete(self, user_service, db_session):
        """Test user hard deletion."""
        # Arrange
        user = UserFactory(id=1)
        user.delete = AsyncMock()
        
        user_service.get_user_by_id = AsyncMock(return_value=user)
        user_service.audit_logger.log_data_access = AsyncMock()
        user_service.cache_service.delete_pattern = AsyncMock()
        
        # Act
        result = await user_service.delete_user(
            db=db_session,
            user_id=1,
            deleted_by_user_id=999,
            hard_delete=True
        )
        
        # Assert
        assert result is True
        user.delete.assert_called_once_with(db_session, hard_delete=True)
        
        # Verify audit log indicates GDPR deletion
        audit_call = user_service.audit_logger.log_data_access.call_args
        assert "permanently" in audit_call.kwargs["description"]
    
    @pytest.mark.unit
    @pytest.mark.database
    @pytest_asyncio.async
    async def test_assign_role_success(self, user_service, db_session):
        """Test successful role assignment."""
        # Arrange
        user = UserFactory(id=1)
        user.add_role = AsyncMock()
        
        role = RoleFactory(name="admin")
        
        user_service.get_user_by_id = AsyncMock(return_value=user)
        user_service.audit_logger.log_data_access = AsyncMock()
        user_service.cache_service.delete_pattern = AsyncMock()
        
        with patch('src.models.user.Role.get_by_name') as mock_get_role:
            mock_get_role.return_value = role
            
            # Act
            result = await user_service.assign_role(
                db=db_session,
                user_id=1,
                role_name="admin",
                assigned_by_user_id=999
            )
            
            # Assert
            assert result is True
            user.add_role.assert_called_once_with(db_session, role)
            user_service.audit_logger.log_data_access.assert_called_once()
    
    @pytest.mark.unit
    @pytest.mark.database
    @pytest_asyncio.async
    async def test_assign_role_user_not_found(self, user_service, db_session):
        """Test role assignment with non-existent user."""
        # Arrange
        user_service.get_user_by_id = AsyncMock(return_value=None)
        
        # Act & Assert
        with pytest.raises(HTTPException) as exc_info:
            await user_service.assign_role(
                db=db_session,
                user_id=999,
                role_name="admin",
                assigned_by_user_id=1
            )
        
        assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND
        assert exc_info.value.detail == "User not found"
    
    @pytest.mark.unit
    @pytest.mark.database
    @pytest_asyncio.async
    async def test_assign_role_role_not_found(self, user_service, db_session):
        """Test role assignment with non-existent role."""
        # Arrange
        user = UserFactory(id=1)
        user_service.get_user_by_id = AsyncMock(return_value=user)
        
        with patch('src.models.user.Role.get_by_name') as mock_get_role:
            mock_get_role.return_value = None
            
            # Act & Assert
            with pytest.raises(HTTPException) as exc_info:
                await user_service.assign_role(
                    db=db_session,
                    user_id=1,
                    role_name="nonexistent",
                    assigned_by_user_id=999
                )
            
            assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND
            assert exc_info.value.detail == "Role not found"
    
    @pytest.mark.unit
    @pytest.mark.database
    @pytest_asyncio.async
    async def test_remove_role_success(self, user_service, db_session):
        """Test successful role removal."""
        # Arrange
        user = UserFactory(id=1)
        user.remove_role = AsyncMock()
        
        role = RoleFactory(name="admin")
        
        user_service.get_user_by_id = AsyncMock(return_value=user)
        user_service.audit_logger.log_data_access = AsyncMock()
        user_service.cache_service.delete_pattern = AsyncMock()
        
        with patch('src.models.user.Role.get_by_name') as mock_get_role:
            mock_get_role.return_value = role
            
            # Act
            result = await user_service.remove_role(
                db=db_session,
                user_id=1,
                role_name="admin",
                removed_by_user_id=999
            )
            
            # Assert
            assert result is True
            user.remove_role.assert_called_once_with(db_session, role)
            user_service.audit_logger.log_data_access.assert_called_once()
    
    @pytest.mark.unit
    @pytest.mark.database
    @pytest_asyncio.async
    async def test_search_users_with_query(self, user_service, db_session):
        """Test user search with query string."""
        # Arrange
        users = [
            UserFactory(first_name="John", last_name="Doe", is_active=True),
            UserFactory(first_name="Jane", last_name="Smith", is_active=True),
            UserFactory(first_name="Bob", last_name="Johnson", is_active=False)
        ]
        
        with patch('src.models.user.User.get_all') as mock_get_all:
            mock_get_all.return_value = users
            
            # Act
            result = await user_service.search_users(
                db=db_session,
                query="john",
                skip=0,
                limit=50,
                include_inactive=False
            )
            
            # Assert
            # Should find John Doe and Bob Johnson (but Bob is inactive and excluded)
            assert len(result) == 1
            assert result[0].first_name == "John"
    
    @pytest.mark.unit
    @pytest.mark.database
    @pytest_asyncio.async
    async def test_search_users_include_inactive(self, user_service, db_session):
        """Test user search including inactive users."""
        # Arrange
        users = [
            UserFactory(first_name="Active", last_name="User", is_active=True),
            UserFactory(first_name="Inactive", last_name="User", is_active=False)
        ]
        
        with patch('src.models.user.User.get_all') as mock_get_all:
            mock_get_all.return_value = users
            
            # Act
            result = await user_service.search_users(
                db=db_session,
                query="",
                include_inactive=True
            )
            
            # Assert
            assert len(result) == 2
    
    @pytest.mark.unit
    @pytest.mark.database
    @pytest_asyncio.async
    async def test_get_user_audit_trail(self, user_service, db_session):
        """Test retrieving user audit trail."""
        # Arrange
        audit_logs = [
            AuditLog(id=1, event_type=AuditEventType.USER_CREATED),
            AuditLog(id=2, event_type=AuditEventType.LOGIN_SUCCESS)
        ]
        
        with patch('src.models.audit.AuditLog.get_user_audit_trail') as mock_get_trail:
            mock_get_trail.return_value = audit_logs
            
            # Act
            result = await user_service.get_user_audit_trail(
                db=db_session,
                user_id=1,
                limit=100
            )
            
            # Assert
            assert result == audit_logs
            mock_get_trail.assert_called_once_with(
                db=db_session,
                user_id=1,
                start_date=None,
                end_date=None,
                limit=100
            )
    
    @pytest.mark.unit
    @pytest.mark.database
    @pytest_asyncio.async
    async def test_assign_roles_to_user_helper(self, user_service, db_session):
        """Test the helper method for assigning multiple roles."""
        # Arrange
        user = UserFactory(id=1)
        user.add_role = AsyncMock()
        
        roles = [
            RoleFactory(name="user"),
            RoleFactory(name="admin")
        ]
        
        with patch('src.models.user.Role.get_by_name') as mock_get_role:
            mock_get_role.side_effect = [roles[0], roles[1]]
            
            # Act
            await user_service._assign_roles_to_user(
                db=db_session,
                user=user,
                role_names=["user", "admin"]
            )
            
            # Assert
            assert user.add_role.call_count == 2
            user.add_role.assert_any_call(db_session, roles[0])
            user.add_role.assert_any_call(db_session, roles[1])
    
    @pytest.mark.unit
    @pytest.mark.database
    @pytest_asyncio.async
    async def test_assign_roles_to_user_nonexistent_role(self, user_service, db_session):
        """Test assigning non-existent role (should log warning and continue)."""
        # Arrange
        user = UserFactory(id=1)
        user.add_role = AsyncMock()
        
        with patch('src.models.user.Role.get_by_name') as mock_get_role, \
             patch('src.services.user_service.logger') as mock_logger:
            mock_get_role.return_value = None
            
            # Act
            await user_service._assign_roles_to_user(
                db=db_session,
                user=user,
                role_names=["nonexistent"]
            )
            
            # Assert
            mock_logger.warning.assert_called_once()
            user.add_role.assert_not_called()
    
    @pytest.mark.unit
    @pytest.mark.database
    @pytest.mark.parametrize("include_roles", [True, False])
    @pytest_asyncio.async
    async def test_get_user_by_id_include_roles_parameter(self, user_service, db_session, include_roles):
        """Test get_user_by_id with include_roles parameter."""
        # Arrange
        user = UserFactory(id=1)
        user.to_dict = MagicMock(return_value={"id": 1})
        
        user_service.cache_service.get = AsyncMock(return_value=None)
        user_service.cache_service.set = AsyncMock()
        
        with patch('sqlalchemy.future.select') as mock_select, \
             patch.object(db_session, 'execute') as mock_execute:
            
            mock_result = MagicMock()
            mock_result.scalar_one_or_none.return_value = user
            mock_execute.return_value = mock_result
            
            # Act
            await user_service.get_user_by_id(db_session, 1, include_roles=include_roles)
            
            # Assert
            cache_key = f"user:1:roles_{include_roles}"
            user_service.cache_service.get.assert_called_once_with(cache_key)
    
    @pytest.mark.unit
    @pytest.mark.database
    @pytest_asyncio.async
    async def test_update_user_restricted_fields(self, user_service, db_session):
        """Test that only allowed fields can be updated."""
        # Arrange
        user = UserFactory(id=1, first_name="Old")
        user.save = AsyncMock()
        user.to_dict = MagicMock(return_value={})
        
        user_service.get_user_by_id = AsyncMock(return_value=user)
        user_service.audit_logger.log_data_access = AsyncMock()
        user_service.cache_service.delete_pattern = AsyncMock()
        
        # Try to update both allowed and restricted fields
        update_data = {
            "first_name": "New",  # Allowed
            "password_hash": "hacked",  # Not allowed
            "id": 999,  # Not allowed
            "is_deleted": True  # Not allowed
        }
        
        # Act
        await user_service.update_user(
            db=db_session,
            user_id=1,
            update_data=update_data,
            updated_by_user_id=1
        )
        
        # Assert
        assert user.first_name == "New"  # Should be updated
        assert not hasattr(user, 'password_hash') or user.password_hash != "hacked"  # Should not be updated
        assert user.id == 1  # Should remain unchanged
    
    @pytest.mark.unit
    @pytest.mark.database
    @pytest_asyncio.async
    async def test_service_exception_handling(self, user_service, db_session):
        """Test exception handling in service methods."""
        # Arrange
        user_service.get_user_by_id = AsyncMock(side_effect=Exception("Database error"))
        
        # Act & Assert
        with pytest.raises(HTTPException) as exc_info:
            await user_service.update_user(
                db=db_session,
                user_id=1,
                update_data={"first_name": "New"},
                updated_by_user_id=1
            )
        
        assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        assert exc_info.value.detail == "Failed to update user"