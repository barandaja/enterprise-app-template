"""Seed initial data for auth service

Revision ID: 002
Revises: 001
Create Date: 2024-01-01 01:00:00.000000

This migration seeds the database with initial data required for the
authentication service to function properly.

Migration Details:
- Revision: 002
- Previous: 001 (initial schema)
- Created: 2024-01-01 01:00:00.000000

SEEDED DATA:
1. Basic permissions for RBAC system
2. System roles (admin, user, readonly)
3. Default superuser account (if configured)
4. Role-permission assignments

IMPORTANT NOTES:
1. The superuser password should be changed immediately after deployment
2. Review and customize permissions based on your application needs
3. This data is essential for the authentication system to work
4. Additional roles and permissions can be added through the API
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import text
from datetime import datetime
import os
import hashlib

# revision identifiers, used by Alembic.
revision: str = '002'
down_revision: Union[str, None] = '001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """
    Seed the database with initial data required for the auth service.
    
    This includes:
    - Basic CRUD permissions for core resources
    - System roles with appropriate permissions
    - Default superuser account (if configured)
    - Role-permission mappings
    
    The seeded data provides a foundation for the RBAC system
    and ensures the service can authenticate and authorize users.
    """
    
    # Get database connection
    connection = op.get_bind()
    
    # Insert basic permissions
    permissions_data = [
        # User management permissions
        ('users:create', 'Create new users', 'users', 'create'),
        ('users:read', 'Read user information', 'users', 'read'),
        ('users:update', 'Update user information', 'users', 'update'),
        ('users:delete', 'Delete users', 'users', 'delete'),
        ('users:list', 'List all users', 'users', 'list'),
        
        # Role management permissions
        ('roles:create', 'Create new roles', 'roles', 'create'),
        ('roles:read', 'Read role information', 'roles', 'read'),
        ('roles:update', 'Update role information', 'roles', 'update'),
        ('roles:delete', 'Delete roles', 'roles', 'delete'),
        ('roles:list', 'List all roles', 'roles', 'list'),
        ('roles:assign', 'Assign roles to users', 'roles', 'assign'),
        
        # Permission management permissions
        ('permissions:create', 'Create new permissions', 'permissions', 'create'),
        ('permissions:read', 'Read permission information', 'permissions', 'read'),
        ('permissions:update', 'Update permission information', 'permissions', 'update'),
        ('permissions:delete', 'Delete permissions', 'permissions', 'delete'),
        ('permissions:list', 'List all permissions', 'permissions', 'list'),
        
        # Session management permissions
        ('sessions:read', 'Read session information', 'sessions', 'read'),
        ('sessions:delete', 'End user sessions', 'sessions', 'delete'),
        ('sessions:list', 'List user sessions', 'sessions', 'list'),
        
        # Audit log permissions
        ('audit:read', 'Read audit logs', 'audit', 'read'),
        ('audit:list', 'List audit logs', 'audit', 'list'),
        ('audit:export', 'Export audit data', 'audit', 'export'),
        
        # System administration permissions
        ('system:admin', 'System administration', 'system', 'admin'),
        ('system:monitor', 'System monitoring', 'system', 'monitor'),
        ('system:backup', 'System backup operations', 'system', 'backup'),
        
        # Profile management permissions
        ('profile:read', 'Read own profile', 'profile', 'read'),
        ('profile:update', 'Update own profile', 'profile', 'update'),
        ('profile:delete', 'Delete own profile', 'profile', 'delete'),
    ]
    
    # Insert permissions
    for name, description, resource, action in permissions_data:
        connection.execute(text("""
            INSERT INTO permission (name, description, resource, action, created_at, updated_at, is_deleted)
            VALUES (:name, :description, :resource, :action, :created_at, :updated_at, :is_deleted)
        """), {
            'name': name,
            'description': description,
            'resource': resource,
            'action': action,
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow(),
            'is_deleted': False
        })
    
    # Insert system roles
    roles_data = [
        ('superuser', 'System superuser with all permissions', True),
        ('admin', 'Administrator with full user and system management permissions', True),
        ('user_manager', 'Can manage users and assign basic roles', True),
        ('auditor', 'Can read audit logs and user information', True),
        ('user', 'Standard user with basic profile permissions', True),
        ('readonly', 'Read-only access to own profile', True),
    ]
    
    # Insert roles
    for name, description, is_system_role in roles_data:
        connection.execute(text("""
            INSERT INTO role (name, description, is_system_role, created_at, updated_at, is_deleted)
            VALUES (:name, :description, :is_system_role, :created_at, :updated_at, :is_deleted)
        """), {
            'name': name,
            'description': description,
            'is_system_role': is_system_role,
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow(),
            'is_deleted': False
        })
    
    # Define role-permission mappings
    role_permissions = {
        'superuser': [
            # Superusers get all permissions
            'users:create', 'users:read', 'users:update', 'users:delete', 'users:list',
            'roles:create', 'roles:read', 'roles:update', 'roles:delete', 'roles:list', 'roles:assign',
            'permissions:create', 'permissions:read', 'permissions:update', 'permissions:delete', 'permissions:list',
            'sessions:read', 'sessions:delete', 'sessions:list',
            'audit:read', 'audit:list', 'audit:export',
            'system:admin', 'system:monitor', 'system:backup',
            'profile:read', 'profile:update', 'profile:delete'
        ],
        'admin': [
            # Admins get most permissions except system-level ones
            'users:create', 'users:read', 'users:update', 'users:delete', 'users:list',
            'roles:read', 'roles:list', 'roles:assign',
            'permissions:read', 'permissions:list',
            'sessions:read', 'sessions:delete', 'sessions:list',
            'audit:read', 'audit:list',
            'system:monitor',
            'profile:read', 'profile:update', 'profile:delete'
        ],
        'user_manager': [
            # User managers can manage users and assign basic roles
            'users:create', 'users:read', 'users:update', 'users:list',
            'roles:read', 'roles:list', 'roles:assign',
            'sessions:read', 'sessions:list',
            'profile:read', 'profile:update'
        ],
        'auditor': [
            # Auditors can read logs and user information
            'users:read', 'users:list',
            'roles:read', 'roles:list',
            'sessions:read', 'sessions:list',
            'audit:read', 'audit:list', 'audit:export',
            'profile:read'
        ],
        'user': [
            # Standard users can manage their own profile and sessions
            'profile:read', 'profile:update',
            'sessions:read', 'sessions:delete'
        ],
        'readonly': [
            # Read-only users can only view their own profile
            'profile:read'
        ]
    }
    
    # Insert role-permission mappings
    for role_name, permission_names in role_permissions.items():
        for permission_name in permission_names:
            connection.execute(text("""
                INSERT INTO role_permissions (role_id, permission_id, assigned_at, assigned_by)
                SELECT r.id, p.id, :assigned_at, NULL
                FROM role r, permission p
                WHERE r.name = :role_name AND p.name = :permission_name
            """), {
                'role_name': role_name,
                'permission_name': permission_name,
                'assigned_at': datetime.utcnow()
            })
    
    # Create default superuser if configured
    admin_email = os.getenv('ADMIN_EMAIL', 'admin@example.com')
    admin_password = os.getenv('ADMIN_PASSWORD', 'ChangeMe123!')
    
    if admin_email and admin_password:
        # Hash the password (simplified - in practice, use proper password hashing)
        from passlib.context import CryptContext
        pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        hashed_password = pwd_context.hash(admin_password)
        
        # Simple encryption for email (in practice, use proper field-level encryption)
        # For now, we'll store it as plain text with a note that it should be encrypted
        encrypted_email = admin_email.encode('utf-8')  # Placeholder - should use proper encryption
        
        # Insert superuser
        connection.execute(text("""
            INSERT INTO "user" (
                email, first_name, last_name, hashed_password, 
                is_active, is_verified, is_superuser,
                data_processing_consent, marketing_consent,
                email_verified_at, password_changed_at,
                created_at, updated_at, is_deleted
            ) VALUES (
                :email, :first_name, :last_name, :hashed_password,
                :is_active, :is_verified, :is_superuser,
                :data_processing_consent, :marketing_consent,
                :email_verified_at, :password_changed_at,
                :created_at, :updated_at, :is_deleted
            )
        """), {
            'email': encrypted_email,
            'first_name': b'System',  # Encrypted placeholder
            'last_name': b'Administrator',  # Encrypted placeholder
            'hashed_password': hashed_password,
            'is_active': True,
            'is_verified': True,
            'is_superuser': True,
            'data_processing_consent': True,
            'marketing_consent': False,
            'email_verified_at': datetime.utcnow(),
            'password_changed_at': datetime.utcnow(),
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow(),
            'is_deleted': False
        })
        
        # Assign superuser role to the admin user
        connection.execute(text("""
            INSERT INTO user_roles (user_id, role_id, assigned_at, assigned_by)
            SELECT u.id, r.id, :assigned_at, u.id
            FROM "user" u, role r
            WHERE u.is_superuser = true AND r.name = 'superuser'
            LIMIT 1
        """), {
            'assigned_at': datetime.utcnow()
        })
    
    # Commit the transaction
    connection.commit()


def downgrade() -> None:
    """
    Remove the seeded initial data.
    
    WARNING: This will remove all seeded roles, permissions, and the superuser account.
    This should only be used in development environments.
    
    The downgrade removes data in reverse dependency order:
    1. User-role assignments
    2. Role-permission assignments  
    3. Users (superuser)
    4. Roles
    5. Permissions
    """
    connection = op.get_bind()
    
    # Remove user-role assignments
    connection.execute(text("DELETE FROM user_roles"))
    
    # Remove role-permission assignments
    connection.execute(text("DELETE FROM role_permissions"))
    
    # Remove superuser (if exists)
    connection.execute(text("DELETE FROM \"user\" WHERE is_superuser = true"))
    
    # Remove roles
    role_names = ['superuser', 'admin', 'user_manager', 'auditor', 'user', 'readonly']
    for role_name in role_names:
        connection.execute(text("DELETE FROM role WHERE name = :name"), {'name': role_name})
    
    # Remove permissions
    permission_names = [
        'users:create', 'users:read', 'users:update', 'users:delete', 'users:list',
        'roles:create', 'roles:read', 'roles:update', 'roles:delete', 'roles:list', 'roles:assign',
        'permissions:create', 'permissions:read', 'permissions:update', 'permissions:delete', 'permissions:list',
        'sessions:read', 'sessions:delete', 'sessions:list',
        'audit:read', 'audit:list', 'audit:export',
        'system:admin', 'system:monitor', 'system:backup',
        'profile:read', 'profile:update', 'profile:delete'
    ]
    
    for permission_name in permission_names:
        connection.execute(text("DELETE FROM permission WHERE name = :name"), {'name': permission_name})
    
    # Commit the transaction
    connection.commit()