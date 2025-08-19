"""Fix superuser authentication issue

Revision ID: 006
Revises: 005
Create Date: 2025-08-04 15:40:00.000000

This migration fixes the superuser authentication issue by:
1. Updating the superuser's password to 'AdminPassword123!' (properly hashed with bcrypt)
2. Adding the email_hash field for the superuser (SHA256 hash of lowercase email)
3. Ensuring all required fields are properly set for authentication

The superuser email is 'admin@example.com' and after this migration,
you can login with admin@example.com / AdminPassword123!
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import text
from datetime import datetime
import hashlib

# revision identifiers, used by Alembic.
revision: str = '006'
down_revision: Union[str, None] = '005_create_enum_types'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """
    Fix the superuser authentication issue.
    
    This migration:
    1. Updates the superuser password to 'AdminPassword123!' using bcrypt
    2. Adds the email_hash field required for authentication
    3. Ensures the superuser record is properly configured
    """
    
    # Get database connection
    connection = op.get_bind()
    
    # Hash the new password using bcrypt (same method as SecurityService)
    from passlib.context import CryptContext
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    new_password = 'AdminPassword123!'
    hashed_password = pwd_context.hash(new_password)
    
    # Generate email hash for 'admin@example.com'
    admin_email = 'admin@example.com'
    email_hash = hashlib.sha256(admin_email.lower().encode('utf-8')).hexdigest()
    
    # Update the superuser record
    update_result = connection.execute(text("""
        UPDATE "user" 
        SET 
            hashed_password = :hashed_password,
            email_hash = :email_hash,
            updated_at = :updated_at
        WHERE is_superuser = true
    """), {
        'hashed_password': hashed_password,
        'email_hash': email_hash,
        'updated_at': datetime.utcnow()
    })
    
    # If no rows were updated, it means the superuser doesn't exist and needs to be created
    # However, we need to also fix the existing superuser email encryption
    
    # First, let's properly encrypt the email using direct encryption (without import issues)
    import base64
    import os
    import hashlib
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    
    # Initialize encryption directly (similar to EncryptionManager)
    encryption_key = os.getenv('ENCRYPTION_KEY', 'fallback-key-for-migration-only-please-set-proper-key')
    master_key = encryption_key.encode('utf-8')
    
    def encrypt_value(value: str) -> bytes:
        """Encrypt a value using the same method as EncryptionManager."""
        if not value:
            return b''
        
        # Generate random salt for this encryption
        salt = os.urandom(32)
        
        # Derive a unique key for this data using the random salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        data_key = base64.urlsafe_b64encode(kdf.derive(master_key))
        
        # Encrypt the value
        fernet = Fernet(data_key)
        encrypted_data = fernet.encrypt(value.encode('utf-8'))
        
        # Combine version, salt, and encrypted data
        version_byte = (1).to_bytes(1, 'big')
        result = version_byte + salt + encrypted_data
        
        return result
    
    # Properly encrypt the email
    encrypted_email = encrypt_value(admin_email)
    encrypted_first_name = encrypt_value('System')
    encrypted_last_name = encrypt_value('Administrator')
    
    if update_result.rowcount == 0:
        # No superuser found, create one with properly encrypted data
        connection.execute(text("""
            INSERT INTO "user" (
                email, email_hash, first_name, last_name, hashed_password, 
                is_active, is_verified, is_superuser,
                failed_login_attempts,
                data_processing_consent, marketing_consent,
                email_verified_at, password_changed_at,
                created_at, updated_at, is_deleted
            ) VALUES (
                :email, :email_hash, :first_name, :last_name, :hashed_password,
                :is_active, :is_verified, :is_superuser,
                :failed_login_attempts,
                :data_processing_consent, :marketing_consent,
                :email_verified_at, :password_changed_at,
                :created_at, :updated_at, :is_deleted
            )
        """), {
            'email': encrypted_email,
            'email_hash': email_hash,
            'first_name': encrypted_first_name,
            'last_name': encrypted_last_name,
            'hashed_password': hashed_password,
            'is_active': True,
            'is_verified': True,
            'is_superuser': True,
            'failed_login_attempts': 0,
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
            AND NOT EXISTS (
                SELECT 1 FROM user_roles ur 
                WHERE ur.user_id = u.id AND ur.role_id = r.id
            )
            LIMIT 1
        """), {
            'assigned_at': datetime.utcnow()
        })
    else:
        # Superuser exists, but we need to fix the encrypted email and names
        connection.execute(text("""
            UPDATE "user" 
            SET 
                email = :email,
                first_name = :first_name,
                last_name = :last_name,
                updated_at = :updated_at
            WHERE is_superuser = true
        """), {
            'email': encrypted_email,
            'first_name': encrypted_first_name,
            'last_name': encrypted_last_name,
            'updated_at': datetime.utcnow()
        })
    
    # Commit the transaction
    connection.commit()
    
    print(f"✅ Superuser authentication fixed!")
    print(f"📧 Email: {admin_email}")
    print(f"🔑 Password: {new_password}")
    print(f"🔐 Email hash: {email_hash}")


def downgrade() -> None:
    """
    Revert the superuser authentication fix.
    
    WARNING: This will revert the superuser to the previous state
    which had authentication issues.
    """
    connection = op.get_bind()
    
    # Hash the old password (from the original migration)
    from passlib.context import CryptContext
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    old_password = 'ChangeMe123!'  # Original default password
    hashed_password = pwd_context.hash(old_password)
    
    # Remove the email_hash and revert password
    connection.execute(text("""
        UPDATE "user" 
        SET 
            hashed_password = :hashed_password,
            email_hash = NULL,
            updated_at = :updated_at
        WHERE is_superuser = true
    """), {
        'hashed_password': hashed_password,
        'updated_at': datetime.utcnow()
    })
    
    # Commit the transaction
    connection.commit()
    
    print("⚠️  Superuser reverted to previous state (authentication may not work)")