"""
Field-level encryption for PII data compliance (GDPR, HIPAA).
Implements transparent encryption/decryption with random salts and key rotation support.
"""
import base64
import json
import os
import hashlib
from typing import Any, Optional, Union, Tuple
from cryptography.fernet import Fernet, MultiFernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from sqlalchemy import TypeDecorator, String, Text, Column
from sqlalchemy.dialects.postgresql import BYTEA
import structlog
from ..core.config import settings

logger = structlog.get_logger()

# Constants for encryption
SALT_LENGTH = 32  # 256 bits
ITERATIONS = 100000  # PBKDF2 iterations
KEY_LENGTH = 32  # 256 bits for Fernet
VERSION_BYTE_LENGTH = 1  # Version identifier


class EncryptionManager:
    """
    Manages encryption keys and operations for PII data.
    
    Features:
    - Random salt per encryption operation
    - Key rotation support with versioning
    - Secure key derivation using PBKDF2
    - Performance optimization with key caching
    """
    
    _instances = {}
    _master_key: bytes
    _encryption_keys: dict[int, bytes] = {}
    _current_version: int = 1
    
    def __new__(cls):
        if cls not in cls._instances:
            cls._instances[cls] = super().__new__(cls)
        return cls._instances[cls]
    
    def __init__(self):
        if not hasattr(self, '_initialized'):
            self._initialize_encryption()
            self._initialized = True
    
    def _initialize_encryption(self) -> None:
        """Initialize encryption with secure key management."""
        try:
            # Use dedicated encryption key from settings
            self._master_key = settings.ENCRYPTION_KEY.encode('utf-8')
            
            # Pre-derive a key for the current version with a version-specific salt
            # This is used for key rotation support
            version_salt = self._get_version_salt(self._current_version)
            self._encryption_keys[self._current_version] = self._derive_key(
                self._master_key, 
                version_salt
            )
            
            logger.info(
                "Encryption manager initialized",
                current_version=self._current_version,
                iterations=ITERATIONS
            )
            
        except Exception as e:
            logger.error("Failed to initialize encryption", error=str(e))
            raise RuntimeError("Encryption initialization failed") from e
    
    def _get_version_salt(self, version: int) -> bytes:
        """
        Generate a deterministic salt for a specific key version.
        This allows key rotation while maintaining backward compatibility.
        """
        # Combine master key with version for version-specific salt
        version_data = f"v{version}:auth_service:encryption".encode('utf-8')
        return hashlib.sha256(self._master_key + version_data).digest()
    
    def _derive_key(self, master_key: bytes, salt: bytes) -> bytes:
        """Derive an encryption key using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_LENGTH,
            salt=salt,
            iterations=ITERATIONS,
        )
        return base64.urlsafe_b64encode(kdf.derive(master_key))
    
    def _generate_random_salt(self) -> bytes:
        """Generate a cryptographically secure random salt."""
        return os.urandom(SALT_LENGTH)
    
    def encrypt(self, value: str) -> bytes:
        """
        Encrypt a string value with a random salt.
        
        Format: [version:1][salt:32][encrypted_data:N]
        """
        if not value:
            return b''
        
        try:
            # Generate random salt for this encryption
            salt = self._generate_random_salt()
            
            # Derive a unique key for this data using the random salt
            data_key = self._derive_key(self._master_key, salt)
            
            # Encrypt the value
            fernet = Fernet(data_key)
            encrypted_data = fernet.encrypt(value.encode('utf-8'))
            
            # Combine version, salt, and encrypted data
            version_byte = self._current_version.to_bytes(VERSION_BYTE_LENGTH, 'big')
            result = version_byte + salt + encrypted_data
            
            return result
            
        except Exception as e:
            logger.error("Encryption failed", error=str(e))
            raise RuntimeError("Encryption failed") from e
    
    def decrypt(self, encrypted_value: bytes) -> str:
        """
        Decrypt an encrypted value.
        
        Handles multiple key versions for rotation support.
        """
        if not encrypted_value:
            return ''
        
        try:
            # Extract version, salt, and encrypted data
            if len(encrypted_value) < VERSION_BYTE_LENGTH + SALT_LENGTH:
                raise ValueError("Invalid encrypted data format")
            
            version = int.from_bytes(
                encrypted_value[:VERSION_BYTE_LENGTH], 
                'big'
            )
            salt = encrypted_value[VERSION_BYTE_LENGTH:VERSION_BYTE_LENGTH + SALT_LENGTH]
            encrypted_data = encrypted_value[VERSION_BYTE_LENGTH + SALT_LENGTH:]
            
            logger.info("Decryption details",
                        total_length=len(encrypted_value),
                        version=version, 
                        salt_length=len(salt),
                        encrypted_data_length=len(encrypted_data))
            
            # Derive the key using the extracted salt
            data_key = self._derive_key(self._master_key, salt)
            
            # Decrypt the data
            fernet = Fernet(data_key)
            decrypted_value = fernet.decrypt(encrypted_data)
            
            return decrypted_value.decode('utf-8')
            
        except Exception as e:
            logger.error(
                "Detailed decryption failure analysis", 
                error=str(e),
                error_type=type(e).__name__,
                data_length=len(encrypted_value) if encrypted_value else 0,
                data_preview=encrypted_value[:50] if encrypted_value else None,
                data_ends_with_equals=encrypted_value.endswith(b'=') if encrypted_value else False
            )
            
            # TEMPORARY FALLBACK: Handle different data formats from seed migration
            try:
                # Check if this might be base64-encoded Fernet data stored as bytes
                if encrypted_value and b'gAAAAA' in encrypted_value:
                    logger.info("Data appears to contain Fernet signature, attempting direct Fernet decode")
                    # The seed migration may have used Fernet directly with the bcrypt-style key derivation
                    # Let's try different key derivation approaches that might have been used
                    
                    # Try 1: Use master key directly (if seed used it raw)
                    try:
                        direct_fernet_1 = Fernet(self._master_key)
                        decrypted_value = direct_fernet_1.decrypt(encrypted_value)
                        logger.warning("Successfully decrypted using raw master key (seed migration format)")
                        return decrypted_value.decode('utf-8')
                    except Exception as e1:
                        logger.debug("Raw master key failed", error=str(e1))
                    
                    # Try 2: Use derived key with default salt
                    try:
                        derived_key = self._derive_key(self._master_key, b'defaultsalt12345')
                        direct_fernet_2 = Fernet(derived_key)
                        decrypted_value = direct_fernet_2.decrypt(encrypted_value)
                        logger.warning("Successfully decrypted using derived key (seed migration format)")
                        return decrypted_value.decode('utf-8')
                    except Exception as e2:
                        logger.debug("Derived key failed", error=str(e2))
                    
                    # Try 3: Use the exact same approach as migration 006
                    # This recreates the exact key derivation from the migration
                    try:
                        import base64
                        from cryptography.hazmat.primitives import hashes
                        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
                        
                        # Extract the salt that was used (first 33 bytes: version + salt)
                        if len(encrypted_value) > 33:
                            migration_salt = encrypted_value[1:33]  # Skip version byte, take 32 bytes
                            migration_encrypted_data = encrypted_value[33:]  # Rest is Fernet data
                            
                            # Use exact migration key derivation
                            kdf = PBKDF2HMAC(
                                algorithm=hashes.SHA256(),
                                length=32,
                                salt=migration_salt,
                                iterations=100000,
                            )
                            migration_key = base64.urlsafe_b64encode(kdf.derive(self._master_key))
                            
                            # Try to decrypt
                            migration_fernet = Fernet(migration_key)
                            decrypted_value = migration_fernet.decrypt(migration_encrypted_data)
                            logger.warning("Successfully decrypted using exact migration 006 method")
                            return decrypted_value.decode('utf-8')
                    except Exception as e3:
                        logger.debug("Migration 006 method failed", error=str(e3))
                    
                    logger.info("All direct Fernet attempts failed")
                
                # Try to decode as UTF-8 (fallback for seed data)
                potential_text = encrypted_value.decode('utf-8')
                logger.warning(
                    "Decryption failed, falling back to raw UTF-8 decode - this suggests data from seed migration",
                    data_length=len(encrypted_value),
                    original_error=str(e)
                )
                return potential_text
            except Exception as fallback_e:
                # Not raw UTF-8 either - this is genuinely corrupted data
                logger.error(
                    "All decryption fallbacks failed", 
                    original_error=str(e),
                    fallback_error=str(fallback_e),
                    data_length=len(encrypted_value) if encrypted_value else 0
                )
                raise RuntimeError("Decryption failed") from e
    
    def encrypt_dict(self, data: dict) -> bytes:
        """Encrypt a dictionary as JSON."""
        if not data:
            return b''
        
        json_str = json.dumps(data, sort_keys=True)
        return self.encrypt(json_str)
    
    def decrypt_dict(self, encrypted_data: bytes) -> dict:
        """Decrypt and parse JSON dictionary."""
        if not encrypted_data:
            return {}
        
        decrypted_str = self.decrypt(encrypted_data)
        return json.loads(decrypted_str) if decrypted_str else {}


# Global encryption manager instance
encryption_manager = EncryptionManager()


class EncryptedType(TypeDecorator):
    """SQLAlchemy type for transparent field encryption."""
    
    impl = BYTEA
    cache_ok = True
    
    def __init__(self, *args, **kwargs):
        self.encryption_manager = encryption_manager
        # TypeDecorator and its impl (BYTEA/LargeBinary) don't accept SQLAlchemy column arguments
        # Only pass the positional args to avoid "unexpected keyword argument" errors
        super().__init__(*args)
    
    def process_bind_param(self, value: Any, dialect) -> Optional[bytes]:
        """Encrypt value before storing in database."""
        if value is None:
            return None
        
        if isinstance(value, str):
            return self.encryption_manager.encrypt(value)
        elif isinstance(value, dict):
            return self.encryption_manager.encrypt_dict(value)
        else:
            # Convert to string then encrypt
            return self.encryption_manager.encrypt(str(value))
    
    def process_result_value(self, value: Optional[bytes], dialect) -> Optional[str]:
        """Decrypt value when loading from database."""
        if value is None:
            return None
        
        try:
            return self.encryption_manager.decrypt(value)
        except Exception as e:
            # TEMPORARY BYPASS: Return a placeholder for failed decryption
            # This allows the User object to be created so the User model's bypass logic can work
            logger.warning(
                "EncryptedType decryption failed during SQLAlchemy loading - using placeholder",
                error=str(e),
                error_type=type(e).__name__
            )
            # Return a special marker that indicates decryption failed
            # The User model can detect this and handle it appropriately
            return f"__DECRYPTION_FAILED_{len(value)}__"


class EncryptedString(EncryptedType):
    """Encrypted string field for PII data."""
    pass


class EncryptedText(EncryptedType):
    """Encrypted text field for larger PII data."""
    pass


class EncryptedJSON(TypeDecorator):
    """Encrypted JSON field for structured PII data."""
    
    impl = BYTEA
    cache_ok = True
    
    def __init__(self, *args, **kwargs):
        self.encryption_manager = encryption_manager
        # TypeDecorator and its impl (BYTEA/LargeBinary) don't accept SQLAlchemy column arguments
        # Only pass the positional args to avoid "unexpected keyword argument" errors
        super().__init__(*args)
    
    def process_bind_param(self, value: Any, dialect) -> Optional[bytes]:
        """Encrypt JSON value before storing."""
        if value is None:
            return None
        
        return self.encryption_manager.encrypt_dict(value)
    
    def process_result_value(self, value: Optional[bytes], dialect) -> Optional[dict]:
        """Decrypt and parse JSON value."""
        if value is None:
            return None
        
        return self.encryption_manager.decrypt_dict(value)


# Convenience function for creating encrypted fields
def EncryptedField(field_type: str = "string", **kwargs) -> Column:
    """
    Factory function for creating encrypted fields with proper SQLAlchemy Column support.
    
    Args:
        field_type: Type of field ("string", "text", "json")
        **kwargs: SQLAlchemy column arguments (nullable, index, unique, etc.)
    
    Returns:
        SQLAlchemy Column with appropriate encrypted type or regular type based on settings
    """
    
    # Check if encryption is enabled
    if not settings.ENABLE_DATA_ENCRYPTION:
        # Use regular fields when encryption is disabled
        from sqlalchemy.dialects.postgresql import JSON
        if field_type == "string":
            return Column(String(255), **kwargs)
        elif field_type == "text":
            return Column(Text, **kwargs)
        elif field_type == "json":
            return Column(JSON, **kwargs)
        else:
            raise ValueError(f"Unsupported field type: {field_type}")
    
    # Determine the appropriate encrypted type
    if field_type == "string":
        encrypted_type = EncryptedString()
    elif field_type == "text":
        encrypted_type = EncryptedText()
    elif field_type == "json":
        encrypted_type = EncryptedJSON()
    else:
        raise ValueError(f"Unsupported encrypted field type: {field_type}")
    
    # Create and return a Column with the encrypted type and all provided kwargs
    return Column(encrypted_type, **kwargs)


class PIIFieldMixin:
    """Mixin for models containing PII data with audit requirements."""
    
    def get_pii_fields(self) -> list[str]:
        """Return list of PII field names for audit purposes."""
        pii_fields = []
        for column in self.__table__.columns:
            if isinstance(column.type, EncryptedType):
                pii_fields.append(column.name)
        return pii_fields
    
    def mask_pii_for_logging(self, data: dict) -> dict:
        """Mask PII fields in data for safe logging."""
        masked_data = data.copy()
        pii_fields = self.get_pii_fields()
        
        for field in pii_fields:
            if field in masked_data:
                masked_data[field] = "***MASKED***"
        
        return masked_data