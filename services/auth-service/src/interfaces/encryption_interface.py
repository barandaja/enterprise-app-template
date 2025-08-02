"""
Encryption service interface for dependency abstraction.
Defines the contract for encryption operations to enable dependency injection
and improve testability.
"""

from typing import Protocol, runtime_checkable


@runtime_checkable
class IEncryptionService(Protocol):
    """Protocol for encryption service operations."""
    
    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt plaintext data.
        
        Args:
            plaintext: Data to encrypt
            
        Returns:
            Encrypted data as string
        """
        ...
    
    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypt encrypted data.
        
        Args:
            ciphertext: Encrypted data to decrypt
            
        Returns:
            Decrypted plaintext
        """
        ...
    
    def hash_data(self, data: str) -> str:
        """
        Create a hash of the data for indexing/comparison.
        
        Args:
            data: Data to hash
            
        Returns:
            Hash of the data
        """
        ...
    
    def verify_hash(self, data: str, hash_value: str) -> bool:
        """
        Verify data against hash.
        
        Args:
            data: Original data
            hash_value: Hash to verify against
            
        Returns:
            True if data matches hash, False otherwise
        """
        ...
    
    def generate_key(self) -> str:
        """
        Generate a new encryption key.
        
        Returns:
            New encryption key
        """
        ...
    
    def encrypt_with_key(self, plaintext: str, key: str) -> str:
        """
        Encrypt data with specific key.
        
        Args:
            plaintext: Data to encrypt
            key: Encryption key to use
            
        Returns:
            Encrypted data
        """
        ...
    
    def decrypt_with_key(self, ciphertext: str, key: str) -> str:
        """
        Decrypt data with specific key.
        
        Args:
            ciphertext: Encrypted data
            key: Decryption key to use
            
        Returns:
            Decrypted data
        """
        ...