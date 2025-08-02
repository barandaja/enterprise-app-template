"""
Security components for event-driven architecture
"""

import hashlib
import hmac
import json
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Any
from uuid import UUID

import jwt
from cryptography.fernet import Fernet
from pydantic import BaseModel, Field


class EventSecurityConfig(BaseModel):
    """Configuration for event security"""
    
    # JWT Configuration
    jwt_secret: str = Field(..., description="Secret key for JWT signing")
    jwt_algorithm: str = Field(default="HS256", description="JWT algorithm")
    jwt_expiry_seconds: int = Field(default=3600, description="JWT token expiry")
    
    # Encryption Configuration
    encryption_key: str = Field(..., description="Fernet encryption key")
    encrypt_sensitive_fields: bool = Field(default=True, description="Enable field encryption")
    sensitive_field_patterns: List[str] = Field(
        default=["password", "secret", "token", "key", "ssn", "credit_card"],
        description="Patterns to identify sensitive fields"
    )
    
    # HMAC Configuration
    hmac_secret: str = Field(..., description="Secret for HMAC signing")
    require_event_signing: bool = Field(default=True, description="Require all events to be signed")
    
    # Rate Limiting
    enable_rate_limiting: bool = Field(default=True, description="Enable rate limiting")
    default_rate_limit_per_minute: int = Field(default=1000, description="Default rate limit")
    
    # Access Control
    enable_rbac: bool = Field(default=True, description="Enable role-based access control")


@dataclass
class ServiceIdentity:
    """Represents a service's identity and permissions"""
    service_name: str
    roles: Set[str]
    permissions: Set[str]
    issued_at: datetime
    expires_at: datetime
    jwt_token: str


class EventPermission:
    """Event permission patterns"""
    
    def __init__(self, pattern: str, actions: Set[str]):
        self.pattern = pattern
        self.actions = actions  # {"publish", "subscribe", "read"}
    
    def matches(self, event_name: str, action: str) -> bool:
        """Check if event name matches pattern and action is allowed"""
        import re
        return re.match(self.pattern, event_name) is not None and action in self.actions


class RoleBasedAccessControl:
    """RBAC for event bus operations"""
    
    def __init__(self):
        self.role_permissions: Dict[str, List[EventPermission]] = {
            "auth-service": [
                EventPermission(r"^auth\..*", {"publish", "subscribe", "read"}),
                EventPermission(r"^user\.profile\.created$", {"subscribe", "read"}),
            ],
            "user-service": [
                EventPermission(r"^user\..*", {"publish", "subscribe", "read"}),
                EventPermission(r"^auth\.user\.registered$", {"subscribe", "read"}),
            ],
            "notification-service": [
                EventPermission(r"^auth\.user\..*", {"subscribe", "read"}),
                EventPermission(r"^user\..*", {"subscribe", "read"}),
                EventPermission(r"^notification\..*", {"publish", "subscribe", "read"}),
            ],
            "admin": [
                EventPermission(r"^.*", {"publish", "subscribe", "read"}),
            ],
        }
    
    def check_permission(self, identity: ServiceIdentity, event_name: str, action: str) -> bool:
        """Check if service has permission for event and action"""
        for role in identity.roles:
            if role in self.role_permissions:
                for permission in self.role_permissions[role]:
                    if permission.matches(event_name, action):
                        return True
        return False
    
    def add_role_permission(self, role: str, permission: EventPermission):
        """Add permission to role"""
        if role not in self.role_permissions:
            self.role_permissions[role] = []
        self.role_permissions[role].append(permission)


class EventEncryption:
    """Handles encryption of sensitive event data"""
    
    def __init__(self, encryption_key: str, sensitive_patterns: List[str]):
        self.fernet = Fernet(encryption_key.encode())
        self.sensitive_patterns = sensitive_patterns
    
    def encrypt_payload(self, payload: Dict[str, Any]) -> tuple[Dict[str, Any], List[str]]:
        """Encrypt sensitive fields in payload, return encrypted payload and list of encrypted fields"""
        encrypted_payload = {}
        encrypted_fields = []
        
        for key, value in payload.items():
            if self._is_sensitive_field(key) and isinstance(value, str):
                encrypted_payload[key] = self.fernet.encrypt(value.encode()).decode()
                encrypted_fields.append(key)
            elif isinstance(value, dict):
                nested_encrypted, nested_fields = self.encrypt_payload(value)
                encrypted_payload[key] = nested_encrypted
                encrypted_fields.extend([f"{key}.{field}" for field in nested_fields])
            else:
                encrypted_payload[key] = value
        
        return encrypted_payload, encrypted_fields
    
    def decrypt_payload(self, payload: Dict[str, Any], encrypted_fields: List[str]) -> Dict[str, Any]:
        """Decrypt encrypted fields in payload"""
        decrypted_payload = {}
        
        for key, value in payload.items():
            field_path = key
            if field_path in encrypted_fields and isinstance(value, str):
                decrypted_payload[key] = self.fernet.decrypt(value.encode()).decode()
            elif isinstance(value, dict):
                # Handle nested fields
                nested_fields = [
                    field.split('.', 1)[1] 
                    for field in encrypted_fields 
                    if field.startswith(f"{key}.")
                ]
                decrypted_payload[key] = self.decrypt_payload(value, nested_fields)
            else:
                decrypted_payload[key] = value
        
        return decrypted_payload
    
    def _is_sensitive_field(self, field_name: str) -> bool:
        """Check if field name matches sensitive patterns"""
        field_lower = field_name.lower()
        return any(pattern in field_lower for pattern in self.sensitive_patterns)


class EventSigner:
    """Handles HMAC signing of events for integrity verification"""
    
    def __init__(self, hmac_secret: str):
        self.hmac_secret = hmac_secret.encode()
    
    def sign_event(self, event_id: str, event_name: str, payload: Dict[str, Any]) -> str:
        """Create HMAC signature for event"""
        # Create canonical representation of event
        canonical = json.dumps({
            "event_id": event_id,
            "event_name": event_name,
            "payload": payload
        }, sort_keys=True, separators=(',', ':'))
        
        # Create HMAC
        signature = hmac.new(
            self.hmac_secret,
            canonical.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return signature
    
    def verify_signature(self, event_id: str, event_name: str, payload: Dict[str, Any], signature: str) -> bool:
        """Verify event signature"""
        expected_signature = self.sign_event(event_id, event_name, payload)
        return hmac.compare_digest(expected_signature, signature)


class RateLimiter:
    """Token bucket rate limiter for event publishing"""
    
    def __init__(self, rate_per_minute: int):
        self.rate_per_minute = rate_per_minute
        self.tokens_per_second = rate_per_minute / 60.0
        self.buckets: Dict[str, Dict[str, float]] = {}  # service_name -> {tokens, last_update}
    
    def check_rate_limit(self, service_name: str) -> bool:
        """Check if service is within rate limit"""
        now = time.time()
        
        if service_name not in self.buckets:
            self.buckets[service_name] = {
                "tokens": self.rate_per_minute,
                "last_update": now
            }
        
        bucket = self.buckets[service_name]
        
        # Calculate tokens to add based on time elapsed
        time_elapsed = now - bucket["last_update"]
        tokens_to_add = time_elapsed * self.tokens_per_second
        
        # Update bucket
        bucket["tokens"] = min(self.rate_per_minute, bucket["tokens"] + tokens_to_add)
        bucket["last_update"] = now
        
        # Check if we have tokens available
        if bucket["tokens"] >= 1:
            bucket["tokens"] -= 1
            return True
        
        return False


class EventSecurityManager:
    """Manages all security aspects of event system"""
    
    def __init__(self, config: EventSecurityConfig):
        self.config = config
        self.rbac = RoleBasedAccessControl()
        self.encryption = EventEncryption(
            config.encryption_key,
            config.sensitive_field_patterns
        )
        self.signer = EventSigner(config.hmac_secret)
        self.rate_limiter = RateLimiter(config.default_rate_limit_per_minute)
        self._token_cache: Dict[str, ServiceIdentity] = {}
    
    def create_service_token(self, service_name: str, roles: Set[str]) -> str:
        """Create JWT token for service"""
        now = datetime.utcnow()
        expires_at = now + timedelta(seconds=self.config.jwt_expiry_seconds)
        
        payload = {
            "service_name": service_name,
            "roles": list(roles),
            "iat": now,
            "exp": expires_at,
            "iss": "event-security-manager"
        }
        
        token = jwt.encode(
            payload,
            self.config.jwt_secret,
            algorithm=self.config.jwt_algorithm
        )
        
        return token
    
    def verify_service_token(self, token: str) -> Optional[ServiceIdentity]:
        """Verify JWT token and return service identity"""
        # Check cache first
        if token in self._token_cache:
            identity = self._token_cache[token]
            if identity.expires_at > datetime.utcnow():
                return identity
            else:
                del self._token_cache[token]
        
        try:
            payload = jwt.decode(
                token,
                self.config.jwt_secret,
                algorithms=[self.config.jwt_algorithm]
            )
            
            identity = ServiceIdentity(
                service_name=payload["service_name"],
                roles=set(payload["roles"]),
                permissions=set(),  # Populated based on roles
                issued_at=datetime.fromtimestamp(payload["iat"]),
                expires_at=datetime.fromtimestamp(payload["exp"]),
                jwt_token=token
            )
            
            # Cache the identity
            self._token_cache[token] = identity
            
            return identity
            
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    
    def authorize_event_operation(self, identity: ServiceIdentity, event_name: str, operation: str) -> bool:
        """Check if service is authorized for event operation"""
        if not self.config.enable_rbac:
            return True
        
        return self.rbac.check_permission(identity, event_name, operation)
    
    def check_rate_limit(self, identity: ServiceIdentity) -> bool:
        """Check if service is within rate limit"""
        if not self.config.enable_rate_limiting:
            return True
        
        return self.rate_limiter.check_rate_limit(identity.service_name)
    
    def prepare_event_for_publish(self, event_id: str, event_name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare event for publishing with encryption and signing"""
        result = {
            "event_id": event_id,
            "event_name": event_name,
            "payload": payload,
            "encrypted_fields": [],
            "signature": None
        }
        
        # Encrypt sensitive fields
        if self.config.encrypt_sensitive_fields:
            encrypted_payload, encrypted_fields = self.encryption.encrypt_payload(payload)
            result["payload"] = encrypted_payload
            result["encrypted_fields"] = encrypted_fields
        
        # Sign the event
        if self.config.require_event_signing:
            result["signature"] = self.signer.sign_event(event_id, event_name, result["payload"])
        
        return result
    
    def verify_and_decrypt_event(self, event_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Verify signature and decrypt event"""
        # Verify signature if required
        if self.config.require_event_signing:
            if "signature" not in event_data:
                return None
            
            if not self.signer.verify_signature(
                event_data["event_id"],
                event_data["event_name"],
                event_data["payload"],
                event_data["signature"]
            ):
                return None
        
        # Decrypt payload if needed
        payload = event_data["payload"]
        if event_data.get("encrypted_fields"):
            payload = self.encryption.decrypt_payload(
                payload,
                event_data["encrypted_fields"]
            )
        
        return {
            "event_id": event_data["event_id"],
            "event_name": event_data["event_name"],
            "payload": payload
        }


class SecureEventBusBase(ABC):
    """Base class for secure event bus implementations"""
    
    def __init__(self, security_config: EventSecurityConfig):
        self.security_manager = EventSecurityManager(security_config)
        self._service_identity: Optional[ServiceIdentity] = None
    
    def authenticate(self, token: str) -> bool:
        """Authenticate service with token"""
        identity = self.security_manager.verify_service_token(token)
        if identity:
            self._service_identity = identity
            return True
        return False
    
    def _check_publish_permission(self, event_name: str) -> bool:
        """Check if current service can publish event"""
        if not self._service_identity:
            return False
        
        if not self.security_manager.authorize_event_operation(
            self._service_identity,
            event_name,
            "publish"
        ):
            return False
        
        if not self.security_manager.check_rate_limit(self._service_identity):
            return False
        
        return True
    
    def _check_subscribe_permission(self, event_name: str) -> bool:
        """Check if current service can subscribe to event"""
        if not self._service_identity:
            return False
        
        return self.security_manager.authorize_event_operation(
            self._service_identity,
            event_name,
            "subscribe"
        )
    
    @abstractmethod
    async def publish_secure(self, event_id: str, event_name: str, payload: Dict[str, Any]) -> None:
        """Publish event with security checks"""
        pass
    
    @abstractmethod  
    async def subscribe_secure(self, event_pattern: str, handler: callable) -> None:
        """Subscribe to events with security checks"""
        pass