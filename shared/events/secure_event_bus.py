"""
Secure Event Bus Implementation with Authentication and Encryption
"""

import asyncio
import hmac
import hashlib
import json
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Type, Set
from uuid import UUID
import jwt
from cryptography.fernet import Fernet
from collections import defaultdict
import time

from .base import EventBus, DomainEvent, EventHandler


@dataclass
class SecurityContext:
    """Security context for event operations"""
    user_id: UUID
    service_name: str
    roles: list[str]
    ip_address: str
    token: str
    expires_at: datetime


class AuthProvider(ABC):
    """Abstract authentication provider"""
    
    @abstractmethod
    async def validate_token(self, token: str) -> Optional[SecurityContext]:
        """Validate authentication token and return security context"""
        pass
    
    @abstractmethod
    async def has_permission(self, context: SecurityContext, action: str, resource: str) -> bool:
        """Check if context has permission for action on resource"""
        pass


class JWTAuthProvider(AuthProvider):
    """JWT-based authentication provider"""
    
    def __init__(self, secret_key: str, issuer: str = "event-bus"):
        self.secret_key = secret_key
        self.issuer = issuer
        self.revoked_tokens: Set[str] = set()
    
    async def validate_token(self, token: str) -> Optional[SecurityContext]:
        """Validate JWT token"""
        try:
            # Decode and verify JWT
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=["HS256"],
                issuer=self.issuer
            )
            
            # Check if token is revoked
            if token in self.revoked_tokens:
                return None
            
            # Create security context
            return SecurityContext(
                user_id=UUID(payload["sub"]),
                service_name=payload.get("service", "unknown"),
                roles=payload.get("roles", []),
                ip_address=payload.get("ip", "unknown"),
                token=token,
                expires_at=datetime.fromtimestamp(payload["exp"])
            )
            
        except (jwt.InvalidTokenError, KeyError, ValueError):
            return None
    
    async def has_permission(self, context: SecurityContext, action: str, resource: str) -> bool:
        """Check permissions based on roles"""
        # Define permission mappings
        permissions = {
            "admin": ["publish:*", "subscribe:*", "manage:*"],
            "service": [f"publish:{context.service_name}:*", f"subscribe:*"],
            "user": ["publish:user:*", "subscribe:user:*"]
        }
        
        # Check each role
        for role in context.roles:
            role_perms = permissions.get(role, [])
            for perm in role_perms:
                if self._match_permission(perm, f"{action}:{resource}"):
                    return True
        
        return False
    
    def _match_permission(self, pattern: str, permission: str) -> bool:
        """Match permission pattern with wildcards"""
        pattern_parts = pattern.split(":")
        perm_parts = permission.split(":")
        
        if len(pattern_parts) != len(perm_parts):
            return False
        
        for pat, perm in zip(pattern_parts, perm_parts):
            if pat != "*" and pat != perm:
                return False
        
        return True
    
    def revoke_token(self, token: str):
        """Revoke a token"""
        self.revoked_tokens.add(token)


class EventEncryption:
    """Handles event payload encryption"""
    
    # Fields that should always be encrypted
    SENSITIVE_FIELDS = {
        'password', 'email', 'ssn', 'credit_card', 'phone',
        'address', 'date_of_birth', 'ip_address', 'session_id'
    }
    
    def __init__(self, encryption_key: Optional[str] = None):
        key = encryption_key or os.environ.get("EVENT_ENCRYPTION_KEY")
        if not key:
            raise ValueError("Encryption key not provided")
        self.cipher = Fernet(key.encode() if isinstance(key, str) else key)
    
    def encrypt_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Encrypt sensitive fields in payload"""
        encrypted_payload = {}
        
        for key, value in payload.items():
            if key.lower() in self.SENSITIVE_FIELDS and value is not None:
                # Encrypt the value
                encrypted_value = self.cipher.encrypt(
                    json.dumps(value).encode()
                ).decode()
                encrypted_payload[key] = {
                    "_encrypted": True,
                    "value": encrypted_value
                }
            else:
                encrypted_payload[key] = value
        
        return encrypted_payload
    
    def decrypt_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Decrypt encrypted fields in payload"""
        decrypted_payload = {}
        
        for key, value in payload.items():
            if isinstance(value, dict) and value.get("_encrypted"):
                # Decrypt the value
                decrypted_value = self.cipher.decrypt(
                    value["value"].encode()
                )
                decrypted_payload[key] = json.loads(decrypted_value.decode())
            else:
                decrypted_payload[key] = value
        
        return decrypted_payload


class EventSigner:
    """Handles event signing and verification"""
    
    def __init__(self, signing_key: Optional[str] = None):
        key = signing_key or os.environ.get("EVENT_SIGNING_KEY")
        if not key:
            raise ValueError("Signing key not provided")
        self.signing_key = key.encode() if isinstance(key, str) else key
    
    def sign_event(self, event_data: Dict[str, Any]) -> str:
        """Create HMAC signature for event"""
        # Remove signature field if present
        data_copy = {k: v for k, v in event_data.items() if k != "signature"}
        
        # Create canonical JSON representation
        message = json.dumps(data_copy, sort_keys=True, separators=(',', ':'))
        
        # Create HMAC signature
        signature = hmac.new(
            self.signing_key,
            message.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return signature
    
    def verify_signature(self, event_data: Dict[str, Any], signature: str) -> bool:
        """Verify event signature"""
        expected_signature = self.sign_event(event_data)
        return hmac.compare_digest(expected_signature, signature)


class RateLimiter:
    """Rate limiting for event operations"""
    
    def __init__(self, max_events: int = 100, window_seconds: int = 60):
        self.max_events = max_events
        self.window_seconds = window_seconds
        self.counters = defaultdict(lambda: {"count": 0, "reset_time": time.time()})
        self.lock = asyncio.Lock()
    
    async def check_rate_limit(self, identifier: str) -> bool:
        """Check if identifier has exceeded rate limit"""
        async with self.lock:
            current_time = time.time()
            counter = self.counters[identifier]
            
            # Reset window if expired
            if current_time - counter["reset_time"] > self.window_seconds:
                counter["count"] = 0
                counter["reset_time"] = current_time
            
            # Check limit
            if counter["count"] >= self.max_events:
                return False
            
            counter["count"] += 1
            return True
    
    async def get_remaining(self, identifier: str) -> Dict[str, int]:
        """Get remaining quota for identifier"""
        async with self.lock:
            current_time = time.time()
            counter = self.counters[identifier]
            
            # Check if window expired
            if current_time - counter["reset_time"] > self.window_seconds:
                return {
                    "remaining": self.max_events,
                    "reset_in": self.window_seconds
                }
            
            remaining = max(0, self.max_events - counter["count"])
            reset_in = int(self.window_seconds - (current_time - counter["reset_time"]))
            
            return {
                "remaining": remaining,
                "reset_in": reset_in
            }


class SecureEventBus(EventBus):
    """Secure event bus with authentication, encryption, and rate limiting"""
    
    def __init__(
        self,
        auth_provider: AuthProvider,
        encryption: Optional[EventEncryption] = None,
        signer: Optional[EventSigner] = None,
        rate_limiter: Optional[RateLimiter] = None,
        audit_logger: Optional[Any] = None
    ):
        self.auth_provider = auth_provider
        self.encryption = encryption
        self.signer = signer
        self.rate_limiter = rate_limiter
        self.audit_logger = audit_logger
        
        # Permission mappings for event types
        self.event_permissions: Dict[str, str] = {}
    
    async def publish(
        self,
        event: DomainEvent,
        auth_token: str,
        ip_address: Optional[str] = None
    ) -> None:
        """Publish event with security checks"""
        # Validate authentication
        context = await self.auth_provider.validate_token(auth_token)
        if not context:
            await self._log_security_event(
                "auth_failed",
                {"event_type": event.event_name, "ip": ip_address}
            )
            raise SecurityException("Authentication failed")
        
        # Update context with IP if provided
        if ip_address:
            context.ip_address = ip_address
        
        # Check rate limit
        if self.rate_limiter:
            rate_limit_key = f"{context.service_name}:{context.user_id}"
            if not await self.rate_limiter.check_rate_limit(rate_limit_key):
                await self._log_security_event(
                    "rate_limit_exceeded",
                    {
                        "event_type": event.event_name,
                        "service": context.service_name,
                        "user_id": str(context.user_id)
                    }
                )
                raise RateLimitException("Rate limit exceeded")
        
        # Check permissions
        resource = self.event_permissions.get(event.event_name, event.event_name)
        if not await self.auth_provider.has_permission(context, "publish", resource):
            await self._log_security_event(
                "permission_denied",
                {
                    "event_type": event.event_name,
                    "service": context.service_name,
                    "user_id": str(context.user_id),
                    "action": "publish"
                }
            )
            raise ForbiddenException(f"Permission denied to publish {event.event_name}")
        
        # Add security metadata
        event.metadata.update({
            "publisher_id": str(context.user_id),
            "publisher_service": context.service_name,
            "published_at": datetime.utcnow().isoformat(),
            "ip_address": context.ip_address
        })
        
        # Prepare event data
        event_data = event.to_dict()
        
        # Encrypt sensitive fields
        if self.encryption:
            payload = event_data.get("payload", {})
            event_data["payload"] = self.encryption.encrypt_payload(payload)
        
        # Sign event
        if self.signer:
            event_data["signature"] = self.signer.sign_event(event_data)
        
        # Log successful publish
        await self._log_security_event(
            "event_published",
            {
                "event_type": event.event_name,
                "event_id": str(event.event_id),
                "service": context.service_name,
                "user_id": str(context.user_id)
            }
        )
        
        # Publish to underlying implementation
        await self._publish_internal(event_data)
    
    async def subscribe(
        self,
        event_type: Type[DomainEvent],
        handler: EventHandler,
        auth_token: str
    ) -> None:
        """Subscribe to events with security checks"""
        # Validate authentication
        context = await self.auth_provider.validate_token(auth_token)
        if not context:
            raise SecurityException("Authentication failed")
        
        # Get event name
        dummy_event = event_type(aggregate_id=UUID('00000000-0000-0000-0000-000000000000'))
        event_name = dummy_event.event_name
        
        # Check permissions
        resource = self.event_permissions.get(event_name, event_name)
        if not await self.auth_provider.has_permission(context, "subscribe", resource):
            await self._log_security_event(
                "permission_denied",
                {
                    "event_type": event_name,
                    "service": context.service_name,
                    "user_id": str(context.user_id),
                    "action": "subscribe"
                }
            )
            raise ForbiddenException(f"Permission denied to subscribe to {event_name}")
        
        # Create secure handler wrapper
        secure_handler = self._create_secure_handler(handler, context)
        
        # Subscribe with underlying implementation
        await self._subscribe_internal(event_type, secure_handler)
        
        await self._log_security_event(
            "subscription_created",
            {
                "event_type": event_name,
                "handler": handler.__class__.__name__,
                "service": context.service_name,
                "user_id": str(context.user_id)
            }
        )
    
    def _create_secure_handler(self, handler: EventHandler, context: SecurityContext) -> EventHandler:
        """Create a secure wrapper for event handler"""
        class SecureEventHandler(EventHandler):
            def __init__(self, wrapped_handler: EventHandler, security_context: SecurityContext):
                self.wrapped_handler = wrapped_handler
                self.security_context = security_context
                self.encryption = self.encryption
                self.signer = self.signer
            
            @property
            def event_type(self) -> Type[DomainEvent]:
                return self.wrapped_handler.event_type
            
            async def handle(self, event: DomainEvent) -> None:
                # Verify event signature
                if self.signer:
                    event_data = event.to_dict()
                    signature = event_data.get("signature")
                    if not signature or not self.signer.verify_signature(event_data, signature):
                        raise SecurityException("Invalid event signature")
                
                # Decrypt payload if needed
                if self.encryption:
                    event_data = event.to_dict()
                    payload = event_data.get("payload", {})
                    decrypted_payload = self.encryption.decrypt_payload(payload)
                    
                    # Update event with decrypted payload
                    for key, value in decrypted_payload.items():
                        if hasattr(event, key):
                            setattr(event, key, value)
                
                # Call wrapped handler
                await self.wrapped_handler.handle(event)
        
        return SecureEventHandler(handler, context)
    
    async def _log_security_event(self, event_type: str, details: Dict[str, Any]):
        """Log security events"""
        if self.audit_logger:
            await self.audit_logger.log(
                level="SECURITY",
                event_type=event_type,
                timestamp=datetime.utcnow().isoformat(),
                details=details
            )
    
    @abstractmethod
    async def _publish_internal(self, event_data: Dict[str, Any]) -> None:
        """Internal publish implementation"""
        pass
    
    @abstractmethod
    async def _subscribe_internal(
        self,
        event_type: Type[DomainEvent],
        handler: EventHandler
    ) -> None:
        """Internal subscribe implementation"""
        pass
    
    async def unsubscribe(
        self,
        event_type: Type[DomainEvent],
        handler: EventHandler
    ) -> None:
        """Unsubscribe from events"""
        # This would need to track secure handler mappings
        pass


class SecurityException(Exception):
    """Base security exception"""
    pass


class UnauthorizedException(SecurityException):
    """Raised when authentication fails"""
    pass


class ForbiddenException(SecurityException):
    """Raised when authorization fails"""
    pass


class RateLimitException(SecurityException):
    """Raised when rate limit is exceeded"""
    pass