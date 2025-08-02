"""
Event Schema Validation for Security
Uses JSON Schema for validation and sanitization
"""

import re
from typing import Dict, Any, Optional, Type
from jsonschema import validate, ValidationError, Draft7Validator
from datetime import datetime
from uuid import UUID

from .base import DomainEvent


class EventSchemaValidator:
    """Validates events against JSON schemas to prevent injection attacks"""
    
    # Base schema for all events
    BASE_EVENT_SCHEMA = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "required": ["event_id", "event_name", "occurred_at", "version"],
        "properties": {
            "event_id": {
                "type": "string",
                "format": "uuid",
                "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
            },
            "event_name": {
                "type": "string",
                "pattern": "^[a-zA-Z0-9._-]+$",
                "maxLength": 255
            },
            "aggregate_id": {
                "type": ["string", "null"],
                "format": "uuid"
            },
            "occurred_at": {
                "type": "string",
                "format": "date-time"
            },
            "version": {
                "type": "integer",
                "minimum": 1
            },
            "metadata": {
                "type": "object",
                "additionalProperties": True
            },
            "payload": {
                "type": "object"
            }
        },
        "additionalProperties": False
    }
    
    # Schema registry for specific event types
    EVENT_SCHEMAS = {
        "user.registered": {
            "type": "object",
            "required": ["user_id", "email", "username", "roles"],
            "properties": {
                "user_id": {
                    "type": "string",
                    "format": "uuid"
                },
                "email": {
                    "type": "string",
                    "format": "email",
                    "maxLength": 255
                },
                "username": {
                    "type": "string",
                    "pattern": "^[a-zA-Z0-9_-]{3,32}$"
                },
                "roles": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "pattern": "^[a-zA-Z0-9_-]+$"
                    },
                    "maxItems": 10
                }
            },
            "additionalProperties": False
        },
        "user.logged_in": {
            "type": "object",
            "required": ["user_id", "session_id", "ip_address", "user_agent"],
            "properties": {
                "user_id": {
                    "type": "string",
                    "format": "uuid"
                },
                "session_id": {
                    "type": "string",
                    "format": "uuid"
                },
                "ip_address": {
                    "type": "string",
                    "format": "ipv4"  # or use pattern for IPv4/IPv6
                },
                "user_agent": {
                    "type": "string",
                    "maxLength": 1000
                }
            },
            "additionalProperties": False
        },
        "user.password_changed": {
            "type": "object",
            "required": ["user_id", "changed_by"],
            "properties": {
                "user_id": {
                    "type": "string",
                    "format": "uuid"
                },
                "changed_by": {
                    "type": "string",
                    "format": "uuid"
                }
            },
            "additionalProperties": False
        }
    }
    
    def __init__(self):
        self.validators = {}
        self._compile_validators()
    
    def _compile_validators(self):
        """Pre-compile validators for performance"""
        for event_name, payload_schema in self.EVENT_SCHEMAS.items():
            # Combine base schema with payload schema
            full_schema = self.BASE_EVENT_SCHEMA.copy()
            full_schema["properties"]["payload"] = payload_schema
            
            # Create validator
            self.validators[event_name] = Draft7Validator(full_schema)
    
    def validate_event(self, event_data: Dict[str, Any]) -> None:
        """Validate event data against schema"""
        event_name = event_data.get("event_name")
        
        if not event_name:
            raise ValidationError("Missing event_name")
        
        # Get validator for event type
        validator = self.validators.get(event_name)
        if not validator:
            # Use base schema for unknown event types
            validator = Draft7Validator(self.BASE_EVENT_SCHEMA)
        
        # Validate
        try:
            validator.validate(event_data)
        except ValidationError as e:
            # Sanitize error message to prevent information disclosure
            safe_message = self._sanitize_error_message(str(e))
            raise ValidationError(safe_message)
    
    def sanitize_event_data(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize event data to prevent injection attacks"""
        return self._deep_sanitize(event_data)
    
    def _deep_sanitize(self, obj: Any) -> Any:
        """Recursively sanitize object"""
        if isinstance(obj, dict):
            return {
                self._sanitize_key(k): self._deep_sanitize(v)
                for k, v in obj.items()
            }
        elif isinstance(obj, list):
            return [self._deep_sanitize(item) for item in obj]
        elif isinstance(obj, str):
            return self._sanitize_string(obj)
        else:
            return obj
    
    def _sanitize_key(self, key: str) -> str:
        """Sanitize dictionary key"""
        # Remove any characters that could be used for injection
        sanitized = re.sub(r'[^\w.-]', '_', key)
        return sanitized[:255]  # Limit length
    
    def _sanitize_string(self, value: str) -> str:
        """Sanitize string value"""
        # Remove null bytes
        value = value.replace('\x00', '')
        
        # Remove control characters except newline and tab
        value = re.sub(r'[\x01-\x08\x0b-\x1f\x7f]', '', value)
        
        # Limit length to prevent DOS
        return value[:10000]
    
    def _sanitize_error_message(self, error: str) -> str:
        """Sanitize error message to prevent information disclosure"""
        # Remove file paths
        error = re.sub(r'(/[^/\s]+)+', '[PATH]', error)
        
        # Remove specific field values
        error = re.sub(r"'[^']{20,}'", "'[VALUE]'", error)
        
        return error
    
    def register_schema(self, event_name: str, payload_schema: Dict[str, Any]):
        """Register a new event schema"""
        # Validate the schema itself
        Draft7Validator.check_schema(payload_schema)
        
        # Add to registry
        self.EVENT_SCHEMAS[event_name] = payload_schema
        
        # Recompile validators
        self._compile_validators()


class InputSanitizer:
    """Sanitizes input to prevent various injection attacks"""
    
    # Patterns for dangerous content
    SQL_INJECTION_PATTERNS = [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|CREATE|ALTER)\b)",
        r"(-{2}|/\*|\*/)",  # SQL comments
        r"(\bOR\b\s*\d+\s*=\s*\d+)",  # OR 1=1
        r"('|\"|;|\\)",  # Quotes and semicolon
    ]
    
    XSS_PATTERNS = [
        r"<script[^>]*>.*?</script>",
        r"javascript:",
        r"on\w+\s*=",  # Event handlers
        r"<iframe",
        r"<object",
        r"<embed",
    ]
    
    LDAP_INJECTION_PATTERNS = [
        r"[()&|!*]",  # LDAP special characters
        r"\\\w{2}",  # Hex encoding
    ]
    
    def __init__(self):
        # Compile patterns for performance
        self.sql_regex = re.compile(
            "|".join(self.SQL_INJECTION_PATTERNS),
            re.IGNORECASE | re.DOTALL
        )
        self.xss_regex = re.compile(
            "|".join(self.XSS_PATTERNS),
            re.IGNORECASE | re.DOTALL
        )
        self.ldap_regex = re.compile(
            "|".join(self.LDAP_INJECTION_PATTERNS),
            re.IGNORECASE
        )
    
    def sanitize_for_sql(self, value: str) -> str:
        """Sanitize string for SQL queries"""
        if self.sql_regex.search(value):
            raise ValueError("Potential SQL injection detected")
        
        # Escape single quotes
        return value.replace("'", "''")
    
    def sanitize_for_html(self, value: str) -> str:
        """Sanitize string for HTML output"""
        if self.xss_regex.search(value):
            raise ValueError("Potential XSS detected")
        
        # HTML entity encoding
        replacements = {
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#x27;",
            "/": "&#x2F;"
        }
        
        for char, entity in replacements.items():
            value = value.replace(char, entity)
        
        return value
    
    def sanitize_for_ldap(self, value: str) -> str:
        """Sanitize string for LDAP queries"""
        if self.ldap_regex.search(value):
            raise ValueError("Potential LDAP injection detected")
        
        # LDAP escape
        escape_chars = {
            '*': r'\2a',
            '(': r'\28',
            ')': r'\29',
            '\\': r'\5c',
            '/': r'\2f'
        }
        
        for char, escaped in escape_chars.items():
            value = value.replace(char, escaped)
        
        return value
    
    def sanitize_filename(self, filename: str) -> str:
        """Sanitize filename to prevent path traversal"""
        # Remove path components
        filename = filename.replace("..", "")
        filename = filename.replace("/", "")
        filename = filename.replace("\\", "")
        
        # Remove null bytes
        filename = filename.replace("\x00", "")
        
        # Allow only safe characters
        filename = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)
        
        # Limit length
        return filename[:255]
    
    def validate_uuid(self, value: str) -> bool:
        """Validate UUID format"""
        try:
            UUID(value)
            return True
        except ValueError:
            return False
    
    def validate_email(self, email: str) -> bool:
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email)) and len(email) <= 255
    
    def validate_url(self, url: str) -> bool:
        """Validate URL format and safety"""
        # Basic URL pattern
        pattern = r'^https?://[a-zA-Z0-9.-]+(?:\.[a-zA-Z]{2,})+(?:/[^"\s]*)?$'
        
        if not re.match(pattern, url):
            return False
        
        # Check for dangerous protocols
        dangerous_protocols = ['javascript:', 'data:', 'vbscript:', 'file:']
        for protocol in dangerous_protocols:
            if url.lower().startswith(protocol):
                return False
        
        return True


# Example usage
def create_secure_event(event_class: Type[DomainEvent], **kwargs) -> DomainEvent:
    """Create an event with validation and sanitization"""
    validator = EventSchemaValidator()
    sanitizer = InputSanitizer()
    
    # Sanitize string inputs
    for key, value in kwargs.items():
        if isinstance(value, str):
            # Basic sanitization
            kwargs[key] = sanitizer._sanitize_string(value)
            
            # Specific validation
            if key == "email":
                if not sanitizer.validate_email(value):
                    raise ValueError(f"Invalid email: {value}")
            elif key.endswith("_id"):
                if not sanitizer.validate_uuid(value):
                    raise ValueError(f"Invalid UUID: {value}")
    
    # Create event
    event = event_class(**kwargs)
    
    # Validate against schema
    event_data = event.to_dict()
    validator.validate_event(event_data)
    
    return event