"""
User service domain events
"""

from dataclasses import dataclass
from datetime import date, datetime
from typing import Optional, Dict, Any
from uuid import UUID

from .base import DomainEvent


@dataclass
class UserProfileCreated(DomainEvent):
    """Event raised when a user profile is created"""
    
    user_id: UUID
    first_name: str
    last_name: str
    display_name: str
    
    @property
    def event_name(self) -> str:
        return "user_profile.created"


@dataclass
class UserProfileUpdated(DomainEvent):
    """Event raised when a user profile is updated"""
    
    user_id: UUID
    changes: Dict[str, Any]  # Field -> new value mapping
    updated_by: UUID
    
    @property
    def event_name(self) -> str:
        return "user_profile.updated"


@dataclass
class UserAvatarUploaded(DomainEvent):
    """Event raised when a user uploads an avatar"""
    
    user_id: UUID
    avatar_url: str
    file_size: int
    mime_type: str
    
    @property
    def event_name(self) -> str:
        return "user_profile.avatar_uploaded"


@dataclass
class UserPreferencesUpdated(DomainEvent):
    """Event raised when user preferences are updated"""
    
    user_id: UUID
    preferences: Dict[str, Any]
    
    @property
    def event_name(self) -> str:
        return "user_profile.preferences_updated"


@dataclass
class UserAddressAdded(DomainEvent):
    """Event raised when a user adds an address"""
    
    user_id: UUID
    address_id: UUID
    address_type: str  # "billing", "shipping", "home", etc.
    street_address: str
    city: str
    state_province: str
    postal_code: str
    country: str
    is_default: bool
    
    @property
    def event_name(self) -> str:
        return "user_profile.address_added"


@dataclass
class UserAddressUpdated(DomainEvent):
    """Event raised when a user updates an address"""
    
    user_id: UUID
    address_id: UUID
    changes: Dict[str, Any]
    
    @property
    def event_name(self) -> str:
        return "user_profile.address_updated"


@dataclass
class UserAddressDeleted(DomainEvent):
    """Event raised when a user deletes an address"""
    
    user_id: UUID
    address_id: UUID
    
    @property
    def event_name(self) -> str:
        return "user_profile.address_deleted"


@dataclass
class UserPhoneNumberAdded(DomainEvent):
    """Event raised when a user adds a phone number"""
    
    user_id: UUID
    phone_id: UUID
    phone_number: str
    phone_type: str  # "mobile", "home", "work"
    is_primary: bool
    is_verified: bool
    
    @property
    def event_name(self) -> str:
        return "user_profile.phone_added"


@dataclass
class UserPhoneNumberVerified(DomainEvent):
    """Event raised when a user verifies their phone number"""
    
    user_id: UUID
    phone_id: UUID
    phone_number: str
    verified_at: datetime
    
    @property
    def event_name(self) -> str:
        return "user_profile.phone_verified"


@dataclass
class UserBirthdateSet(DomainEvent):
    """Event raised when a user sets their birthdate"""
    
    user_id: UUID
    birthdate: date
    age_verified: bool
    
    @property
    def event_name(self) -> str:
        return "user_profile.birthdate_set"


@dataclass
class UserConsentGiven(DomainEvent):
    """Event raised when a user gives consent"""
    
    user_id: UUID
    consent_type: str  # "marketing", "data_processing", "cookies", etc.
    consent_version: str
    ip_address: str
    
    @property
    def event_name(self) -> str:
        return "user_profile.consent_given"


@dataclass
class UserConsentRevoked(DomainEvent):
    """Event raised when a user revokes consent"""
    
    user_id: UUID
    consent_type: str
    revoked_at: datetime
    
    @property
    def event_name(self) -> str:
        return "user_profile.consent_revoked"


@dataclass
class UserDataExportRequested(DomainEvent):
    """Event raised when a user requests data export (GDPR)"""
    
    user_id: UUID
    export_id: UUID
    requested_data_types: list[str]
    
    @property
    def event_name(self) -> str:
        return "user_profile.data_export_requested"


@dataclass
class UserDataExportCompleted(DomainEvent):
    """Event raised when user data export is completed"""
    
    user_id: UUID
    export_id: UUID
    download_url: str
    expires_at: datetime
    
    @property
    def event_name(self) -> str:
        return "user_profile.data_export_completed"


@dataclass
class UserDeletionRequested(DomainEvent):
    """Event raised when a user requests account deletion (GDPR)"""
    
    user_id: UUID
    deletion_reason: Optional[str]
    scheduled_deletion_date: datetime
    
    @property
    def event_name(self) -> str:
        return "user_profile.deletion_requested"


@dataclass
class UserNotificationPreferencesUpdated(DomainEvent):
    """Event raised when user notification preferences are updated"""
    
    user_id: UUID
    email_notifications: bool
    sms_notifications: bool
    push_notifications: bool
    notification_categories: Dict[str, bool]  # Category -> enabled mapping
    
    @property
    def event_name(self) -> str:
        return "user_profile.notification_preferences_updated"


@dataclass
class UserVerificationDocumentUploaded(DomainEvent):
    """Event raised when a user uploads a verification document"""
    
    user_id: UUID
    document_id: UUID
    document_type: str  # "id_card", "passport", "driver_license", etc.
    verification_purpose: str  # "identity", "address", "age"
    
    @property
    def event_name(self) -> str:
        return "user_profile.verification_document_uploaded"


@dataclass
class UserVerificationCompleted(DomainEvent):
    """Event raised when user verification is completed"""
    
    user_id: UUID
    verification_type: str
    verification_level: str  # "basic", "enhanced", "full"
    verified_by: Optional[UUID]  # Admin who verified
    
    @property
    def event_name(self) -> str:
        return "user_profile.verification_completed"


@dataclass
class UserTagAdded(DomainEvent):
    """Event raised when a tag is added to a user (for segmentation)"""
    
    user_id: UUID
    tag: str
    added_by: UUID
    
    @property
    def event_name(self) -> str:
        return "user_profile.tag_added"


@dataclass
class UserTagRemoved(DomainEvent):
    """Event raised when a tag is removed from a user"""
    
    user_id: UUID
    tag: str
    removed_by: UUID
    
    @property
    def event_name(self) -> str:
        return "user_profile.tag_removed"