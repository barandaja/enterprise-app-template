"""
GDPR Consent Management Service.
Handles granular consent tracking, versioning, and withdrawal mechanisms.
"""
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from fastapi import HTTPException, status
import structlog

from ..models.user import User
from ..models.gdpr_consent import (
    ConsentType, ConsentStatus, ConsentLegalBasis,
    ConsentVersion, UserConsent
)
from ..models.audit import AuditEventType, AuditLogger
from ..core.config import settings

logger = structlog.get_logger()


class ConsentService:
    """Enhanced consent management service with GDPR compliance."""
    
    def __init__(self):
        self.audit_logger = AuditLogger()
        self.default_consent_expiry_days = getattr(settings, 'CONSENT_EXPIRY_DAYS', 365)
    
    async def initialize_consent_versions(self, db: AsyncSession) -> None:
        """Initialize default consent versions if they don't exist."""
        try:
            default_consents = [
                {
                    'consent_type': ConsentType.DATA_PROCESSING,
                    'version': '1.0',
                    'title': 'Data Processing Consent',
                    'description': 'Consent for processing personal data for service provision',
                    'consent_text': 'I consent to the processing of my personal data as described in the Privacy Policy for the purpose of providing the requested services.',
                    'legal_basis': ConsentLegalBasis.CONSENT
                },
                {
                    'consent_type': ConsentType.MARKETING_EMAIL,
                    'version': '1.0', 
                    'title': 'Email Marketing Consent',
                    'description': 'Consent for receiving marketing emails',
                    'consent_text': 'I consent to receiving marketing communications via email about products, services, and promotions.',
                    'legal_basis': ConsentLegalBasis.CONSENT
                },
                {
                    'consent_type': ConsentType.THIRD_PARTY_SHARING,
                    'version': '1.0',
                    'title': 'Third-Party Data Sharing Consent', 
                    'description': 'Consent for sharing data with trusted third parties',
                    'consent_text': 'I consent to sharing my data with trusted third-party partners for the purpose of improving services and providing relevant offers.',
                    'legal_basis': ConsentLegalBasis.CONSENT
                },
                {
                    'consent_type': ConsentType.ANALYTICS,
                    'version': '1.0',
                    'title': 'Analytics Consent',
                    'description': 'Consent for analytics and usage tracking',
                    'consent_text': 'I consent to the collection and analysis of usage data to improve service quality and user experience.',
                    'legal_basis': ConsentLegalBasis.LEGITIMATE_INTERESTS
                },
                {
                    'consent_type': ConsentType.COOKIES_FUNCTIONAL,
                    'version': '1.0',
                    'title': 'Functional Cookies Consent',
                    'description': 'Consent for functional cookies',
                    'consent_text': 'I consent to the use of functional cookies that are necessary for the website to function properly.',
                    'legal_basis': ConsentLegalBasis.LEGITIMATE_INTERESTS
                },
                {
                    'consent_type': ConsentType.COOKIES_ANALYTICS,
                    'version': '1.0',
                    'title': 'Analytics Cookies Consent',
                    'description': 'Consent for analytics cookies',
                    'consent_text': 'I consent to the use of analytics cookies to help us understand how visitors interact with our website.',
                    'legal_basis': ConsentLegalBasis.CONSENT
                },
                {
                    'consent_type': ConsentType.COOKIES_MARKETING,
                    'version': '1.0',
                    'title': 'Marketing Cookies Consent',
                    'description': 'Consent for marketing cookies',
                    'consent_text': 'I consent to the use of marketing cookies to show relevant advertisements and measure their effectiveness.',
                    'legal_basis': ConsentLegalBasis.CONSENT
                }
            ]
            
            for consent_data in default_consents:
                existing = await ConsentVersion.get_active_version(
                    db, consent_data['consent_type']
                )
                
                if not existing:
                    await ConsentVersion.create_version(
                        db=db,
                        consent_type=consent_data['consent_type'],
                        version_number=consent_data['version'],
                        title=consent_data['title'],
                        description=consent_data['description'],
                        consent_text=consent_data['consent_text'],
                        legal_basis=consent_data['legal_basis']
                    )
            
            logger.info("Consent versions initialized")
            
        except Exception as e:
            logger.error("Failed to initialize consent versions", error=str(e))
            raise
    
    async def get_consent_versions(
        self,
        db: AsyncSession,
        consent_type: Optional[ConsentType] = None,
        active_only: bool = True
    ) -> List[Dict[str, Any]]:
        """Get consent versions."""
        try:
            query = select(ConsentVersion)
            
            if consent_type:
                query = query.where(ConsentVersion.consent_type == consent_type)
            
            if active_only:
                query = query.where(ConsentVersion.is_active == True)
            
            query = query.order_by(ConsentVersion.consent_type, ConsentVersion.effective_from.desc())
            
            result = await db.execute(query)
            versions = result.scalars().all()
            
            return [
                {
                    'id': version.id,
                    'consent_type': version.consent_type.value,
                    'version_number': version.version_number,
                    'title': version.title,
                    'description': version.description,
                    'consent_text': version.consent_text,
                    'legal_basis': version.legal_basis.value,
                    'effective_from': version.effective_from.isoformat() if version.effective_from else None,
                    'effective_until': version.effective_until.isoformat() if version.effective_until else None,
                    'is_active': version.is_active,
                    'created_at': version.created_at.isoformat() if version.created_at else None
                }
                for version in versions
            ]
            
        except Exception as e:
            logger.error("Failed to get consent versions", error=str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve consent versions"
            )
    
    async def create_consent_version(
        self,
        db: AsyncSession,
        consent_type: ConsentType,
        version_number: str,
        title: str,
        description: str,
        consent_text: str,
        legal_basis: ConsentLegalBasis,
        created_by_user_id: int,
        effective_from: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Create a new consent version."""
        try:
            # Validate user has permission to create consent versions
            user = await User.get_by_id(db, created_by_user_id)
            if not user or not user.is_superuser:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Insufficient permissions to create consent version"
                )
            
            version = await ConsentVersion.create_version(
                db=db,
                consent_type=consent_type,
                version_number=version_number,
                title=title,
                description=description,
                consent_text=consent_text,
                legal_basis=legal_basis,
                created_by_user_id=created_by_user_id,
                effective_from=effective_from
            )
            
            # Log consent version creation
            await self.audit_logger.log_data_access(
                db=db,
                action="create_consent_version",
                resource_type="consent_version",
                resource_id=str(version.id),
                user_id=created_by_user_id,
                success=True,
                description=f"Created consent version {version_number} for {consent_type.value}",
                event_data={
                    'consent_type': consent_type.value,
                    'version_number': version_number,
                    'legal_basis': legal_basis.value
                }
            )
            
            logger.info(
                "Consent version created",
                consent_type=consent_type.value,
                version_number=version_number,
                created_by=created_by_user_id
            )
            
            return version.to_dict()
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Failed to create consent version", error=str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create consent version"
            )
    
    async def grant_consent(
        self,
        db: AsyncSession,
        user_id: int,
        consent_type: ConsentType,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        consent_method: str = 'web_form',
        expires_at: Optional[datetime] = None,
        consent_metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Grant consent for a user."""
        try:
            # Validate user exists
            user = await User.get_by_id(db, user_id)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
            
            # Set default expiry if not provided
            if not expires_at:
                expires_at = datetime.utcnow() + timedelta(days=self.default_consent_expiry_days)
            
            consent = await UserConsent.grant_consent(
                db=db,
                user_id=user_id,
                consent_type=consent_type,
                ip_address=ip_address,
                user_agent=user_agent,
                consent_method=consent_method,
                expires_at=expires_at,
                consent_metadata=consent_metadata
            )
            
            # Log consent grant
            await self.audit_logger.log_data_access(
                db=db,
                action="grant_consent",
                resource_type="user_consent",
                resource_id=str(consent.id),
                user_id=user_id,
                ip_address=ip_address,
                success=True,
                description=f"Granted {consent_type.value} consent",
                event_data={
                    'consent_type': consent_type.value,
                    'consent_method': consent_method,
                    'expires_at': expires_at.isoformat() if expires_at else None
                }
            )
            
            logger.info(
                "Consent granted",
                user_id=user_id,
                consent_type=consent_type.value,
                method=consent_method
            )
            
            return consent.to_dict()
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Failed to grant consent", error=str(e), user_id=user_id)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to grant consent"
            )
    
    async def withdraw_consent(
        self,
        db: AsyncSession,
        user_id: int,
        consent_type: ConsentType,
        withdrawal_reason: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Dict[str, Any]:
        """Withdraw consent for a user."""
        try:
            # Validate user exists
            user = await User.get_by_id(db, user_id)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
            
            consent = await UserConsent.withdraw_consent(
                db=db,
                user_id=user_id,
                consent_type=consent_type,
                withdrawal_reason=withdrawal_reason,
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            if not consent:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="No active consent found to withdraw"
                )
            
            # Log consent withdrawal
            await self.audit_logger.log_data_access(
                db=db,
                action="withdraw_consent",
                resource_type="user_consent",
                resource_id=str(consent.id),
                user_id=user_id,
                ip_address=ip_address,
                success=True,
                description=f"Withdrew {consent_type.value} consent",
                event_data={
                    'consent_type': consent_type.value,
                    'withdrawal_reason': withdrawal_reason
                }
            )
            
            logger.info(
                "Consent withdrawn",
                user_id=user_id,
                consent_type=consent_type.value,
                reason=withdrawal_reason
            )
            
            return consent.to_dict()
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Failed to withdraw consent", error=str(e), user_id=user_id)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to withdraw consent"
            )
    
    async def get_user_consents(
        self,
        db: AsyncSession,
        user_id: int,
        consent_types: Optional[List[ConsentType]] = None,
        include_history: bool = False
    ) -> Dict[str, Any]:
        """Get user consents."""
        try:
            # Validate user exists
            user = await User.get_by_id(db, user_id)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
            
            if include_history:
                consents = await UserConsent.get_consent_history(
                    db=db,
                    user_id=user_id,
                    consent_type=consent_types[0] if consent_types and len(consent_types) == 1 else None
                )
            else:
                consents = await UserConsent.get_user_consents(
                    db=db,
                    user_id=user_id,
                    consent_types=consent_types
                )
            
            consent_data = []
            for consent in consents:
                consent_dict = consent.to_dict()
                
                # Add version information if available
                if hasattr(consent, 'consent_version') and consent.consent_version:
                    consent_dict.update({
                        'consent_type': consent.consent_version.consent_type.value,
                        'consent_title': consent.consent_version.title,
                        'consent_description': consent.consent_version.description,
                        'legal_basis': consent.consent_version.legal_basis.value,
                        'version_number': consent.consent_version.version_number
                    })
                
                consent_data.append(consent_dict)
            
            # Group current consents by type for easy access
            current_consents = {}
            if not include_history:
                for consent in consent_data:
                    consent_type = consent.get('consent_type')
                    if consent_type and consent.get('is_valid'):
                        current_consents[consent_type] = consent
            
            return {
                'user_id': user_id,
                'consents': consent_data,
                'current_consents': current_consents,
                'total_count': len(consent_data),
                'retrieved_at': datetime.utcnow().isoformat()
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Failed to get user consents", error=str(e), user_id=user_id)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve user consents"
            )
    
    async def bulk_grant_consents(
        self,
        db: AsyncSession,
        user_id: int,
        consents: Dict[ConsentType, Dict[str, Any]],
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        consent_method: str = 'web_form'
    ) -> Dict[str, Any]:
        """Grant multiple consents at once."""
        try:
            # Validate user exists
            user = await User.get_by_id(db, user_id)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
            
            granted_consents = []
            failed_consents = []
            
            for consent_type, consent_data in consents.items():
                try:
                    expires_at = None
                    if consent_data.get('expires_at'):
                        expires_at = datetime.fromisoformat(consent_data['expires_at'])
                    
                    consent = await self.grant_consent(
                        db=db,
                        user_id=user_id,
                        consent_type=consent_type,
                        ip_address=ip_address,
                        user_agent=user_agent,
                        consent_method=consent_method,
                        expires_at=expires_at,
                        consent_metadata=consent_data.get('metadata')
                    )
                    
                    granted_consents.append(consent)
                    
                except Exception as e:
                    failed_consents.append({
                        'consent_type': consent_type.value,
                        'error': str(e)
                    })
            
            logger.info(
                "Bulk consent grant completed",
                user_id=user_id,
                granted_count=len(granted_consents),
                failed_count=len(failed_consents)
            )
            
            return {
                'user_id': user_id,
                'granted_consents': granted_consents,
                'failed_consents': failed_consents,
                'total_requested': len(consents),
                'successful_count': len(granted_consents),
                'failed_count': len(failed_consents)
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Failed to bulk grant consents", error=str(e), user_id=user_id)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to grant consents"
            )
    
    async def check_consent_validity(
        self,
        db: AsyncSession,
        user_id: int,
        consent_type: ConsentType
    ) -> Dict[str, Any]:
        """Check if user has valid consent for a specific type."""
        try:
            consent = await UserConsent.get_user_consent(
                db=db,
                user_id=user_id,
                consent_type=consent_type
            )
            
            if not consent:
                return {
                    'user_id': user_id,
                    'consent_type': consent_type.value,
                    'has_valid_consent': False,
                    'consent_required': True,
                    'reason': 'No consent record found'
                }
            
            is_valid = consent.is_valid()
            is_expired = consent.is_expired()
            
            return {
                'user_id': user_id,
                'consent_type': consent_type.value,
                'has_valid_consent': is_valid,
                'consent_required': not is_valid,
                'is_expired': is_expired,
                'granted_at': consent.granted_at.isoformat() if consent.granted_at else None,
                'expires_at': consent.expires_at.isoformat() if consent.expires_at else None,
                'withdrawn_at': consent.withdrawn_at.isoformat() if consent.withdrawn_at else None,
                'status': consent.status.value,
                'legal_basis': consent.consent_version.legal_basis.value if consent.consent_version else None
            }
            
        except Exception as e:
            logger.error("Failed to check consent validity", error=str(e), user_id=user_id)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to check consent validity"
            )
    
    async def cleanup_expired_consents(self, db: AsyncSession) -> Dict[str, int]:
        """Clean up expired consents."""
        try:
            now = datetime.utcnow()
            
            # Get expired consents
            query = select(UserConsent).where(
                UserConsent.expires_at < now,
                UserConsent.status == ConsentStatus.GRANTED
            )
            
            result = await db.execute(query)
            expired_consents = result.scalars().all()
            
            updated_count = 0
            for consent in expired_consents:
                consent.status = ConsentStatus.EXPIRED
                await consent.save(db)
                updated_count += 1
            
            logger.info(
                "Expired consents cleaned up",
                updated_count=updated_count,
                cutoff_date=now.isoformat()
            )
            
            return {
                'updated_count': updated_count,
                'cutoff_date': now.isoformat()
            }
            
        except Exception as e:
            logger.error("Failed to cleanup expired consents", error=str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to cleanup expired consents"
            )