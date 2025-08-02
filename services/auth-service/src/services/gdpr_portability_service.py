"""
GDPR Data Portability Service (Article 20).
Provides structured data export with secure time-limited download links.
"""
import json
import uuid
import tempfile
import zipfile
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Union
from pathlib import Path
from dataclasses import dataclass
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from fastapi import HTTPException, status

from ..models.user import User
from ..models.session import UserSession
from ..models.audit import AuditLog, AuditEventType, AuditLogger
from ..models.gdpr_consent import UserConsent, ConsentVersion
from ..core.config import settings
from ..core.redis import get_cache_service
from ..core.security import SecurityService

logger = structlog.get_logger()


@dataclass
class PortabilityRequest:
    """Data portability request configuration."""
    
    request_id: str
    user_id: int
    requested_by_user_id: int
    format: str
    include_metadata: bool
    include_system_data: bool
    data_categories: List[str]
    requested_at: datetime
    expires_at: datetime
    status: str


class PortabilityFormat:
    """Supported data portability formats."""
    
    JSON = "json"
    CSV = "csv"
    XML = "xml"
    STRUCTURED_JSON = "structured_json"  # JSON-LD with schema.org annotations


class PortabilityStatus:
    """Data portability request status."""
    
    PENDING = "pending"
    PROCESSING = "processing" 
    READY = "ready"
    DOWNLOADED = "downloaded"
    EXPIRED = "expired"
    FAILED = "failed"


class DataCategory:
    """Categories of data that can be exported."""
    
    PROFILE = "profile"
    AUTHENTICATION = "authentication"
    SESSIONS = "sessions"
    CONSENTS = "consents"
    AUDIT_TRAIL = "audit_trail"
    PREFERENCES = "preferences"
    METADATA = "metadata"


class GDPRPortabilityService:
    """Data portability service for GDPR Article 20 compliance."""
    
    def __init__(self):
        self.cache_service = get_cache_service()
        self.audit_logger = AuditLogger()
        self.download_expiry_hours = getattr(settings, 'PORTABILITY_DOWNLOAD_EXPIRY_HOURS', 72)
        self.max_file_size_mb = getattr(settings, 'MAX_PORTABILITY_FILE_SIZE_MB', 100)
    
    async def create_portability_request(
        self,
        db: AsyncSession,
        user_id: int,
        export_format: str = PortabilityFormat.STRUCTURED_JSON,
        data_categories: Optional[List[str]] = None,
        include_metadata: bool = True,
        include_system_data: bool = False,
        requested_by_user_id: Optional[int] = None,
        ip_address: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create a new data portability request.
        
        Args:
            db: Database session
            user_id: User requesting data portability
            export_format: Export format (json, csv, xml, structured_json)
            data_categories: Specific data categories to export
            include_metadata: Include technical metadata
            include_system_data: Include system-generated data
            requested_by_user_id: User making the request (for admin requests)
            ip_address: IP address of requester
            
        Returns:
            Dict with request information
        """
        try:
            # Validate user exists
            user = await User.get_by_id(db, user_id)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
            
            # Validate requester permissions
            requester_id = requested_by_user_id or user_id
            if requester_id != user_id:
                requester = await User.get_by_id(db, requester_id)
                if not requester or not requester.is_superuser:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Insufficient permissions"
                    )
            
            # Set default data categories
            if data_categories is None:
                data_categories = [
                    DataCategory.PROFILE,
                    DataCategory.AUTHENTICATION,
                    DataCategory.SESSIONS,
                    DataCategory.CONSENTS,
                    DataCategory.PREFERENCES
                ]
            
            # Generate request ID
            request_id = str(uuid.uuid4())
            
            # Create portability request
            portability_request = PortabilityRequest(
                request_id=request_id,
                user_id=user_id,
                requested_by_user_id=requester_id,
                format=export_format,
                include_metadata=include_metadata,
                include_system_data=include_system_data,
                data_categories=data_categories,
                requested_at=datetime.utcnow(),
                expires_at=datetime.utcnow() + timedelta(hours=self.download_expiry_hours),
                status=PortabilityStatus.PENDING
            )
            
            # Store request in cache
            cache_key = f"portability_request:{request_id}"
            request_data = {
                'request_id': request_id,
                'user_id': user_id,
                'requested_by_user_id': requester_id,
                'format': export_format,
                'include_metadata': include_metadata,
                'include_system_data': include_system_data,
                'data_categories': data_categories,
                'requested_at': portability_request.requested_at.isoformat(),
                'expires_at': portability_request.expires_at.isoformat(),
                'status': PortabilityStatus.PENDING,
                'ip_address': ip_address
            }
            
            await self.cache_service.set(
                cache_key,
                request_data,
                ttl=self.download_expiry_hours * 3600
            )
            
            # Log portability request
            await self.audit_logger.log_data_access(
                db=db,
                action="portability_request",
                resource_type="user_data",
                resource_id=str(user_id),
                user_id=requester_id,
                ip_address=ip_address,
                success=True,
                description="Data portability request created",
                event_data={
                    'request_id': request_id,
                    'format': export_format,
                    'data_categories': data_categories,
                    'include_metadata': include_metadata
                },
                pii_accessed=True
            )
            
            # Start background processing
            import asyncio
            asyncio.create_task(self._process_portability_request(db, request_id))
            
            logger.info(
                "Portability request created",
                request_id=request_id,
                user_id=user_id,
                format=export_format
            )
            
            return {
                'request_id': request_id,
                'status': PortabilityStatus.PENDING,
                'estimated_completion': datetime.utcnow() + timedelta(minutes=5),
                'expires_at': portability_request.expires_at.isoformat(),
                'data_categories': data_categories,
                'format': export_format
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Failed to create portability request", error=str(e), user_id=user_id)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create portability request"
            )
    
    async def get_request_status(
        self,
        db: AsyncSession,
        request_id: str,
        user_id: int
    ) -> Dict[str, Any]:
        """Get status of a portability request."""
        try:
            cache_key = f"portability_request:{request_id}"
            request_data = await self.cache_service.get(cache_key)
            
            if not request_data:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Request not found or expired"
                )
            
            # Verify user has access
            if request_data['user_id'] != user_id:
                requesting_user = await User.get_by_id(db, user_id)
                if not requesting_user or not requesting_user.is_superuser:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Access denied"
                    )
            
            # Check if expired
            expires_at = datetime.fromisoformat(request_data['expires_at'])
            if datetime.utcnow() > expires_at:
                request_data['status'] = PortabilityStatus.EXPIRED
                await self.cache_service.set(cache_key, request_data)
            
            return {
                'request_id': request_id,
                'status': request_data['status'],
                'requested_at': request_data['requested_at'],
                'expires_at': request_data['expires_at'],
                'format': request_data['format'],
                'data_categories': request_data['data_categories'],
                'download_ready': request_data['status'] == PortabilityStatus.READY,
                'file_size_bytes': request_data.get('file_size_bytes'),
                'record_count': request_data.get('record_count')
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Failed to get request status", error=str(e), request_id=request_id)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to get request status"
            )
    
    async def download_portable_data(
        self,
        db: AsyncSession,
        request_id: str,
        user_id: int,
        ip_address: Optional[str] = None
    ) -> Dict[str, Any]:
        """Generate secure download link for portable data."""
        try:
            cache_key = f"portability_request:{request_id}"
            request_data = await self.cache_service.get(cache_key)
            
            if not request_data:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Request not found or expired"
                )
            
            # Verify user has access
            if request_data['user_id'] != user_id:
                requesting_user = await User.get_by_id(db, user_id)
                if not requesting_user or not requesting_user.is_superuser:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Access denied"
                    )
            
            # Check status
            if request_data['status'] != PortabilityStatus.READY:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Request not ready for download. Status: {request_data['status']}"
                )
            
            # Check expiry
            expires_at = datetime.fromisoformat(request_data['expires_at'])
            if datetime.utcnow() > expires_at:
                raise HTTPException(
                    status_code=status.HTTP_410_GONE,
                    detail="Download link has expired"
                )
            
            # Generate secure download token
            download_token = SecurityService.create_download_token({
                'request_id': request_id,
                'user_id': user_id,
                'type': 'portability_download',
                'format': request_data['format']
            })
            
            # Mark as downloaded
            request_data['status'] = PortabilityStatus.DOWNLOADED
            request_data['downloaded_at'] = datetime.utcnow().isoformat()
            request_data['download_ip'] = ip_address
            await self.cache_service.set(cache_key, request_data)
            
            # Log download
            await self.audit_logger.log_data_access(
                db=db,
                action="portability_download",
                resource_type="user_data",
                resource_id=str(request_data['user_id']),
                user_id=user_id,
                ip_address=ip_address,
                success=True,
                description="Portable data downloaded",
                event_data={'request_id': request_id, 'format': request_data['format']},
                pii_accessed=True
            )
            
            return {
                'download_token': download_token,
                'expires_at': request_data['expires_at'],
                'file_size_bytes': request_data.get('file_size_bytes'),
                'filename': request_data.get('filename'),
                'format': request_data['format']
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Failed to generate download link", error=str(e), request_id=request_id)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to generate download link"
            )
    
    async def _process_portability_request(self, db: AsyncSession, request_id: str) -> None:
        """Background task to process portability request."""
        try:
            cache_key = f"portability_request:{request_id}"
            request_data = await self.cache_service.get(cache_key)
            
            if not request_data:
                logger.error("Request data not found", request_id=request_id)
                return
            
            # Update status
            request_data['status'] = PortabilityStatus.PROCESSING
            request_data['processing_started_at'] = datetime.utcnow().isoformat()
            await self.cache_service.set(cache_key, request_data)
            
            # Extract user data according to categories
            portable_data = await self._extract_portable_data(
                db=db,
                user_id=request_data['user_id'],
                data_categories=request_data['data_categories'],
                include_metadata=request_data['include_metadata'],
                include_system_data=request_data['include_system_data']
            )
            
            # Generate export file
            file_path, file_size = await self._generate_portable_file(
                data=portable_data,
                export_format=request_data['format'],
                request_id=request_id
            )
            
            # Update request with completion info
            request_data['status'] = PortabilityStatus.READY
            request_data['completed_at'] = datetime.utcnow().isoformat()
            request_data['file_path'] = str(file_path)
            request_data['file_size_bytes'] = file_size
            request_data['record_count'] = self._count_records(portable_data)
            request_data['filename'] = f"portable_data_{request_data['user_id']}_{request_id[:8]}.{request_data['format']}"
            
            await self.cache_service.set(cache_key, request_data)
            
            logger.info(
                "Portability request completed",
                request_id=request_id,
                user_id=request_data['user_id'],
                file_size=file_size
            )
            
        except Exception as e:
            logger.error("Failed to process portability request", error=str(e), request_id=request_id)
            
            # Mark as failed
            try:
                request_data['status'] = PortabilityStatus.FAILED
                request_data['error'] = str(e)
                request_data['failed_at'] = datetime.utcnow().isoformat()
                await self.cache_service.set(cache_key, request_data)
            except Exception as cache_error:
                logger.error("Failed to update failed status", error=str(cache_error))
    
    async def _extract_portable_data(
        self,
        db: AsyncSession,
        user_id: int,
        data_categories: List[str],
        include_metadata: bool,
        include_system_data: bool
    ) -> Dict[str, Any]:
        """Extract user data according to GDPR Article 20 requirements."""
        data = {}
        
        # Get user with relationships
        user_query = select(User).options(
            selectinload(User.roles),
            selectinload(User.sessions),
            selectinload(User.audit_logs)
        ).where(User.id == user_id)
        
        user_result = await db.execute(user_query)
        user = user_result.scalar_one_or_none()
        
        if not user:
            raise ValueError("User not found")
        
        # Profile data
        if DataCategory.PROFILE in data_categories:
            data['profile'] = {
                'personal_information': {
                    'user_id': user.id,
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'phone_number': user.phone_number,
                    'profile_data': user.profile_data
                },
                'account_status': {
                    'is_active': user.is_active,
                    'is_verified': user.is_verified,
                    'email_verified_at': user.email_verified_at.isoformat() if user.email_verified_at else None
                },
                'preferences': user.preferences
            }
        
        # Authentication data
        if DataCategory.AUTHENTICATION in data_categories:
            data['authentication'] = {
                'account_created': user.created_at.isoformat() if user.created_at else None,
                'last_login': user.last_login_at.isoformat() if user.last_login_at else None,
                'password_last_changed': user.password_changed_at.isoformat() if user.password_changed_at else None,
                'terms_accepted_at': user.terms_accepted_at.isoformat() if user.terms_accepted_at else None,
                'privacy_policy_accepted_at': user.privacy_policy_accepted_at.isoformat() if user.privacy_policy_accepted_at else None
            }
        
        # Sessions data
        if DataCategory.SESSIONS in data_categories:
            session_query = select(UserSession).where(
                UserSession.user_id == user_id,
                UserSession.is_deleted == False
            )
            session_result = await db.execute(session_query)
            sessions = session_result.scalars().all()
            
            data['sessions'] = [
                {
                    'session_id': session.session_id,
                    'created_at': session.created_at.isoformat() if session.created_at else None,
                    'last_accessed_at': session.last_accessed_at.isoformat() if session.last_accessed_at else None,
                    'expires_at': session.expires_at.isoformat() if session.expires_at else None,
                    'is_active': session.is_active,
                    'device_info': session.device_info if include_system_data else None,
                    'location_data': session.location_data if include_system_data else None
                }
                for session in sessions
            ]
        
        # Consents data
        if DataCategory.CONSENTS in data_categories:
            consent_query = select(UserConsent).options(
                selectinload(UserConsent.consent_version)
            ).where(
                UserConsent.user_id == user_id,
                UserConsent.is_deleted == False
            )
            
            consent_result = await db.execute(consent_query)
            consents = consent_result.scalars().all()
            
            data['consents'] = [
                {
                    'consent_type': consent.consent_version.consent_type.value if consent.consent_version else 'unknown',
                    'consent_title': consent.consent_version.title if consent.consent_version else None,
                    'status': consent.status.value,
                    'granted_at': consent.granted_at.isoformat() if consent.granted_at else None,
                    'withdrawn_at': consent.withdrawn_at.isoformat() if consent.withdrawn_at else None,
                    'expires_at': consent.expires_at.isoformat() if consent.expires_at else None,
                    'consent_method': consent.consent_method,
                    'legal_basis': consent.consent_version.legal_basis.value if consent.consent_version else None,
                    'version_number': consent.consent_version.version_number if consent.consent_version else None
                }
                for consent in consents
            ]
        
        # Audit trail (user-relevant events only)
        if DataCategory.AUDIT_TRAIL in data_categories and include_system_data:
            audit_query = select(AuditLog).where(
                AuditLog.user_id == user_id,
                AuditLog.event_type.in_([
                    AuditEventType.LOGIN_SUCCESS,
                    AuditEventType.PASSWORD_CHANGE,
                    AuditEventType.USER_UPDATED,
                    AuditEventType.GDPR_DATA_REQUEST,
                    AuditEventType.DATA_EXPORT
                ])
            ).order_by(AuditLog.timestamp.desc()).limit(100)
            
            audit_result = await db.execute(audit_query)
            audit_logs = audit_result.scalars().all()
            
            data['audit_trail'] = [
                {
                    'event_type': log.event_type.value,
                    'timestamp': log.timestamp.isoformat() if log.timestamp else None,
                    'action': log.action,
                    'description': log.description,
                    'success': log.success
                }
                for log in audit_logs
            ]
        
        # Add metadata
        if include_metadata:
            data['_metadata'] = {
                'export_info': {
                    'exported_at': datetime.utcnow().isoformat(),
                    'export_format': 'structured_data',
                    'gdpr_article': 'Article 20 - Right to data portability',
                    'data_controller': getattr(settings, 'DATA_CONTROLLER_NAME', 'Your Organization'),
                    'contact_email': getattr(settings, 'DPO_EMAIL', 'dpo@yourorg.com')
                },
                'user_info': {
                    'user_id': user_id,
                    'account_created': user.created_at.isoformat() if user.created_at else None,
                    'data_categories_included': data_categories
                },
                'technical_info': {
                    'schema_version': '1.0',
                    'encoding': 'UTF-8',
                    'total_records': self._count_records(data)
                }
            }
        
        return data
    
    async def _generate_portable_file(
        self,
        data: Dict[str, Any],
        export_format: str,
        request_id: str
    ) -> tuple[Path, int]:
        """Generate portable data file in specified format."""
        temp_dir = Path(tempfile.gettempdir()) / "portability_exports"
        temp_dir.mkdir(exist_ok=True)
        
        if export_format == PortabilityFormat.STRUCTURED_JSON:
            # JSON-LD with schema.org annotations
            structured_data = self._add_jsonld_context(data)
            filename = f"portable_data_{request_id}.json"
            file_path = temp_dir / filename
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(structured_data, f, indent=2, ensure_ascii=False, default=str)
        
        elif export_format == PortabilityFormat.JSON:
            filename = f"portable_data_{request_id}.json"
            file_path = temp_dir / filename
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        
        elif export_format == PortabilityFormat.CSV:
            # Create ZIP with multiple CSV files
            zip_filename = f"portable_data_{request_id}.zip"
            zip_path = temp_dir / zip_filename
            
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for category, category_data in data.items():
                    if category.startswith('_'):
                        continue  # Skip metadata
                    
                    if isinstance(category_data, list) and category_data:
                        csv_content = self._convert_to_csv(category_data)
                        zipf.writestr(f"{category}.csv", csv_content)
                    elif isinstance(category_data, dict):
                        # Flatten nested dict to CSV
                        flattened = self._flatten_dict(category_data)
                        csv_content = self._dict_to_csv(flattened)
                        zipf.writestr(f"{category}.csv", csv_content)
            
            file_path = zip_path
        
        elif export_format == PortabilityFormat.XML:
            xml_content = self._convert_to_xml(data)
            filename = f"portable_data_{request_id}.xml"
            file_path = temp_dir / filename
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(xml_content)
        
        else:
            raise ValueError(f"Unsupported export format: {export_format}")
        
        # Check file size
        file_size = file_path.stat().st_size
        if file_size > self.max_file_size_mb * 1024 * 1024:
            logger.warning(
                "Portable data file exceeds size limit",
                file_size_mb=file_size / (1024 * 1024),
                limit_mb=self.max_file_size_mb
            )
        
        return file_path, file_size
    
    def _add_jsonld_context(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add JSON-LD context for structured data."""
        structured = {
            "@context": {
                "@vocab": "http://schema.org/",
                "gdpr": "https://gdpr.eu/article-",
                "profile": {
                    "@type": "Person",
                    "@context": {
                        "email": "email",
                        "givenName": "first_name",
                        "familyName": "last_name",
                        "telephone": "phone_number"
                    }
                }
            },
            "@type": "Dataset",
            "@id": f"urn:gdpr:portability:{datetime.utcnow().isoformat()}",
            "name": "Personal Data Export - GDPR Article 20",
            "description": "Structured personal data export for data portability rights",
            "dateCreated": datetime.utcnow().isoformat(),
            "license": "https://gdpr.eu/article-20/",
            "data": data
        }
        
        return structured
    
    def _convert_to_csv(self, data: List[Dict[str, Any]]) -> str:
        """Convert list of dicts to CSV."""
        import csv
        import io
        
        if not data:
            return ""
        
        output = io.StringIO()
        fieldnames = set()
        
        # Get all fieldnames
        for item in data:
            fieldnames.update(self._flatten_dict(item).keys())
        
        fieldnames = sorted(fieldnames)
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        
        for item in data:
            flattened = self._flatten_dict(item)
            writer.writerow(flattened)
        
        return output.getvalue()
    
    def _dict_to_csv(self, data: Dict[str, Any]) -> str:
        """Convert dict to CSV."""
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Field', 'Value'])
        
        for key, value in data.items():
            if isinstance(value, (dict, list)):
                value = json.dumps(value)
            writer.writerow([key, str(value)])
        
        return output.getvalue()
    
    def _flatten_dict(self, d: Dict[str, Any], parent_key: str = '', sep: str = '.') -> Dict[str, Any]:
        """Flatten nested dictionary."""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            elif isinstance(v, list) and v and isinstance(v[0], dict):
                # Handle list of dicts
                for i, item in enumerate(v):
                    if isinstance(item, dict):
                        items.extend(self._flatten_dict(item, f"{new_key}[{i}]", sep=sep).items())
                    else:
                        items.append((f"{new_key}[{i}]", item))
            else:
                items.append((new_key, v))
        return dict(items)
    
    def _convert_to_xml(self, data: Dict[str, Any]) -> str:
        """Convert data to XML format."""
        import xml.etree.ElementTree as ET
        
        root = ET.Element("portable_data")
        root.set("xmlns:gdpr", "https://gdpr.eu/")
        root.set("article", "20")
        
        def dict_to_xml(parent: ET.Element, data: Union[Dict, List, Any], name: str = "item"):
            if isinstance(data, dict):
                element = ET.SubElement(parent, name)
                for key, value in data.items():
                    dict_to_xml(element, value, key.replace(' ', '_'))
            elif isinstance(data, list):
                for i, item in enumerate(data):
                    dict_to_xml(parent, item, f"{name}_{i}")
            else:
                element = ET.SubElement(parent, name)
                element.text = str(data) if data is not None else ""
        
        for key, value in data.items():
            dict_to_xml(root, value, key.replace(' ', '_'))
        
        # Format XML
        ET.indent(root, space="  ")
        return ET.tostring(root, encoding='unicode', xml_declaration=True)
    
    def _count_records(self, data: Dict[str, Any]) -> int:
        """Count total records in data structure."""
        count = 0
        for value in data.values():
            if isinstance(value, list):
                count += len(value)
            elif isinstance(value, dict) and not value.keys() & {'_metadata', 'export_info'}:
                count += 1
        return count