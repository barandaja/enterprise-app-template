"""
GDPR Data Subject Access Request (DSAR) Service.
Implements secure data export functionality with machine-readable formats.
"""
import json
import uuid
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Union
from pathlib import Path
import tempfile
import zipfile
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from fastapi import HTTPException, status

from ..models.user import User
from ..models.session import UserSession
from ..models.audit import AuditLog, AuditEventType, AuditSeverity, AuditLogger
from ..models.gdpr_consent import UserConsent, ConsentVersion
from ..core.config import settings
from ..core.redis import get_cache_service
from ..core.security import SecurityService

logger = structlog.get_logger()


class DataExportFormat:
    """Supported data export formats."""
    
    JSON = "json"
    CSV = "csv"
    XML = "xml"


class DSARStatus:
    """DSAR request status."""
    
    PENDING = "pending"
    PROCESSING = "processing"
    READY = "ready"
    DOWNLOADED = "downloaded"
    EXPIRED = "expired"
    FAILED = "failed"


class DSARService:
    """Data Subject Access Request service for GDPR compliance."""
    
    def __init__(self):
        self.cache_service = get_cache_service()
        self.audit_logger = AuditLogger()
        self.download_expiry_hours = getattr(settings, 'DSAR_DOWNLOAD_EXPIRY_HOURS', 72)
    
    async def create_data_request(
        self,
        db: AsyncSession,
        user_id: int,
        export_format: str = DataExportFormat.JSON,
        include_deleted: bool = False,
        requested_by_user_id: Optional[int] = None,
        ip_address: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create a new data subject access request.
        
        Args:
            db: Database session
            user_id: User requesting data
            export_format: Export format (json, csv, xml)
            include_deleted: Include soft-deleted records
            requested_by_user_id: ID of user making request (for admin requests)
            ip_address: IP address of requester
            
        Returns:
            Dict with request ID and status
        """
        try:
            # Validate user exists
            user = await self._get_user_with_data(db, user_id)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
            
            # Generate unique request ID
            request_id = str(uuid.uuid4())
            
            # Create request metadata
            request_data = {
                'request_id': request_id,
                'user_id': user_id,
                'requested_by_user_id': requested_by_user_id or user_id,
                'export_format': export_format,
                'include_deleted': include_deleted,
                'status': DSARStatus.PENDING,
                'requested_at': datetime.utcnow().isoformat(),
                'ip_address': ip_address,
                'expires_at': (datetime.utcnow() + timedelta(hours=self.download_expiry_hours)).isoformat()
            }
            
            # Store request in cache
            cache_key = f"dsar_request:{request_id}"
            await self.cache_service.set(
                cache_key, 
                request_data, 
                ttl=self.download_expiry_hours * 3600
            )
            
            # Log DSAR request
            await self.audit_logger.log_data_access(
                db=db,
                action="dsar_request",
                resource_type="user_data",
                resource_id=str(user_id),
                user_id=requested_by_user_id or user_id,
                ip_address=ip_address,
                success=True,
                description=f"DSAR request created for user {user_id}",
                event_data={'request_id': request_id, 'export_format': export_format},
                pii_accessed=True
            )
            
            # Start background processing
            asyncio.create_task(self._process_data_request(db, request_id))
            
            logger.info(
                "DSAR request created",
                request_id=request_id,
                user_id=user_id,
                requested_by=requested_by_user_id
            )
            
            return {
                'request_id': request_id,
                'status': DSARStatus.PENDING,
                'estimated_completion': datetime.utcnow() + timedelta(minutes=5),
                'expires_at': request_data['expires_at']
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Failed to create DSAR request", error=str(e), user_id=user_id)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create data request"
            )
    
    async def get_request_status(
        self,
        db: AsyncSession,
        request_id: str,
        user_id: int
    ) -> Dict[str, Any]:
        """Get status of a data request."""
        try:
            cache_key = f"dsar_request:{request_id}"
            request_data = await self.cache_service.get(cache_key)
            
            if not request_data:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Request not found or expired"
                )
            
            # Verify user has access to this request
            if request_data['user_id'] != user_id:
                # Allow admin users to view any request
                requesting_user = await User.get_by_id(db, user_id)
                if not requesting_user or not requesting_user.is_superuser:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Access denied"
                    )
            
            # Check if expired
            expires_at = datetime.fromisoformat(request_data['expires_at'])
            if datetime.utcnow() > expires_at:
                request_data['status'] = DSARStatus.EXPIRED
                await self.cache_service.set(cache_key, request_data)
            
            return {
                'request_id': request_id,
                'status': request_data['status'],
                'requested_at': request_data['requested_at'],
                'expires_at': request_data['expires_at'],
                'download_ready': request_data['status'] == DSARStatus.READY,
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
    
    async def download_data(
        self,
        db: AsyncSession,
        request_id: str,
        user_id: int,
        ip_address: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get download information for processed data request.
        
        Returns:
            Dict with download URL and expiry information
        """
        try:
            cache_key = f"dsar_request:{request_id}"
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
            if request_data['status'] != DSARStatus.READY:
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
                'type': 'dsar_download'
            })
            
            # Mark as downloaded
            request_data['status'] = DSARStatus.DOWNLOADED
            request_data['downloaded_at'] = datetime.utcnow().isoformat()
            request_data['download_ip'] = ip_address
            await self.cache_service.set(cache_key, request_data)
            
            # Log download
            await self.audit_logger.log_data_access(
                db=db,
                action="dsar_download",
                resource_type="user_data",
                resource_id=str(request_data['user_id']),
                user_id=user_id,
                ip_address=ip_address,
                success=True,
                description=f"DSAR data downloaded for request {request_id}",
                event_data={'request_id': request_id},
                pii_accessed=True
            )
            
            logger.info(
                "DSAR download initiated",
                request_id=request_id,
                user_id=user_id,
                download_ip=ip_address
            )
            
            return {
                'download_token': download_token,
                'expires_at': request_data['expires_at'],
                'file_size_bytes': request_data.get('file_size_bytes'),
                'filename': request_data.get('filename')
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Failed to initiate download", error=str(e), request_id=request_id)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to initiate download"
            )
    
    async def _process_data_request(self, db: AsyncSession, request_id: str) -> None:
        """Background task to process data request."""
        try:
            cache_key = f"dsar_request:{request_id}"
            request_data = await self.cache_service.get(cache_key)
            
            if not request_data:
                logger.error("Request data not found for processing", request_id=request_id)
                return
            
            # Update status to processing
            request_data['status'] = DSARStatus.PROCESSING
            request_data['processing_started_at'] = datetime.utcnow().isoformat()
            await self.cache_service.set(cache_key, request_data)
            
            user_id = request_data['user_id']
            export_format = request_data['export_format']
            include_deleted = request_data['include_deleted']
            
            # Extract all user data
            user_data = await self._extract_user_data(db, user_id, include_deleted)
            
            # Generate export file
            file_path, file_size = await self._generate_export_file(
                user_data, 
                export_format, 
                request_id
            )
            
            # Update request with completion info
            request_data['status'] = DSARStatus.READY
            request_data['completed_at'] = datetime.utcnow().isoformat()
            request_data['file_path'] = str(file_path)
            request_data['file_size_bytes'] = file_size
            request_data['record_count'] = len(user_data)
            request_data['filename'] = f"user_data_{user_id}_{request_id[:8]}.{export_format}"
            
            await self.cache_service.set(cache_key, request_data)
            
            logger.info(
                "DSAR request completed",
                request_id=request_id,
                user_id=user_id,
                record_count=len(user_data),
                file_size=file_size
            )
            
        except Exception as e:
            logger.error("Failed to process DSAR request", error=str(e), request_id=request_id)
            
            # Mark as failed
            try:
                request_data['status'] = DSARStatus.FAILED
                request_data['error'] = str(e)
                request_data['failed_at'] = datetime.utcnow().isoformat()
                await self.cache_service.set(cache_key, request_data)
            except Exception as cache_error:
                logger.error("Failed to update failed status", error=str(cache_error))
    
    async def _get_user_with_data(self, db: AsyncSession, user_id: int) -> Optional[User]:
        """Get user with all related data loaded."""
        query = select(User).options(
            selectinload(User.roles),
            selectinload(User.sessions),
            selectinload(User.audit_logs)
        ).where(User.id == user_id)
        
        result = await db.execute(query)
        return result.scalar_one_or_none()
    
    async def _extract_user_data(
        self, 
        db: AsyncSession, 
        user_id: int, 
        include_deleted: bool = False
    ) -> Dict[str, Any]:
        """Extract all user data for export."""
        data = {}
        
        # User profile data
        user = await self._get_user_with_data(db, user_id)
        if user:
            data['user_profile'] = {
                'id': user.id,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'phone_number': user.phone_number,
                'is_active': user.is_active,
                'is_verified': user.is_verified,
                'created_at': user.created_at.isoformat() if user.created_at else None,
                'updated_at': user.updated_at.isoformat() if user.updated_at else None,
                'last_login_at': user.last_login_at.isoformat() if user.last_login_at else None,
                'email_verified_at': user.email_verified_at.isoformat() if user.email_verified_at else None,
                'terms_accepted_at': user.terms_accepted_at.isoformat() if user.terms_accepted_at else None,
                'privacy_policy_accepted_at': user.privacy_policy_accepted_at.isoformat() if user.privacy_policy_accepted_at else None,
                'profile_data': user.profile_data,
                'preferences': user.preferences
            }
            
            # User roles
            data['roles'] = [
                {
                    'name': role.name,
                    'description': role.description,
                    'assigned_at': role.created_at.isoformat() if role.created_at else None
                }
                for role in user.roles
            ]
        
        # User sessions
        session_query = select(UserSession).where(UserSession.user_id == user_id)
        if not include_deleted:
            session_query = session_query.where(UserSession.is_deleted == False)
        
        session_result = await db.execute(session_query)
        sessions = session_result.scalars().all()
        
        data['sessions'] = [
            {
                'session_id': session.session_id,
                'created_at': session.created_at.isoformat() if session.created_at else None,
                'expires_at': session.expires_at.isoformat() if session.expires_at else None,
                'last_accessed_at': session.last_accessed_at.isoformat() if session.last_accessed_at else None,
                'ip_address': session.ip_address,
                'user_agent': session.user_agent,
                'is_active': session.is_active,
                'device_info': session.device_info,
                'location_data': session.location_data
            }
            for session in sessions
        ]
        
        # Audit logs (limited to user-specific events)
        audit_query = select(AuditLog).where(AuditLog.user_id == user_id)
        audit_result = await db.execute(audit_query)
        audit_logs = audit_result.scalars().all()
        
        data['audit_logs'] = [
            {
                'event_type': log.event_type.value,
                'timestamp': log.timestamp.isoformat() if log.timestamp else None,
                'action': log.action,
                'description': log.description,
                'ip_address': log.ip_address,
                'success': log.success,
                'severity': log.severity.value
            }
            for log in audit_logs
        ]
        
        # User consents
        consent_query = select(UserConsent).options(
            selectinload(UserConsent.consent_version)
        ).where(UserConsent.user_id == user_id)
        
        consent_result = await db.execute(consent_query)
        consents = consent_result.scalars().all()
        
        data['consents'] = [
            {
                'consent_type': consent.consent_version.consent_type.value if consent.consent_version else 'unknown',
                'status': consent.status.value,
                'granted_at': consent.granted_at.isoformat() if consent.granted_at else None,
                'withdrawn_at': consent.withdrawn_at.isoformat() if consent.withdrawn_at else None,
                'expires_at': consent.expires_at.isoformat() if consent.expires_at else None,
                'consent_method': consent.consent_method,
                'version_number': consent.consent_version.version_number if consent.consent_version else None,
                'legal_basis': consent.consent_version.legal_basis.value if consent.consent_version else None
            }
            for consent in consents
        ]
        
        # Metadata
        data['export_metadata'] = {
            'exported_at': datetime.utcnow().isoformat(),
            'user_id': user_id,
            'include_deleted': include_deleted,
            'total_records': sum(len(v) for v in data.values() if isinstance(v, list)),
            'gdpr_article': 'Article 15 - Right of access by the data subject'
        }
        
        return data
    
    async def _generate_export_file(
        self, 
        data: Dict[str, Any], 
        export_format: str, 
        request_id: str
    ) -> tuple[Path, int]:
        """Generate export file in specified format."""
        temp_dir = Path(tempfile.gettempdir()) / "dsar_exports"
        temp_dir.mkdir(exist_ok=True)
        
        filename = f"user_data_{request_id}.{export_format}"
        file_path = temp_dir / filename
        
        if export_format == DataExportFormat.JSON:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        
        elif export_format == DataExportFormat.CSV:
            # For CSV, create a ZIP with multiple CSV files
            zip_path = temp_dir / f"user_data_{request_id}.zip"
            
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for section, section_data in data.items():
                    if isinstance(section_data, list) and section_data:
                        csv_content = self._convert_to_csv(section_data)
                        zipf.writestr(f"{section}.csv", csv_content)
                    elif isinstance(section_data, dict):
                        csv_content = self._dict_to_csv(section_data)
                        zipf.writestr(f"{section}.csv", csv_content)
            
            file_path = zip_path
        
        elif export_format == DataExportFormat.XML:
            xml_content = self._convert_to_xml(data)
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(xml_content)
        
        else:
            raise ValueError(f"Unsupported export format: {export_format}")
        
        # Get file size
        file_size = file_path.stat().st_size
        
        return file_path, file_size
    
    def _convert_to_csv(self, data: List[Dict[str, Any]]) -> str:
        """Convert list of dictionaries to CSV format."""
        import csv
        import io
        
        if not data:
            return ""
        
        output = io.StringIO()
        fieldnames = set()
        
        # Get all possible fieldnames
        for item in data:
            fieldnames.update(item.keys())
        
        fieldnames = sorted(fieldnames)
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)
        
        return output.getvalue()
    
    def _dict_to_csv(self, data: Dict[str, Any]) -> str:
        """Convert dictionary to CSV format."""
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
    
    def _convert_to_xml(self, data: Dict[str, Any]) -> str:
        """Convert data to XML format."""
        import xml.etree.ElementTree as ET
        
        root = ET.Element("user_data")
        
        def dict_to_xml(parent: ET.Element, data: Union[Dict, List, Any], name: str = "item"):
            if isinstance(data, dict):
                element = ET.SubElement(parent, name)
                for key, value in data.items():
                    dict_to_xml(element, value, key)
            elif isinstance(data, list):
                for item in data:
                    dict_to_xml(parent, item, name)
            else:
                element = ET.SubElement(parent, name)
                element.text = str(data)
        
        for key, value in data.items():
            dict_to_xml(root, value, key)
        
        # Format XML
        ET.indent(root, space="  ")
        return ET.tostring(root, encoding='unicode', xml_declaration=True)