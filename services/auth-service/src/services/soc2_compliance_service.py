"""
SOC2 Compliance Service implementing incident response, anomaly detection,
vendor access management, and change tracking.
"""
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import and_, or_, desc, func
import structlog
import asyncio
from dataclasses import dataclass
import statistics

from ..models.soc2_compliance import (
    SecurityIncident, SecurityAnomaly, VendorAccess, ChangeManagement, ComplianceControl,
    IncidentSeverity, IncidentStatus, IncidentCategory, AnomalyType, 
    VendorAccessLevel, ChangeType, ChangeStatus, TrustServiceCriteria
)
from ..models.audit import AuditLog, AuditEventType, AuditSeverity
from ..models.user import User
from ..core.config import settings

logger = structlog.get_logger()


@dataclass
class AnomalyDetectionResult:
    """Result of anomaly detection analysis."""
    is_anomaly: bool
    confidence_score: float
    risk_score: float
    description: str
    anomalous_behavior: Dict[str, Any]
    baseline_behavior: Optional[Dict[str, Any]] = None


class SOC2ComplianceService:
    """Service for SOC2 compliance operations."""
    
    def __init__(self):
        self.logger = structlog.get_logger("soc2_compliance")
        self.anomaly_detection_threshold = getattr(settings, 'SOC2_ANOMALY_DETECTION_THRESHOLD', 0.7)
        self.incident_sla_hours = getattr(settings, 'SOC2_INCIDENT_SLA_HOURS', 4)
        self.change_approval_required_risk_levels = getattr(settings, 'SOC2_CHANGE_APPROVAL_RISK_LEVELS', ['high', 'critical'])
    
    async def create_security_incident(
        self,
        db: AsyncSession,
        category: IncidentCategory,
        severity: IncidentSeverity,
        title: str,
        description: str,
        trust_criteria_affected: List[str],
        detected_at: Optional[datetime] = None,
        reported_by_user_id: Optional[int] = None,
        systems_affected: Optional[List[str]] = None,
        users_affected_count: Optional[int] = None,
        data_affected: bool = False,
        customer_impact: bool = False,
        **kwargs
    ) -> SecurityIncident:
        """
        Create a new security incident with automatic escalation rules.
        
        Args:
            db: Database session
            category: Incident category
            severity: Incident severity
            title: Incident title
            description: Detailed description
            trust_criteria_affected: List of SOC2 criteria affected
            Other parameters: Additional incident details
        
        Returns:
            SecurityIncident: Created security incident
        """
        try:
            # Create security incident
            incident = await SecurityIncident.create_incident(
                db=db,
                category=category,
                severity=severity,
                title=title,
                description=description,
                trust_criteria_affected=trust_criteria_affected,
                detected_at=detected_at,
                reported_by_user_id=reported_by_user_id,
                systems_affected=systems_affected or [],
                users_affected_count=users_affected_count,
                data_affected=data_affected,
                customer_impact=customer_impact,
                **kwargs
            )
            
            # Create corresponding audit log
            await AuditLog.create_audit_log(
                db=db,
                event_type=AuditEventType.SECURITY_ALERT,
                action="incident_created",
                description=f"Security incident created: {title}",
                user_id=reported_by_user_id,
                success=True,
                severity=self._map_incident_severity_to_audit(severity),
                event_data={
                    "incident_id": incident.incident_id,
                    "incident_number": incident.incident_number,
                    "category": category.value,
                    "severity": severity.value,
                    "trust_criteria_affected": trust_criteria_affected,
                    "systems_affected": systems_affected,
                    "data_affected": data_affected,
                    "customer_impact": customer_impact
                }
            )
            
            # Auto-escalate critical incidents
            if severity == IncidentSeverity.CRITICAL:
                await self._auto_escalate_incident(db, incident)
            
            # Check if external reporting is required
            if data_affected or customer_impact or severity == IncidentSeverity.CRITICAL:
                incident.external_reporting_required = True
                await incident.save(db)
            
            self.logger.info(
                "Security incident created",
                incident_id=incident.incident_id,
                incident_number=incident.incident_number,
                category=category.value,
                severity=severity.value,
                title=title
            )
            
            return incident
            
        except Exception as e:
            self.logger.error(
                "Failed to create security incident",
                error=str(e),
                category=category.value,
                severity=severity.value,
                title=title
            )
            raise
    
    async def detect_security_anomalies(
        self,
        db: AsyncSession,
        user_id: Optional[int] = None,
        session_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        event_data: Optional[Dict[str, Any]] = None
    ) -> List[AnomalyDetectionResult]:
        """
        Detect security anomalies based on user behavior patterns.
        
        Args:
            db: Database session
            user_id: User ID to analyze
            session_id: Session ID
            ip_address: IP address
            event_data: Additional event data for analysis
        
        Returns:
            List[AnomalyDetectionResult]: Detected anomalies
        """
        try:
            anomalies = []
            
            if user_id:
                # Check for login anomalies
                login_anomaly = await self._detect_login_anomalies(db, user_id, ip_address)
                if login_anomaly:
                    anomalies.append(login_anomaly)
                
                # Check for access pattern anomalies
                access_anomaly = await self._detect_access_pattern_anomalies(db, user_id, event_data)
                if access_anomaly:
                    anomalies.append(access_anomaly)
                
                # Check for time pattern anomalies
                time_anomaly = await self._detect_time_pattern_anomalies(db, user_id)
                if time_anomaly:
                    anomalies.append(time_anomaly)
            
            if ip_address:
                # Check for location anomalies
                location_anomaly = await self._detect_location_anomalies(db, ip_address, user_id)
                if location_anomaly:
                    anomalies.append(location_anomaly)
            
            # Create anomaly records for detected anomalies
            for anomaly_result in anomalies:
                if anomaly_result.confidence_score >= self.anomaly_detection_threshold:
                    await self._create_security_anomaly(
                        db=db,
                        anomaly_result=anomaly_result,
                        user_id=user_id,
                        session_id=session_id,
                        ip_address=ip_address
                    )
            
            return anomalies
            
        except Exception as e:
            self.logger.error(
                "Failed to detect security anomalies",
                error=str(e),
                user_id=user_id,
                session_id=session_id
            )
            return []
    
    async def create_vendor_access_request(
        self,
        db: AsyncSession,
        vendor_name: str,
        vendor_contact_email: str,
        access_level: VendorAccessLevel,
        systems_accessed: List[str],
        access_purpose: str,
        business_justification: str,
        access_start_date: datetime,
        access_end_date: datetime,
        requested_by_user_id: int,
        **kwargs
    ) -> VendorAccess:
        """
        Create a new vendor access request with approval workflow.
        
        Args:
            db: Database session
            vendor_name: Name of vendor
            vendor_contact_email: Vendor contact email
            access_level: Level of access requested
            systems_accessed: List of systems to access
            access_purpose: Purpose of access
            business_justification: Business justification
            access_start_date: Start date for access
            access_end_date: End date for access
            requested_by_user_id: ID of requesting user
        
        Returns:
            VendorAccess: Created vendor access request
        """
        try:
            # Validate access duration
            access_duration = access_end_date - access_start_date
            if access_duration.days > 90:  # Maximum 90 days
                raise ValueError("Vendor access duration cannot exceed 90 days")
            
            # Create vendor access request
            vendor_access = await VendorAccess.create_vendor_access(
                db=db,
                vendor_name=vendor_name,
                vendor_contact_email=vendor_contact_email,
                access_level=access_level,
                systems_accessed=systems_accessed,
                access_purpose=access_purpose,
                business_justification=business_justification,
                access_start_date=access_start_date,
                access_end_date=access_end_date,
                requested_by_user_id=requested_by_user_id,
                **kwargs
            )
            
            # Create audit log
            await AuditLog.create_audit_log(
                db=db,
                event_type=AuditEventType.PERMISSION_GRANTED,
                action="vendor_access_requested",
                description=f"Vendor access requested for {vendor_name}",
                user_id=requested_by_user_id,
                success=True,
                severity=AuditSeverity.MEDIUM,
                event_data={
                    "access_id": vendor_access.access_id,
                    "vendor_name": vendor_name,
                    "access_level": access_level.value,
                    "systems_accessed": systems_accessed,
                    "access_duration_days": access_duration.days
                }
            )
            
            self.logger.info(
                "Vendor access request created",
                access_id=vendor_access.access_id,
                vendor_name=vendor_name,
                access_level=access_level.value,
                requested_by_user_id=requested_by_user_id
            )
            
            return vendor_access
            
        except Exception as e:
            self.logger.error(
                "Failed to create vendor access request",
                error=str(e),
                vendor_name=vendor_name,
                access_level=access_level.value
            )
            raise
    
    async def create_change_request(
        self,
        db: AsyncSession,
        change_type: ChangeType,
        title: str,
        description: str,
        business_justification: str,
        systems_affected: List[str],
        trust_criteria_impact: List[str],
        requested_implementation_date: datetime,
        implementation_steps: List[str],
        rollback_plan: str,
        requested_by_user_id: int,
        risk_level: str = "medium",
        **kwargs
    ) -> ChangeManagement:
        """
        Create a new change request with automatic approval routing.
        
        Args:
            db: Database session
            change_type: Type of change
            title: Change title
            description: Detailed description
            business_justification: Business justification
            systems_affected: List of affected systems
            trust_criteria_impact: SOC2 criteria impacted
            requested_implementation_date: Requested implementation date
            implementation_steps: List of implementation steps
            rollback_plan: Rollback plan
            requested_by_user_id: ID of requesting user
            risk_level: Risk level assessment
        
        Returns:
            ChangeManagement: Created change request
        """
        try:
            # Validate implementation date
            if requested_implementation_date <= datetime.utcnow():
                raise ValueError("Implementation date must be in the future")
            
            # Determine if approval is required
            approval_required = (
                risk_level in self.change_approval_required_risk_levels or
                change_type in [ChangeType.EMERGENCY, ChangeType.SECURITY_POLICY] or
                len(systems_affected) > 1
            )
            
            # Create change request
            change_request = await ChangeManagement.create_change_request(
                db=db,
                change_type=change_type,
                title=title,
                description=description,
                business_justification=business_justification,
                systems_affected=systems_affected,
                trust_criteria_impact=trust_criteria_impact,
                requested_implementation_date=requested_implementation_date,
                implementation_steps=implementation_steps,
                rollback_plan=rollback_plan,
                requested_by_user_id=requested_by_user_id,
                risk_level=risk_level,
                approval_required=approval_required,
                **kwargs
            )
            
            # Create audit log
            await AuditLog.create_audit_log(
                db=db,
                event_type=AuditEventType.CONFIG_CHANGE,
                action="change_request_created",
                description=f"Change request created: {title}",
                user_id=requested_by_user_id,
                success=True,
                severity=self._map_risk_level_to_audit_severity(risk_level),
                event_data={
                    "change_id": change_request.change_id,
                    "change_number": change_request.change_number,
                    "change_type": change_type.value,
                    "risk_level": risk_level,
                    "systems_affected": systems_affected,
                    "trust_criteria_impact": trust_criteria_impact,
                    "approval_required": approval_required
                }
            )
            
            # Auto-approve standard changes if low risk
            if change_type == ChangeType.STANDARD and risk_level == "low":
                await change_request.approve_change(db, requested_by_user_id)
                self.logger.info(
                    "Standard low-risk change auto-approved",
                    change_id=change_request.change_id,
                    change_number=change_request.change_number
                )
            
            self.logger.info(
                "Change request created",
                change_id=change_request.change_id,
                change_number=change_request.change_number,
                change_type=change_type.value,
                risk_level=risk_level,
                title=title
            )
            
            return change_request
            
        except Exception as e:
            self.logger.error(
                "Failed to create change request",
                error=str(e),
                change_type=change_type.value,
                title=title
            )
            raise
    
    async def monitor_compliance_controls(
        self,
        db: AsyncSession
    ) -> Dict[str, Any]:
        """
        Monitor SOC2 compliance controls effectiveness and testing status.
        
        Args:
            db: Database session
        
        Returns:
            Dict: Compliance control monitoring report
        """
        try:
            # Get controls due for testing
            controls_due = await ComplianceControl.get_controls_due_for_testing(db, days_ahead=7)
            overdue_controls = await ComplianceControl.get_controls_due_for_testing(db, days_ahead=-1)
            
            # Get control effectiveness statistics
            total_controls_query = select(func.count(ComplianceControl.id)).where(
                ComplianceControl.is_implemented == True
            )
            total_controls_result = await db.execute(total_controls_query)
            total_controls = total_controls_result.scalar()
            
            effective_controls_query = select(func.count(ComplianceControl.id)).where(
                ComplianceControl.is_implemented == True,
                ComplianceControl.is_effective == True
            )
            effective_controls_result = await db.execute(effective_controls_query)
            effective_controls = effective_controls_result.scalar()
            
            deficient_controls_query = select(func.count(ComplianceControl.id)).where(
                ComplianceControl.is_implemented == True,
                ComplianceControl.deficiency_identified == True
            )
            deficient_controls_result = await db.execute(deficient_controls_query)
            deficient_controls = deficient_controls_result.scalar()
            
            # Calculate effectiveness percentage
            effectiveness_percentage = (
                (effective_controls / total_controls * 100) if total_controls > 0 else 0
            )
            
            # Get controls by trust criteria
            controls_by_criteria = {}
            for criteria in TrustServiceCriteria:
                criteria_query = select(func.count(ComplianceControl.id)).where(
                    ComplianceControl.trust_criteria == criteria,
                    ComplianceControl.is_implemented == True
                )
                criteria_result = await db.execute(criteria_query)
                controls_by_criteria[criteria.value] = criteria_result.scalar()
            
            report = {
                "total_controls": total_controls,
                "effective_controls": effective_controls,
                "deficient_controls": deficient_controls,
                "effectiveness_percentage": effectiveness_percentage,
                "controls_due_for_testing": len(controls_due),
                "overdue_controls": len(overdue_controls),
                "controls_by_criteria": controls_by_criteria,
                "due_controls_details": [
                    {
                        "control_id": control.control_id,
                        "control_number": control.control_number,
                        "control_title": control.control_title,
                        "next_test_due": control.next_test_due_date,
                        "trust_criteria": control.trust_criteria.value
                    }
                    for control in controls_due[:10]  # Top 10 due controls
                ]
            }
            
            self.logger.info(
                "Compliance controls monitoring completed",
                total_controls=total_controls,
                effectiveness_percentage=effectiveness_percentage,
                controls_due=len(controls_due),
                overdue_controls=len(overdue_controls)
            )
            
            return report
            
        except Exception as e:
            self.logger.error(
                "Failed to monitor compliance controls",
                error=str(e)
            )
            raise
    
    async def generate_soc2_compliance_report(
        self,
        db: AsyncSession,
        start_date: datetime,
        end_date: datetime,
        trust_criteria: Optional[List[TrustServiceCriteria]] = None
    ) -> Dict[str, Any]:
        """
        Generate comprehensive SOC2 compliance report.
        
        Args:
            db: Database session
            start_date: Report start date
            end_date: Report end date
            trust_criteria: Optional filter by trust criteria
        
        Returns:
            Dict: Comprehensive compliance report
        """
        try:
            # Get incident statistics
            incident_stats = await self._get_incident_statistics(db, start_date, end_date)
            
            # Get anomaly detection statistics
            anomaly_stats = await self._get_anomaly_statistics(db, start_date, end_date)
            
            # Get vendor access statistics
            vendor_stats = await self._get_vendor_access_statistics(db, start_date, end_date)
            
            # Get change management statistics
            change_stats = await self._get_change_management_statistics(db, start_date, end_date)
            
            # Get control effectiveness
            control_effectiveness = await self.monitor_compliance_controls(db)
            
            # Get audit trail statistics
            audit_stats = await self._get_audit_trail_statistics(db, start_date, end_date)
            
            report = {
                "report_period": {
                    "start_date": start_date.isoformat(),
                    "end_date": end_date.isoformat()
                },
                "incident_management": incident_stats,
                "anomaly_detection": anomaly_stats,
                "vendor_access_management": vendor_stats,
                "change_management": change_stats,
                "control_effectiveness": control_effectiveness,
                "audit_trail": audit_stats,
                "generated_at": datetime.utcnow().isoformat(),
                "compliance_score": self._calculate_compliance_score(
                    incident_stats, anomaly_stats, vendor_stats, 
                    change_stats, control_effectiveness
                )
            }
            
            self.logger.info(
                "SOC2 compliance report generated",
                start_date=start_date.isoformat(),
                end_date=end_date.isoformat(),
                compliance_score=report["compliance_score"]
            )
            
            return report
            
        except Exception as e:
            self.logger.error(
                "Failed to generate SOC2 compliance report",
                error=str(e),
                start_date=start_date.isoformat(),
                end_date=end_date.isoformat()
            )
            raise
    
    # Private helper methods
    
    async def _detect_login_anomalies(
        self, 
        db: AsyncSession, 
        user_id: int, 
        ip_address: Optional[str]
    ) -> Optional[AnomalyDetectionResult]:
        """Detect login-related anomalies."""
        try:
            # Get recent login history
            login_query = select(AuditLog).where(
                AuditLog.user_id == user_id,
                AuditLog.event_type == AuditEventType.LOGIN_SUCCESS,
                AuditLog.timestamp >= datetime.utcnow() - timedelta(days=30)
            ).order_by(desc(AuditLog.timestamp)).limit(50)
            
            result = await db.execute(login_query)
            recent_logins = result.scalars().all()
            
            if len(recent_logins) < 5:  # Not enough data
                return None
            
            # Analyze IP address patterns
            ip_addresses = [login.ip_address for login in recent_logins if login.ip_address]
            unique_ips = set(ip_addresses)
            
            # Check for new IP address
            if ip_address and ip_address not in unique_ips and len(unique_ips) > 0:
                confidence_score = 0.8
                risk_score = 7.0
                
                return AnomalyDetectionResult(
                    is_anomaly=True,
                    confidence_score=confidence_score,
                    risk_score=risk_score,
                    description=f"Login from new IP address: {ip_address}",
                    anomalous_behavior={"new_ip_address": ip_address},
                    baseline_behavior={"known_ip_addresses": list(unique_ips)}
                )
            
            return None
            
        except Exception as e:
            self.logger.error("Failed to detect login anomalies", error=str(e), user_id=user_id)
            return None
    
    async def _detect_access_pattern_anomalies(
        self, 
        db: AsyncSession, 
        user_id: int, 
        event_data: Optional[Dict[str, Any]]
    ) -> Optional[AnomalyDetectionResult]:
        """Detect access pattern anomalies."""
        try:
            # Get recent access patterns
            access_query = select(AuditLog).where(
                AuditLog.user_id == user_id,
                AuditLog.event_type.in_([
                    AuditEventType.DATA_READ,
                    AuditEventType.DATA_CREATE,
                    AuditEventType.DATA_UPDATE,
                    AuditEventType.DATA_DELETE
                ]),
                AuditLog.timestamp >= datetime.utcnow() - timedelta(days=7)
            ).order_by(desc(AuditLog.timestamp)).limit(100)
            
            result = await db.execute(access_query)
            recent_accesses = result.scalars().all()
            
            if len(recent_accesses) < 10:  # Not enough data
                return None
            
            # Analyze access volume
            daily_access_counts = {}
            for access in recent_accesses:
                date_key = access.timestamp.date()
                daily_access_counts[date_key] = daily_access_counts.get(date_key, 0) + 1
            
            if len(daily_access_counts) < 3:
                return None
            
            # Calculate baseline (average daily access)
            baseline_avg = statistics.mean(daily_access_counts.values())
            baseline_std = statistics.stdev(daily_access_counts.values()) if len(daily_access_counts) > 1 else 0
            
            # Check today's access count
            today = datetime.utcnow().date()
            today_count = daily_access_counts.get(today, 0)
            
            # Anomaly if today's count is more than 2 standard deviations above average
            threshold = baseline_avg + (2 * baseline_std)
            if today_count > threshold and baseline_std > 0:
                confidence_score = min(0.9, (today_count - baseline_avg) / (3 * baseline_std))
                risk_score = min(10.0, 5.0 + (today_count - threshold))
                
                return AnomalyDetectionResult(
                    is_anomaly=True,
                    confidence_score=confidence_score,
                    risk_score=risk_score,
                    description=f"Unusual access volume: {today_count} accesses (baseline: {baseline_avg:.1f})",
                    anomalous_behavior={"daily_access_count": today_count},
                    baseline_behavior={"average_daily_access": baseline_avg, "std_deviation": baseline_std}
                )
            
            return None
            
        except Exception as e:
            self.logger.error("Failed to detect access pattern anomalies", error=str(e), user_id=user_id)
            return None
    
    async def _detect_time_pattern_anomalies(
        self, 
        db: AsyncSession, 
        user_id: int
    ) -> Optional[AnomalyDetectionResult]:
        """Detect time-based access pattern anomalies."""
        try:
            current_hour = datetime.utcnow().hour
            
            # Get recent access times
            access_query = select(AuditLog).where(
                AuditLog.user_id == user_id,
                AuditLog.timestamp >= datetime.utcnow() - timedelta(days=14)
            ).order_by(desc(AuditLog.timestamp)).limit(200)
            
            result = await db.execute(access_query)
            recent_accesses = result.scalars().all()
            
            if len(recent_accesses) < 20:  # Not enough data
                return None
            
            # Analyze hourly access patterns
            hourly_counts = {}
            for access in recent_accesses:
                hour = access.timestamp.hour
                hourly_counts[hour] = hourly_counts.get(hour, 0) + 1
            
            # Check if current hour is unusual (less than 5% of historical access)
            total_accesses = sum(hourly_counts.values())
            current_hour_percentage = (hourly_counts.get(current_hour, 0) / total_accesses) * 100
            
            if current_hour_percentage < 5 and hourly_counts.get(current_hour, 0) == 0:
                # Accessing during unusual hours
                confidence_score = 0.7
                risk_score = 6.0
                
                return AnomalyDetectionResult(
                    is_anomaly=True,
                    confidence_score=confidence_score,
                    risk_score=risk_score,
                    description=f"Access during unusual hours: {current_hour}:00",
                    anomalous_behavior={"access_hour": current_hour},
                    baseline_behavior={"hourly_access_pattern": hourly_counts}
                )
            
            return None
            
        except Exception as e:
            self.logger.error("Failed to detect time pattern anomalies", error=str(e), user_id=user_id)
            return None
    
    async def _detect_location_anomalies(
        self, 
        db: AsyncSession, 
        ip_address: str, 
        user_id: Optional[int]
    ) -> Optional[AnomalyDetectionResult]:
        """Detect location-based anomalies (simplified IP-based detection)."""
        try:
            if not user_id:
                return None
            
            # Get recent IP addresses for user
            ip_query = select(AuditLog.ip_address).where(
                AuditLog.user_id == user_id,
                AuditLog.ip_address.isnot(None),
                AuditLog.timestamp >= datetime.utcnow() - timedelta(days=30)
            ).distinct().limit(20)
            
            result = await db.execute(ip_query)
            recent_ips = [row[0] for row in result.fetchall()]
            
            if len(recent_ips) < 2:  # Not enough data
                return None
            
            # Simple check: if IP is completely new
            if ip_address not in recent_ips:
                confidence_score = 0.6
                risk_score = 5.0
                
                return AnomalyDetectionResult(
                    is_anomaly=True,
                    confidence_score=confidence_score,
                    risk_score=risk_score,
                    description=f"Access from new location/IP: {ip_address}",
                    anomalous_behavior={"new_ip_address": ip_address},
                    baseline_behavior={"known_ip_addresses": recent_ips}
                )
            
            return None
            
        except Exception as e:
            self.logger.error("Failed to detect location anomalies", error=str(e), ip_address=ip_address)
            return None
    
    async def _create_security_anomaly(
        self,
        db: AsyncSession,
        anomaly_result: AnomalyDetectionResult,
        user_id: Optional[int] = None,
        session_id: Optional[str] = None,
        ip_address: Optional[str] = None
    ) -> SecurityAnomaly:
        """Create a security anomaly record."""
        anomaly_type = self._determine_anomaly_type(anomaly_result.description)
        
        return await SecurityAnomaly.create_anomaly(
            db=db,
            anomaly_type=anomaly_type,
            description=anomaly_result.description,
            anomalous_behavior=anomaly_result.anomalous_behavior,
            confidence_score=anomaly_result.confidence_score,
            risk_score=anomaly_result.risk_score,
            potential_impact=self._assess_potential_impact(anomaly_result.risk_score),
            detection_source="soc2_compliance_service",
            user_id=user_id,
            session_id=session_id,
            ip_address=ip_address,
            baseline_behavior=anomaly_result.baseline_behavior
        )
    
    def _determine_anomaly_type(self, description: str) -> AnomalyType:
        """Determine anomaly type based on description."""
        description_lower = description.lower()
        
        if "login" in description_lower or "ip" in description_lower:
            return AnomalyType.LOGIN_ANOMALY
        elif "access" in description_lower and "volume" in description_lower:
            return AnomalyType.ACCESS_PATTERN
        elif "time" in description_lower or "hour" in description_lower:
            return AnomalyType.TIME_PATTERN
        elif "location" in description_lower:
            return AnomalyType.LOCATION_ANOMALY
        else:
            return AnomalyType.SYSTEM_BEHAVIOR
    
    def _assess_potential_impact(self, risk_score: float) -> str:
        """Assess potential impact based on risk score."""
        if risk_score >= 8.0:
            return "High - Potential security breach or unauthorized access"
        elif risk_score >= 6.0:
            return "Medium - Unusual behavior requiring investigation"
        elif risk_score >= 4.0:
            return "Low - Minor deviation from normal patterns"
        else:
            return "Minimal - Slight variation in behavior"
    
    async def _auto_escalate_incident(self, db: AsyncSession, incident: SecurityIncident) -> None:
        """Auto-escalate critical incidents."""
        incident.status = IncidentStatus.ESCALATED
        await incident.save(db)
        
        self.logger.info(
            "Critical incident auto-escalated",
            incident_id=incident.incident_id,
            incident_number=incident.incident_number
        )
    
    def _map_incident_severity_to_audit(self, severity: IncidentSeverity) -> AuditSeverity:
        """Map incident severity to audit severity."""
        mapping = {
            IncidentSeverity.LOW: AuditSeverity.LOW,
            IncidentSeverity.MEDIUM: AuditSeverity.MEDIUM,
            IncidentSeverity.HIGH: AuditSeverity.HIGH,
            IncidentSeverity.CRITICAL: AuditSeverity.CRITICAL
        }
        return mapping.get(severity, AuditSeverity.MEDIUM)
    
    def _map_risk_level_to_audit_severity(self, risk_level: str) -> AuditSeverity:
        """Map risk level to audit severity."""
        mapping = {
            "low": AuditSeverity.LOW,
            "medium": AuditSeverity.MEDIUM,
            "high": AuditSeverity.HIGH,
            "critical": AuditSeverity.CRITICAL
        }
        return mapping.get(risk_level.lower(), AuditSeverity.MEDIUM)
    
    async def _get_incident_statistics(
        self, 
        db: AsyncSession, 
        start_date: datetime, 
        end_date: datetime
    ) -> Dict[str, Any]:
        """Get incident management statistics."""
        # Total incidents
        total_query = select(func.count(SecurityIncident.id)).where(
            SecurityIncident.detected_at.between(start_date, end_date)
        )
        total_result = await db.execute(total_query)
        total_incidents = total_result.scalar()
        
        # Incidents by severity
        severity_stats = {}
        for severity in IncidentSeverity:
            severity_query = select(func.count(SecurityIncident.id)).where(
                SecurityIncident.detected_at.between(start_date, end_date),
                SecurityIncident.severity == severity
            )
            severity_result = await db.execute(severity_query)
            severity_stats[severity.value] = severity_result.scalar()
        
        # Average resolution time
        resolved_query = select(SecurityIncident).where(
            SecurityIncident.detected_at.between(start_date, end_date),
            SecurityIncident.resolved_at.isnot(None)
        )
        resolved_result = await db.execute(resolved_query)
        resolved_incidents = resolved_result.scalars().all()
        
        avg_resolution_hours = 0
        if resolved_incidents:
            resolution_times = [
                (incident.resolved_at - incident.detected_at).total_seconds() / 3600
                for incident in resolved_incidents
            ]
            avg_resolution_hours = statistics.mean(resolution_times)
        
        return {
            "total_incidents": total_incidents,
            "incidents_by_severity": severity_stats,
            "resolved_incidents": len(resolved_incidents),
            "average_resolution_hours": avg_resolution_hours,
            "sla_compliance": (avg_resolution_hours <= self.incident_sla_hours) if avg_resolution_hours > 0 else True
        }
    
    async def _get_anomaly_statistics(
        self, 
        db: AsyncSession, 
        start_date: datetime, 
        end_date: datetime
    ) -> Dict[str, Any]:
        """Get anomaly detection statistics."""
        total_query = select(func.count(SecurityAnomaly.id)).where(
            SecurityAnomaly.detected_at.between(start_date, end_date)
        )
        total_result = await db.execute(total_query)
        total_anomalies = total_result.scalar()
        
        # High-risk anomalies
        high_risk_query = select(func.count(SecurityAnomaly.id)).where(
            SecurityAnomaly.detected_at.between(start_date, end_date),
            SecurityAnomaly.risk_score >= 7.0
        )
        high_risk_result = await db.execute(high_risk_query)
        high_risk_anomalies = high_risk_result.scalar()
        
        # False positives
        false_positive_query = select(func.count(SecurityAnomaly.id)).where(
            SecurityAnomaly.detected_at.between(start_date, end_date),
            SecurityAnomaly.false_positive == True
        )
        false_positive_result = await db.execute(false_positive_query)
        false_positives = false_positive_result.scalar()
        
        return {
            "total_anomalies": total_anomalies,
            "high_risk_anomalies": high_risk_anomalies,
            "false_positives": false_positives,
            "accuracy_rate": ((total_anomalies - false_positives) / total_anomalies * 100) if total_anomalies > 0 else 100
        }
    
    async def _get_vendor_access_statistics(
        self, 
        db: AsyncSession, 
        start_date: datetime, 
        end_date: datetime
    ) -> Dict[str, Any]:
        """Get vendor access management statistics."""
        # Active vendor access
        active_query = select(func.count(VendorAccess.id)).where(
            VendorAccess.is_active == True,
            VendorAccess.access_start_date <= end_date,
            VendorAccess.access_end_date >= start_date
        )
        active_result = await db.execute(active_query)
        active_access = active_result.scalar()
        
        # Expired access not properly revoked
        expired_query = select(func.count(VendorAccess.id)).where(
            VendorAccess.access_end_date < datetime.utcnow(),
            VendorAccess.is_active == True,
            VendorAccess.is_revoked == False
        )
        expired_result = await db.execute(expired_query)
        expired_unrevoked = expired_result.scalar()
        
        return {
            "active_vendor_access": active_access,
            "expired_unrevoked_access": expired_unrevoked,
            "access_hygiene_score": ((active_access - expired_unrevoked) / active_access * 100) if active_access > 0 else 100
        }
    
    async def _get_change_management_statistics(
        self, 
        db: AsyncSession, 
        start_date: datetime, 
        end_date: datetime
    ) -> Dict[str, Any]:
        """Get change management statistics."""
        total_query = select(func.count(ChangeManagement.id)).where(
            ChangeManagement.created_at.between(start_date, end_date)
        )
        total_result = await db.execute(total_query)
        total_changes = total_result.scalar()
        
        # Successful changes
        successful_query = select(func.count(ChangeManagement.id)).where(
            ChangeManagement.created_at.between(start_date, end_date),
            ChangeManagement.implementation_successful == True
        )
        successful_result = await db.execute(successful_query)
        successful_changes = successful_result.scalar()
        
        return {
            "total_changes": total_changes,
            "successful_changes": successful_changes,
            "success_rate": (successful_changes / total_changes * 100) if total_changes > 0 else 100
        }
    
    async def _get_audit_trail_statistics(
        self, 
        db: AsyncSession, 
        start_date: datetime, 
        end_date: datetime
    ) -> Dict[str, Any]:
        """Get audit trail statistics."""
        total_query = select(func.count(AuditLog.id)).where(
            AuditLog.timestamp.between(start_date, end_date)
        )
        total_result = await db.execute(total_query)
        total_events = total_result.scalar()
        
        # Security events
        security_query = select(func.count(AuditLog.id)).where(
            AuditLog.timestamp.between(start_date, end_date),
            AuditLog.event_type.in_([
                AuditEventType.SECURITY_ALERT,
                AuditEventType.SUSPICIOUS_ACTIVITY,
                AuditEventType.UNAUTHORIZED_ACCESS
            ])
        )
        security_result = await db.execute(security_query)
        security_events = security_result.scalar()
        
        return {
            "total_audit_events": total_events,
            "security_events": security_events,
            "audit_coverage": "Comprehensive" if total_events > 1000 else "Basic"
        }
    
    def _calculate_compliance_score(
        self, 
        incident_stats: Dict, 
        anomaly_stats: Dict, 
        vendor_stats: Dict,
        change_stats: Dict, 
        control_effectiveness: Dict
    ) -> float:
        """Calculate overall compliance score."""
        scores = []
        
        # Incident management score (0-100)
        if incident_stats.get("sla_compliance", True):
            scores.append(90)
        else:
            scores.append(70)
        
        # Anomaly detection score (0-100)
        accuracy_rate = anomaly_stats.get("accuracy_rate", 100)
        scores.append(min(100, accuracy_rate))
        
        # Vendor access score (0-100)
        access_hygiene = vendor_stats.get("access_hygiene_score", 100)
        scores.append(min(100, access_hygiene))
        
        # Change management score (0-100)
        change_success = change_stats.get("success_rate", 100)
        scores.append(min(100, change_success))
        
        # Control effectiveness score (0-100)
        control_effectiveness_pct = control_effectiveness.get("effectiveness_percentage", 100)
        scores.append(min(100, control_effectiveness_pct))
        
        # Calculate weighted average
        return statistics.mean(scores)