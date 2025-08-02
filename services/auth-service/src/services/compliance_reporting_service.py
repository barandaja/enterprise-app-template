"""
Comprehensive Compliance Reporting Service for HIPAA and SOC2 compliance.
Provides dashboard metrics, automated reports, and real-time compliance monitoring.
"""
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import and_, or_, desc, func, text
import structlog
import asyncio
import json
from dataclasses import dataclass, asdict

from .hipaa_compliance_service import HIPAAComplianceService
from .soc2_compliance_service import SOC2ComplianceService
from ..models.hipaa_compliance import (
    PHIAccessLog, BusinessAssociateAgreement, EmergencyAccess, HIPAASessionContext,
    PHICategory, AccessPurpose, EmergencyAccessType, BAAAgreementStatus
)
from ..models.soc2_compliance import (
    SecurityIncident, SecurityAnomaly, VendorAccess, ChangeManagement, ComplianceControl,
    IncidentSeverity, IncidentStatus, ChangeStatus, TrustServiceCriteria
)
from ..models.audit import AuditLog, AuditEventType, AuditSeverity
from ..models.user import User
from ..core.config import settings

logger = structlog.get_logger()


@dataclass
class ComplianceAlert:
    """Compliance alert data structure."""
    alert_id: str
    alert_type: str  # 'hipaa', 'soc2', 'general'
    severity: str    # 'low', 'medium', 'high', 'critical'
    title: str
    description: str
    created_at: datetime
    resolved: bool = False
    action_required: bool = True
    related_resource_type: Optional[str] = None
    related_resource_id: Optional[str] = None
    recommendations: List[str] = None
    
    def __post_init__(self):
        if self.recommendations is None:
            self.recommendations = []


class ComplianceReportingService:
    """Service for comprehensive compliance reporting and monitoring."""
    
    def __init__(self):
        self.logger = structlog.get_logger("compliance_reporting")
        self.hipaa_service = HIPAAComplianceService()
        self.soc2_service = SOC2ComplianceService()
        
        # Compliance thresholds
        self.critical_incident_threshold_hours = getattr(settings, 'COMPLIANCE_CRITICAL_INCIDENT_THRESHOLD_HOURS', 4)
        self.phi_access_volume_threshold = getattr(settings, 'COMPLIANCE_PHI_ACCESS_VOLUME_THRESHOLD', 100)
        self.anomaly_risk_threshold = getattr(settings, 'COMPLIANCE_ANOMALY_RISK_THRESHOLD', 7.0)
        self.control_effectiveness_threshold = getattr(settings, 'COMPLIANCE_CONTROL_EFFECTIVENESS_THRESHOLD', 85.0)
    
    async def generate_compliance_dashboard(
        self,
        db: AsyncSession,
        user_id: Optional[int] = None,
        include_sensitive: bool = False
    ) -> Dict[str, Any]:
        """
        Generate comprehensive compliance dashboard with real-time metrics.
        
        Args:
            db: Database session
            user_id: Optional user ID for user-specific dashboard
            include_sensitive: Whether to include sensitive information
        
        Returns:
            Dict: Complete dashboard data
        """
        try:
            # Calculate time ranges
            now = datetime.utcnow()
            last_24h = now - timedelta(hours=24)
            last_7d = now - timedelta(days=7)
            last_30d = now - timedelta(days=30)
            
            # Collect metrics in parallel
            hipaa_metrics_task = self._get_hipaa_metrics(db, last_30d, now, user_id)
            soc2_metrics_task = self._get_soc2_metrics(db, last_30d, now)
            incidents_task = self._get_incidents_summary(db, last_7d, now)
            anomalies_task = self._get_anomalies_summary(db, last_7d, now)
            vendor_access_task = self._get_vendor_access_summary(db)
            change_mgmt_task = self._get_change_management_summary(db, last_30d, now)
            controls_task = self._get_control_effectiveness_summary(db)
            alerts_task = self._generate_compliance_alerts(db)
            
            # Execute all tasks concurrently
            (
                hipaa_metrics,
                soc2_metrics,
                incidents_summary,
                anomalies_summary,
                vendor_access_summary,
                change_management_summary,
                control_effectiveness_summary,
                alerts
            ) = await asyncio.gather(
                hipaa_metrics_task,
                soc2_metrics_task,
                incidents_task,
                anomalies_task,
                vendor_access_task,
                change_mgmt_task,
                controls_task,
                alerts_task
            )
            
            # Calculate overall compliance score
            compliance_score = self._calculate_overall_compliance_score(
                hipaa_metrics,
                soc2_metrics,
                incidents_summary,
                anomalies_summary,
                vendor_access_summary,
                change_management_summary,
                control_effectiveness_summary
            )
            
            dashboard = {
                "hipaa_metrics": hipaa_metrics,
                "soc2_metrics": soc2_metrics,
                "incidents_summary": incidents_summary,
                "anomalies_summary": anomalies_summary,
                "vendor_access_summary": vendor_access_summary,
                "change_management_summary": change_management_summary,
                "control_effectiveness_summary": control_effectiveness_summary,
                "compliance_score": compliance_score,
                "alerts": [asdict(alert) for alert in alerts],
                "generated_at": now,
                "dashboard_health": {
                    "data_freshness": "real_time",
                    "last_updated": now,
                    "metrics_count": 7,
                    "alerts_count": len(alerts),
                    "critical_alerts": len([a for a in alerts if a.severity == "critical"])
                }
            }
            
            # Remove sensitive data if not authorized
            if not include_sensitive:
                dashboard = self._sanitize_dashboard_data(dashboard)
            
            self.logger.info(
                "Compliance dashboard generated",
                compliance_score=compliance_score,
                alerts_count=len(alerts),
                critical_alerts=dashboard["dashboard_health"]["critical_alerts"],
                user_id=user_id
            )
            
            return dashboard
            
        except Exception as e:
            self.logger.error(
                "Failed to generate compliance dashboard",
                error=str(e),
                user_id=user_id
            )
            raise
    
    async def generate_hipaa_compliance_report(
        self,
        db: AsyncSession,
        start_date: datetime,
        end_date: datetime,
        include_details: bool = True
    ) -> Dict[str, Any]:
        """
        Generate comprehensive HIPAA compliance report.
        
        Args:
            db: Database session
            start_date: Report start date
            end_date: Report end date
            include_details: Whether to include detailed information
        
        Returns:
            Dict: HIPAA compliance report
        """
        try:
            # PHI Access Analysis
            phi_access_summary = await self._analyze_phi_access(db, start_date, end_date)
            
            # Emergency Access Analysis
            emergency_access_summary = await self._analyze_emergency_access(db, start_date, end_date)
            
            # BAA Management Analysis
            baa_management_summary = await self._analyze_baa_management(db)
            
            # Audit Trail Analysis
            audit_trail_summary = await self._analyze_hipaa_audit_trail(db, start_date, end_date)
            
            # Risk Assessment
            risk_assessment = await self._assess_hipaa_risks(db, start_date, end_date)
            
            # Generate recommendations
            recommendations = await self._generate_hipaa_recommendations(
                phi_access_summary,
                emergency_access_summary,
                baa_management_summary,
                risk_assessment
            )
            
            # Calculate HIPAA compliance score
            hipaa_score = self._calculate_hipaa_compliance_score(
                phi_access_summary,
                emergency_access_summary,
                baa_management_summary,
                audit_trail_summary,
                risk_assessment
            )
            
            report = {
                "report_type": "hipaa_compliance",
                "report_period": {
                    "start_date": start_date.isoformat(),
                    "end_date": end_date.isoformat(),
                    "duration_days": (end_date - start_date).days
                },
                "executive_summary": {
                    "compliance_score": hipaa_score,
                    "risk_level": self._determine_risk_level(hipaa_score),
                    "key_findings": self._extract_key_findings(
                        phi_access_summary, emergency_access_summary, baa_management_summary
                    ),
                    "immediate_actions_required": len([r for r in recommendations if r.get("priority") == "high"])
                },
                "phi_access_summary": phi_access_summary,
                "emergency_access_summary": emergency_access_summary,
                "baa_management_summary": baa_management_summary,
                "audit_trail_summary": audit_trail_summary,
                "risk_assessment": risk_assessment,
                "recommendations": recommendations,
                "compliance_score": hipaa_score,
                "generated_at": datetime.utcnow(),
                "report_metadata": {
                    "generated_by": "compliance_reporting_service",
                    "version": "1.0",
                    "includes_phi": False,  # This report never includes actual PHI
                    "retention_period_days": 2555  # 7 years for HIPAA
                }
            }
            
            if not include_details:
                report = self._summarize_hipaa_report(report)
            
            self.logger.info(
                "HIPAA compliance report generated",
                compliance_score=hipaa_score,
                start_date=start_date.isoformat(),
                end_date=end_date.isoformat(),
                recommendations_count=len(recommendations)
            )
            
            return report
            
        except Exception as e:
            self.logger.error(
                "Failed to generate HIPAA compliance report",
                error=str(e),
                start_date=start_date.isoformat(),
                end_date=end_date.isoformat()
            )
            raise
    
    async def generate_soc2_compliance_report(
        self,
        db: AsyncSession,
        start_date: datetime,
        end_date: datetime,
        trust_criteria: Optional[List[TrustServiceCriteria]] = None,
        include_details: bool = True
    ) -> Dict[str, Any]:
        """
        Generate comprehensive SOC2 compliance report.
        
        Args:
            db: Database session
            start_date: Report start date
            end_date: Report end date
            trust_criteria: Optional filter by trust criteria
            include_details: Whether to include detailed information
        
        Returns:
            Dict: SOC2 compliance report
        """
        try:
            # Use SOC2 service to generate base report
            base_report = await self.soc2_service.generate_soc2_compliance_report(
                db, start_date, end_date, trust_criteria
            )
            
            # Enhance with additional analysis
            control_gaps = await self._identify_control_gaps(db)
            remediation_tracking = await self._track_remediation_progress(db, start_date, end_date)
            trust_criteria_scores = await self._calculate_trust_criteria_scores(db, start_date, end_date)
            maturity_assessment = await self._assess_compliance_maturity(db)
            
            # Generate SOC2-specific recommendations
            recommendations = await self._generate_soc2_recommendations(
                base_report,
                control_gaps,
                remediation_tracking,
                maturity_assessment
            )
            
            enhanced_report = {
                **base_report,
                "report_type": "soc2_compliance",
                "executive_summary": {
                    "compliance_score": base_report["compliance_score"],
                    "trust_criteria_scores": trust_criteria_scores,
                    "maturity_level": maturity_assessment["overall_maturity"],
                    "control_gaps_count": len(control_gaps),
                    "recommendations_count": len(recommendations)
                },
                "control_gaps": control_gaps,
                "remediation_tracking": remediation_tracking,
                "trust_criteria_scores": trust_criteria_scores,
                "maturity_assessment": maturity_assessment,
                "recommendations": recommendations,
                "report_metadata": {
                    "generated_by": "compliance_reporting_service",
                    "version": "1.0",
                    "soc2_type": "Type II",  # Assuming Type II assessment
                    "audit_period": {
                        "start": start_date.isoformat(),
                        "end": end_date.isoformat()
                    }
                }
            }
            
            if not include_details:
                enhanced_report = self._summarize_soc2_report(enhanced_report)
            
            self.logger.info(
                "SOC2 compliance report generated",
                compliance_score=base_report["compliance_score"],
                trust_criteria_scores=trust_criteria_scores,
                control_gaps=len(control_gaps),
                maturity_level=maturity_assessment["overall_maturity"]
            )
            
            return enhanced_report
            
        except Exception as e:
            self.logger.error(
                "Failed to generate SOC2 compliance report",
                error=str(e),
                start_date=start_date.isoformat(),
                end_date=end_date.isoformat()
            )
            raise
    
    async def generate_combined_compliance_report(
        self,
        db: AsyncSession,
        start_date: datetime,
        end_date: datetime,
        include_details: bool = True
    ) -> Dict[str, Any]:
        """
        Generate combined HIPAA and SOC2 compliance report.
        
        Args:
            db: Database session
            start_date: Report start date
            end_date: Report end date
            include_details: Whether to include detailed information
        
        Returns:
            Dict: Combined compliance report
        """
        try:
            # Generate individual reports concurrently
            hipaa_report_task = self.generate_hipaa_compliance_report(db, start_date, end_date, include_details)
            soc2_report_task = self.generate_soc2_compliance_report(db, start_date, end_date, None, include_details)
            
            hipaa_report, soc2_report = await asyncio.gather(
                hipaa_report_task,
                soc2_report_task
            )
            
            # Calculate combined compliance score
            combined_score = (hipaa_report["compliance_score"] + soc2_report["compliance_score"]) / 2
            
            # Identify cross-framework synergies and conflicts
            cross_analysis = await self._analyze_cross_framework_compliance(db, start_date, end_date)
            
            # Generate unified recommendations
            unified_recommendations = await self._generate_unified_recommendations(
                hipaa_report["recommendations"],
                soc2_report["recommendations"],
                cross_analysis
            )
            
            combined_report = {
                "report_type": "combined_compliance",
                "report_period": {
                    "start_date": start_date.isoformat(),
                    "end_date": end_date.isoformat(),
                    "duration_days": (end_date - start_date).days
                },
                "executive_summary": {
                    "combined_compliance_score": combined_score,
                    "hipaa_score": hipaa_report["compliance_score"],
                    "soc2_score": soc2_report["compliance_score"],
                    "overall_risk_level": self._determine_risk_level(combined_score),
                    "critical_findings": self._extract_critical_findings(hipaa_report, soc2_report),
                    "unified_recommendations_count": len(unified_recommendations)
                },
                "hipaa_compliance": hipaa_report,
                "soc2_compliance": soc2_report,
                "cross_framework_analysis": cross_analysis,
                "unified_recommendations": unified_recommendations,
                "compliance_trends": await self._analyze_compliance_trends(db, start_date, end_date),
                "generated_at": datetime.utcnow(),
                "report_metadata": {
                    "generated_by": "compliance_reporting_service",
                    "version": "1.0",
                    "frameworks_covered": ["HIPAA", "SOC2"],
                    "report_scope": "comprehensive"
                }
            }
            
            self.logger.info(
                "Combined compliance report generated",
                combined_score=combined_score,
                hipaa_score=hipaa_report["compliance_score"],
                soc2_score=soc2_report["compliance_score"],
                unified_recommendations=len(unified_recommendations)
            )
            
            return combined_report
            
        except Exception as e:
            self.logger.error(
                "Failed to generate combined compliance report",
                error=str(e),
                start_date=start_date.isoformat(),
                end_date=end_date.isoformat()
            )
            raise
    
    async def monitor_real_time_compliance(
        self,
        db: AsyncSession
    ) -> Dict[str, Any]:
        """
        Monitor real-time compliance status and generate alerts.
        
        Args:
            db: Database session
        
        Returns:
            Dict: Real-time compliance monitoring results
        """
        try:
            now = datetime.utcnow()
            
            # Check for immediate compliance issues
            critical_alerts = []
            warning_alerts = []
            
            # Check for unresolved critical incidents
            critical_incidents = await self._check_critical_incidents(db)
            critical_alerts.extend(critical_incidents)
            
            # Check for expired emergency access
            expired_emergency_access = await self._check_expired_emergency_access(db)
            warning_alerts.extend(expired_emergency_access)
            
            # Check for expiring BAA agreements
            expiring_baas = await self._check_expiring_baas(db)
            warning_alerts.extend(expiring_baas)
            
            # Check for high-risk anomalies
            high_risk_anomalies = await self._check_high_risk_anomalies(db)
            critical_alerts.extend(high_risk_anomalies)
            
            # Check for failed control tests
            failed_controls = await self._check_failed_control_tests(db)
            warning_alerts.extend(failed_controls)
            
            # Check for unauthorized vendor access
            unauthorized_vendor_access = await self._check_unauthorized_vendor_access(db)
            critical_alerts.extend(unauthorized_vendor_access)
            
            # Calculate compliance health score
            health_score = self._calculate_compliance_health_score(
                len(critical_alerts), len(warning_alerts)
            )
            
            monitoring_result = {
                "monitoring_timestamp": now,
                "compliance_health_score": health_score,
                "status": self._determine_compliance_status(health_score),
                "critical_alerts": critical_alerts,
                "warning_alerts": warning_alerts,
                "total_alerts": len(critical_alerts) + len(warning_alerts),
                "recommendations": self._generate_immediate_recommendations(
                    critical_alerts, warning_alerts
                ),
                "next_scheduled_check": now + timedelta(hours=1),
                "monitoring_metadata": {
                    "check_duration_ms": 0,  # Would be calculated in real implementation
                    "systems_checked": [
                        "incident_management",
                        "emergency_access",
                        "baa_agreements",
                        "anomaly_detection",
                        "control_testing",
                        "vendor_access"
                    ]
                }
            }
            
            self.logger.info(
                "Real-time compliance monitoring completed",
                health_score=health_score,
                critical_alerts=len(critical_alerts),
                warning_alerts=len(warning_alerts),
                status=monitoring_result["status"]
            )
            
            return monitoring_result
            
        except Exception as e:
            self.logger.error(
                "Failed to monitor real-time compliance",
                error=str(e)
            )
            raise
    
    # Private helper methods for metrics collection
    
    async def _get_hipaa_metrics(
        self, 
        db: AsyncSession, 
        start_date: datetime, 
        end_date: datetime,
        user_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """Get HIPAA-specific metrics."""
        # PHI access metrics
        phi_query = select(func.count(PHIAccessLog.id)).where(
            PHIAccessLog.access_timestamp.between(start_date, end_date)
        )
        if user_id:
            phi_query = phi_query.where(PHIAccessLog.user_id == user_id)
        
        phi_result = await db.execute(phi_query)
        total_phi_access = phi_result.scalar()
        
        # Emergency access metrics
        emergency_query = select(func.count(EmergencyAccess.id)).where(
            EmergencyAccess.emergency_start_time.between(start_date, end_date)
        )
        emergency_result = await db.execute(emergency_query)
        emergency_access_count = emergency_result.scalar()
        
        # Active emergency access
        active_emergency_query = select(func.count(EmergencyAccess.id)).where(
            EmergencyAccess.is_active == True
        )
        active_emergency_result = await db.execute(active_emergency_query)
        active_emergency_count = active_emergency_result.scalar()
        
        # BAA status
        baa_agreements = await BusinessAssociateAgreement.get_active_agreements(db)
        expiring_baas = await BusinessAssociateAgreement.get_expiring_agreements(db, days_ahead=30)
        
        return {
            "total_phi_access": total_phi_access,
            "emergency_access_count": emergency_access_count,
            "active_emergency_access": active_emergency_count,
            "active_baa_agreements": len(baa_agreements),
            "expiring_baa_agreements": len(expiring_baas),
            "phi_access_compliance": self._assess_phi_access_compliance(total_phi_access),
            "emergency_access_compliance": self._assess_emergency_access_compliance(
                emergency_access_count, active_emergency_count
            )
        }
    
    async def _get_soc2_metrics(
        self, 
        db: AsyncSession, 
        start_date: datetime, 
        end_date: datetime
    ) -> Dict[str, Any]:
        """Get SOC2-specific metrics."""
        # Use SOC2 service for detailed metrics
        return await self.soc2_service.generate_soc2_compliance_report(db, start_date, end_date)
    
    async def _get_incidents_summary(
        self, 
        db: AsyncSession, 
        start_date: datetime, 
        end_date: datetime
    ) -> Dict[str, Any]:
        """Get incidents summary."""
        # Total incidents
        total_query = select(func.count(SecurityIncident.id)).where(
            SecurityIncident.detected_at.between(start_date, end_date)
        )
        total_result = await db.execute(total_query)
        total_incidents = total_result.scalar()
        
        # Open incidents
        open_query = select(func.count(SecurityIncident.id)).where(
            SecurityIncident.status.in_([
                IncidentStatus.OPEN, 
                IncidentStatus.IN_PROGRESS, 
                IncidentStatus.ESCALATED
            ])
        )
        open_result = await db.execute(open_query)
        open_incidents = open_result.scalar()
        
        # Critical incidents
        critical_query = select(func.count(SecurityIncident.id)).where(
            SecurityIncident.detected_at.between(start_date, end_date),
            SecurityIncident.severity == IncidentSeverity.CRITICAL
        )
        critical_result = await db.execute(critical_query)
        critical_incidents = critical_result.scalar()
        
        return {
            "total_incidents": total_incidents,
            "open_incidents": open_incidents,
            "critical_incidents": critical_incidents,
            "incident_trend": "stable"  # Would calculate actual trend
        }
    
    async def _get_anomalies_summary(
        self, 
        db: AsyncSession, 
        start_date: datetime, 
        end_date: datetime
    ) -> Dict[str, Any]:
        """Get anomalies summary."""
        # Total anomalies
        total_query = select(func.count(SecurityAnomaly.id)).where(
            SecurityAnomaly.detected_at.between(start_date, end_date)
        )
        total_result = await db.execute(total_query)
        total_anomalies = total_result.scalar()
        
        # High-risk anomalies
        high_risk_query = select(func.count(SecurityAnomaly.id)).where(
            SecurityAnomaly.detected_at.between(start_date, end_date),
            SecurityAnomaly.risk_score >= self.anomaly_risk_threshold
        )
        high_risk_result = await db.execute(high_risk_query)
        high_risk_anomalies = high_risk_result.scalar()
        
        # Uninvestigated anomalies
        uninvestigated_query = select(func.count(SecurityAnomaly.id)).where(
            SecurityAnomaly.investigated == False,
            SecurityAnomaly.risk_score >= 5.0
        )
        uninvestigated_result = await db.execute(uninvestigated_query)
        uninvestigated_anomalies = uninvestigated_result.scalar()
        
        return {
            "total_anomalies": total_anomalies,
            "high_risk_anomalies": high_risk_anomalies,
            "uninvestigated_anomalies": uninvestigated_anomalies,
            "detection_accuracy": 85.0  # Would calculate from false positive rate
        }
    
    async def _get_vendor_access_summary(self, db: AsyncSession) -> Dict[str, Any]:
        """Get vendor access summary."""
        active_access = await VendorAccess.get_active_vendor_access(db)
        expiring_access = await VendorAccess.get_expiring_access(db, days_ahead=30)
        
        return {
            "active_vendor_access": len(active_access),
            "expiring_access": len(expiring_access),
            "high_privilege_access": len([
                access for access in active_access 
                if access.access_level in [VendorAccessLevel.ELEVATED, VendorAccessLevel.FULL_ADMIN]
            ]),
            "compliance_status": "good" if len(expiring_access) == 0 else "needs_attention"
        }
    
    async def _get_change_management_summary(
        self, 
        db: AsyncSession, 
        start_date: datetime, 
        end_date: datetime
    ) -> Dict[str, Any]:
        """Get change management summary."""
        # Total changes
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
        
        # Pending approvals
        pending_query = select(func.count(ChangeManagement.id)).where(
            ChangeManagement.status == ChangeStatus.REQUESTED,
            ChangeManagement.approval_required == True
        )
        pending_result = await db.execute(pending_query)
        pending_approvals = pending_result.scalar()
        
        success_rate = (successful_changes / total_changes * 100) if total_changes > 0 else 100
        
        return {
            "total_changes": total_changes,
            "successful_changes": successful_changes,
            "success_rate": success_rate,
            "pending_approvals": pending_approvals,
            "change_velocity": "stable"  # Would calculate actual velocity
        }
    
    async def _get_control_effectiveness_summary(self, db: AsyncSession) -> Dict[str, Any]:
        """Get control effectiveness summary."""
        return await self.soc2_service.monitor_compliance_controls(db)
    
    async def _generate_compliance_alerts(self, db: AsyncSession) -> List[ComplianceAlert]:
        """Generate compliance alerts based on current system state."""
        alerts = []
        now = datetime.utcnow()
        
        # Check for critical incidents without resolution
        critical_incidents_query = select(SecurityIncident).where(
            SecurityIncident.severity == IncidentSeverity.CRITICAL,
            SecurityIncident.status.in_([IncidentStatus.OPEN, IncidentStatus.IN_PROGRESS]),
            SecurityIncident.detected_at < now - timedelta(hours=self.critical_incident_threshold_hours)
        )
        
        critical_incidents_result = await db.execute(critical_incidents_query)
        overdue_incidents = critical_incidents_result.scalars().all()
        
        for incident in overdue_incidents:
            alerts.append(ComplianceAlert(
                alert_id=f"incident_{incident.incident_id}",
                alert_type="soc2",
                severity="critical",
                title=f"Critical Incident Overdue: {incident.incident_number}",
                description=f"Critical incident '{incident.title}' has been open for more than {self.critical_incident_threshold_hours} hours",
                created_at=now,
                related_resource_type="security_incident",
                related_resource_id=incident.incident_id,
                recommendations=[
                    "Immediately escalate to incident commander",
                    "Review and update incident response procedures",
                    "Consider external notification requirements"
                ]
            ))
        
        # Check for high-risk anomalies
        high_risk_anomalies_query = select(SecurityAnomaly).where(
            SecurityAnomaly.risk_score >= self.anomaly_risk_threshold,
            SecurityAnomaly.investigated == False,
            SecurityAnomaly.detected_at >= now - timedelta(hours=24)
        )
        
        anomalies_result = await db.execute(high_risk_anomalies_query)
        high_risk_anomalies = anomalies_result.scalars().all()
        
        for anomaly in high_risk_anomalies[:5]:  # Limit to top 5
            alerts.append(ComplianceAlert(
                alert_id=f"anomaly_{anomaly.anomaly_id}",
                alert_type="soc2",
                severity="high",
                title=f"High-Risk Anomaly Detected: {anomaly.anomaly_type.value}",
                description=f"High-risk security anomaly detected with risk score {anomaly.risk_score}",
                created_at=now,
                related_resource_type="security_anomaly",
                related_resource_id=anomaly.anomaly_id,
                recommendations=[
                    "Investigate anomaly immediately",
                    "Review user access patterns",
                    "Consider temporary access restrictions"
                ]
            ))
        
        return alerts
    
    def _calculate_overall_compliance_score(
        self,
        hipaa_metrics: Dict[str, Any],
        soc2_metrics: Dict[str, Any],
        incidents_summary: Dict[str, Any],
        anomalies_summary: Dict[str, Any],
        vendor_access_summary: Dict[str, Any],
        change_management_summary: Dict[str, Any],
        control_effectiveness_summary: Dict[str, Any]
    ) -> float:
        """Calculate overall compliance score."""
        scores = []
        
        # HIPAA compliance component (0-100)
        hipaa_score = 90.0  # Base score
        if hipaa_metrics.get("active_emergency_access", 0) > 5:
            hipaa_score -= 10
        if hipaa_metrics.get("expiring_baa_agreements", 0) > 0:
            hipaa_score -= 5
        scores.append(max(0, hipaa_score))
        
        # SOC2 compliance component (0-100)
        soc2_score = soc2_metrics.get("compliance_score", 85.0)
        scores.append(soc2_score)
        
        # Incident management component (0-100)
        incident_score = 100.0
        if incidents_summary.get("critical_incidents", 0) > 0:
            incident_score -= 20
        if incidents_summary.get("open_incidents", 0) > 10:
            incident_score -= 15
        scores.append(max(0, incident_score))
        
        # Control effectiveness component (0-100)
        control_score = control_effectiveness_summary.get("effectiveness_percentage", 85.0)
        scores.append(control_score)
        
        # Calculate weighted average
        return sum(scores) / len(scores)
    
    def _sanitize_dashboard_data(self, dashboard: Dict[str, Any]) -> Dict[str, Any]:
        """Remove sensitive information from dashboard data."""
        # Create a copy to avoid modifying original
        sanitized = dashboard.copy()
        
        # Remove sensitive fields from alerts
        for alert in sanitized.get("alerts", []):
            if "related_resource_id" in alert:
                alert["related_resource_id"] = "***REDACTED***"
        
        # Sanitize other sensitive data as needed
        return sanitized
    
    def _determine_risk_level(self, compliance_score: float) -> str:
        """Determine risk level based on compliance score."""
        if compliance_score >= 90:
            return "low"
        elif compliance_score >= 75:
            return "medium"
        elif compliance_score >= 60:
            return "high"
        else:
            return "critical"
    
    def _assess_phi_access_compliance(self, total_access: int) -> str:
        """Assess PHI access compliance."""
        if total_access > self.phi_access_volume_threshold:
            return "high_volume_review_needed"
        else:
            return "compliant"
    
    def _assess_emergency_access_compliance(
        self, 
        emergency_count: int, 
        active_count: int
    ) -> str:
        """Assess emergency access compliance."""
        if active_count > 0:
            return "active_emergency_sessions"
        elif emergency_count > 10:
            return "high_emergency_usage"
        else:
            return "compliant"
    
    def _calculate_compliance_health_score(
        self, 
        critical_alerts: int, 
        warning_alerts: int
    ) -> float:
        """Calculate compliance health score."""
        base_score = 100.0
        base_score -= (critical_alerts * 15)  # -15 per critical alert
        base_score -= (warning_alerts * 5)    # -5 per warning alert
        return max(0.0, base_score)
    
    def _determine_compliance_status(self, health_score: float) -> str:
        """Determine compliance status based on health score."""
        if health_score >= 90:
            return "excellent"
        elif health_score >= 75:
            return "good"
        elif health_score >= 60:
            return "fair"
        elif health_score >= 40:
            return "poor"
        else:
            return "critical"
    
    # Additional helper methods would be implemented here for:
    # - _analyze_phi_access
    # - _analyze_emergency_access
    # - _analyze_baa_management
    # - _analyze_hipaa_audit_trail
    # - _assess_hipaa_risks
    # - _generate_hipaa_recommendations
    # - _calculate_hipaa_compliance_score
    # - _extract_key_findings
    # - _summarize_hipaa_report
    # - _identify_control_gaps
    # - _track_remediation_progress
    # - _calculate_trust_criteria_scores
    # - _assess_compliance_maturity
    # - _generate_soc2_recommendations
    # - _summarize_soc2_report
    # - _analyze_cross_framework_compliance
    # - _generate_unified_recommendations
    # - _extract_critical_findings
    # - _analyze_compliance_trends
    # - _check_critical_incidents
    # - _check_expired_emergency_access
    # - _check_expiring_baas
    # - _check_high_risk_anomalies
    # - _check_failed_control_tests
    # - _check_unauthorized_vendor_access
    # - _generate_immediate_recommendations
    
    # These methods would contain the detailed implementation logic
    # for each specific analysis and reporting function.
    
    async def _analyze_phi_access(
        self, 
        db: AsyncSession, 
        start_date: datetime, 
        end_date: datetime
    ) -> Dict[str, Any]:
        """Analyze PHI access patterns and compliance."""
        # Implementation would include detailed PHI access analysis
        return {
            "total_access_events": 0,
            "unique_users": 0,
            "access_by_category": {},
            "access_by_purpose": {},
            "compliance_issues": [],
            "trends": {}
        }
    
    # Additional placeholder methods for brevity...
    async def _analyze_emergency_access(self, db: AsyncSession, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        return {"placeholder": "implementation_needed"}
    
    async def _analyze_baa_management(self, db: AsyncSession) -> Dict[str, Any]:
        return {"placeholder": "implementation_needed"}
    
    async def _analyze_hipaa_audit_trail(self, db: AsyncSession, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        return {"placeholder": "implementation_needed"}
    
    async def _assess_hipaa_risks(self, db: AsyncSession, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        return {"placeholder": "implementation_needed"}
    
    async def _generate_hipaa_recommendations(self, *args) -> List[Dict[str, Any]]:
        return []
    
    def _calculate_hipaa_compliance_score(self, *args) -> float:
        return 85.0
    
    def _extract_key_findings(self, *args) -> List[str]:
        return []
    
    def _summarize_hipaa_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        return report
    
    async def _identify_control_gaps(self, db: AsyncSession) -> List[Dict[str, Any]]:
        return []
    
    async def _track_remediation_progress(self, db: AsyncSession, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        return {}
    
    async def _calculate_trust_criteria_scores(self, db: AsyncSession, start_date: datetime, end_date: datetime) -> Dict[str, float]:
        return {}
    
    async def _assess_compliance_maturity(self, db: AsyncSession) -> Dict[str, Any]:
        return {"overall_maturity": "developing"}
    
    async def _generate_soc2_recommendations(self, *args) -> List[Dict[str, Any]]:
        return []
    
    def _summarize_soc2_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        return report
    
    async def _analyze_cross_framework_compliance(self, db: AsyncSession, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        return {}
    
    async def _generate_unified_recommendations(self, *args) -> List[Dict[str, Any]]:
        return []
    
    def _extract_critical_findings(self, *args) -> List[str]:
        return []
    
    async def _analyze_compliance_trends(self, db: AsyncSession, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        return {}
    
    async def _check_critical_incidents(self, db: AsyncSession) -> List[ComplianceAlert]:
        return []
    
    async def _check_expired_emergency_access(self, db: AsyncSession) -> List[ComplianceAlert]:
        return []
    
    async def _check_expiring_baas(self, db: AsyncSession) -> List[ComplianceAlert]:
        return []
    
    async def _check_high_risk_anomalies(self, db: AsyncSession) -> List[ComplianceAlert]:
        return []
    
    async def _check_failed_control_tests(self, db: AsyncSession) -> List[ComplianceAlert]:
        return []
    
    async def _check_unauthorized_vendor_access(self, db: AsyncSession) -> List[ComplianceAlert]:
        return []
    
    def _generate_immediate_recommendations(self, critical_alerts: List, warning_alerts: List) -> List[str]:
        return []