"""
Audit log factories for testing compliance and monitoring scenarios.
"""
import factory
from factory import Faker, SubFactory, LazyAttribute, LazyFunction
from faker import Faker as FakerInstance
from datetime import datetime, timedelta
import json

from src.models.audit import AuditLog, AuditEventType, AuditSeverity
from .user_factory import UserFactory

fake = FakerInstance()


class AuditLogFactory(factory.Factory):
    """Factory for AuditLog model."""
    
    class Meta:
        model = AuditLog
    
    # Event classification
    event_type = Faker('random_element', elements=[
        AuditEventType.LOGIN_SUCCESS,
        AuditEventType.LOGIN_FAILURE,
        AuditEventType.LOGOUT,
        AuditEventType.PASSWORD_CHANGE,
        AuditEventType.PASSWORD_RESET,
        AuditEventType.USER_CREATED,
        AuditEventType.USER_UPDATED,
        AuditEventType.USER_DELETED,
        AuditEventType.DATA_READ,
        AuditEventType.DATA_UPDATE,
        AuditEventType.DATA_DELETE,
        AuditEventType.PERMISSION_GRANTED,
        AuditEventType.PERMISSION_REVOKED,
        AuditEventType.SECURITY_ALERT,
        AuditEventType.SUSPICIOUS_ACTIVITY
    ])
    
    severity = Faker('random_element', elements=[
        AuditSeverity.LOW,
        AuditSeverity.MEDIUM,
        AuditSeverity.HIGH,
        AuditSeverity.CRITICAL
    ])
    
    # Event details
    action = Faker('random_element', elements=[
        'create', 'read', 'update', 'delete', 'login', 'logout', 
        'password_change', 'role_assignment', 'permission_check'
    ])
    
    resource_type = Faker('random_element', elements=[
        'user', 'role', 'permission', 'session', 'audit_log', 'system'
    ])
    
    resource_id = Faker('uuid4')
    description = Faker('sentence', nb_words=8)
    
    # User and system information
    user_id = SubFactory(UserFactory)
    session_id = Faker('uuid4')
    ip_address = Faker('ipv4')
    user_agent = LazyFunction(lambda: fake.random_element([
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
    ]))
    
    # Event outcome
    success = Faker('boolean', chance_of_getting_true=80)
    
    # Additional event data (JSON field simulation)
    event_data = LazyFunction(lambda: {
        "request_id": fake.uuid4(),
        "endpoint": fake.uri_path(),
        "method": fake.random_element(["GET", "POST", "PUT", "DELETE"]),
        "response_code": fake.random_element([200, 201, 400, 401, 403, 404, 500]),
        "duration_ms": fake.random_int(10, 5000),
        "user_roles": [fake.job() for _ in range(fake.random_int(1, 3))],
        "affected_fields": [fake.word() for _ in range(fake.random_int(1, 5))]
    })
    
    # Compliance fields
    pii_accessed = Faker('boolean', chance_of_getting_true=30)
    retention_date = LazyFunction(lambda: datetime.utcnow() + timedelta(days=365))
    
    # Timestamps
    timestamp = Faker('date_time_between', start_date='-30d', end_date='now')
    created_at = LazyAttribute(lambda obj: obj.timestamp)


class LoginAuditFactory(AuditLogFactory):
    """Factory for login-related audit logs."""
    
    event_type = AuditEventType.LOGIN_SUCCESS
    action = "login"
    resource_type = "session"
    description = LazyFunction(lambda: f"User login from {fake.ipv4()}")
    
    event_data = LazyFunction(lambda: {
        "login_method": fake.random_element(["password", "oauth", "sso"]),
        "remember_me": fake.boolean(),
        "device_info": {
            "device_type": fake.random_element(["desktop", "mobile", "tablet"]),
            "os": fake.random_element(["Windows", "macOS", "Linux", "iOS", "Android"]),
            "browser": fake.random_element(["Chrome", "Firefox", "Safari", "Edge"])
        },
        "location": {
            "country": fake.country_code(),
            "city": fake.city(),
            "latitude": float(fake.latitude()),
            "longitude": float(fake.longitude())
        },
        "risk_score": fake.random_int(0, 100)
    })


class FailedLoginAuditFactory(AuditLogFactory):
    """Factory for failed login audit logs."""
    
    event_type = AuditEventType.LOGIN_FAILURE
    action = "login"
    resource_type = "session"
    success = False
    severity = AuditSeverity.MEDIUM
    description = LazyFunction(lambda: f"Failed login attempt from {fake.ipv4()}")
    
    event_data = LazyFunction(lambda: {
        "failure_reason": fake.random_element([
            "invalid_credentials", "account_locked", "account_inactive", 
            "too_many_attempts", "suspicious_activity"
        ]),
        "attempt_count": fake.random_int(1, 10),
        "account_locked": fake.boolean(chance_of_getting_true=20),
        "device_info": {
            "device_type": fake.random_element(["desktop", "mobile", "tablet"]),
            "suspicious_indicators": fake.random_element([
                ["new_device", "unusual_location"],
                ["rapid_attempts", "bot_like_behavior"],
                ["proxy_detected", "tor_usage"]
            ])
        }
    })


class DataAccessAuditFactory(AuditLogFactory):
    """Factory for data access audit logs."""
    
    event_type = AuditEventType.DATA_READ
    action = "read"
    resource_type = Faker('random_element', elements=['user', 'role', 'permission'])
    pii_accessed = True
    severity = AuditSeverity.LOW
    
    event_data = LazyFunction(lambda: {
        "fields_accessed": fake.random_elements(
            elements=['email', 'first_name', 'last_name', 'phone_number', 'address'],
            length=fake.random_int(1, 3),
            unique=True
        ),
        "query_type": fake.random_element(["single_record", "list_query", "search"]),
        "result_count": fake.random_int(1, 100),
        "filters_applied": {
            "status": fake.random_element(["active", "inactive", "all"]),
            "role": fake.job(),
            "date_range": f"{fake.date()} to {fake.date()}"
        }
    })


class SecurityAuditFactory(AuditLogFactory):
    """Factory for security-related audit logs."""
    
    event_type = AuditEventType.SECURITY_ALERT
    severity = AuditSeverity.HIGH
    action = "security_check"
    resource_type = "system"
    description = LazyFunction(lambda: f"Security alert: {fake.sentence()}")
    
    event_data = LazyFunction(lambda: {
        "alert_type": fake.random_element([
            "brute_force_attempt", "suspicious_location", "privilege_escalation",
            "data_exfiltration", "unauthorized_access", "session_hijacking"
        ]),
        "threat_level": fake.random_element(["low", "medium", "high", "critical"]),
        "indicators": fake.random_elements(
            elements=[
                "multiple_failed_logins", "unusual_data_access", "privilege_abuse",
                "anomalous_behavior", "known_threat_ip", "suspicious_user_agent"
            ],
            length=fake.random_int(1, 4),
            unique=True
        ),
        "mitigation_actions": fake.random_elements(
            elements=[
                "account_locked", "session_terminated", "admin_notified",
                "additional_verification_required", "ip_blocked"
            ],
            length=fake.random_int(1, 3),
            unique=True
        ),
        "false_positive_likelihood": fake.random_int(0, 100)
    })


class PermissionAuditFactory(AuditLogFactory):
    """Factory for permission-related audit logs."""
    
    event_type = AuditEventType.PERMISSION_GRANTED
    action = Faker('random_element', elements=['grant_permission', 'revoke_permission', 'check_permission'])
    resource_type = "permission"
    severity = AuditSeverity.MEDIUM
    
    event_data = LazyFunction(lambda: {
        "permission_name": f"{fake.word()}:{fake.random_element(['create', 'read', 'update', 'delete'])}",
        "resource": fake.word(),
        "role_name": fake.job(),
        "granted_by": fake.name(),
        "justification": fake.sentence(),
        "temporary": fake.boolean(chance_of_getting_true=20),
        "expires_at": fake.future_datetime(end_date='+30d').isoformat() if fake.boolean() else None
    })


class ComplianceAuditFactory(AuditLogFactory):
    """Factory for compliance-related audit logs."""
    
    event_type = Faker('random_element', elements=[
        AuditEventType.GDPR_DATA_ACCESS,
        AuditEventType.GDPR_DATA_DELETE,
        AuditEventType.GDPR_CONSENT_UPDATE
    ])
    
    pii_accessed = True
    severity = AuditSeverity.MEDIUM
    action = Faker('random_element', elements=['gdpr_request', 'data_export', 'data_deletion', 'consent_update'])
    
    event_data = LazyFunction(lambda: {
        "compliance_framework": fake.random_element(["GDPR", "HIPAA", "SOC2", "PCI-DSS"]),
        "request_type": fake.random_element([
            "data_subject_access", "right_to_be_forgotten", "data_portability",
            "consent_withdrawal", "rectification"
        ]),
        "legal_basis": fake.random_element([
            "consent", "contract", "legal_obligation", "vital_interests",
            "public_task", "legitimate_interests"
        ]),
        "data_categories": fake.random_elements(
            elements=[
                "personal_identifiers", "financial_data", "health_data",
                "biometric_data", "location_data", "behavioral_data"
            ],
            length=fake.random_int(1, 3),
            unique=True
        ),
        "retention_period": fake.random_int(30, 2555),  # days
        "data_processor": fake.company(),
        "cross_border_transfer": fake.boolean(chance_of_getting_true=30)
    })


class SystemAuditFactory(AuditLogFactory):
    """Factory for system-level audit logs."""
    
    event_type = AuditEventType.SYSTEM_ERROR
    action = "system_operation"
    resource_type = "system"
    user_id = None  # System events might not have associated users
    
    event_data = LazyFunction(lambda: {
        "component": fake.random_element([
            "database", "redis", "authentication", "authorization",
            "session_management", "audit_logging", "encryption"
        ]),
        "operation": fake.random_element([
            "backup", "cleanup", "migration", "health_check",
            "configuration_update", "security_scan"
        ]),
        "status": fake.random_element(["success", "warning", "error", "critical"]),
        "error_code": fake.random_element([None, "DB_001", "REDIS_002", "AUTH_003", "SYS_004"]),
        "error_message": fake.sentence() if fake.boolean() else None,
        "performance_metrics": {
            "cpu_usage": fake.random_int(0, 100),
            "memory_usage": fake.random_int(0, 100),
            "response_time_ms": fake.random_int(10, 5000),
            "throughput": fake.random_int(1, 1000)
        }
    })


class AuditTestScenarios:
    """Predefined audit scenarios for testing."""
    
    @staticmethod
    def create_attack_scenario():
        """Create audit logs representing a coordinated attack."""
        attack_ip = fake.ipv4()
        attack_start = fake.date_time_between(start_date='-1d', end_date='now')
        
        logs = []
        
        # Initial reconnaissance
        logs.append(FailedLoginAuditFactory(
            ip_address=attack_ip,
            timestamp=attack_start,
            event_data={
                "failure_reason": "account_enumeration",
                "attack_phase": "reconnaissance"
            }
        ))
        
        # Brute force attempts
        for i in range(10):
            logs.append(FailedLoginAuditFactory(
                ip_address=attack_ip,
                timestamp=attack_start + timedelta(minutes=i),
                event_data={
                    "failure_reason": "invalid_credentials",
                    "attempt_number": i + 1,
                    "attack_phase": "brute_force"
                }
            ))
        
        # Successful breach
        logs.append(LoginAuditFactory(
            ip_address=attack_ip,
            timestamp=attack_start + timedelta(minutes=15),
            event_data={
                "attack_phase": "successful_breach",
                "compromised_account": True
            }
        ))
        
        # Data exfiltration
        logs.append(DataAccessAuditFactory(
            ip_address=attack_ip,
            timestamp=attack_start + timedelta(minutes=20),
            event_data={
                "attack_phase": "data_exfiltration",
                "suspicious_data_access": True,
                "large_result_set": True
            }
        ))
        
        return logs
    
    @staticmethod
    def create_compliance_audit_trail(user_id: int):
        """Create comprehensive audit trail for compliance demonstration."""
        base_time = fake.date_time_between(start_date='-30d', end_date='now')
        
        logs = []
        
        # User creation
        logs.append(AuditLogFactory(
            event_type=AuditEventType.USER_CREATED,
            user_id=user_id,
            timestamp=base_time,
            pii_accessed=True,
            event_data={
                "compliance_framework": "GDPR",
                "consent_obtained": True,
                "lawful_basis": "consent"
            }
        ))
        
        # Data access events
        for i in range(5):
            logs.append(DataAccessAuditFactory(
                user_id=user_id,
                timestamp=base_time + timedelta(days=i*2),
                event_data={
                    "compliance_check": "passed",
                    "purpose_limitation": "service_delivery"
                }
            ))
        
        # Consent update
        logs.append(ComplianceAuditFactory(
            user_id=user_id,
            timestamp=base_time + timedelta(days=15),
            event_type=AuditEventType.GDPR_CONSENT_UPDATE,
            event_data={
                "consent_type": "marketing",
                "consent_status": "withdrawn",
                "method": "user_portal"
            }
        ))
        
        return logs
    
    @staticmethod
    def create_performance_test_logs(count: int = 1000):
        """Create large number of audit logs for performance testing."""
        logs = []
        base_time = datetime.utcnow() - timedelta(hours=24)
        
        for i in range(count):
            timestamp = base_time + timedelta(seconds=i * 86.4)  # Distributed over 24 hours
            
            log = AuditLogFactory(
                timestamp=timestamp,
                event_data={
                    "performance_test": True,
                    "batch_number": i // 100,
                    "sequence_number": i
                }
            )
            logs.append(log)
        
        return logs


class LoadTestAuditFactory:
    """Factory optimized for load testing scenarios."""
    
    @staticmethod
    def create_audit_batch(batch_size: int = 1000):
        """Create batch of audit logs for load testing."""
        logs = []
        base_time = datetime.utcnow()
        
        for i in range(batch_size):
            log = AuditLog(
                event_type=AuditEventType.DATA_READ,
                action="read",
                resource_type="user",
                resource_id=str(fake.uuid4()),
                user_id=fake.random_int(1, 1000),
                ip_address=fake.ipv4(),
                success=True,
                timestamp=base_time + timedelta(seconds=i),
                event_data={"load_test": True, "batch_id": i // 100},
                description=f"Load test audit log {i}"
            )
            logs.append(log)
        
        return logs