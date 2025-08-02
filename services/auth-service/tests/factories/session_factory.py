"""
Session model factories for testing.
Creates realistic session data for various testing scenarios.
"""
import factory
from factory import Faker, SubFactory, LazyAttribute, LazyFunction
from faker import Faker as FakerInstance
from datetime import datetime, timedelta
import secrets
import uuid

from src.models.session import UserSession
from .user_factory import UserFactory

fake = FakerInstance()


class SessionFactory(factory.Factory):
    """Factory for UserSession model."""
    
    class Meta:
        model = UserSession
    
    # Generate unique session ID
    session_id = LazyFunction(lambda: str(uuid.uuid4()))
    
    # User relationship
    user_id = SubFactory(UserFactory)
    
    # Session timing
    created_at = Faker('date_time_between', start_date='-7d', end_date='now')
    last_activity_at = LazyAttribute(lambda obj: obj.created_at)
    expires_at = LazyAttribute(lambda obj: obj.created_at + timedelta(hours=24))
    
    # Client information
    ip_address = Faker('ipv4')
    user_agent = LazyFunction(lambda: fake.random_element([
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15",
        "Mozilla/5.0 (Android 11; Mobile; rv:91.0) Gecko/91.0 Firefox/91.0"
    ]))
    
    # Device information (JSON field simulation)
    device_info = LazyFunction(lambda: {
        "device_type": fake.random_element(["desktop", "mobile", "tablet"]),
        "os": fake.random_element(["Windows", "macOS", "Linux", "iOS", "Android"]),
        "browser": fake.random_element(["Chrome", "Firefox", "Safari", "Edge"]),
        "screen_resolution": fake.random_element(["1920x1080", "1366x768", "375x667", "414x896"]),
        "timezone": fake.timezone(),
        "language": fake.language_code()
    })
    
    # Location data (JSON field simulation)
    location_data = LazyFunction(lambda: {
        "country": fake.country_code(),
        "country_name": fake.country(),
        "region": fake.state(),
        "city": fake.city(),
        "latitude": float(fake.latitude()),
        "longitude": float(fake.longitude()),
        "timezone": fake.timezone(),
        "isp": fake.company()
    })
    
    # Session state
    is_active = True
    is_trusted_device = Faker('boolean', chance_of_getting_true=30)
    suspicious_activity = False
    end_reason = None
    ended_at = None
    
    # Token management
    refresh_token_id = LazyFunction(lambda: str(uuid.uuid4()))
    token_version = 1


class ActiveSessionFactory(SessionFactory):
    """Factory for active sessions."""
    
    is_active = True
    expires_at = LazyFunction(lambda: datetime.utcnow() + timedelta(hours=24))
    last_activity_at = LazyFunction(lambda: datetime.utcnow() - timedelta(minutes=fake.random_int(1, 30)))


class ExpiredSessionFactory(SessionFactory):
    """Factory for expired sessions."""
    
    is_active = False
    expires_at = LazyFunction(lambda: datetime.utcnow() - timedelta(hours=fake.random_int(1, 48)))
    end_reason = "expired"
    ended_at = LazyAttribute(lambda obj: obj.expires_at)


class EndedSessionFactory(SessionFactory):
    """Factory for manually ended sessions."""
    
    is_active = False
    end_reason = Faker('random_element', elements=['logout', 'admin_action', 'security_violation'])
    ended_at = Faker('date_time_between', start_date='-7d', end_date='now')
    expires_at = LazyAttribute(lambda obj: obj.ended_at + timedelta(hours=24))


class SuspiciousSessionFactory(SessionFactory):
    """Factory for sessions with suspicious activity."""
    
    suspicious_activity = True
    device_info = LazyFunction(lambda: {
        "device_type": "desktop",
        "os": "Linux", 
        "browser": "Chrome",
        "suspicious_indicators": [
            "unusual_location",
            "new_device",
            "rapid_requests"
        ],
        "risk_score": fake.random_int(70, 95)
    })
    
    location_data = LazyFunction(lambda: {
        "country": fake.random_element(["RU", "CN", "IR", "KP"]),  # High-risk countries
        "country_name": fake.country(),
        "region": fake.state(),
        "city": fake.city(),
        "latitude": float(fake.latitude()),
        "longitude": float(fake.longitude()),
        "is_proxy": True,
        "is_tor": fake.boolean(chance_of_getting_true=30),
        "threat_score": fake.random_int(60, 90)
    })


class MobileSessionFactory(SessionFactory):
    """Factory for mobile device sessions."""
    
    user_agent = LazyFunction(lambda: fake.random_element([
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Android 11; Mobile; rv:91.0) Gecko/91.0 Firefox/91.0",
        "Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36"
    ]))
    
    device_info = LazyFunction(lambda: {
        "device_type": "mobile",
        "os": fake.random_element(["iOS", "Android"]),
        "browser": fake.random_element(["Safari", "Chrome", "Firefox"]),
        "screen_resolution": fake.random_element(["375x667", "414x896", "360x640", "375x812"]),
        "is_mobile": True,
        "device_model": fake.random_element(["iPhone 12", "Samsung Galaxy S21", "Google Pixel 5"]),
        "push_token": f"fcm:{fake.uuid4()}"
    })


class TrustedDeviceSessionFactory(SessionFactory):
    """Factory for trusted device sessions."""
    
    is_trusted_device = True
    device_info = LazyFunction(lambda: {
        "device_type": "desktop",
        "os": fake.random_element(["Windows", "macOS", "Linux"]),
        "browser": fake.random_element(["Chrome", "Firefox", "Safari"]),
        "device_fingerprint": fake.uuid4(),
        "trust_score": fake.random_int(80, 99),
        "first_seen": fake.date_time_between(start_date='-90d', end_date='-30d').isoformat(),
        "last_used": fake.date_time_between(start_date='-7d', end_date='now').isoformat()
    })


class RememberMeSessionFactory(SessionFactory):
    """Factory for extended 'remember me' sessions."""
    
    expires_at = LazyFunction(lambda: datetime.utcnow() + timedelta(days=30))
    device_info = LazyFunction(lambda: {
        "device_type": fake.random_element(["desktop", "mobile"]),
        "os": fake.random_element(["Windows", "macOS", "iOS", "Android"]),
        "browser": fake.random_element(["Chrome", "Safari", "Firefox"]),
        "remember_me": True,
        "extended_session": True
    })


class SessionTestScenarios:
    """Predefined session scenarios for testing."""
    
    @staticmethod
    def concurrent_sessions(user_id: int, count: int = 3):
        """Create multiple active sessions for the same user."""
        sessions = []
        for i in range(count):
            session = ActiveSessionFactory(
                user_id=user_id,
                ip_address=fake.ipv4(),
                device_info={
                    "device_type": fake.random_element(["desktop", "mobile", "tablet"]),
                    "session_number": i + 1
                }
            )
            sessions.append(session)
        return sessions
    
    @staticmethod
    def location_anomaly_session(user_id: int):
        """Create session with location anomaly."""
        return SuspiciousSessionFactory(
            user_id=user_id,
            location_data={
                "country": "RU",
                "country_name": "Russia",
                "region": "Moscow",
                "city": "Moscow",
                "latitude": 55.7558,
                "longitude": 37.6176,
                "anomaly_detected": True,
                "distance_from_last_login": 8000  # km
            }
        )
    
    @staticmethod
    def rapid_session_creation(user_id: int, count: int = 10):
        """Create sessions that were created rapidly (bot-like behavior)."""
        base_time = datetime.utcnow()
        sessions = []
        
        for i in range(count):
            session = SessionFactory(
                user_id=user_id,
                created_at=base_time + timedelta(seconds=i * 2),
                suspicious_activity=True,
                device_info={
                    "rapid_creation_detected": True,
                    "creation_interval_seconds": 2,
                    "sequence_number": i + 1
                }
            )
            sessions.append(session)
        
        return sessions


class LoadTestSessionFactory:
    """Factory optimized for load testing scenarios."""
    
    @staticmethod
    def create_session_batch(user_ids: list, batch_size: int = 1000):
        """Create a batch of sessions for load testing."""
        sessions = []
        for i in range(batch_size):
            user_id = fake.random_element(user_ids)
            session = UserSession(
                session_id=str(uuid.uuid4()),
                user_id=user_id,
                ip_address=fake.ipv4(),
                user_agent="LoadTest/1.0",
                device_info={"device_type": "test", "load_test": True},
                location_data={"country": "US", "city": "Test City"},
                created_at=datetime.utcnow(),
                last_activity_at=datetime.utcnow(),
                expires_at=datetime.utcnow() + timedelta(hours=24),
                is_active=True,
                refresh_token_id=str(uuid.uuid4())
            )
            sessions.append(session)
        return sessions
    
    @staticmethod
    def create_performance_test_scenarios():
        """Create various scenarios for performance testing."""
        return {
            "high_activity_sessions": [
                SessionFactory(
                    last_activity_at=datetime.utcnow() - timedelta(seconds=fake.random_int(1, 60))
                ) for _ in range(100)
            ],
            "expiring_sessions": [
                SessionFactory(
                    expires_at=datetime.utcnow() + timedelta(minutes=fake.random_int(1, 5))
                ) for _ in range(50)
            ],
            "suspicious_sessions": [
                SuspiciousSessionFactory() for _ in range(25)
            ]
        }


class SecurityTestSessionFactory:
    """Factory for security testing scenarios."""
    
    @staticmethod
    def create_session_hijacking_scenario():
        """Create scenario for testing session hijacking detection."""
        original_session = SessionFactory(
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            location_data={"country": "US", "city": "New York"}
        )
        
        hijacked_session = SessionFactory(
            session_id=original_session.session_id,
            user_id=original_session.user_id,
            ip_address="1.2.3.4",  # Different IP
            user_agent="Different User Agent",
            location_data={"country": "RU", "city": "Moscow"},  # Different location
            suspicious_activity=True
        )
        
        return original_session, hijacked_session
    
    @staticmethod
    def create_session_fixation_scenario():
        """Create scenario for testing session fixation attacks."""
        return SessionFactory(
            session_id="fixed-session-id",  # Predictable session ID
            device_info={
                "session_fixation_attempt": True,
                "fixed_session_id": True
            }
        )
    
    @staticmethod 
    def create_brute_force_sessions(user_id: int, count: int = 50):
        """Create sessions indicating brute force attack."""
        sessions = []
        base_time = datetime.utcnow()
        
        for i in range(count):
            session = SessionFactory(
                user_id=user_id,
                created_at=base_time + timedelta(seconds=i * 1),  # Rapid creation
                ip_address=fake.ipv4(),
                is_active=False,
                end_reason="authentication_failed",
                ended_at=base_time + timedelta(seconds=i * 1 + 1),
                suspicious_activity=True,
                device_info={
                    "brute_force_indicator": True,
                    "attempt_number": i + 1,
                    "attack_pattern": "rapid_login_attempts"
                }
            )
            sessions.append(session)
        
        return sessions


class ComplianceSessionFactory:
    """Factory for compliance testing scenarios."""
    
    @staticmethod
    def create_gdpr_session():
        """Create session with GDPR-relevant data."""
        return SessionFactory(
            location_data={
                "country": "DE",
                "country_name": "Germany", 
                "is_eu_citizen": True,
                "gdpr_applicable": True
            },
            device_info={
                "tracking_consent": True,
                "analytics_consent": False,
                "marketing_consent": False,
                "gdpr_consent_version": "1.0"
            }
        )
    
    @staticmethod
    def create_hipaa_session():
        """Create session for HIPAA compliance testing."""
        return SessionFactory(
            device_info={
                "hipaa_compliant_device": True,
                "encryption_enabled": True,
                "medical_data_access": True,
                "audit_logging_enabled": True
            },
            location_data={
                "healthcare_facility": True,
                "facility_id": f"HCF{fake.random_int(1000, 9999)}"
            }
        )
    
    @staticmethod
    def create_audit_trail_session():
        """Create session with comprehensive audit trail."""
        return SessionFactory(
            device_info={
                "audit_enabled": True,
                "log_all_actions": True,
                "compliance_mode": "SOC2"
            }
        )