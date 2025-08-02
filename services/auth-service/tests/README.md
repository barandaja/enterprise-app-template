# Auth Service Test Suite

This directory contains comprehensive tests for the enterprise authentication service, providing 90%+ code coverage and testing all critical paths, security vulnerabilities, and compliance requirements.

## Test Structure

```
tests/
├── conftest.py                 # Pytest configuration and fixtures
├── factories/                  # Test data factories
│   ├── user_factory.py        # User, Role, Permission factories
│   ├── session_factory.py     # Session test data generation
│   └── audit_factory.py       # Audit log factories
├── unit/                       # Unit tests (fast, isolated)
│   ├── test_auth_service.py    # AuthService tests
│   ├── test_user_service.py    # UserService tests
│   └── test_session_service.py # SessionService tests
├── integration/                # Integration tests (API endpoints)
│   └── test_auth_endpoints.py  # End-to-end API testing
├── security/                   # Security vulnerability tests
│   └── test_security_vulnerabilities.py
├── performance/                # Performance and load tests
│   └── test_load_testing.py    # Response time and throughput
├── compliance/                 # Regulatory compliance tests
│   └── test_gdpr_compliance.py # GDPR/HIPAA/SOC2 requirements
└── edge_cases/                 # Edge cases and boundary conditions
    └── test_boundary_conditions.py
```

## Test Categories

### Unit Tests (`tests/unit/`)
- **Purpose**: Test individual components in isolation
- **Speed**: Fast (< 50ms per test)
- **Coverage**: Business logic, error handling, edge cases
- **Dependencies**: Mocked external services (database, Redis, etc.)

**Key Test Files:**
- `test_auth_service.py`: Authentication flows, token management, password reset
- `test_user_service.py`: User CRUD operations, role management
- `test_session_service.py`: Session lifecycle, validation, cleanup

### Integration Tests (`tests/integration/`)
- **Purpose**: Test complete request/response flows
- **Speed**: Medium (100-500ms per test)
- **Coverage**: API endpoints, middleware, database integration
- **Dependencies**: Test database and Redis instances

**Key Test Files:**
- `test_auth_endpoints.py`: Login, logout, password reset, session management APIs

### Security Tests (`tests/security/`)
- **Purpose**: Verify protection against common vulnerabilities
- **Speed**: Medium to slow (varies by test)
- **Coverage**: OWASP Top 10, injection attacks, authentication bypass
- **Dependencies**: Real application stack for realistic security testing

**Security Tests Include:**
- SQL injection protection
- XSS prevention
- CSRF protection
- Rate limiting
- Session security
- JWT token validation
- Brute force protection
- Information disclosure prevention

### Performance Tests (`tests/performance/`)
- **Purpose**: Ensure acceptable performance under load
- **Speed**: Slow (seconds to minutes)
- **Coverage**: Response times, throughput, resource usage
- **Dependencies**: Performance monitoring tools

**Performance Metrics:**
- Login endpoint: < 200ms response time
- Concurrent requests: > 100 req/s throughput
- Database queries: < 50ms average
- Memory usage: Stable under load

### Compliance Tests (`tests/compliance/`)
- **Purpose**: Verify regulatory compliance (GDPR, HIPAA, SOC2)
- **Speed**: Medium (100-1000ms per test)
- **Coverage**: Data protection rights, audit trails, consent management
- **Dependencies**: Full application stack with audit logging

**Compliance Areas:**
- **GDPR**: Right to access, rectification, erasure, portability
- **HIPAA**: Data encryption, access controls, audit logs
- **SOC2**: Security controls, availability, confidentiality

### Edge Case Tests (`tests/edge_cases/`)
- **Purpose**: Test boundary conditions and unusual inputs
- **Speed**: Fast to medium
- **Coverage**: Input validation, error handling, system limits
- **Dependencies**: Minimal (mostly input validation)

## Running Tests

### Prerequisites

1. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-test.txt
   ```

2. **Set Environment Variables**:
   ```bash
   export DATABASE_URL="postgresql+asyncpg://test:test@localhost:5432/test_authdb"
   export REDIS_URL="redis://localhost:6379/1"
   export SECRET_KEY="test-secret-key"
   export TESTING=true
   ```

3. **Start Test Services**:
   ```bash
   # PostgreSQL (using Docker)
   docker run -d --name test-postgres \
     -e POSTGRES_PASSWORD=test \
     -e POSTGRES_USER=test \
     -e POSTGRES_DB=test_authdb \
     -p 5432:5432 postgres:15

   # Redis (using Docker)
   docker run -d --name test-redis \
     -p 6379:6379 redis:7-alpine
   ```

### Running All Tests

```bash
# Run complete test suite with coverage
pytest --cov=src --cov-report=html --cov-report=term-missing --cov-fail-under=90

# Run with parallel execution (faster)
pytest -n auto --cov=src --cov-report=html
```

### Running Specific Test Categories

```bash
# Unit tests only (fast)
pytest tests/unit/ -m unit

# Integration tests
pytest tests/integration/ -m integration

# Security tests
pytest tests/security/ -m security

# Performance tests (slow)
pytest tests/performance/ -m performance

# Compliance tests  
pytest tests/compliance/ -m compliance

# Edge case tests
pytest tests/edge_cases/ -m edge_case
```

### Running Tests by Priority

```bash
# Critical tests only
pytest -m "unit or integration or security"

# All tests except slow ones
pytest -m "not slow"

# Smoke tests for CI/CD
pytest -m smoke
```

## Test Configuration

### Pytest Configuration (`pytest.ini`)

Key configuration options:
- **Async Support**: `asyncio_mode = auto`
- **Coverage**: 90% minimum threshold
- **Parallel Execution**: `-n auto` for speed
- **Test Discovery**: Automatic test file detection
- **Markers**: Categorize tests by type and speed

### Test Fixtures (`conftest.py`)

**Database Fixtures:**
- `test_engine`: Async SQLAlchemy engine
- `db_session`: Fresh database session per test
- `test_user`, `test_admin_user`: Pre-created test users

**Redis Fixtures:**
- `redis_client`: Fake Redis for testing
- `mock_cache_service`: Mocked cache operations

**Authentication Fixtures:**
- `authenticated_headers`: Valid JWT headers
- `auth_service`, `user_service`, `session_service`: Service instances

**Test Data Fixtures:**
- `valid_login_data`: Standard login payload
- `client_info`: Device and location data
- `malicious_inputs`: Security test payloads

## Test Data Factories

### User Factory (`tests/factories/user_factory.py`)

```python
# Standard user
user = UserFactory()

# Admin user
admin = AdminUserFactory()

# Inactive user
inactive_user = InactiveUserFactory()

# User with specific traits
suspicious_user = UserFactory(**UserTraits.suspicious_activity())

# Bulk users for performance testing
users = LoadTestUserFactory.create_users(count=1000)
```

### Session Factory (`tests/factories/session_factory.py`)

```python
# Active session
session = ActiveSessionFactory()

# Expired session
expired = ExpiredSessionFactory()

# Suspicious session with security flags
suspicious = SuspiciousSessionFactory()

# Mobile device session
mobile = MobileSessionFactory()
```

### Audit Factory (`tests/factories/audit_factory.py`)

```python
# Login audit log
login_log = LoginAuditFactory()

# Security alert
security_alert = SecurityAuditFactory()

# GDPR compliance log
gdpr_log = ComplianceAuditFactory()
```

## Coverage Requirements

### Overall Coverage Target: 90%+

**Coverage by Component:**
- **Services**: 95%+ (critical business logic)
- **API Endpoints**: 90%+ (all paths tested)
- **Models**: 85%+ (database operations)
- **Utilities**: 80%+ (helper functions)

**Coverage Reports:**
- **HTML Report**: `htmlcov/index.html`
- **XML Report**: `coverage.xml` (for CI/CD)
- **Terminal**: Real-time coverage during test runs

### Coverage Analysis

```bash
# Generate detailed coverage report
pytest --cov=src --cov-report=html --cov-report=term-missing

# Check coverage for specific module
pytest --cov=src.services.auth_service --cov-report=term-missing tests/unit/test_auth_service.py

# Find uncovered lines
coverage report --show-missing
```

## CI/CD Integration

### GitHub Actions (`.github/workflows/test.yml`)

**Test Pipeline Stages:**

1. **Lint and Security Scan**
   - Code formatting (Black, isort)
   - Static analysis (flake8, mypy)
   - Security scan (bandit, safety)

2. **Unit Tests**
   - Fast isolated tests
   - 85%+ coverage requirement
   - Parallel execution

3. **Integration Tests**
   - API endpoint testing
   - Database integration
   - Redis integration

4. **Security Tests**
   - Vulnerability scanning
   - Penetration testing
   - Authentication bypass attempts

5. **Performance Tests** (main branch only)
   - Load testing
   - Response time validation
   - Resource usage monitoring

6. **Compliance Tests**
   - GDPR compliance verification
   - Audit trail validation
   - Data protection testing

### Test Environment Setup

**CI Environment Variables:**
```yaml
env:
  DATABASE_URL: postgresql+asyncpg://test_user:test_password@localhost:5432/test_authdb
  REDIS_URL: redis://localhost:6379/1
  SECRET_KEY: test-secret-key-for-ci
  TESTING: true
  ENVIRONMENT: testing
```

**Service Dependencies:**
- PostgreSQL 15 (test database)
- Redis 7 (test cache)
- Python 3.11
- All test dependencies

## Performance Benchmarks

### Target Performance Metrics

**Response Times:**
- Login endpoint: < 200ms (P95)
- Token refresh: < 100ms (P95)
- Session validation: < 50ms (P95)
- Password reset: < 300ms (P95)

**Throughput:**
- Concurrent logins: > 100 req/s
- Session validation: > 500 req/s
- Database operations: > 200 ops/s

**Resource Usage:**
- Memory: < 512MB under normal load
- CPU: < 50% under load
- Database connections: < 20 concurrent

### Running Performance Tests

```bash
# Basic performance test
pytest tests/performance/ -m performance

# With benchmarking
pytest tests/performance/ --benchmark-json=results.json

# Load testing with custom parameters
pytest tests/performance/test_load_testing.py::test_concurrent_login_performance -s
```

## Debugging Tests

### Common Issues and Solutions

**1. Test Database Connection Issues:**
```bash
# Check PostgreSQL is running
docker ps | grep postgres

# Reset test database
docker exec test-postgres psql -U test -d test_authdb -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
```

**2. Redis Connection Issues:**
```bash
# Check Redis is running
docker ps | grep redis

# Test Redis connection
redis-cli ping
```

**3. Async Test Issues:**
```python
# Ensure proper async test decoration
@pytest_asyncio.async
async def test_async_function():
    result = await some_async_function()
    assert result is not None
```

**4. Fixture Dependency Issues:**
```python
# Check fixture dependencies are correctly ordered
@pytest.fixture
async def dependent_fixture(base_fixture):
    # base_fixture will be created first
    return setup_dependent_resource(base_fixture)
```

### Test Debugging Commands

```bash
# Run single test with verbose output
pytest tests/unit/test_auth_service.py::test_authenticate_user_success -v -s

# Run tests with pdb debugging
pytest --pdb tests/unit/test_auth_service.py::test_authenticate_user_success

# Show test durations
pytest --durations=10

# Run only failed tests from last run
pytest --lf
```

## Test Data Management

### Database Test Data

**Isolation Strategy:**
- Each test gets a fresh database session
- Automatic cleanup after each test
- No test interdependencies

**Test Data Creation:**
```python
# Using factories for consistent data
user = UserFactory(email="test@example.com")
session = SessionFactory(user_id=user.id)

# Using fixtures for common scenarios  
def test_login(test_user, valid_login_data):
    # test_user and valid_login_data provided by fixtures
    pass
```

### Redis Test Data

**Isolation Strategy:**
- FakeRedis for unit tests (in-memory)
- Separate Redis database for integration tests
- Automatic cleanup between tests

## Security Test Coverage

### OWASP Top 10 Coverage

1. **A01 - Broken Access Control**: ✅ Covered
2. **A02 - Cryptographic Failures**: ✅ Covered
3. **A03 - Injection**: ✅ SQL injection tests
4. **A04 - Insecure Design**: ✅ Architecture tests
5. **A05 - Security Misconfiguration**: ✅ Config tests
6. **A06 - Vulnerable Components**: ✅ Dependency scans
7. **A07 - Authentication Failures**: ✅ Comprehensive auth tests
8. **A08 - Software Integrity Failures**: ✅ Input validation
9. **A09 - Logging Failures**: ✅ Audit log tests
10. **A10 - Server-Side Request Forgery**: ✅ SSRF protection

### Security Test Examples

```python
# SQL injection test
@pytest.mark.security
async def test_sql_injection_protection():
    malicious_input = "'; DROP TABLE users; --"
    response = await client.post("/login", json={
        "email": malicious_input,
        "password": "test"
    })
    assert response.status_code != 500  # Should not crash

# XSS protection test
@pytest.mark.security
async def test_xss_protection():
    xss_payload = "<script>alert('xss')</script>"
    response = await client.post("/register", json={
        "email": f"test{xss_payload}@example.com"
    })
    assert "<script>" not in response.text
```

## Compliance Test Coverage

### GDPR Compliance Tests

**Data Subject Rights:**
- ✅ Right to access (Article 15)
- ✅ Right to rectification (Article 16)
- ✅ Right to erasure (Article 17)
- ✅ Right to data portability (Article 20)
- ✅ Right to object (Article 21)

**Privacy by Design:**
- ✅ Data minimization
- ✅ Purpose limitation
- ✅ Storage limitation
- ✅ Consent management

### Example Compliance Test

```python
@pytest.mark.compliance
async def test_gdpr_data_export():
    """Test user can export their personal data."""
    response = await client.get("/user/data-export", headers=auth_headers)
    
    assert response.status_code == 200
    data = response.json()
    
    # Should include all personal data
    assert "email" in data
    assert "first_name" in data
    assert "created_at" in data
    
    # Should include processing metadata
    assert "data_processing_consent" in data
    assert "export_date" in data
```

## Maintenance and Updates

### Regular Maintenance Tasks

**Weekly:**
- Review test failure patterns
- Update test data factories
- Check coverage metrics
- Review security test results

**Monthly:**
- Update test dependencies
- Review and update test documentation
- Analyze performance trends
- Update compliance test coverage

**Quarterly:**
- Full security test review
- Performance benchmark updates
- Test suite optimization
- Compliance requirement updates

### Adding New Tests

**1. Choose Appropriate Category:**
```python
# Unit test for new service method
@pytest.mark.unit
async def test_new_service_method():
    pass

# Integration test for new API endpoint
@pytest.mark.integration
async def test_new_api_endpoint():
    pass
```

**2. Use Existing Patterns:**
```python
# Follow established patterns
async def test_new_feature(auth_service, db_session):
    # Arrange
    user = UserFactory()
    
    # Act
    result = await auth_service.new_method(db_session, user.id)
    
    # Assert
    assert result is not None
```

**3. Add Appropriate Markers:**
```python
@pytest.mark.unit
@pytest.mark.auth
@pytest_asyncio.async
async def test_new_auth_feature():
    pass
```

### Test Quality Guidelines

**1. Test Naming:**
- Use descriptive names: `test_authenticate_user_with_invalid_password`
- Include expected behavior: `test_login_should_fail_with_locked_account`
- Use consistent patterns: `test_[method]_[scenario]_[expected_result]`

**2. Test Structure (AAA Pattern):**
```python
async def test_example():
    # Arrange - Set up test data and conditions
    user = UserFactory()
    login_data = {"email": user.email, "password": "test"}
    
    # Act - Execute the code under test
    result = await auth_service.authenticate_user(db, **login_data)
    
    # Assert - Verify the expected outcomes
    assert result is not None
    assert result.user.id == user.id
```

**3. Test Independence:**
- Each test should be independent
- No shared state between tests
- Use fixtures for common setup
- Clean up after each test

**4. Error Testing:**
```python
# Test both success and failure cases
async def test_login_success():
    # Test successful login
    pass

async def test_login_invalid_credentials():
    # Test login failure
    with pytest.raises(HTTPException) as exc_info:
        await auth_service.authenticate_user(db, "invalid", "invalid")
    assert exc_info.value.status_code == 401
```

This comprehensive test suite ensures the auth service is reliable, secure, and compliant with enterprise requirements while maintaining high performance and quality standards.