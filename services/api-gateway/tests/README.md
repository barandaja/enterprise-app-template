# API Gateway Test Suite

This comprehensive test suite provides >90% code coverage for the API Gateway service with tests across the entire testing pyramid.

## Test Structure

```
tests/
├── conftest.py                 # Test configuration and shared fixtures
├── factories/                  # Mock factories for external services
│   └── test_mock_factories.py
├── unit/                      # Unit tests for individual components
│   ├── test_circuit_breaker.py
│   ├── test_rate_limiter.py
│   └── test_service_registry.py
├── integration/               # Integration tests for service communication
│   ├── test_middleware_stack.py
│   └── test_service_communication.py
├── security/                  # Security and authentication tests
│   ├── test_authentication.py
│   └── test_security_vulnerabilities.py
├── performance/              # Performance and load tests
│   └── test_load_testing.py
├── websocket/               # WebSocket functionality tests
│   └── test_websocket_proxy.py
├── compliance/              # Regulatory compliance tests
│   ├── test_gdpr_compliance.py
│   ├── test_hipaa_compliance.py
│   └── test_soc2_compliance.py
└── edge_cases/              # Edge cases and error scenarios
    └── test_error_scenarios.py
```

## Test Categories

### Unit Tests (`tests/unit/`)
- **Circuit Breaker**: State management, failure detection, recovery
- **Rate Limiter**: Sliding window implementation, burst limits, Redis operations
- **Service Registry**: Service discovery, health checking, load balancing

### Integration Tests (`tests/integration/`)
- **Middleware Stack**: Complete request flow through all middleware
- **Service Communication**: Request proxying, load balancing, failover

### Security Tests (`tests/security/`)
- **Authentication**: JWT validation, token handling, session management
- **Security Vulnerabilities**: OWASP Top 10, injection attacks, XSS prevention

### Performance Tests (`tests/performance/`)
- **Load Testing**: Latency, throughput, concurrent users
- **Scalability**: Resource utilization, breaking points, stress testing

### WebSocket Tests (`tests/websocket/`)
- **Connection Management**: Authentication, connection lifecycle
- **Message Routing**: Real-time communication, subscription handling

### Compliance Tests (`tests/compliance/`)
- **GDPR**: Data protection, consent management, data subject rights
- **HIPAA**: PHI protection, access controls, audit logging
- **SOC 2**: Security, availability, processing integrity controls

### Edge Case Tests (`tests/edge_cases/`)
- **Boundary Conditions**: Size limits, numeric boundaries, concurrency
- **Error Scenarios**: Network failures, resource exhaustion, data corruption

## Running Tests

### Prerequisites

Install test dependencies:
```bash
pip install -r requirements-test.txt
```

### Quick Start

Run all tests with coverage:
```bash
./scripts/run-tests.sh
```

### Test Categories

Run specific test categories:
```bash
# Unit tests only
./scripts/run-tests.sh -t unit

# Security tests with HTML report
./scripts/run-tests.sh -t security -f html

# Performance tests including slow tests
./scripts/run-tests.sh -t performance -s

# Integration tests in parallel
./scripts/run-tests.sh -t integration -p
```

### Advanced Options

```bash
# Verbose output with coverage
./scripts/run-tests.sh -v -c

# Generate all report formats
./scripts/run-tests.sh -f all

# Custom timeout and fail fast
./scripts/run-tests.sh --timeout 600 --fail-fast

# Run only previously failed tests
./scripts/run-tests.sh --lf
```

### Direct pytest Usage

For more control, use pytest directly:
```bash
# Run unit tests with coverage
pytest tests/unit/ --cov=src --cov-report=html

# Run security tests with markers
pytest -m security -v

# Run performance tests excluding slow ones
pytest tests/performance/ -m "performance and not slow"

# Run specific test file
pytest tests/unit/test_circuit_breaker.py -v
```

## Test Configuration

### Markers

Tests are organized using pytest markers:
- `unit`: Unit tests for individual components
- `integration`: Integration tests for service communication
- `security`: Security and authentication tests
- `performance`: Performance and load tests
- `compliance`: Compliance tests (GDPR, HIPAA, SOC2)
- `websocket`: WebSocket functionality tests
- `edge_case`: Edge cases and error scenarios
- `slow`: Tests that take longer to run

### Fixtures

Key fixtures available in `conftest.py`:
- `client`: FastAPI test client with mocked dependencies
- `auth_headers`: Authentication headers for different user types
- `mock_*`: Comprehensive mocks for external services
- `performance_monitor`: Performance metrics collection
- `compliance_test_data`: Test data for compliance scenarios

### Environment Variables

Set these for test execution:
```bash
export TESTING=true
export ENVIRONMENT=test
export DATABASE_URL=sqlite+aiosqlite:///:memory:
export REDIS_URL=redis://localhost:6379/15
```

## Coverage Requirements

The test suite aims for >90% code coverage across:
- **Statement Coverage**: All code lines executed
- **Branch Coverage**: All conditional branches tested
- **Function Coverage**: All functions called
- **Integration Coverage**: All service interactions tested

### Coverage Reports

Generate coverage reports:
```bash
# HTML coverage report
pytest --cov=src --cov-report=html

# Terminal coverage report
pytest --cov=src --cov-report=term-missing

# XML coverage report (for CI/CD)
pytest --cov=src --cov-report=xml
```

## Mock Strategy

### Service Mocks
- **Auth Service**: User authentication and authorization
- **Service Registry**: Service discovery and health checking
- **Rate Limiter**: Request rate limiting with Redis
- **Circuit Breaker**: Service resilience and failure handling

### External Service Mocks
- **Database**: SQL operations and transactions
- **Redis**: Caching and session storage
- **HTTP Clients**: External API calls
- **WebSocket Connections**: Real-time communication

### Data Factories
Realistic test data generation for:
- User profiles and authentication tokens
- Service configurations and health status
- Transaction and audit data
- Compliance and regulatory data

## Performance Testing

### Load Testing Scenarios
- **Latency Testing**: Response time under normal load
- **Throughput Testing**: Requests per second capacity
- **Concurrent Users**: Multiple simultaneous users
- **Stress Testing**: Breaking point identification

### Performance Metrics
- Average response time < 100ms
- 95th percentile < 200ms
- 99th percentile < 500ms
- Throughput > 100 RPS
- Memory usage stable under load

## Security Testing

### Authentication Tests
- JWT token validation and expiration
- Role-based access control (RBAC)
- Session management and timeout
- Multi-factor authentication support

### Vulnerability Tests
- OWASP Top 10 protection
- SQL/NoSQL injection prevention
- XSS and CSRF protection
- Input validation and sanitization

## Compliance Testing

### GDPR Compliance
- Consent management and withdrawal
- Data subject rights (access, rectification, erasure)
- Data portability and processing lawfulness
- Privacy by design and default

### HIPAA Compliance
- PHI protection and encryption
- Access controls and audit logging
- Minimum necessary standard
- Breach notification procedures

### SOC 2 Compliance
- Security controls and monitoring
- Availability and uptime requirements
- Processing integrity and accuracy
- Confidentiality and privacy controls

## CI/CD Integration

### GitHub Actions Example
```yaml
- name: Run Tests
  run: |
    ./scripts/run-tests.sh -f xml --no-coverage
    
- name: Upload Coverage
  uses: codecov/codecov-action@v3
  with:
    file: ./test-reports/coverage/coverage.xml
```

### Quality Gates
- Minimum 90% code coverage
- All security tests pass
- Performance benchmarks met
- Zero high-severity vulnerabilities

## Troubleshooting

### Common Issues

1. **Import Errors**: Ensure `PYTHONPATH` includes `src` directory
2. **Redis Connection**: Use fakeredis for tests or local Redis instance
3. **Timeout Issues**: Increase timeout for slow tests with `--timeout`
4. **Memory Issues**: Run tests sequentially instead of parallel

### Debug Mode
```bash
# Run with debug output
pytest -v -s --tb=long

# Run single test with debugging
pytest tests/unit/test_circuit_breaker.py::TestCircuitBreaker::test_successful_call -v -s
```

### Test Data Cleanup
```bash
# Clean test artifacts
./scripts/run-tests.sh --clean

# Remove coverage data
rm -rf .coverage htmlcov coverage.xml
```

## Contributing

### Adding New Tests

1. Place tests in appropriate category directory
2. Use descriptive test names and docstrings
3. Add appropriate pytest markers
4. Include both positive and negative test cases
5. Mock external dependencies properly

### Test Naming Convention
```python
def test_component_action_expected_result():
    """Test that component performs action and returns expected result."""
    pass
```

### Best Practices
- Test behavior, not implementation
- Use fixtures for common test data
- Keep tests independent and isolated
- Include edge cases and error conditions
- Mock external dependencies consistently

## Reporting Issues

When reporting test issues:
1. Include full command used
2. Provide test output and error messages
3. Specify environment details (OS, Python version)
4. Include relevant configuration

For more information, see the main API Gateway documentation.