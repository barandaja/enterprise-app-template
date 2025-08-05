# Backend Services Backlog

## High Priority

### 1. Email Service Configuration
- **Issue**: Email service is not configured, causing email verification to fail
- **Current Workaround**: `verification_sent` is hardcoded to `true` in registration endpoint for development
- **Location**: `/services/auth-service/src/api/auth.py` lines 196-199
- **Tasks**:
  - Configure email service (SMTP/SendGrid/AWS SES)
  - Remove the hardcoded `verification_sent = True` workaround
  - Test email delivery for:
    - User registration verification
    - Password reset emails
    - Account security notifications

### 2. JWT Config Endpoint
- **Issue**: API Gateway tries to fetch JWT config from `/api/v1/auth/config/jwt` which doesn't exist
- **Current Workaround**: Falls back to environment variable configuration
- **Tasks**:
  - Implement JWT config endpoint in auth service
  - Or remove the config fetch attempt from API gateway

## Medium Priority

### 3. User Service Implementation
- **Issue**: User service has no API endpoints implemented
- **Location**: `/services/user-service/src/api/` is empty
- **Tasks**:
  - Decide if user management should stay in auth service or move to user service
  - If moving, implement user CRUD endpoints in user service
  - Update API gateway routing accordingly

### 4. Proper CORS Configuration
- **Issue**: CORS origins are empty in production
- **Location**: Auth service and API gateway CORS configuration
- **Tasks**:
  - Configure proper CORS origins for production
  - Implement environment-specific CORS policies

### 5. Rate Limiting Redis Keys
- **Issue**: Rate limiting might need namespacing to avoid conflicts
- **Tasks**:
  - Add service-specific prefixes to Redis keys
  - Implement rate limit monitoring/alerting

## Low Priority

### 6. Audit Log Retention
- **Issue**: No audit log cleanup/retention policy
- **Tasks**:
  - Implement audit log archival
  - Add retention policies based on compliance requirements

### 7. Session Location Data
- **Issue**: Session location data is always empty
- **Tasks**:
  - Implement IP geolocation service
  - Add location data to sessions

### 8. Device Fingerprinting
- **Issue**: Device info is minimal (only device_type is set)
- **Tasks**:
  - Implement proper user agent parsing
  - Add device fingerprinting for security

## Tech Debt

### 9. Hardcoded API Version Paths
- **Issue**: Some paths still use hardcoded `/api/v1/` instead of dynamic versioning
- **Tasks**:
  - Audit all endpoints for hardcoded paths
  - Use settings.API_V1_STR consistently

### 10. Error Message Consistency
- **Issue**: Some errors have empty messages
- **Tasks**:
  - Implement consistent error response format
  - Add proper error codes and messages

## Notes
- This backlog was created on 2025-08-05
- Items should be prioritized based on business needs
- Security-related items should be addressed first