# Technical Debt and Minor Issues Tracker

This document tracks technical debt, minor issues, and future improvements identified during development and code reviews.

## Status Legend
- 🔴 **Critical** - Must fix before production
- 🟡 **High** - Should fix soon
- 🟢 **Low** - Nice to have
- ✅ **Resolved** - Fixed and verified

---

## Auth Service

### Security & Configuration

#### 1. Database Pool Recycle Time Mismatch ✅
- **Issue**: Config sets `DATABASE_POOL_RECYCLE = 1800` but database.py hardcodes `pool_recycle=3600`
- **Impact**: Connection timeout misalignment could cause unexpected disconnections
- **File**: `/services/auth-service/src/core/database.py`
- **Fix**: Use `settings.DATABASE_POOL_RECYCLE` instead of hardcoded value
- **Effort**: 5 minutes
- **Status**: Resolved - Fixed in line 22

#### 2. IP Address Logging Implementation ✅
- **Issue**: IP address logging shows `ip_address=None # TODO: Get from request context`
- **Impact**: Cannot track suspicious login patterns by IP
- **File**: `/services/auth-service/src/core/security.py:205`
- **Fix**: Implement request context middleware to extract client IP
- **Effort**: 1 hour
- **Status**: Resolved - Implemented with Request dependency
- **Code Example**:
```python
# Add to middleware
request.state.client_ip = request.client.host
# Use in security.py
ip_address = getattr(request.state, "client_ip", None)
```

### Testing & Quality

#### 3. Load Testing Connection Pools 🟡
- **Issue**: Connection pool settings not validated under actual 1000 user load
- **Impact**: Potential connection exhaustion in production
- **Fix**: Create load test scenario with Locust simulating 1000 concurrent users
- **Effort**: 2 hours
- **Status**: Pending

#### 4. Email Hash Collision Testing 🟢
- **Issue**: Email hash collision handling not tested under production load
- **Impact**: Extremely rare but should be monitored
- **Fix**: Add monitoring metric for hash collisions
- **Effort**: 30 minutes
- **Status**: Pending

### Documentation

#### 5. API Documentation Examples 🟢
- **Issue**: Example passwords in API docs use simple values
- **Impact**: None - documentation only
- **Fix**: Update examples to use more complex passwords
- **File**: OpenAPI specifications
- **Effort**: 15 minutes
- **Status**: Pending

### Performance Monitoring

#### 6. Enhanced Monitoring Alerts ✅
- **Issue**: Missing specific alerts for critical thresholds
- **Impact**: Delayed incident response
- **Missing Alerts**:
  - Connection pool > 70% utilization
  - Encryption/decryption error rate > 0
  - Email hash collision rate (should be 0)
  - Connection timeout rate > 1%
- **Fix**: Add Prometheus alert rules
- **Effort**: 1 hour
- **Status**: Resolved - Complete monitoring stack with Prometheus, Grafana, and runbooks

### Migration & Deployment

#### 7. Email Hash Migration Automation 🟡
- **Issue**: Migration comments suggest manual data population might be needed
- **Impact**: Risk of human error during migration
- **File**: `/services/auth-service/alembic/versions/003_add_email_hash_index.py`
- **Fix**: Ensure migration script fully automates email hash population
- **Effort**: 1 hour
- **Status**: Pending

---

## API Gateway Service
*To be populated during implementation*

---

## Frontend Application
*To be populated during implementation*

---

## Infrastructure & DevOps
*To be populated during implementation*

---

## Tracking Process

1. **During Development**: Add items as `TODO` comments in code
2. **During Reviews**: Log items in this document
3. **Sprint Planning**: Review and prioritize items
4. **Before Release**: Ensure all 🔴 Critical items are resolved

## Resolution Workflow

1. Create a branch: `fix/ISSUE_NUMBER-brief-description`
2. Fix the issue with appropriate tests
3. Update this document marking as ✅ Resolved
4. Reference in PR: "Resolves Technical Debt #NUMBER"

## Metrics

- **Total Items**: 7
- **Critical**: 0
- **High Priority**: 2 (was 5)
- **Low Priority**: 2
- **Resolved**: 3

Last Updated: 2024-01-08