# Auth Service TODO List

## High Priority 🟡

### 1. Fix Database Pool Recycle Mismatch
```python
# File: src/core/database.py
# Line: ~30
# Current: pool_recycle=3600  # Hardcoded
# Should be: pool_recycle=settings.DATABASE_POOL_RECYCLE
```

### 2. Implement IP Address Logging
```python
# File: src/core/security.py
# Line: 205
# Current: ip_address=None  # TODO: Get from request context
# Need: Middleware to extract and pass client IP
```

### 3. Load Test Connection Pools
- Simulate 1000 concurrent users
- Verify pool settings are adequate
- Monitor for connection exhaustion

### 4. Add Critical Monitoring Alerts
- Connection pool > 70% utilization
- Encryption error rate > 0
- Email hash collision rate monitoring
- Connection timeout rate > 1%

### 5. Verify Email Hash Migration
- Ensure automated population in migration script
- Test with large dataset
- Add progress tracking

## Low Priority 🟢

### 6. Monitor Email Hash Collisions
- Add metric to track collision rate
- Should always be 0 in production

### 7. Update API Documentation Examples
- Use more complex password examples
- Update OpenAPI spec examples

## Completed ✅

*Move items here when resolved*

---

## Quick Fixes Script

For quick resolution of known issues:

```bash
#!/bin/bash
# fix-known-issues.sh

echo "Fixing database pool recycle mismatch..."
sed -i 's/pool_recycle=3600/pool_recycle=settings.DATABASE_POOL_RECYCLE/g' src/core/database.py

echo "Adding TODO marker for IP logging..."
# Already present, just needs implementation

echo "Done! Please review changes before committing."
```