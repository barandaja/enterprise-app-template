# Authentication Failure Rate High

**Alert Names**: `AuthenticationFailureRateHigh`, `AuthenticationFailureRateCritical`

## Overview
High authentication failure rates can indicate security attacks, system issues, or user experience problems. This alert monitors the percentage of failed authentication attempts versus total attempts.

## Severity Levels
- **Warning (>10%)**: Elevated failure rate requiring investigation
- **Critical (>25%)**: Very high failure rate indicating potential attack or system failure

## Immediate Response

### 1. Assess Current Situation
```bash
# Check current authentication metrics
curl -s http://auth-service:8000/metrics | grep -E "auth_service_auth_(attempts|failures|successes)_total"

# Calculate current failure rate
kubectl exec -it deployment/auth-service -- python3 -c "
import requests
import re
metrics = requests.get('http://localhost:8000/metrics').text
attempts = float(re.search(r'auth_service_auth_attempts_total ([0-9.]+)', metrics).group(1))
failures = float(re.search(r'auth_service_auth_failures_total ([0-9.]+)', metrics).group(1))
rate = (failures / attempts * 100) if attempts > 0 else 0
print(f'Current failure rate: {rate:.2f}%')
print(f'Total attempts: {attempts}')
print(f'Total failures: {failures}')
"
```

### 2. Check Service Health
```bash
# Verify service is responding
curl -f http://auth-service:8000/health
curl -f http://auth-service:8000/ready

# Check recent application logs
kubectl logs -l app=auth-service --since=15m | grep -i -E "(auth|login|fail)"
```

### 3. Identify Attack Patterns
```bash
# Look for brute force attack indicators
kubectl logs -l app=auth-service --since=30m | grep "authentication failed" | head -20

# Check for suspicious IP addresses
kubectl logs -l app=auth-service --since=30m | grep "authentication failed" | \
grep -o "client_ip: [0-9.]*" | sort | uniq -c | sort -nr | head -10

# Look for account enumeration attempts
kubectl logs -l app=auth-service --since=30m | grep "user not found" | \
grep -o "email: [a-zA-Z0-9@.]*" | sort | uniq -c | sort -nr | head -10
```

## Root Cause Analysis

### Common Causes

1. **Security Attacks**
   - Brute force attacks against user accounts
   - Credential stuffing with leaked passwords
   - Account enumeration attempts
   - Distributed attacks from multiple IPs

2. **System Issues**
   - Database connectivity problems
   - Password hashing service failures
   - Session management issues
   - Integration problems with external auth providers

3. **User Experience Issues**
   - Password policy changes confusing users
   - Account lockout policies too aggressive
   - UI/UX issues in login forms
   - Mobile app authentication bugs

4. **Configuration Issues**
   - Incorrect authentication logic
   - Wrong password validation rules
   - Clock synchronization issues (for TOTP)
   - SSL/TLS certificate problems

## Detailed Investigation

### Step 1: Analyze Failure Patterns
```bash
# Get detailed failure breakdown by reason
kubectl logs -l app=auth-service --since=1h | grep "authentication failed" | \
grep -o "reason: [a-zA-Z_]*" | sort | uniq -c | sort -nr

# Check temporal patterns
kubectl logs -l app=auth-service --since=2h | grep "authentication failed" | \
grep -o "\d\d:\d\d:\d\d" | cut -c1-5 | sort | uniq -c

# Analyze user agent patterns (potential bot attacks)
kubectl logs -l app=auth-service --since=1h | grep "authentication failed" | \
grep -o "user_agent: [^\"]*" | sort | uniq -c | sort -nr | head -10
```

### Step 2: Check for Specific Attack Types
```bash
# Look for credential stuffing (same IP, multiple users)
kubectl logs -l app=auth-service --since=1h | grep "authentication failed" | \
awk '{print $X_for_IP, $X_for_email}' | sort | uniq -c | awk '$1 > 10' | head -20

# Check for brute force (same user, multiple attempts)
kubectl logs -l app=auth-service --since=1h | grep "authentication failed" | \
grep -o "email: [a-zA-Z0-9@.]*" | sort | uniq -c | awk '$1 > 5' | head -20

# Look for distributed attacks (many IPs, similar patterns)
kubectl logs -l app=auth-service --since=1h | grep "authentication failed" | \
grep -o "client_ip: [0-9.]*" | sort | uniq | wc -l
```

### Step 3: Verify System Components
```sql
-- Connect to database and check user account status
SELECT 
  COUNT(*) as total_users,
  COUNT(*) FILTER (WHERE locked_until > NOW()) as locked_users,
  COUNT(*) FILTER (WHERE password_expires_at < NOW()) as expired_passwords,
  COUNT(*) FILTER (WHERE failed_login_attempts >= 5) as high_failure_count
FROM users;

-- Check recent password changes
SELECT COUNT(*) as recent_password_changes
FROM users 
WHERE password_updated_at > NOW() - INTERVAL '24 hours';

-- Look for unusual account activity
SELECT email, failed_login_attempts, last_login_attempt, locked_until
FROM users 
WHERE failed_login_attempts > 3 OR locked_until > NOW()
ORDER BY failed_login_attempts DESC, last_login_attempt DESC
LIMIT 20;
```

### Step 4: Check External Dependencies
```bash
# If using external identity providers
# Check OAuth/SAML provider status
curl -f https://your-identity-provider.com/health

# Check LDAP/Active Directory connectivity
ldapsearch -H ldap://your-ldap-server -x -b "dc=company,dc=com" "(cn=test)" dn

# Verify time synchronization (important for TOTP)
ntpq -p
```

## Resolution Strategies

### Immediate Actions for Attacks

#### 1. Block Malicious IPs
```bash
# Get top attacking IP addresses
ATTACKING_IPS=$(kubectl logs -l app=auth-service --since=1h | \
grep "authentication failed" | grep -o "client_ip: [0-9.]*" | \
cut -d' ' -f2 | sort | uniq -c | awk '$1 > 20 {print $2}')

# Apply rate limiting or blocking (example with nginx ingress)
for ip in $ATTACKING_IPS; do
  kubectl annotate ingress auth-service-ingress \
    nginx.ingress.kubernetes.io/whitelist-source-range="0.0.0.0/0,!$ip/32"
done

# Or use a more sophisticated approach with fail2ban or cloud WAF
```

#### 2. Implement Emergency Rate Limiting
```bash
# Increase rate limiting temporarily
kubectl set env deployment/auth-service RATE_LIMIT_LOGIN_PER_MINUTE=2
kubectl set env deployment/auth-service RATE_LIMIT_LOGIN_PER_HOUR=10

# Enable additional security measures
kubectl set env deployment/auth-service REQUIRE_CAPTCHA_AFTER_FAILURES=3
kubectl set env deployment/auth-service EXTENDED_LOCKOUT_ENABLED=true
```

#### 3. Enable Additional Logging
```bash
# Increase logging verbosity for authentication events
kubectl set env deployment/auth-service LOG_LEVEL=DEBUG
kubectl set env deployment/auth-service AUDIT_AUTH_ATTEMPTS=true

# Enable geographic IP tracking
kubectl set env deployment/auth-service ENABLE_GEO_IP_LOGGING=true
```

### System Issue Resolutions

#### 1. Database Connection Issues
```bash
# Check database connectivity
kubectl exec -it deployment/auth-service -- python3 -c "
import asyncpg
import asyncio

async def test_db():
    try:
        conn = await asyncpg.connect('$DATABASE_URL')
        result = await conn.fetchval('SELECT 1')
        print(f'Database connection test: SUCCESS (result: {result})')
        await conn.close()
    except Exception as e:
        print(f'Database connection test: FAILED - {e}')

asyncio.run(test_db())
"

# If connection issues found, check connection pool
kubectl logs -l app=auth-service --since=30m | grep -i "connection"
```

#### 2. Password Hashing Issues
```bash
# Test password hashing functionality
kubectl exec -it deployment/auth-service -- python3 -c "
from src.core.security import hash_password, verify_password

test_password = 'test_password_123'
try:
    hashed = hash_password(test_password)
    verified = verify_password(test_password, hashed)
    print(f'Password hashing test: {'SUCCESS' if verified else 'FAILED'}')
except Exception as e:
    print(f'Password hashing test: FAILED - {e}')
"
```

#### 3. Session Management Issues
```bash
# Check Redis connectivity for session storage
kubectl exec -it deployment/auth-service -- python3 -c "
import redis
import os

try:
    r = redis.from_url(os.getenv('REDIS_URL'))
    r.ping()
    print('Redis connection test: SUCCESS')
except Exception as e:
    print(f'Redis connection test: FAILED - {e}')
"
```

### User Experience Fixes

#### 1. Account Unlock for Legitimate Users
```sql
-- Unlock accounts that may have been caught in legitimate lockouts
UPDATE users 
SET locked_until = NULL, failed_login_attempts = 0
WHERE locked_until > NOW() 
  AND last_successful_login > NOW() - INTERVAL '7 days'
  AND failed_login_attempts < 10;
```

#### 2. Temporary Password Policy Relaxation
```bash
# Temporarily relax password requirements if policy change caused issues
kubectl set env deployment/auth-service PASSWORD_MIN_LENGTH=8
kubectl set env deployment/auth-service PASSWORD_REQUIRE_SPECIAL=false

# Remember to revert these changes after resolution
```

## Advanced Analysis

### Security Intelligence
```bash
# Check against threat intelligence feeds
# (Replace with your threat intelligence service)
for ip in $(kubectl logs -l app=auth-service --since=1h | grep "authentication failed" | \
grep -o "client_ip: [0-9.]*" | cut -d' ' -f2 | sort -u); do
  echo "Checking IP: $ip"
  curl -s "https://api.abuseipdb.com/api/v2/check?ipAddress=$ip" \
    -H "Key: YOUR_API_KEY" | jq '.abuseConfidencePercentage'
done

# Check for known compromised credentials
# (This requires integration with services like HaveIBeenPwned)
```

### Performance Impact Analysis
```bash
# Check if high failure rate is affecting performance
kubectl top pods -l app=auth-service

# Monitor response times during the incident
curl -s http://auth-service:8000/metrics | grep http_request_duration_seconds
```

## Prevention Strategies

### Enhanced Security Measures
```python
# Implement adaptive authentication
class AdaptiveAuth:
    def __init__(self):
        self.failure_threshold = 3
        self.time_window = 300  # 5 minutes
        
    async def should_require_additional_auth(self, user_id: str, client_ip: str) -> bool:
        # Check recent failure rate for user
        user_failures = await self.get_recent_failures(user_id, self.time_window)
        
        # Check recent failures from IP
        ip_failures = await self.get_ip_failures(client_ip, self.time_window)
        
        # Require CAPTCHA or 2FA if thresholds exceeded
        return user_failures >= self.failure_threshold or ip_failures >= (self.failure_threshold * 2)
```

### Monitoring Enhancements
```yaml
# Additional metrics to implement
- auth_service_auth_failures_by_reason_total
- auth_service_auth_failures_by_ip_total
- auth_service_suspicious_patterns_detected_total
- auth_service_account_lockouts_total
- auth_service_captcha_challenges_total
```

### User Education
- Implement account security notifications
- Provide clear error messages for locked accounts
- Send security alerts for unusual login patterns
- Offer password reset guidance

## Escalation

### When to Escalate
- Failure rate remains >25% for >10 minutes after initial response
- Evidence of coordinated attack across multiple services
- System components failing causing authentication issues
- Suspected compromise of authentication mechanisms

### Escalation Path
1. **Security Team** - For attack-related incidents
2. **Platform Team** - For infrastructure issues
3. **Database Team** - For data-related problems
4. **CISO** - For significant security incidents
5. **Communications Team** - For user-facing issues

### Information to Provide
- Current failure rate and duration
- Attack pattern analysis (if applicable)
- Affected user count estimate
- System health status
- Actions taken so far

## Post-Incident Actions

### Immediate
- [ ] Analyze attack patterns and update defenses
- [ ] Review and update rate limiting policies
- [ ] Check for any compromised accounts
- [ ] Document lessons learned

### Follow-up
- [ ] Conduct security review of authentication system
- [ ] Update monitoring and alerting thresholds
- [ ] Implement additional security measures
- [ ] Review and update incident response procedures
- [ ] Consider security training for users if needed

## Related Runbooks
- [Rate Limit Violations](./rate-limit-violations.md)
- [Security Incidents](./security-incidents.md)
- [Service Down](./service-down.md)
- [Slow Response Times](./slow-response-times.md)