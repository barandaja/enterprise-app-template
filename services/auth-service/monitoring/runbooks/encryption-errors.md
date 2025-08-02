# Encryption/Decryption Errors

**Alert Name**: `EncryptionErrorsDetected`

## Overview
Encryption/decryption errors are critical security incidents that indicate potential data integrity issues, key management problems, or malicious attacks. Any encryption error rate > 0 requires immediate investigation.

## Severity Level
- **Critical**: ANY encryption/decryption errors (should be zero)

## Immediate Response

### 1. Acknowledge and Assess Impact
```bash
# Acknowledge the alert immediately
# Check current error rate
curl -s http://auth-service:8000/metrics | grep auth_service_encryption_errors_total

# Check service health
curl -f http://auth-service:8000/health
curl -f http://auth-service:8000/ready
```

### 2. Check Recent Logs for Error Details
```bash
# Get recent encryption-related logs
kubectl logs -l app=auth-service --since=10m | grep -i -E "(encrypt|decrypt|cipher|key)"

# Look for specific error patterns
kubectl logs -l app=auth-service --since=10m | grep -E "(EncryptionError|DecryptionError|InvalidKey|CipherError)"

# Check for stack traces
kubectl logs -l app=auth-service --since=10m --previous | grep -A 10 -B 5 "encryption"
```

### 3. Verify Key Management Service Status
```bash
# Check if using external key management (e.g., AWS KMS, HashiCorp Vault)
# Replace with your key management service health check
curl -f https://your-kms-service/health

# Check key access permissions
kubectl get secrets -n auth-service | grep encryption
```

## Root Cause Analysis

### Common Causes

1. **Key Management Issues**
   - Encryption keys rotated without proper application restart
   - Key management service downtime
   - Invalid or corrupted encryption keys
   - Permission issues accessing keys

2. **Data Corruption**
   - Corrupted encrypted data in database
   - Incomplete encryption operations
   - Database transaction rollbacks during encryption

3. **Application Issues**
   - Bug in encryption/decryption code
   - Incorrect cipher configuration
   - Memory corruption affecting encryption context

4. **Infrastructure Issues**
   - Hardware security module (HSM) failures
   - Network connectivity to key management service
   - Certificate expiration

5. **Security Incidents**
   - Malicious attempts to decrypt data
   - Key compromise or unauthorized access
   - Man-in-the-middle attacks

## Detailed Investigation

### Step 1: Analyze Error Patterns
```bash
# Get detailed error breakdown
kubectl logs -l app=auth-service --since=30m | grep -i encrypt | head -50

# Check error frequency and timing
kubectl logs -l app=auth-service --since=1h | grep -i encrypt | grep -o "\d\d:\d\d:\d\d" | sort | uniq -c

# Identify affected operations
kubectl logs -l app=auth-service --since=30m | grep -E "(encrypt|decrypt)" | grep -o "operation: [a-zA-Z_]*" | sort | uniq -c
```

### Step 2: Check Database for Data Integrity
```sql
-- Connect to auth database and check for encryption-related issues
-- Check for NULL or empty encrypted fields that should have data
SELECT COUNT(*) FROM users WHERE encrypted_email IS NULL AND email IS NOT NULL;
SELECT COUNT(*) FROM users WHERE encrypted_pii IS NULL AND sensitive_data IS NOT NULL;

-- Look for recently modified encrypted data
SELECT id, updated_at, created_at 
FROM users 
WHERE encrypted_email IS NOT NULL 
  AND updated_at > NOW() - INTERVAL '1 hour'
ORDER BY updated_at DESC
LIMIT 10;

-- Check for consistency issues
SELECT COUNT(*) as total,
       COUNT(encrypted_email) as encrypted_count,
       COUNT(email_hash) as hash_count
FROM users
WHERE created_at > NOW() - INTERVAL '1 hour';
```

### Step 3: Verify Encryption Configuration
```bash
# Check current encryption configuration
kubectl describe configmap auth-service-config | grep -i encrypt

# Verify environment variables
kubectl exec -it deployment/auth-service -- env | grep -E "(ENCRYPT|KEY|CIPHER)"

# Check mounted secrets
kubectl exec -it deployment/auth-service -- ls -la /etc/secrets/
```

### Step 4: Test Encryption/Decryption Functions
```bash
# Create a test script to verify encryption functionality
kubectl exec -it deployment/auth-service -- python3 -c "
from src.core.security import encrypt_data, decrypt_data
test_data = 'test_encryption_data'
try:
    encrypted = encrypt_data(test_data)
    decrypted = decrypt_data(encrypted)
    print(f'Test successful: {decrypted == test_data}')
except Exception as e:
    print(f'Encryption test failed: {e}')
"
```

## Resolution Strategies

### Immediate Actions

#### 1. If Key Management Service is Down
```bash
# Check key service status
curl -f https://your-key-service/health

# If using AWS KMS
aws kms describe-key --key-id your-key-id

# If using HashiCorp Vault
vault status
vault auth -method=aws
vault read secret/auth-service/encryption-key
```

#### 2. If Keys are Corrupted/Invalid
```bash
# Rotate to backup encryption key (if available)
kubectl set env deployment/auth-service ENCRYPTION_KEY_VERSION=backup

# Or restore from key backup
kubectl create secret generic auth-encryption-key \
  --from-literal=key="$(cat backup-encryption-key.txt)" \
  --dry-run=client -o yaml | kubectl apply -f -
```

#### 3. If Application Code Issue
```bash
# Roll back to previous version
kubectl rollout undo deployment/auth-service

# Check rollout status
kubectl rollout status deployment/auth-service

# Verify error resolution
sleep 60
curl -s http://auth-service:8000/metrics | grep auth_service_encryption_errors_total
```

### Emergency Procedures

#### 1. Stop All Encryption Operations (Last Resort)
```bash
# Set service to read-only mode to prevent data corruption
kubectl set env deployment/auth-service ENCRYPTION_ENABLED=false
kubectl set env deployment/auth-service READ_ONLY_MODE=true

# Scale down to single instance to prevent race conditions
kubectl scale deployment auth-service --replicas=1
```

#### 2. Data Backup and Recovery
```bash
# Create immediate database backup
kubectl exec -it postgres-pod -- pg_dump authdb > emergency-backup-$(date +%Y%m%d-%H%M%S).sql

# If data corruption suspected, restore from last known good backup
# kubectl exec -it postgres-pod -- psql authdb < last-good-backup.sql
```

### Long-term Fixes

#### 1. Implement Encryption Key Rotation
```python
# Add proper key versioning support
class EncryptionService:
    def __init__(self):
        self.current_key_version = os.getenv('ENCRYPTION_KEY_VERSION', 'v1')
        self.keys = {
            'v1': os.getenv('ENCRYPTION_KEY_V1'),
            'v2': os.getenv('ENCRYPTION_KEY_V2'),
        }
    
    def encrypt(self, data: str) -> str:
        key = self.keys[self.current_key_version]
        # Add key version to encrypted data
        encrypted = cipher.encrypt(data, key)
        return f"{self.current_key_version}:{encrypted}"
    
    def decrypt(self, encrypted_data: str) -> str:
        version, data = encrypted_data.split(':', 1)
        key = self.keys[version]
        return cipher.decrypt(data, key)
```

#### 2. Add Encryption Health Checks
```python
# Add encryption health monitoring
async def encryption_health_check():
    try:
        test_data = "health-check-data"
        encrypted = await encrypt_data(test_data)
        decrypted = await decrypt_data(encrypted)
        
        if decrypted != test_data:
            raise Exception("Encryption round-trip failed")
        
        return {"status": "healthy", "encryption": "operational"}
    except Exception as e:
        logger.error("Encryption health check failed", error=str(e))
        raise
```

#### 3. Implement Encryption Monitoring
```python
# Add detailed encryption metrics
ENCRYPTION_OPERATIONS = Counter(
    'auth_service_encryption_operations_total',
    'Total encryption operations',
    ['operation', 'status']
)

ENCRYPTION_DURATION = Histogram(
    'auth_service_encryption_duration_seconds',
    'Encryption operation duration'
)

def track_encryption_operation(operation: str):
    def decorator(func):
        async def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = await func(*args, **kwargs)
                ENCRYPTION_OPERATIONS.labels(operation=operation, status='success').inc()
                return result
            except Exception as e:
                ENCRYPTION_OPERATIONS.labels(operation=operation, status='error').inc()
                raise
            finally:
                ENCRYPTION_DURATION.observe(time.time() - start_time)
        return wrapper
    return decorator
```

## Security Considerations

### Immediate Security Actions
- [ ] Rotate encryption keys if compromise suspected
- [ ] Review access logs for unauthorized key access
- [ ] Check for unusual data access patterns
- [ ] Verify certificate validity and expiration dates

### Forensic Data Collection
```bash
# Collect logs for security analysis
kubectl logs -l app=auth-service --since=24h > encryption-incident-logs.txt

# Export relevant metrics
curl -s http://auth-service:8000/metrics > encryption-incident-metrics.txt

# Database audit logs (if available)
# psql authdb -c "SELECT * FROM audit_log WHERE operation LIKE '%encrypt%' AND timestamp > NOW() - INTERVAL '24 hours';"
```

### Incident Classification
- **Data Breach Risk**: If decryption errors expose sensitive data
- **Key Compromise**: If unauthorized access to encryption keys suspected
- **System Integrity**: If data corruption affects encrypted data
- **Availability Impact**: If encryption failures prevent normal operations

## Prevention

### Monitoring Enhancements
```yaml
# Additional metrics to implement
- auth_service_key_rotation_last_time
- auth_service_encryption_key_age_days
- auth_service_encryption_operations_per_second
- auth_service_decryption_latency_percentiles
```

### Key Management Best Practices
- Implement automatic key rotation
- Use hardware security modules (HSMs)
- Separate encryption keys by environment
- Regular key backup and recovery testing
- Implement key versioning and migration

### Code Quality Measures
- Comprehensive encryption unit tests
- Integration tests for key rotation scenarios
- Code review requirements for encryption changes
- Static analysis for cryptographic vulnerabilities

## Escalation

### When to Escalate Immediately
- Any encryption errors persist after initial remediation
- Suspected security breach or key compromise
- Data corruption detected in encrypted fields
- Key management service unavailable for >15 minutes

### Escalation Path
1. **Security Team** - For potential security incidents
2. **Database Team** - For data integrity issues
3. **Infrastructure Team** - For key management service issues
4. **CISO/Legal** - If data breach suspected
5. **Executive Team** - For business-critical impact

### Information to Provide
- Error rate and duration
- Affected operations and data types
- Security assessment of potential data exposure
- Steps taken for immediate containment
- Estimated business impact

## Post-Incident Actions

### Immediate
- [ ] Document all actions taken
- [ ] Preserve forensic evidence
- [ ] Notify compliance team if applicable
- [ ] Review and update encryption procedures

### Follow-up
- [ ] Conduct thorough post-mortem analysis
- [ ] Review and update encryption key management procedures
- [ ] Test key rotation and recovery procedures
- [ ] Update monitoring and alerting based on learnings
- [ ] Consider security training for development team

## Related Runbooks
- [Email Hash Collisions](./email-hash-collisions.md)
- [Audit Log Failures](./audit-log-failures.md)
- [Security Incidents](./security-incidents.md)
- [Data Retention Violations](./data-retention-violations.md)