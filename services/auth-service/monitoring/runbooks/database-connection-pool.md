# Database Connection Pool Issues

**Alert Names**: `DatabaseConnectionPoolHigh`, `DatabaseConnectionPoolCritical`

## Overview
Database connection pool utilization alerts indicate that the auth service is approaching or has reached the maximum number of database connections. This can lead to request failures and service degradation.

## Severity Levels
- **Warning (>70%)**: Connection pool utilization is high but manageable
- **Critical (>90%)**: Connection pool is nearly exhausted, immediate action required

## Immediate Response (Critical)

### 1. Assess Current Impact
```bash
# Check current connection pool status
kubectl logs -l app=auth-service --tail=100 | grep -i "connection"

# Check if requests are failing
curl -f http://auth-service:8000/health
curl -f http://auth-service:8000/ready
```

### 2. Check Database Connection Status
```sql
-- Connect to the database and run:
SELECT 
  datname,
  count(*) as total_connections,
  count(*) FILTER (WHERE state = 'active') as active,
  count(*) FILTER (WHERE state = 'idle') as idle,
  count(*) FILTER (WHERE state = 'idle in transaction') as idle_in_transaction,
  max(EXTRACT(epoch FROM (now() - query_start))) as longest_query_seconds
FROM pg_stat_activity 
WHERE datname = 'authdb' 
GROUP BY datname;
```

### 3. Identify Connection Leaks
```sql
-- Check for long-running queries
SELECT 
  pid,
  now() - pg_stat_activity.query_start AS duration,
  query,
  state,
  client_addr
FROM pg_stat_activity 
WHERE datname = 'authdb' 
  AND now() - pg_stat_activity.query_start > interval '1 minute'
ORDER BY duration DESC;

-- Check for idle connections in transaction
SELECT 
  pid,
  state,
  now() - state_change as state_duration,
  query
FROM pg_stat_activity 
WHERE datname = 'authdb' 
  AND state = 'idle in transaction'
  AND now() - state_change > interval '30 seconds';
```

## Root Cause Analysis

### Common Causes
1. **Application Code Issues**
   - Connection leaks in application code
   - Missing connection cleanup in error handlers
   - Long-running transactions not being committed

2. **Database Performance Issues**
   - Slow queries holding connections longer
   - Lock contention causing transactions to wait
   - Database maintenance operations

3. **Load Increases**
   - Traffic spikes exceeding expected capacity
   - New features increasing database usage
   - Batch jobs running during peak hours

4. **Configuration Issues**
   - Pool size too small for current load
   - Connection timeout settings too high
   - Improper connection pooling configuration

## Troubleshooting Steps

### Step 1: Check Application Logs
```bash
# Look for connection-related errors
kubectl logs -l app=auth-service --since=30m | grep -E "(connection|pool|timeout|database)"

# Check for specific error patterns
kubectl logs -l app=auth-service --since=30m | grep -E "(Connection pool exhausted|Connection timeout|Too many connections)"
```

### Step 2: Analyze Current Connections
```sql
-- Get detailed connection information
SELECT 
  pid,
  usename,
  application_name,
  client_addr,
  state,
  query_start,
  state_change,
  query
FROM pg_stat_activity 
WHERE datname = 'authdb'
ORDER BY query_start;
```

### Step 3: Check for Blocking Queries
```sql
-- Identify blocking queries
SELECT 
  blocked_locks.pid AS blocked_pid,
  blocked_activity.usename AS blocked_user,
  blocking_locks.pid AS blocking_pid,
  blocking_activity.usename AS blocking_user,
  blocked_activity.query AS blocked_statement,
  blocking_activity.query AS current_statement_in_blocking_process
FROM pg_catalog.pg_locks blocked_locks
JOIN pg_catalog.pg_stat_activity blocked_activity ON blocked_activity.pid = blocked_locks.pid
JOIN pg_catalog.pg_locks blocking_locks ON blocking_locks.locktype = blocked_locks.locktype
    AND blocking_locks.DATABASE IS NOT DISTINCT FROM blocked_locks.DATABASE
    AND blocking_locks.relation IS NOT DISTINCT FROM blocked_locks.relation
    AND blocking_locks.page IS NOT DISTINCT FROM blocked_locks.page
    AND blocking_locks.tuple IS NOT DISTINCT FROM blocked_locks.tuple
    AND blocking_locks.virtualxid IS NOT DISTINCT FROM blocked_locks.virtualxid
    AND blocking_locks.transactionid IS NOT DISTINCT FROM blocked_locks.transactionid
    AND blocking_locks.classid IS NOT DISTINCT FROM blocked_locks.classid
    AND blocking_locks.objid IS NOT DISTINCT FROM blocked_locks.objid
    AND blocking_locks.objsubid IS NOT DISTINCT FROM blocked_locks.objsubid
    AND blocking_locks.pid != blocked_locks.pid
JOIN pg_catalog.pg_stat_activity blocking_activity ON blocking_activity.pid = blocking_locks.pid
WHERE NOT blocked_locks.GRANTED;
```

## Resolution Strategies

### Immediate Fixes

#### 1. Kill Long-Running Queries (Extreme Cases Only)
```sql
-- Kill specific problematic queries (use with caution)
SELECT pg_terminate_backend(pid) 
FROM pg_stat_activity 
WHERE datname = 'authdb' 
  AND state = 'idle in transaction'
  AND now() - state_change > interval '10 minutes';
```

#### 2. Restart Application Instances
```bash
# Rolling restart to clear connection leaks
kubectl rollout restart deployment/auth-service

# Wait for rollout to complete
kubectl rollout status deployment/auth-service
```

#### 3. Temporary Pool Size Increase
```bash
# Increase connection pool size (if possible)
kubectl set env deployment/auth-service DATABASE_POOL_SIZE=100
kubectl set env deployment/auth-service DATABASE_MAX_OVERFLOW=150
```

### Long-term Solutions

#### 1. Optimize Database Queries
- Review slow query log
- Add missing indexes
- Optimize JOIN operations
- Use EXPLAIN ANALYZE for query plans

#### 2. Review Connection Pool Configuration
```python
# Recommended connection pool settings
DATABASE_POOL_SIZE = 20  # Base pool size
DATABASE_MAX_OVERFLOW = 40  # Maximum overflow connections
DATABASE_POOL_TIMEOUT = 30  # Connection timeout in seconds
DATABASE_POOL_RECYCLE = 1800  # Recycle connections every 30 minutes
DATABASE_POOL_PRE_PING = True  # Test connections before use
```

#### 3. Implement Connection Monitoring
```python
# Add connection pool metrics to application
from prometheus_client import Gauge

CONNECTION_POOL_SIZE = Gauge('auth_service_db_connections_total', 'Total database connections in pool')
CONNECTION_POOL_ACTIVE = Gauge('auth_service_db_connections_active', 'Active database connections')
CONNECTION_POOL_IDLE = Gauge('auth_service_db_connections_idle', 'Idle database connections')
```

#### 4. Add Circuit Breaker Pattern
```python
# Implement circuit breaker for database operations
from circuitbreaker import circuit

@circuit(failure_threshold=5, recovery_timeout=10)
async def database_operation():
    # Database operation with circuit breaker
    pass
```

## Prevention

### Code Review Checklist
- [ ] All database connections are properly closed
- [ ] Connection cleanup in exception handlers
- [ ] Use context managers for database operations
- [ ] Avoid long-running transactions
- [ ] Implement proper error handling

### Monitoring Setup
- [ ] Connection pool utilization metrics
- [ ] Connection timeout rate monitoring
- [ ] Query execution time tracking
- [ ] Database lock monitoring

### Capacity Planning
- [ ] Regular load testing
- [ ] Connection pool sizing based on expected load
- [ ] Auto-scaling policies for high load
- [ ] Database performance monitoring

## Escalation

### When to Escalate
- Connection pool remains above 90% for >10 minutes
- Service becomes unavailable due to connection issues
- Database performance severely degraded
- Multiple application restarts don't resolve the issue

### Escalation Path
1. **Database Team** - For database-specific issues
2. **Platform Team** - For infrastructure-related problems
3. **Development Team** - For application code issues
4. **Management** - If business impact is significant

### Information to Provide
- Current connection pool utilization
- Recent application changes
- Database performance metrics
- Error logs and stack traces
- Timeline of the incident

## Post-Incident Actions

### Immediate
- [ ] Document the incident in post-mortem
- [ ] Review and update alert thresholds if needed
- [ ] Check for similar issues in other services

### Follow-up
- [ ] Conduct root cause analysis
- [ ] Implement preventive measures
- [ ] Update monitoring and alerting
- [ ] Schedule capacity planning review
- [ ] Update runbooks based on learnings

## Related Runbooks
- [Slow Response Times](./slow-response-times.md)
- [Database Performance Issues](./database-performance.md)
- [Service Down](./service-down.md)