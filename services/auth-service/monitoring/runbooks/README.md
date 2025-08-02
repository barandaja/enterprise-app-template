# Auth Service Monitoring Runbooks

This directory contains incident response runbooks for the Enterprise Auth Service monitoring alerts. Each runbook provides step-by-step troubleshooting procedures, escalation paths, and resolution strategies.

## Quick Reference

| Alert | Severity | Response Time | Runbook |
|-------|----------|---------------|---------|
| AuthServiceDown | Critical | 1 minute | [Service Down](#service-down) |
| EncryptionErrorsDetected | Critical | 1 minute | [Encryption Errors](#encryption-errors) |
| EmailHashCollisionsDetected | Critical | 1 minute | [Email Hash Collisions](#email-hash-collisions) |
| DatabaseConnectionPoolCritical | Critical | 1 minute | [DB Pool Critical](#database-connection-pool) |
| AuthenticationFailureRateCritical | Critical | 1 minute | [Auth Failure Rate](#authentication-failure-rate) |
| AuditLogWriteFailures | Critical | 1 minute | [Audit Log Failures](#audit-log-failures) |
| DataRetentionPolicyViolation | Critical | 1 minute | [Data Retention](#data-retention-violations) |
| DatabaseConnectionPoolHigh | Warning | 5 minutes | [DB Pool High](#database-connection-pool) |
| AuthEndpointResponseTimeSlow | Warning | 5 minutes | [Slow Response Times](#slow-response-times) |
| RateLimitViolationsHigh | Warning | 5 minutes | [Rate Limit Violations](#rate-limit-violations) |

## Alert Categories

### 🚨 Critical Alerts (Page Immediately)
- Service availability issues
- Security breaches
- Data integrity problems
- Compliance violations

### ⚠️ Warning Alerts (Notify Team)
- Performance degradation
- Resource utilization issues
- Capacity concerns

### ℹ️ Info Alerts (Dashboard/Reports)
- Usage patterns
- Trends and analytics
- Preventive maintenance

## General Troubleshooting Workflow

1. **Acknowledge Alert** - Acknowledge in AlertManager/PagerDuty
2. **Assess Impact** - Check service status and user impact
3. **Initial Investigation** - Review dashboards and recent changes
4. **Escalate if Needed** - Follow escalation matrix
5. **Implement Fix** - Apply solution with minimal risk
6. **Verify Resolution** - Confirm alert clears and service is healthy
7. **Document** - Update incident log and post-mortem if needed

## Escalation Matrix

| Issue Type | Primary | Secondary | Management |
|------------|---------|-----------|------------|
| Security | Security Team | CISO | CTO |
| Compliance | Compliance Team | Legal | CEO |
| Infrastructure | DevOps Team | Platform Team | VP Engineering |
| Application | Development Team | Technical Lead | Engineering Manager |

## Communication Channels

- **Critical Incidents**: #incident-response
- **Security Issues**: #security-alerts
- **Infrastructure**: #devops-alerts
- **General**: #auth-service-alerts

## Tools and Access

### Required Access
- Grafana: Monitoring dashboards
- Prometheus: Metrics and alerts
- AlertManager: Alert management
- Kubectl: Kubernetes cluster access
- Database: Read access to auth DB
- Logs: Centralized logging system

### Emergency Contacts
- On-Call Engineer: Use PagerDuty
- Security Team: security@company.com
- Database Team: dba@company.com
- Compliance Team: compliance@company.com

## Dashboard Quick Links

- [Auth Service Overview](http://grafana.company.com/d/auth-service/auth-service-overview)
- [Security Dashboard](http://grafana.company.com/d/auth-security/auth-service-security)
- [Performance Dashboard](http://grafana.company.com/d/auth-performance/auth-service-performance)
- [Infrastructure Dashboard](http://grafana.company.com/d/auth-infra/auth-service-infrastructure)

## Common Commands

### Service Status
```bash
# Check service health
curl -f http://auth-service:8000/health

# Check readiness
curl -f http://auth-service:8000/ready

# View metrics
curl http://auth-service:8000/metrics
```

### Database
```bash
# Check connections
SELECT count(*), state FROM pg_stat_activity WHERE datname='authdb' GROUP BY state;

# Check slow queries
SELECT query, calls, total_time, rows, 100.0 * shared_blks_hit / nullif(shared_blks_hit + shared_blks_read, 0) AS hit_percent FROM pg_stat_statements ORDER BY total_time DESC LIMIT 10;
```

### Redis
```bash
# Check Redis status
redis-cli ping

# Check memory usage
redis-cli info memory

# Check connection count
redis-cli info clients
```

### Kubernetes
```bash
# Check pod status
kubectl get pods -l app=auth-service

# View logs
kubectl logs -l app=auth-service --tail=100

# Check resource usage
kubectl top pods -l app=auth-service
```

## Next Steps

Refer to individual runbook files for detailed troubleshooting procedures for each alert type.