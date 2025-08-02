# Auth Service Monitoring Stack

This directory contains a comprehensive monitoring setup for the Enterprise Auth Service with Prometheus, AlertManager, Grafana, and associated tooling.

## 🚀 Quick Start

### 1. Configuration Setup
```bash
# Copy environment configuration
cp .env.example .env

# Edit the configuration with your actual values
nano .env
```

### 2. Start Monitoring Stack
```bash
# Start core monitoring services
docker-compose -f docker-compose.monitoring.yml up -d

# Start with logging (optional)
docker-compose -f docker-compose.monitoring.yml --profile logging up -d

# Start with tracing (optional) 
docker-compose -f docker-compose.monitoring.yml --profile tracing up -d

# Start with database monitoring (if using external DB)
docker-compose -f docker-compose.monitoring.yml --profile postgres-monitoring up -d

# Start with Redis monitoring (if using external Redis)
docker-compose -f docker-compose.monitoring.yml --profile redis-monitoring up -d
```

### 3. Access Monitoring Services
- **Grafana**: http://localhost:3000 (admin/admin123)
- **Prometheus**: http://localhost:9090
- **AlertManager**: http://localhost:9093
- **Jaeger** (if enabled): http://localhost:16686

## 📊 Dashboards

### Available Dashboards
1. **Auth Service Overview** - Main service metrics and health
2. **Auth Service Security** - Security-focused monitoring and threat detection
3. **Auth Service Performance** - Performance metrics and optimization insights
4. **Auth Service Infrastructure** - System resources and dependencies

### Dashboard Features
- Real-time metrics visualization
- Alerting integration
- Template variables for multi-instance environments
- Drill-down capabilities
- Export/import functionality

## 🔔 Alerting

### Alert Categories

#### Critical Alerts (Immediate Response)
- Service unavailability
- Encryption/decryption errors
- Email hash collisions
- Database connection pool exhaustion (>90%)
- Authentication failure rate >25%
- Compliance violations
- Audit log failures

#### Warning Alerts (Team Notification)
- High connection pool utilization (>70%)
- Slow response times (>500ms)
- High authentication failure rate (>10%)
- Connection timeouts (>1%)
- Resource utilization issues

### Alert Routing
- **Critical alerts** → PagerDuty + Slack + Email
- **Security alerts** → Security team + SIEM integration
- **Compliance alerts** → Compliance team + Management
- **Warning alerts** → Team channels + Email

## 📈 Metrics

### Key Metrics Monitored

#### Security Metrics
- `auth_service_auth_attempts_total` - Authentication attempts
- `auth_service_auth_failures_total` - Authentication failures
- `auth_service_encryption_errors_total` - Encryption/decryption errors
- `auth_service_email_hash_collisions_total` - Email hash collisions
- `auth_service_rate_limit_violations_total` - Rate limit violations

#### Performance Metrics
- `http_request_duration_seconds` - Request response times
- `auth_service_db_connections_active` - Active database connections
- `auth_service_db_connections_total` - Total connection pool size
- `auth_service_redis_connections_active` - Active Redis connections

#### System Metrics
- `process_resident_memory_bytes` - Memory usage
- `process_cpu_seconds_total` - CPU usage
- `up` - Service availability

### Custom Metrics Integration
To add custom metrics to your auth service:

```python
from prometheus_client import Counter, Histogram, Gauge

# Example metrics
LOGIN_ATTEMPTS = Counter(
    'auth_service_login_attempts_total',
    'Total login attempts',
    ['status', 'method']
)

RESPONSE_TIME = Histogram(
    'auth_service_operation_duration_seconds',
    'Operation response time',
    ['operation']
)

ACTIVE_SESSIONS = Gauge(
    'auth_service_active_sessions',
    'Number of active user sessions'
)
```

## 🚨 Runbooks

Comprehensive incident response runbooks are available in the `runbooks/` directory:

- [Database Connection Pool Issues](./runbooks/database-connection-pool.md)
- [Encryption/Decryption Errors](./runbooks/encryption-errors.md)
- [Authentication Failure Rate](./runbooks/authentication-failure-rate.md)
- [Service Down](./runbooks/service-down.md)
- [Performance Issues](./runbooks/performance-issues.md)

Each runbook includes:
- Immediate response procedures
- Root cause analysis steps
- Resolution strategies
- Prevention measures
- Escalation paths

## 🔧 Configuration

### Prometheus Configuration
- **Scrape interval**: 15 seconds
- **Retention**: 30 days
- **Storage**: 50GB limit
- **Alert evaluation**: 15 seconds

### AlertManager Configuration
- **Group wait**: 30 seconds
- **Group interval**: 5 minutes
- **Repeat interval**: 12 hours
- **Inhibition rules**: Configured to prevent alert spam

### Grafana Configuration
- **Refresh interval**: 30 seconds
- **Time range**: Last 1 hour (default)
- **Data source**: Prometheus (primary)
- **Authentication**: Admin user with configurable password

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Auth Service  │───▶│   Prometheus    │───▶│  AlertManager   │
│                 │    │                 │    │                 │
│  /metrics       │    │  - Scraping     │    │  - Alerting     │
│  /health        │    │  - Storage      │    │  - Routing      │
│  /ready         │    │  - Querying     │    │  - Notifications│
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       ▼                       ▼
         ▼              ┌─────────────────┐    ┌─────────────────┐
┌─────────────────┐    │    Grafana      │    │    Slack/Email  │
│  System Metrics │    │                 │    │                 │
│                 │    │  - Dashboards   │    │  - Notifications│
│  - Node Exp.    │    │  - Visualization│    │  - PagerDuty    │
│  - cAdvisor     │    │  - Alerting     │    │  - SMS          │
│  - Blackbox     │    └─────────────────┘    └─────────────────┘
└─────────────────┘
```

## 🔒 Security Considerations

### Access Control
- Grafana admin credentials should be changed from defaults
- Prometheus and AlertManager should be behind authentication
- Network security groups should restrict access to monitoring ports
- Service accounts should use minimal required permissions

### Data Protection
- Sensitive data should not be included in metrics labels
- Alert messages should not contain PII
- Monitoring data retention should comply with data protection policies
- Logs should be sanitized of sensitive information

### Network Security
- All communications should use TLS in production
- Monitoring services should be in isolated network segments
- Firewall rules should restrict access to authorized systems only
- VPN access required for external monitoring access

## 🚀 Production Deployment

### Prerequisites
- Docker and Docker Compose installed
- Sufficient disk space for metrics storage (recommend 100GB+)
- Network connectivity to auth service instances
- SMTP server for email notifications
- Slack workspace and webhook URL
- PagerDuty account and integration key

### High Availability Setup
For production environments, consider:

```yaml
# Example HA Prometheus setup
prometheus:
  replicas: 2
  storage:
    class: ssd
    size: 100Gi
  affinity:
    podAntiAffinity: true

# Example HA Grafana setup  
grafana:
  replicas: 2
  database:
    type: postgres
    host: grafana-db.example.com
  persistence:
    enabled: true
    size: 10Gi
```

### Backup and Recovery
```bash
# Backup Prometheus data
docker exec prometheus tar czf /backup/prometheus-$(date +%Y%m%d).tar.gz /prometheus

# Backup Grafana data
docker exec grafana tar czf /backup/grafana-$(date +%Y%m%d).tar.gz /var/lib/grafana

# Backup AlertManager data
docker exec alertmanager tar czf /backup/alertmanager-$(date +%Y%m%d).tar.gz /alertmanager
```

## 📝 Maintenance

### Regular Tasks
- [ ] Weekly: Review and tune alert thresholds
- [ ] Monthly: Archive old metrics data
- [ ] Quarterly: Review and update dashboards
- [ ] Annually: Update monitoring stack versions

### Monitoring the Monitoring
- Set up alerts for monitoring stack health
- Monitor disk usage for metrics storage
- Track alert noise and false positive rates
- Regular testing of notification channels

## 🤝 Contributing

### Adding New Metrics
1. Add metric definition to auth service code
2. Update Prometheus configuration if needed
3. Create/update Grafana dashboards
4. Add relevant alerts to AlertManager
5. Document in runbooks if critical

### Improving Dashboards
1. Use template variables for flexibility
2. Include relevant documentation panels
3. Set appropriate refresh rates
4. Test across different time ranges
5. Export and version control dashboard JSON

## 📚 References

- [Prometheus Documentation](https://prometheus.io/docs/)
- [Grafana Documentation](https://grafana.com/docs/)
- [AlertManager Documentation](https://prometheus.io/docs/alerting/latest/alertmanager/)
- [Monitoring Best Practices](https://sre.google/workbook/monitoring/)
- [Site Reliability Engineering](https://sre.google/books/)

## 🆘 Support

For issues with the monitoring setup:
1. Check the troubleshooting section in individual runbooks
2. Review service logs: `docker-compose logs <service_name>`
3. Verify configuration files
4. Contact the platform/DevOps team
5. Create an issue in the monitoring repository