# Database Management Guide

This guide provides best practices for managing databases and migrations in our enterprise microservices architecture.

## Overview

Our application follows a **database-per-service** pattern where each microservice owns and manages its own database:

- **auth-service** → `auth_db`
- **user-service** → `user_db`
- **api-gateway** → `gateway_db`

This pattern ensures service autonomy, independent scaling, and clear bounded contexts.

## Current Implementation

### Database Structure
```
/services/
├── auth-service/
│   ├── alembic.ini
│   └── alembic/
│       └── versions/
│           ├── 001_initial_auth_schema.py
│           ├── 002_seed_initial_data.py
│           ├── 003_add_email_hash_index.py
│           └── 004_add_hipaa_soc2_compliance.py
├── user-service/
│   └── alembic/
└── api-gateway/
    └── alembic/
```

### Database Initialization
- PostgreSQL with multiple databases
- Initialization script: `/scripts/init-multiple-databases.sh`
- Docker Compose configuration for local development

## Best Practices

### 1. Migration Management

#### Standardized Structure
Each service should maintain this structure:
```
/services/{service-name}/
├── alembic.ini
├── alembic/
│   ├── env.py
│   ├── script.py.mako
│   └── versions/
├── database/
│   ├── seeds/
│   │   ├── essential/      # Critical system data
│   │   ├── development/    # Dev environment data
│   │   ├── staging/        # Staging environment data
│   │   └── production/     # Production-only data
│   ├── views/              # Database views
│   ├── functions/          # Stored procedures
│   └── indexes/            # Performance indexes
└── scripts/
    ├── db-init.sh
    ├── db-migrate.sh
    └── db-rollback.sh
```

#### Migration Naming Convention
```
{sequence}_{description}.py

Examples:
001_initial_schema.py
002_add_user_roles.py
003_add_performance_indexes.py
```

#### Migration Best Practices
1. **Always test migrations** in development first
2. **Include rollback logic** in every migration
3. **Keep migrations idempotent** when possible
4. **Avoid data migrations** in schema migrations
5. **Use transactions** for data safety

### 2. Seed Data Management

#### Environment-Specific Seeds
```python
# Example: alembic/versions/002_seed_essential_data.py
def upgrade():
    # Essential data for all environments
    op.bulk_insert(role_table, [
        {'name': 'admin', 'is_system_role': True},
        {'name': 'user', 'is_system_role': True}
    ])
    
    # Environment-specific data
    if os.getenv('ENVIRONMENT') == 'development':
        load_development_data()

def load_development_data():
    # Test users, sample data, etc.
    pass
```

#### Seed Data Categories
1. **Essential**: System roles, permissions, configurations
2. **Development**: Test users, sample data
3. **Staging**: Limited test data
4. **Production**: Production-specific configurations

### 3. Production Migration Strategy

#### Pre-Migration Checklist
- [ ] Backup current database
- [ ] Test migration in staging
- [ ] Review migration SQL
- [ ] Check disk space
- [ ] Schedule maintenance window
- [ ] Notify stakeholders

#### Safe Migration Process
```bash
# 1. Backup
pg_dump $DATABASE_URL > backup_$(date +%Y%m%d_%H%M%S).sql

# 2. Test migration (dry run)
alembic upgrade head --sql

# 3. Execute migration
alembic upgrade head

# 4. Verify
alembic current
```

#### Rollback Procedures
```bash
# Immediate rollback (last migration)
alembic downgrade -1

# Specific version rollback
alembic downgrade {revision_id}

# Emergency restore from backup
psql $DATABASE_URL < backup_20240101_120000.sql
```

### 4. Cross-Service Data Consistency

Since each service owns its data, we need patterns for maintaining consistency:

#### Event-Driven Architecture (Recommended)
```
User Registration Flow:
1. auth-service creates user → publishes UserCreated event
2. user-service receives event → creates user profile
3. gateway-service receives event → updates routing rules
```

#### Saga Pattern for Distributed Transactions
```python
# Choreography-based saga
class UserRegistrationSaga:
    steps = [
        CreateAuthUser(),
        CreateUserProfile(),
        SendWelcomeEmail(),
        UpdateAnalytics()
    ]
    
    compensations = [
        DeleteAuthUser(),
        DeleteUserProfile(),
        # No compensation needed for email
        # No compensation needed for analytics
    ]
```

### 5. Database Performance

#### Essential Indexes
```sql
-- User email lookup (encrypted field)
CREATE INDEX idx_user_email_hash ON "user" USING hash(email);

-- Session management
CREATE INDEX idx_session_expires ON user_session (expires_at) 
WHERE is_active = true;

-- Audit trail queries
CREATE INDEX idx_audit_user_time ON audit_log (user_id, timestamp DESC);
```

#### Monitoring Queries
```sql
-- Slow queries
SELECT query, mean_time, calls 
FROM pg_stat_statements 
WHERE mean_time > 1000 
ORDER BY mean_time DESC;

-- Unused indexes
SELECT indexname, idx_scan 
FROM pg_stat_user_indexes 
WHERE idx_scan = 0;

-- Table bloat
SELECT tablename, n_dead_tup 
FROM pg_stat_user_tables 
WHERE n_dead_tup > n_live_tup * 0.1;
```

### 6. Backup and Recovery

#### Automated Backup Strategy
```yaml
# docker-compose.yml addition
backup:
  image: postgres:15-alpine
  environment:
    - BACKUP_SCHEDULE="0 2 * * *"  # Daily at 2 AM
    - RETENTION_DAYS=7
  volumes:
    - ./backups:/backups
  command: ["/scripts/automated-backup.sh"]
```

#### Recovery Time Objectives
- **RTO** (Recovery Time Objective): < 4 hours
- **RPO** (Recovery Point Objective): < 1 hour

### 7. Security Considerations

#### Database Access
- Each service has its own database user
- Minimal required permissions
- Connection encryption (SSL/TLS)
- No shared database access between services

#### Sensitive Data
- Encrypt PII at rest
- Use column-level encryption for sensitive fields
- Audit all access to sensitive data
- Regular security scans

## Migration Workflow

### Development Workflow
```bash
# 1. Create new migration
cd services/auth-service
alembic revision -m "add user preferences table"

# 2. Edit migration file
# Add upgrade() and downgrade() logic

# 3. Test locally
docker-compose up -d postgres
alembic upgrade head

# 4. Verify
alembic current
```

### Production Deployment
```bash
# 1. Deploy new code (without running migrations)
kubectl apply -f k8s/auth-service.yaml

# 2. Run migration job
kubectl apply -f k8s/jobs/auth-service-migrate.yaml

# 3. Monitor migration
kubectl logs -f job/auth-service-migrate

# 4. Verify and scale up
kubectl scale deployment auth-service --replicas=3
```

## Common Issues and Solutions

### Issue: Migration Conflicts
**Solution**: Use sequential numbering and coordinate migrations across team

### Issue: Slow Migrations
**Solution**: Run migrations during maintenance windows, use `CONCURRENTLY` for indexes

### Issue: Failed Migrations
**Solution**: Always include rollback logic, maintain recent backups

### Issue: Cross-Service Queries
**Solution**: Use API calls or events instead of direct database access

## SQL File Organization

If you need to maintain SQL files outside of migrations:

```
/database/
├── schemas/           # Reference schemas
├── views/            # Complex views
├── functions/        # Stored procedures
├── monitoring/       # Performance queries
└── maintenance/      # Cleanup scripts
```

## Tools and Scripts

### Database Migration Script
```bash
#!/bin/bash
# /scripts/db-migrate.sh

SERVICE=$1
ENVIRONMENT=${ENVIRONMENT:-development}

cd services/$SERVICE
alembic upgrade head
```

### Health Check Script
```bash
#!/bin/bash
# /scripts/db-health.sh

for db in auth_db user_db gateway_db; do
    psql $db -c "SELECT 1" > /dev/null && echo "$db: OK" || echo "$db: FAILED"
done
```

## Future Enhancements

1. **Event Sourcing**: For complete audit trail
2. **Change Data Capture**: For real-time data synchronization
3. **Read Replicas**: For scaling read operations
4. **Database Sharding**: For horizontal scaling
5. **Automated Failover**: For high availability

## References

- [Alembic Documentation](https://alembic.sqlalchemy.org/)
- [PostgreSQL Best Practices](https://wiki.postgresql.org/wiki/Main_Page)
- [Microservices Database Patterns](https://microservices.io/patterns/data/database-per-service.html)
- [Distributed Transaction Patterns](https://developers.redhat.com/blog/2018/10/01/patterns-for-distributed-transactions-within-a-microservices-architecture)