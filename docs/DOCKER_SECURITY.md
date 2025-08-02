# Docker Compose Security Improvements

This document outlines the security and architectural improvements made to the Docker Compose configuration.

## Overview

The new `docker-compose.secure.yml` file addresses all security and architectural concerns identified during the security audit:

### Security Issues Fixed

1. **Hardcoded Credentials** ✅
   - All sensitive values moved to environment variables
   - Secure password generation script provided
   - `.env.docker` template with password generation commands

2. **Redis Authentication** ✅
   - Redis now requires password authentication
   - ACL (Access Control Lists) configured for fine-grained permissions
   - Dangerous commands disabled

3. **Network Segmentation** ✅
   - Four isolated networks:
     - `edge_network`: Internet-facing (nginx only)
     - `frontend_network`: DMZ for frontend services
     - `backend_network`: Internal services (no external access)
     - `database_network`: Database tier (no external access)
     - `admin_network`: Admin tools (restricted access)

4. **Non-Root Containers** ✅
   - All services run as non-root users
   - Each service has unique UID/GID
   - Proper file permissions set

5. **Read-Only Filesystems** ✅
   - Application code mounted as read-only
   - Writable volumes only where necessary
   - tmpfs mounts for temporary files

6. **Resource Limits** ✅
   - CPU and memory limits for all services
   - Prevents resource exhaustion attacks
   - Configurable via environment variables

7. **Security Hardening** ✅
   - Dropped all unnecessary Linux capabilities
   - Added security options (`no-new-privileges`)
   - Health checks for all services
   - Removed sensitive debug information

8. **SSL/TLS Support** ✅
   - PostgreSQL SSL configuration
   - Nginx SSL configuration ready
   - Self-signed certificates for development

### Architectural Issues Fixed

1. **Service Dependencies** ✅
   - Proper health checks before dependent services start
   - Restart policies configured
   - Maximum retry limits

2. **Volume Management** ✅
   - Bind mounts for data persistence
   - Separate volumes for logs
   - Proper permissions on all volumes

3. **Port Binding** ✅
   - Services bind to localhost only (127.0.0.1)
   - Internal services use `expose` instead of `ports`
   - Only nginx exposes public ports

4. **Configuration Management** ✅
   - Secure configuration files for Redis and Nginx
   - Environment-specific overrides
   - Development vs production separation

## Usage

### Initial Setup

1. Run the initialization script:
   ```bash
   ./scripts/init-docker-secure.sh
   ```

2. Review the generated `.env` file and adjust as needed

3. Check security settings:
   ```bash
   ./check-security.sh
   ```

### Running the Secure Environment

For production-like security:
```bash
docker-compose -f docker-compose.secure.yml up
```

For development with hot-reload:
```bash
docker-compose -f docker-compose.secure.yml -f docker-compose.override.yml up
```

### Accessing Services

- Frontend: http://localhost
- API: http://localhost/api
- PgAdmin: http://localhost:5050 (only with `--profile tools`)
- Redis Commander: http://localhost:8081 (only with `--profile tools`)

### Admin Tools

To run with admin tools:
```bash
docker-compose -f docker-compose.secure.yml --profile tools up
```

## Security Best Practices

1. **Never commit `.env` files** - Use `.env.example` as template
2. **Rotate passwords regularly** - Especially in production
3. **Use proper SSL certificates** - Replace self-signed certs in production
4. **Monitor logs** - Check log volumes for suspicious activity
5. **Update regularly** - Keep base images updated
6. **Limit access** - Use firewalls to restrict access to admin tools

## Network Architecture

```
Internet
    |
[Edge Network]
    |
  Nginx (80/443)
    |
[Frontend Network] 
    |
  Frontend ← → API Gateway
                    |
              [Backend Network] (Internal)
                    |
              Auth Service
              User Service
                    |
              [Database Network] (Internal)
                    |
              PostgreSQL
               Redis

[Admin Network] (Isolated)
    |
  PgAdmin
  Redis Commander
```

## Resource Limits

Default resource limits (configurable via environment variables):

| Service | CPU Limit | Memory Limit | CPU Reservation | Memory Reservation |
|---------|-----------|--------------|-----------------|-------------------|
| PostgreSQL | 1.0 | 1GB | 0.25 | 256MB |
| Redis | 0.5 | 512MB | 0.1 | 128MB |
| Services | 0.5 | 512MB | 0.1 | 128MB |
| Frontend | 0.25 | 256MB | 0.1 | 64MB |
| Nginx | 0.5 | 256MB | 0.1 | 64MB |

## Monitoring and Logging

- All services write logs to dedicated volumes
- Log rotation should be configured on the host
- Health checks run every 30 seconds
- Failed health checks trigger restarts

## Troubleshooting

### Permission Denied Errors
- Ensure data directories have correct ownership
- Check that UIDs in Dockerfiles match your system

### Connection Refused
- Verify services are healthy: `docker-compose ps`
- Check network connectivity: `docker network ls`
- Review service logs: `docker-compose logs <service>`

### High Memory Usage
- Adjust resource limits in `.env`
- Monitor with: `docker stats`

## Migration from Old docker-compose.yml

1. Backup existing data
2. Stop old containers: `docker-compose down`
3. Run initialization script
4. Copy data from old volumes if needed
5. Start new secure environment

## Production Considerations

1. Use external secret management (e.g., HashiCorp Vault)
2. Enable TLS for all services
3. Use managed databases where possible
4. Implement proper backup strategies
5. Enable audit logging
6. Use container scanning in CI/CD
7. Implement network policies in Kubernetes