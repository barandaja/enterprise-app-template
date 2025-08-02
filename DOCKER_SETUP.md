# Docker Development Setup

This document provides instructions for running the enterprise application stack locally using Docker Compose.

## Quick Start

1. **Ensure Docker is running**
   ```bash
   docker --version
   docker-compose --version
   ```

2. **Start the development environment**
   ```bash
   ./scripts/start-dev.sh
   ```

3. **Access the application**
   - Frontend: http://localhost
   - API Gateway: http://localhost:8000
   - Auth Service: http://localhost:8001
   - User Service: http://localhost:8002

## Architecture Overview

The development environment consists of the following services:

### Core Services
- **Frontend**: React application with Vite dev server (port 5173)
- **API Gateway**: Central routing and authentication (port 8000)
- **Auth Service**: Authentication and authorization (port 8001)
- **User Service**: User management and profiles (port 8002)

### Supporting Services
- **PostgreSQL**: Database server (port 5432)
- **Redis**: Caching and session storage (port 6379)
- **Nginx**: Reverse proxy and static file serving (port 80)

### Optional Admin Tools (Profile: tools)
- **PgAdmin**: Database administration (port 5050)
- **Redis Commander**: Redis administration (port 8081)

## Service Configuration

### Environment Variables

Each service uses environment-specific configuration:

#### Auth Service
- `DATABASE_URL`: PostgreSQL connection for auth database
- `REDIS_URL`: Redis connection for sessions
- `JWT_SECRET_KEY`: Secret for JWT token signing
- `CORS_ORIGINS`: Allowed CORS origins

#### User Service
- `DATABASE_URL`: PostgreSQL connection for user database
- `REDIS_URL`: Redis connection for caching
- `AUTH_SERVICE_URL`: Auth service endpoint

#### API Gateway
- `DATABASE_URL`: PostgreSQL connection for gateway database
- `REDIS_URL`: Redis connection for rate limiting
- `AUTH_SERVICE_URL`: Auth service endpoint
- `USER_SERVICE_URL`: User service endpoint

#### Frontend
- `VITE_API_URL`: API Gateway endpoint
- `VITE_AUTH_SERVICE_URL`: Direct auth service endpoint
- `VITE_USER_SERVICE_URL`: Direct user service endpoint

### Volume Mounts

Development mode uses volume mounts for hot reload:

- **Source code**: Mounted read-only for hot reload
- **Node modules**: Excluded for performance
- **Database data**: Persistent volumes
- **Redis data**: Persistent volumes

## Commands

### Basic Operations

```bash
# Start all services
./scripts/start-dev.sh

# Stop all services
./scripts/start-dev.sh stop

# Restart all services
./scripts/start-dev.sh restart

# View service status
./scripts/start-dev.sh status

# Check service health
./scripts/start-dev.sh health

# Clean up (stop and remove volumes)
./scripts/start-dev.sh clean
```

### Logs

```bash
# View all logs
./scripts/start-dev.sh logs

# View specific service logs
./scripts/start-dev.sh logs auth-service
./scripts/start-dev.sh logs frontend
./scripts/start-dev.sh logs postgres

# Follow logs in real-time
docker-compose logs -f
docker-compose logs -f auth-service
```

### Individual Service Management

```bash
# Rebuild a specific service
docker-compose up -d --build auth-service

# Restart a specific service
docker-compose restart frontend

# Stop a specific service
docker-compose stop user-service

# Start optional admin tools
docker-compose --profile tools up -d
```

### Database Operations

```bash
# Access PostgreSQL
docker-compose exec postgres psql -U enterprise_user -d auth_db

# Run migrations for auth service
docker-compose exec auth-service alembic upgrade head

# Create a new migration
docker-compose exec auth-service alembic revision --autogenerate -m "description"
```

### Redis Operations

```bash
# Access Redis CLI
docker-compose exec redis redis-cli

# Monitor Redis commands
docker-compose exec redis redis-cli monitor

# Check Redis info
docker-compose exec redis redis-cli info
```

## Development Workflow

### Hot Reload

All services are configured for hot reload in development:

- **Frontend**: Vite dev server with HMR
- **Backend Services**: Uvicorn with `--reload` flag
- **Configuration Changes**: Require service restart

### Code Changes

1. **Frontend**: Changes are automatically detected and hot-reloaded
2. **Backend**: Python files are watched and automatically reloaded
3. **Configuration**: Requires `docker-compose restart [service]`
4. **Dependencies**: Requires `docker-compose up -d --build [service]`

### Adding New Dependencies

#### Frontend
```bash
# Add dependency and rebuild
cd frontend
npm install new-package
docker-compose up -d --build frontend
```

#### Backend Services
```bash
# Update requirements.txt
echo "new-package==1.0.0" >> services/auth-service/requirements.txt

# Rebuild service
docker-compose up -d --build auth-service
```

### Database Schema Changes

```bash
# Create migration
docker-compose exec auth-service alembic revision --autogenerate -m "add new table"

# Apply migration
docker-compose exec auth-service alembic upgrade head

# Rollback migration
docker-compose exec auth-service alembic downgrade -1
```

## Troubleshooting

### Common Issues

#### Port Conflicts
```bash
# Check what's using a port
lsof -i :8000

# Kill process using port
kill $(lsof -t -i:8000)
```

#### Service Not Starting
```bash
# Check service logs
docker-compose logs auth-service

# Check service health
curl http://localhost:8001/health

# Restart service
docker-compose restart auth-service
```

#### Database Connection Issues
```bash
# Check if database is running
docker-compose ps postgres

# Check database logs
docker-compose logs postgres

# Test database connection
docker-compose exec postgres pg_isready -U enterprise_user
```

#### Permission Issues
```bash
# Fix script permissions
chmod +x scripts/*.sh

# Check Docker permissions
docker run hello-world
```

### Performance Issues

#### Slow Startup
- Ensure Docker has sufficient resources (4GB+ RAM)
- Use Docker Desktop resource limits appropriately
- Consider disabling unnecessary services

#### Hot Reload Not Working
- Check volume mounts in docker-compose.yml
- Restart the specific service
- Ensure file paths are correct

### Network Issues

#### Services Can't Communicate
```bash
# Check network configuration
docker network ls
docker network inspect enterprise_network

# Test service connectivity
docker-compose exec frontend curl http://api-gateway:8000/health
```

## Production Differences

Development configuration differs from production:

### Development Features
- Hot reload enabled
- Debug logging
- Exposed debug endpoints
- Relaxed security settings
- Volume mounts for source code

### Production Differences
- Multi-stage builds for optimization
- Security-hardened configurations
- No debug endpoints
- Optimized resource usage
- Proper secret management

## Security Considerations

### Development Security
- Default passwords (change for production)
- CORS allows localhost origins
- Debug endpoints enabled
- Relaxed rate limiting

### Production Checklist
- [ ] Change all default passwords
- [ ] Configure proper CORS origins
- [ ] Disable debug endpoints
- [ ] Enable rate limiting
- [ ] Use proper secret management
- [ ] Configure HTTPS
- [ ] Set up monitoring and alerting

## Monitoring and Observability

### Health Checks
All services include health check endpoints:
- Auth Service: `http://localhost:8001/health`
- User Service: `http://localhost:8002/health`
- API Gateway: `http://localhost:8000/health`

### Metrics
Services expose Prometheus metrics at `/metrics` endpoint.

### Logging
Structured JSON logging is configured for all services.

## Additional Resources

- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [React + Vite Documentation](https://vitejs.dev/)
- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [Redis Documentation](https://redis.io/documentation)