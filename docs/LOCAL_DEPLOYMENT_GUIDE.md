# Local Deployment Guide

This guide provides step-by-step instructions for deploying the enterprise application template locally with all security features enabled.

## Prerequisites

- Docker Desktop (version 20.10+)
- Docker Compose (version 2.0+)
- Node.js (version 18+)
- Python (version 3.10+)
- OpenSSL (for certificate generation)
- At least 8GB of free RAM
- 20GB of free disk space

## Deployment Order

The proper sequence for local deployment is critical due to service dependencies:

1. **Infrastructure Setup** (databases, message queues)
2. **Security Configuration** (certificates, secrets)
3. **Backend Services** (auth, user, gateway)
4. **Frontend Application**
5. **Event Infrastructure** (Kafka, event store)
6. **Monitoring & Tools**

## Step 1: Initial Setup

### 1.1 Clone and Navigate
```bash
git clone <repository-url>
cd enterprise-app-template
```

### 1.2 Create Required Directories
```bash
mkdir -p data/{postgres,redis,event_store}
mkdir -p logs/{auth,user,gateway,frontend}
mkdir -p config/kafka/secrets
mkdir -p config/ssl/{certs,private}
```

### 1.3 Set Directory Permissions
```bash
# PostgreSQL requires specific permissions
chmod 700 data/postgres
chmod 700 data/event_store

# Set ownership for PostgreSQL directories (UID 999)
sudo chown -R 999:999 data/postgres
sudo chown -R 999:999 data/event_store
```

## Step 2: Generate SSL Certificates

### 2.1 Create Certificate Authority
```bash
# Generate CA private key
openssl genrsa -out config/ssl/private/ca.key 4096

# Generate CA certificate
openssl req -new -x509 -days 3650 -key config/ssl/private/ca.key \
  -out config/ssl/certs/ca.crt \
  -subj "/C=US/ST=State/L=City/O=Enterprise/CN=Enterprise CA"
```

### 2.2 Generate Server Certificates
```bash
# PostgreSQL certificate
openssl genrsa -out config/ssl/private/server.key 2048
openssl req -new -key config/ssl/private/server.key \
  -out config/ssl/private/server.csr \
  -subj "/C=US/ST=State/L=City/O=Enterprise/CN=postgres"
openssl x509 -req -days 365 -in config/ssl/private/server.csr \
  -CA config/ssl/certs/ca.crt -CAkey config/ssl/private/ca.key \
  -CAcreateserial -out config/ssl/certs/server.crt

# Set PostgreSQL certificate permissions
chmod 600 config/ssl/private/server.key
sudo chown 999:999 config/ssl/private/server.key
sudo chown 999:999 config/ssl/certs/server.crt
```

### 2.3 Generate Kafka Certificates
```bash
cd config/kafka/secrets

# Create keystore for Kafka
keytool -keystore kafka.keystore.jks -alias kafka -validity 365 \
  -genkey -keyalg RSA -storetype pkcs12 \
  -dname "CN=kafka, OU=Enterprise, O=Enterprise, L=City, ST=State, C=US" \
  -storepass changeit -keypass changeit

# Create truststore
keytool -keystore kafka.truststore.jks -alias CARoot \
  -import -file ../../ssl/certs/ca.crt \
  -storepass changeit -noprompt

# Create credential files
echo "changeit" > keystore_creds
echo "changeit" > key_creds
echo "changeit" > truststore_creds

cd ../../..
```

## Step 3: Environment Configuration

### 3.1 Create Main .env File
```bash
cat > .env << 'EOF'
# Database
POSTGRES_PASSWORD=CHANGE_ME_postgres_password_$(openssl rand -hex 16)
REDIS_PASSWORD=CHANGE_ME_redis_password_$(openssl rand -hex 16)
EVENT_STORE_PASSWORD=CHANGE_ME_event_store_password_$(openssl rand -hex 16)

# JWT Secrets
JWT_SECRET_KEY=CHANGE_ME_jwt_secret_$(openssl rand -hex 32)
EVENT_JWT_SECRET=CHANGE_ME_event_jwt_$(openssl rand -hex 32)

# Encryption Keys
SECRET_KEY=CHANGE_ME_secret_key_$(openssl rand -hex 32)
EVENT_ENCRYPTION_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")

# Event Security
EVENT_HMAC_SECRET=CHANGE_ME_event_hmac_$(openssl rand -hex 32)

# Kafka Security
KAFKA_UI_PASSWORD=CHANGE_ME_kafka_ui_password_$(openssl rand -hex 16)

# API Keys
OPENAI_API_KEY=your_openai_api_key_here
SENDGRID_API_KEY=your_sendgrid_api_key_here
TWILIO_ACCOUNT_SID=your_twilio_account_sid
TWILIO_AUTH_TOKEN=your_twilio_auth_token

# Feature Flags
ENABLE_RATE_LIMITING=true
ENABLE_EVENT_STORE=true
ENABLE_SAGAS=true
ENABLE_RBAC=true

# Service URLs (for local development)
AUTH_SERVICE_URL=http://auth-service:8000
USER_SERVICE_URL=http://user-service:8001
API_GATEWAY_URL=http://localhost:8080
FRONTEND_URL=http://localhost:3000
EOF
```

### 3.2 Create Service-Specific .env Files

#### Auth Service (.env.auth)
```bash
cat > services/auth-service/.env << 'EOF'
DATABASE_URL=postgresql://auth_user:auth_pass@postgres:5432/auth_db
REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379/0
EVENT_BUS_TYPE=redis
SERVICE_NAME=auth_service
SERVICE_ROLE=auth-service
EOF
```

#### User Service (.env.user)
```bash
cat > services/user-service/.env << 'EOF'
DATABASE_URL=postgresql://user_user:user_pass@postgres:5432/user_db
REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379/1
EVENT_BUS_TYPE=redis
SERVICE_NAME=user_service
SERVICE_ROLE=user-service
EOF
```

#### Frontend (.env.local)
```bash
cat > frontend/.env.local << 'EOF'
NEXT_PUBLIC_API_URL=http://localhost:8080
NEXT_PUBLIC_WS_URL=ws://localhost:8080
NEXT_PUBLIC_ENABLE_MOCK_API=false
EOF
```

## Step 4: Docker Network Setup

```bash
# Create required networks
docker network create enterprise_backend
docker network create enterprise_database
docker network create enterprise_frontend
```

## Step 5: Infrastructure Deployment

### 5.1 Start Core Infrastructure
```bash
# Start databases and cache
docker-compose up -d postgres redis

# Wait for PostgreSQL to be ready
docker-compose exec postgres pg_isready -U postgres

# Initialize databases
docker-compose exec postgres psql -U postgres -f /docker-entrypoint-initdb.d/init-databases.sql
```

### 5.2 Run Database Migrations
```bash
# Auth service migrations
cd services/auth-service
alembic upgrade head
cd ../..

# User service migrations
cd services/user-service
alembic upgrade head
cd ../..
```

## Step 6: Backend Services Deployment

### 6.1 Build Backend Services
```bash
# Build all services
docker-compose build auth-service user-service api-gateway
```

### 6.2 Start Backend Services
```bash
# Start in dependency order
docker-compose up -d auth-service
docker-compose up -d user-service
docker-compose up -d api-gateway

# Check health
docker-compose ps
docker-compose logs --tail=50 auth-service
```

## Step 7: Frontend Deployment

### 7.1 Install Dependencies
```bash
cd frontend
npm install
```

### 7.2 Build Frontend
```bash
npm run build
```

### 7.3 Start Frontend
```bash
# Development mode
npm run dev

# Or using Docker
cd ..
docker-compose up -d frontend
```

## Step 8: Event Infrastructure (Optional for Basic Setup)

### 8.1 Start Event Infrastructure
```bash
# For Redis-based events (development)
# Already running with core infrastructure

# For Kafka-based events (production-like)
docker-compose -f docker-compose.events.secure.yml up -d zookeeper
docker-compose -f docker-compose.events.secure.yml up -d kafka
docker-compose -f docker-compose.events.secure.yml up -d event-store-db

# Run Kafka setup
docker-compose -f docker-compose.events.secure.yml --profile setup up kafka-setup
```

### 8.2 Initialize Event Store
```bash
docker-compose -f docker-compose.events.secure.yml exec event-store-db \
  psql -U event_user -d event_store -f /docker-entrypoint-initdb.d/init.sql
```

## Step 9: Monitoring and Tools

### 9.1 Start Monitoring Stack
```bash
docker-compose -f docker-compose.monitoring.yml up -d
```

### 9.2 Start Development Tools
```bash
# Kafka UI (if using Kafka)
docker-compose -f docker-compose.events.secure.yml --profile tools up -d kafka-ui

# pgAdmin for database management
docker-compose --profile tools up -d pgadmin
```

## Step 10: Verification

### 10.1 Check Service Health
```bash
# Check all services are running
docker-compose ps

# Check API Gateway health
curl http://localhost:8080/health

# Check Auth Service health
curl http://localhost:8080/auth/health

# Check Frontend
curl http://localhost:3000
```

### 10.2 Test Authentication Flow
```bash
# Register a new user
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "Test123!@#",
    "username": "testuser"
  }'

# Login
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "Test123!@#"
  }'
```

## Troubleshooting

### Common Issues

1. **PostgreSQL Permission Errors**
   ```bash
   sudo chown -R 999:999 data/postgres
   sudo chmod 700 data/postgres
   ```

2. **Port Already in Use**
   ```bash
   # Find process using port
   lsof -i :8080
   # Kill process or change port in docker-compose.yml
   ```

3. **SSL Certificate Issues**
   ```bash
   # Regenerate certificates
   rm -rf config/ssl/*
   # Follow Step 2 again
   ```

4. **Kafka Connection Issues**
   ```bash
   # Check Kafka logs
   docker-compose -f docker-compose.events.secure.yml logs kafka
   # Ensure Zookeeper is healthy first
   ```

5. **Frontend Build Errors**
   ```bash
   cd frontend
   rm -rf node_modules package-lock.json
   npm install
   npm run build
   ```

### Logs and Debugging

```bash
# View all logs
docker-compose logs -f

# View specific service logs
docker-compose logs -f auth-service

# View last 100 lines
docker-compose logs --tail=100 api-gateway

# Save logs to file
docker-compose logs > deployment.log
```

### Clean Restart

```bash
# Stop all services
docker-compose down
docker-compose -f docker-compose.events.secure.yml down

# Remove volumes (WARNING: Deletes all data)
docker-compose down -v

# Remove all containers and networks
docker system prune -a

# Start fresh
# Follow from Step 4
```

## Security Notes

1. **Change Default Passwords**: All passwords in this guide should be changed before any production use
2. **Certificate Security**: Keep private keys secure and never commit them to version control
3. **Network Isolation**: Services communicate only through defined Docker networks
4. **Rate Limiting**: Enabled by default on all API endpoints
5. **Encryption**: All sensitive data is encrypted at rest and in transit

## Next Steps

1. Access the application at http://localhost:3000
2. View API documentation at http://localhost:8080/docs
3. Monitor services at http://localhost:9090 (Prometheus)
4. View traces at http://localhost:16686 (Jaeger)
5. Manage databases at http://localhost:5050 (pgAdmin)

## Production Considerations

This local setup is designed for development. For production:

1. Use proper certificate management (Let's Encrypt, AWS ACM)
2. Enable backup strategies for all databases
3. Use managed services for databases and message queues
4. Implement proper log aggregation
5. Set up alerting and monitoring
6. Use Kubernetes or ECS for orchestration
7. Implement blue-green or canary deployments
8. Enable distributed tracing across all services