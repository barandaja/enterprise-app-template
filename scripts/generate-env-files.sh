#!/bin/bash

# Environment File Generation Script
# Generates secure .env files for all services

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Base directory
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo -e "${GREEN}=== Environment File Generation Script ===${NC}"

# Function to generate secure password
generate_password() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-25
}

# Generate Fernet key for encryption
generate_fernet_key() {
    python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
}

# Create main .env file
echo -e "\n${YELLOW}Creating main .env file...${NC}"
cat > "${BASE_DIR}/.env" << EOF
# Generated on $(date)
# WARNING: These are auto-generated passwords. Keep this file secure!

# Database Passwords
POSTGRES_PASSWORD=$(generate_password)
REDIS_PASSWORD=$(generate_password)
EVENT_STORE_PASSWORD=$(generate_password)

# Database Users Passwords
AUTH_DB_PASSWORD=$(generate_password)
USER_DB_PASSWORD=$(generate_password)

# JWT Secrets (256-bit keys)
JWT_SECRET_KEY=$(openssl rand -hex 32)
JWT_REFRESH_SECRET_KEY=$(openssl rand -hex 32)

# Event Security
EVENT_JWT_SECRET=$(openssl rand -hex 32)
EVENT_ENCRYPTION_KEY=$(generate_fernet_key)
EVENT_HMAC_SECRET=$(openssl rand -hex 32)

# Service Secrets
SECRET_KEY=$(openssl rand -hex 32)
API_GATEWAY_SECRET=$(openssl rand -hex 32)

# Kafka Security
KAFKA_UI_PASSWORD=$(generate_password)

# API Keys (replace with actual keys)
OPENAI_API_KEY=sk-REPLACE_WITH_ACTUAL_KEY
SENDGRID_API_KEY=REPLACE_WITH_ACTUAL_KEY
TWILIO_ACCOUNT_SID=REPLACE_WITH_ACTUAL_KEY
TWILIO_AUTH_TOKEN=REPLACE_WITH_ACTUAL_KEY
STRIPE_SECRET_KEY=sk_test_REPLACE_WITH_ACTUAL_KEY
STRIPE_WEBHOOK_SECRET=whsec_REPLACE_WITH_ACTUAL_KEY

# AWS Configuration (for S3, SES, etc.)
AWS_ACCESS_KEY_ID=REPLACE_WITH_ACTUAL_KEY
AWS_SECRET_ACCESS_KEY=REPLACE_WITH_ACTUAL_KEY
AWS_REGION=us-east-1
S3_BUCKET_NAME=enterprise-app-uploads

# Feature Flags
ENABLE_RATE_LIMITING=true
ENABLE_EVENT_STORE=true
ENABLE_SAGAS=true
ENABLE_RBAC=true
ENABLE_AUDIT_LOGGING=true
ENABLE_ENCRYPTION=true

# Service URLs (for local development)
AUTH_SERVICE_URL=http://auth-service:8000
USER_SERVICE_URL=http://user-service:8001
NOTIFICATION_SERVICE_URL=http://notification-service:8002
API_GATEWAY_URL=http://api-gateway:8080
FRONTEND_URL=http://localhost:3000

# Event Bus Configuration
EVENT_BUS_TYPE=redis
REDIS_EVENT_URL=redis://\${REDIS_PASSWORD}@redis:6379/2
KAFKA_BOOTSTRAP_SERVERS=kafka:9094
KAFKA_SECURITY_PROTOCOL=SASL_SSL
KAFKA_SASL_MECHANISM=SCRAM-SHA-512

# Monitoring
PROMETHEUS_ENDPOINT=http://prometheus:9090
JAEGER_ENDPOINT=http://jaeger:14268
GRAFANA_ADMIN_PASSWORD=$(generate_password)

# Email Configuration
EMAIL_FROM=noreply@enterprise-app.local
EMAIL_FROM_NAME=Enterprise App

# Security Settings
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8080
SESSION_COOKIE_SECURE=false  # Set to true in production with HTTPS
SESSION_COOKIE_HTTPONLY=true
SESSION_COOKIE_SAMESITE=lax

# Development Settings
DEBUG=false
LOG_LEVEL=INFO
EOF

# Create auth service .env
echo -e "\n${YELLOW}Creating auth service .env...${NC}"
cat > "${BASE_DIR}/services/auth-service/.env" << EOF
# Auth Service Configuration
SERVICE_NAME=auth-service
SERVICE_PORT=8000

# Database
DATABASE_URL=postgresql://auth_user:\${AUTH_DB_PASSWORD}@postgres:5432/auth_db
DATABASE_POOL_SIZE=20
DATABASE_MAX_OVERFLOW=40

# Redis
REDIS_URL=redis://:\${REDIS_PASSWORD}@redis:6379/0

# JWT Configuration
JWT_SECRET_KEY=\${JWT_SECRET_KEY}
JWT_REFRESH_SECRET_KEY=\${JWT_REFRESH_SECRET_KEY}
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30
JWT_REFRESH_TOKEN_EXPIRE_DAYS=7

# Event Bus
EVENT_BUS_TYPE=\${EVENT_BUS_TYPE}
REDIS_EVENT_URL=\${REDIS_EVENT_URL}
SERVICE_ROLE=auth-service

# Security
SECRET_KEY=\${SECRET_KEY}
BCRYPT_ROUNDS=12
PASSWORD_MIN_LENGTH=8
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION_MINUTES=30

# Rate Limiting
RATE_LIMIT_ENABLED=\${ENABLE_RATE_LIMITING}
RATE_LIMIT_PER_MINUTE=60
RATE_LIMIT_PER_HOUR=1000

# OAuth Providers (optional)
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=

# CORS
CORS_ALLOWED_ORIGINS=\${CORS_ALLOWED_ORIGINS}

# Monitoring
ENABLE_METRICS=true
METRICS_PORT=9100
EOF

# Create user service .env
echo -e "\n${YELLOW}Creating user service .env...${NC}"
cat > "${BASE_DIR}/services/user-service/.env" << EOF
# User Service Configuration
SERVICE_NAME=user-service
SERVICE_PORT=8001

# Database
DATABASE_URL=postgresql://user_user:\${USER_DB_PASSWORD}@postgres:5432/user_db
DATABASE_POOL_SIZE=20
DATABASE_MAX_OVERFLOW=40

# Redis
REDIS_URL=redis://:\${REDIS_PASSWORD}@redis:6379/1

# Event Bus
EVENT_BUS_TYPE=\${EVENT_BUS_TYPE}
REDIS_EVENT_URL=\${REDIS_EVENT_URL}
SERVICE_ROLE=user-service

# Security
SECRET_KEY=\${SECRET_KEY}
ENCRYPTION_KEY=\${EVENT_ENCRYPTION_KEY}

# File Upload
MAX_UPLOAD_SIZE_MB=10
ALLOWED_UPLOAD_EXTENSIONS=jpg,jpeg,png,gif,pdf,doc,docx
UPLOAD_PATH=/app/uploads
S3_BUCKET_NAME=\${S3_BUCKET_NAME}

# Profile Settings
DEFAULT_AVATAR_URL=https://ui-avatars.com/api/
PROFILE_CACHE_TTL_SECONDS=3600

# CORS
CORS_ALLOWED_ORIGINS=\${CORS_ALLOWED_ORIGINS}

# Monitoring
ENABLE_METRICS=true
METRICS_PORT=9101
EOF

# Create API Gateway .env
echo -e "\n${YELLOW}Creating API Gateway .env...${NC}"
cat > "${BASE_DIR}/services/api-gateway/.env" << EOF
# API Gateway Configuration
SERVICE_NAME=api-gateway
SERVICE_PORT=8080

# Redis for rate limiting and caching
REDIS_URL=redis://:\${REDIS_PASSWORD}@redis:6379/3

# Service Discovery
AUTH_SERVICE_URL=\${AUTH_SERVICE_URL}
USER_SERVICE_URL=\${USER_SERVICE_URL}
NOTIFICATION_SERVICE_URL=\${NOTIFICATION_SERVICE_URL}

# Security
SECRET_KEY=\${API_GATEWAY_SECRET}
JWT_SECRET_KEY=\${JWT_SECRET_KEY}

# Rate Limiting
RATE_LIMIT_ENABLED=\${ENABLE_RATE_LIMITING}
RATE_LIMIT_PER_MINUTE=100
RATE_LIMIT_PER_HOUR=5000
RATE_LIMIT_BURST=20

# Request Settings
REQUEST_TIMEOUT_SECONDS=30
MAX_REQUEST_SIZE_MB=50
ENABLE_REQUEST_LOGGING=true

# CORS
CORS_ALLOWED_ORIGINS=\${CORS_ALLOWED_ORIGINS}
CORS_ALLOW_CREDENTIALS=true

# Circuit Breaker
CIRCUIT_BREAKER_ENABLED=true
CIRCUIT_BREAKER_FAILURE_THRESHOLD=5
CIRCUIT_BREAKER_RECOVERY_TIMEOUT=60

# Monitoring
ENABLE_METRICS=true
METRICS_PORT=9102
ENABLE_TRACING=true
JAEGER_AGENT_HOST=jaeger
JAEGER_AGENT_PORT=6831
EOF

# Create frontend .env.local
echo -e "\n${YELLOW}Creating frontend .env.local...${NC}"
cat > "${BASE_DIR}/frontend/.env.local" << EOF
# Frontend Environment Variables
NEXT_PUBLIC_API_URL=http://localhost:8080
NEXT_PUBLIC_WS_URL=ws://localhost:8080
NEXT_PUBLIC_APP_NAME=Enterprise App
NEXT_PUBLIC_APP_VERSION=1.0.0

# Feature Flags
NEXT_PUBLIC_ENABLE_ANALYTICS=false
NEXT_PUBLIC_ENABLE_ERROR_REPORTING=false
NEXT_PUBLIC_ENABLE_MOCK_API=false

# Third-party Services (public keys only)
NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_test_REPLACE_WITH_ACTUAL_KEY
NEXT_PUBLIC_GOOGLE_ANALYTICS_ID=
NEXT_PUBLIC_SENTRY_DSN=

# API Configuration
NEXT_PUBLIC_API_TIMEOUT=30000
NEXT_PUBLIC_MAX_UPLOAD_SIZE_MB=10

# UI Configuration
NEXT_PUBLIC_DEFAULT_THEME=light
NEXT_PUBLIC_ENABLE_THEME_TOGGLE=true
EOF

# Create Docker override file for environment variables
echo -e "\n${YELLOW}Creating docker-compose.override.yml...${NC}"
cat > "${BASE_DIR}/docker-compose.override.yml" << EOF
version: '3.8'

# This file is automatically generated and contains environment variable references
# It allows services to use variables from the main .env file

services:
  postgres:
    environment:
      - POSTGRES_PASSWORD=\${POSTGRES_PASSWORD}
      - AUTH_DB_PASSWORD=\${AUTH_DB_PASSWORD}
      - USER_DB_PASSWORD=\${USER_DB_PASSWORD}

  redis:
    command: redis-server --requirepass \${REDIS_PASSWORD}

  auth-service:
    env_file:
      - .env
      - ./services/auth-service/.env

  user-service:
    env_file:
      - .env
      - ./services/user-service/.env

  api-gateway:
    env_file:
      - .env
      - ./services/api-gateway/.env

  frontend:
    env_file:
      - ./frontend/.env.local
EOF

# Create .env.example for version control
echo -e "\n${YELLOW}Creating .env.example...${NC}"
cat > "${BASE_DIR}/.env.example" << EOF
# Copy this file to .env and update with your values
# Run: cp .env.example .env

# Database Passwords
POSTGRES_PASSWORD=CHANGE_ME
REDIS_PASSWORD=CHANGE_ME
EVENT_STORE_PASSWORD=CHANGE_ME
AUTH_DB_PASSWORD=CHANGE_ME
USER_DB_PASSWORD=CHANGE_ME

# JWT Secrets (use: openssl rand -hex 32)
JWT_SECRET_KEY=CHANGE_ME
JWT_REFRESH_SECRET_KEY=CHANGE_ME

# Event Security
EVENT_JWT_SECRET=CHANGE_ME
EVENT_ENCRYPTION_KEY=CHANGE_ME  # Use: python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
EVENT_HMAC_SECRET=CHANGE_ME

# API Keys
OPENAI_API_KEY=sk-YOUR_KEY_HERE
SENDGRID_API_KEY=YOUR_KEY_HERE
# ... etc
EOF

# Set secure permissions
chmod 600 "${BASE_DIR}/.env"
chmod 600 "${BASE_DIR}/services/auth-service/.env"
chmod 600 "${BASE_DIR}/services/user-service/.env"
chmod 600 "${BASE_DIR}/services/api-gateway/.env"

echo -e "\n${GREEN}=== Environment Files Generated Successfully ===${NC}"
echo -e "\nGenerated files:"
echo "  Main: ${BASE_DIR}/.env"
echo "  Auth Service: ${BASE_DIR}/services/auth-service/.env"
echo "  User Service: ${BASE_DIR}/services/user-service/.env"
echo "  API Gateway: ${BASE_DIR}/services/api-gateway/.env"
echo "  Frontend: ${BASE_DIR}/frontend/.env.local"
echo "  Docker Override: ${BASE_DIR}/docker-compose.override.yml"

echo -e "\n${YELLOW}IMPORTANT NOTES:${NC}"
echo "1. Update API keys with actual values before deploying"
echo "2. Keep .env files secure and never commit them to version control"
echo "3. The generated passwords are cryptographically secure"
echo "4. For production, use a proper secret management service"

echo -e "\n${GREEN}Next step: Start the Docker services${NC}"