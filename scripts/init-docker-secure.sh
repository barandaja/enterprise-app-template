#!/bin/bash

# Initialize secure Docker Compose environment
# This script sets up the necessary directories and generates secure passwords

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Initializing secure Docker environment...${NC}"

# Create data directories with proper permissions
echo -e "${YELLOW}Creating data directories...${NC}"
mkdir -p data/{postgres,redis,pgadmin}
chmod 700 data/postgres
chmod 700 data/redis
chmod 700 data/pgadmin

# Create log directories
echo -e "${YELLOW}Creating log directories...${NC}"
mkdir -p logs/{auth,user,gateway,nginx}
chmod 755 logs

# Create SSL directory for certificates
echo -e "${YELLOW}Creating SSL directories...${NC}"
mkdir -p config/nginx/ssl
mkdir -p config/postgres
chmod 700 config/nginx/ssl
chmod 700 config/postgres

# Generate .env file if it doesn't exist
if [ ! -f .env ]; then
    echo -e "${YELLOW}Generating .env file with secure passwords...${NC}"
    cp .env.docker .env
    
    # Generate secure passwords
    POSTGRES_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
    REDIS_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
    JWT_SECRET_KEY=$(openssl rand -base64 64 | tr -d "=+/" | cut -c1-50)
    PGADMIN_PASSWORD=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-16)
    
    # Replace placeholders with actual passwords
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        sed -i '' "s/changeme_\$(openssl rand -hex 16)/${POSTGRES_PASSWORD}/" .env
        sed -i '' "s/changeme_\$(openssl rand -hex 16)/${REDIS_PASSWORD}/" .env
        sed -i '' "s/changeme_\$(openssl rand -hex 32)/${JWT_SECRET_KEY}/" .env
        sed -i '' "s/changeme_\$(openssl rand -hex 8)/${PGADMIN_PASSWORD}/" .env
    else
        # Linux
        sed -i "s/changeme_\$(openssl rand -hex 16)/${POSTGRES_PASSWORD}/g" .env
        sed -i "s/changeme_\$(openssl rand -hex 32)/${JWT_SECRET_KEY}/" .env
        sed -i "s/changeme_\$(openssl rand -hex 8)/${PGADMIN_PASSWORD}/" .env
    fi
    
    echo -e "${GREEN}Generated secure passwords in .env file${NC}"
    echo -e "${RED}IMPORTANT: Keep the .env file secure and never commit it to version control!${NC}"
else
    echo -e "${YELLOW}.env file already exists, skipping password generation${NC}"
fi

# Generate self-signed SSL certificates for development
if [ ! -f config/nginx/ssl/cert.pem ]; then
    echo -e "${YELLOW}Generating self-signed SSL certificates for development...${NC}"
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout config/nginx/ssl/key.pem \
        -out config/nginx/ssl/cert.pem \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
    chmod 600 config/nginx/ssl/key.pem
    chmod 644 config/nginx/ssl/cert.pem
    echo -e "${GREEN}SSL certificates generated${NC}"
fi

# Generate PostgreSQL SSL certificates
if [ ! -f config/postgres/server.key ]; then
    echo -e "${YELLOW}Generating PostgreSQL SSL certificates...${NC}"
    openssl req -new -text -passout pass:abcd -subj /CN=localhost -out config/postgres/server.req -keyout config/postgres/privkey.pem
    openssl rsa -in config/postgres/privkey.pem -passin pass:abcd -out config/postgres/server.key
    openssl req -x509 -in config/postgres/server.req -text -key config/postgres/server.key -out config/postgres/server.crt
    chmod 600 config/postgres/server.key
    chmod 644 config/postgres/server.crt
    rm config/postgres/server.req config/postgres/privkey.pem
    echo -e "${GREEN}PostgreSQL SSL certificates generated${NC}"
fi

# Create Redis ACL file
echo -e "${YELLOW}Creating Redis ACL configuration...${NC}"
cat > config/redis/users.acl << EOF
# Redis ACL Configuration
# Default user with full access (for admin)
user default on +@all ~* &* nopass

# Application user with limited access
user app on +@read +@write +@list +@set +@hash +@stream -@dangerous ~* &* >${REDIS_PASSWORD:-changeme}
EOF
chmod 600 config/redis/users.acl

# Create docker-compose override for development
if [ ! -f docker-compose.override.yml ]; then
    echo -e "${YELLOW}Creating docker-compose.override.yml for development...${NC}"
    cat > docker-compose.override.yml << EOF
# Development overrides
# This file is automatically loaded by docker-compose
version: '3.8'

services:
  # Development-specific configurations
  auth-service:
    build:
      target: development
    volumes:
      - ./services/auth-service/src:/app/src:rw
    environment:
      - ENVIRONMENT=development
      - LOG_LEVEL=DEBUG

  user-service:
    build:
      target: development
    volumes:
      - ./services/user-service/src:/app/src:rw
    environment:
      - ENVIRONMENT=development
      - LOG_LEVEL=DEBUG

  api-gateway:
    build:
      target: development
    volumes:
      - ./services/api-gateway/src:/app/src:rw
    environment:
      - ENVIRONMENT=development
      - LOG_LEVEL=DEBUG

  frontend:
    build:
      target: development
    volumes:
      - ./frontend/src:/app/src:rw
      - ./frontend/public:/app/public:rw
    environment:
      - NODE_ENV=development
EOF
fi

# Create a script to check security settings
cat > check-security.sh << 'EOF'
#!/bin/bash

echo "Checking Docker Compose security settings..."

# Check if .env file has proper permissions
if [ -f .env ]; then
    perms=$(stat -c %a .env 2>/dev/null || stat -f %p .env | cut -c4-6)
    if [ "$perms" != "600" ]; then
        echo "WARNING: .env file should have 600 permissions (current: $perms)"
    fi
fi

# Check if passwords are still default
if grep -q "changeme_" .env 2>/dev/null; then
    echo "ERROR: Default passwords found in .env file! Please regenerate."
    exit 1
fi

# Check Docker daemon security
docker version --format '{{.Server.Version}}' > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "Docker daemon is accessible"
else
    echo "ERROR: Cannot access Docker daemon"
    exit 1
fi

echo "Security check completed!"
EOF
chmod +x check-security.sh

echo -e "${GREEN}Initialization complete!${NC}"
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Review and modify the .env file as needed"
echo "2. Run ./check-security.sh to verify security settings"
echo "3. Start the secure environment: docker-compose -f docker-compose.secure.yml up"
echo "4. For development with hot-reload: docker-compose -f docker-compose.secure.yml -f docker-compose.override.yml up"