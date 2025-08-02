#!/bin/bash

# SSL Certificate Generation Script for Enterprise App Template
# This script generates all necessary certificates for secure local deployment

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Base directory
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SSL_DIR="${BASE_DIR}/config/ssl"
KAFKA_DIR="${BASE_DIR}/config/kafka/secrets"

echo -e "${GREEN}=== SSL Certificate Generation Script ===${NC}"
echo "Base directory: ${BASE_DIR}"

# Create directories
echo -e "\n${YELLOW}Creating directories...${NC}"
mkdir -p "${SSL_DIR}/certs"
mkdir -p "${SSL_DIR}/private"
mkdir -p "${KAFKA_DIR}"

# Function to generate a random password
generate_password() {
    openssl rand -hex 16
}

# Store passwords
KEYSTORE_PASSWORD="changeit"  # Standard Java keystore password, should be changed in production
KEY_PASSWORD="changeit"
TRUSTSTORE_PASSWORD="changeit"

echo -e "\n${YELLOW}Generating Certificate Authority (CA)...${NC}"

# Generate CA private key
openssl genrsa -out "${SSL_DIR}/private/ca.key" 4096

# Generate CA certificate
openssl req -new -x509 -days 3650 -key "${SSL_DIR}/private/ca.key" \
  -out "${SSL_DIR}/certs/ca.crt" \
  -subj "/C=US/ST=State/L=City/O=Enterprise/CN=Enterprise Root CA"

echo -e "${GREEN}✓ CA certificate generated${NC}"

# Function to generate server certificate
generate_server_cert() {
    local name=$1
    local cn=$2
    local san=$3
    
    echo -e "\n${YELLOW}Generating certificate for ${name}...${NC}"
    
    # Generate private key
    openssl genrsa -out "${SSL_DIR}/private/${name}.key" 2048
    
    # Create config file with SAN
    cat > "${SSL_DIR}/private/${name}.conf" << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = State
L = City
O = Enterprise
CN = ${cn}

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = ${san}
EOF
    
    # Generate CSR
    openssl req -new -key "${SSL_DIR}/private/${name}.key" \
      -out "${SSL_DIR}/private/${name}.csr" \
      -config "${SSL_DIR}/private/${name}.conf"
    
    # Sign certificate
    openssl x509 -req -days 365 \
      -in "${SSL_DIR}/private/${name}.csr" \
      -CA "${SSL_DIR}/certs/ca.crt" \
      -CAkey "${SSL_DIR}/private/ca.key" \
      -CAcreateserial \
      -out "${SSL_DIR}/certs/${name}.crt" \
      -extensions v3_req \
      -extfile "${SSL_DIR}/private/${name}.conf"
    
    # Set permissions
    chmod 600 "${SSL_DIR}/private/${name}.key"
    
    echo -e "${GREEN}✓ ${name} certificate generated${NC}"
}

# Generate PostgreSQL certificates
generate_server_cert "postgres" "postgres" "DNS:postgres,DNS:localhost,IP:127.0.0.1"

# Copy PostgreSQL certificates with correct names
cp "${SSL_DIR}/certs/postgres.crt" "${SSL_DIR}/certs/server.crt"
cp "${SSL_DIR}/private/postgres.key" "${SSL_DIR}/private/server.key"

# Generate certificates for other services
generate_server_cert "redis" "redis" "DNS:redis,DNS:localhost,IP:127.0.0.1"
generate_server_cert "kafka" "kafka" "DNS:kafka,DNS:localhost,IP:127.0.0.1"
generate_server_cert "auth-service" "auth-service" "DNS:auth-service,DNS:localhost,IP:127.0.0.1"
generate_server_cert "user-service" "user-service" "DNS:user-service,DNS:localhost,IP:127.0.0.1"
generate_server_cert "api-gateway" "api-gateway" "DNS:api-gateway,DNS:localhost,IP:127.0.0.1"

echo -e "\n${YELLOW}Generating Kafka keystores and truststores...${NC}"

# Create Kafka keystore
keytool -genkeypair \
  -alias kafka \
  -keyalg RSA \
  -keysize 2048 \
  -validity 365 \
  -keystore "${KAFKA_DIR}/kafka.keystore.jks" \
  -storetype PKCS12 \
  -dname "CN=kafka, OU=Enterprise, O=Enterprise, L=City, ST=State, C=US" \
  -storepass "${KEYSTORE_PASSWORD}" \
  -keypass "${KEY_PASSWORD}" \
  -ext "SAN=DNS:kafka,DNS:localhost,IP:127.0.0.1" \
  2>/dev/null || true

# Export Kafka certificate
keytool -exportcert \
  -alias kafka \
  -keystore "${KAFKA_DIR}/kafka.keystore.jks" \
  -storepass "${KEYSTORE_PASSWORD}" \
  -file "${KAFKA_DIR}/kafka.crt" \
  2>/dev/null || true

# Create truststore and import CA
keytool -importcert \
  -alias ca \
  -file "${SSL_DIR}/certs/ca.crt" \
  -keystore "${KAFKA_DIR}/kafka.truststore.jks" \
  -storetype PKCS12 \
  -storepass "${TRUSTSTORE_PASSWORD}" \
  -noprompt \
  2>/dev/null || true

# Import Kafka cert to truststore
keytool -importcert \
  -alias kafka \
  -file "${KAFKA_DIR}/kafka.crt" \
  -keystore "${KAFKA_DIR}/kafka.truststore.jks" \
  -storepass "${TRUSTSTORE_PASSWORD}" \
  -noprompt \
  2>/dev/null || true

# Create credential files
echo "${KEYSTORE_PASSWORD}" > "${KAFKA_DIR}/keystore_creds"
echo "${KEY_PASSWORD}" > "${KAFKA_DIR}/key_creds"
echo "${TRUSTSTORE_PASSWORD}" > "${KAFKA_DIR}/truststore_creds"

# Create keystores for other services
for service in "schema-registry" "zookeeper"; do
    echo -e "\n${YELLOW}Creating keystore for ${service}...${NC}"
    
    keytool -genkeypair \
      -alias "${service}" \
      -keyalg RSA \
      -keysize 2048 \
      -validity 365 \
      -keystore "${KAFKA_DIR}/${service}.keystore.jks" \
      -storetype PKCS12 \
      -dname "CN=${service}, OU=Enterprise, O=Enterprise, L=City, ST=State, C=US" \
      -storepass "${KEYSTORE_PASSWORD}" \
      -keypass "${KEY_PASSWORD}" \
      2>/dev/null || true
    
    cp "${KAFKA_DIR}/kafka.truststore.jks" "${KAFKA_DIR}/${service}.truststore.jks"
done

echo -e "${GREEN}✓ Kafka keystores generated${NC}"

# Generate client certificates for services
echo -e "\n${YELLOW}Generating client certificates for services...${NC}"

for service in "auth-service" "user-service" "notification-service"; do
    # Generate client key and certificate
    openssl genrsa -out "${SSL_DIR}/private/${service}-client.key" 2048
    
    openssl req -new -key "${SSL_DIR}/private/${service}-client.key" \
      -out "${SSL_DIR}/private/${service}-client.csr" \
      -subj "/C=US/ST=State/L=City/O=Enterprise/CN=${service}"
    
    openssl x509 -req -days 365 \
      -in "${SSL_DIR}/private/${service}-client.csr" \
      -CA "${SSL_DIR}/certs/ca.crt" \
      -CAkey "${SSL_DIR}/private/ca.key" \
      -CAcreateserial \
      -out "${SSL_DIR}/certs/${service}-client.crt"
    
    # Create PKCS12 keystore for the service
    openssl pkcs12 -export \
      -in "${SSL_DIR}/certs/${service}-client.crt" \
      -inkey "${SSL_DIR}/private/${service}-client.key" \
      -out "${KAFKA_DIR}/${service}.p12" \
      -name "${service}" \
      -CAfile "${SSL_DIR}/certs/ca.crt" \
      -caname "CA" \
      -password "pass:${KEYSTORE_PASSWORD}"
    
    echo -e "${GREEN}✓ ${service} client certificate generated${NC}"
done

# Set proper permissions
echo -e "\n${YELLOW}Setting permissions...${NC}"

# PostgreSQL requires specific ownership
if [ -f "${SSL_DIR}/private/server.key" ]; then
    chmod 600 "${SSL_DIR}/private/server.key"
    # Note: chown to 999:999 should be done when deploying with Docker
    echo -e "${YELLOW}Note: PostgreSQL certificates will need ownership set to 999:999 when deploying${NC}"
fi

# Protect all private keys
chmod 600 "${SSL_DIR}/private/"*.key 2>/dev/null || true
chmod 600 "${KAFKA_DIR}/"*.jks 2>/dev/null || true
chmod 600 "${KAFKA_DIR}/"*_creds 2>/dev/null || true

# Create certificate summary
echo -e "\n${GREEN}=== Certificate Generation Complete ===${NC}"
echo -e "\nGenerated certificates:"
echo "  CA Certificate: ${SSL_DIR}/certs/ca.crt"
echo "  PostgreSQL: ${SSL_DIR}/certs/postgres.crt"
echo "  Redis: ${SSL_DIR}/certs/redis.crt"
echo "  Kafka: ${KAFKA_DIR}/kafka.keystore.jks"
echo "  Services: ${SSL_DIR}/certs/*-service.crt"

# Create verification script
cat > "${BASE_DIR}/scripts/verify-certificates.sh" << 'EOF'
#!/bin/bash

SSL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../config/ssl" && pwd)"
KAFKA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../config/kafka/secrets" && pwd)"

echo "=== Certificate Verification ==="

# Verify CA
echo -e "\nCA Certificate:"
openssl x509 -in "${SSL_DIR}/certs/ca.crt" -noout -subject -dates

# Verify server certificates
for cert in postgres redis kafka auth-service user-service api-gateway; do
    if [ -f "${SSL_DIR}/certs/${cert}.crt" ]; then
        echo -e "\n${cert} Certificate:"
        openssl x509 -in "${SSL_DIR}/certs/${cert}.crt" -noout -subject -dates
        openssl verify -CAfile "${SSL_DIR}/certs/ca.crt" "${SSL_DIR}/certs/${cert}.crt"
    fi
done

# Verify Kafka keystore
if [ -f "${KAFKA_DIR}/kafka.keystore.jks" ]; then
    echo -e "\nKafka Keystore:"
    keytool -list -keystore "${KAFKA_DIR}/kafka.keystore.jks" -storepass changeit 2>/dev/null | grep "Entry type"
fi
EOF

chmod +x "${BASE_DIR}/scripts/verify-certificates.sh"

echo -e "\n${YELLOW}To verify certificates, run:${NC}"
echo "  ./scripts/verify-certificates.sh"

echo -e "\n${YELLOW}Next steps:${NC}"
echo "1. Set PostgreSQL certificate ownership:"
echo "   sudo chown 999:999 ${SSL_DIR}/private/server.key"
echo "   sudo chown 999:999 ${SSL_DIR}/certs/server.crt"
echo ""
echo "2. Update passwords in .env files"
echo "3. Start services with: docker-compose up -d"

echo -e "\n${GREEN}Certificate generation complete!${NC}"