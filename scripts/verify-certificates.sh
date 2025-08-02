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
