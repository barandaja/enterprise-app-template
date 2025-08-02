#!/bin/bash
# HashiCorp Vault integration for secret management

# Vault configuration
VAULT_ADDR="${VAULT_ADDR:-https://vault.example.com}"
VAULT_NAMESPACE="${VAULT_NAMESPACE:-enterprise}"

# Authenticate with Vault using GitHub Actions OIDC
vault_authenticate() {
    local role=$1
    local jwt_token=$2
    
    # Authenticate using JWT auth method
    VAULT_TOKEN=$(vault write -field=token auth/jwt/login \
        role="$role" \
        jwt="$jwt_token")
    
    export VAULT_TOKEN
}

# Fetch secrets from Vault
fetch_secrets() {
    local service=$1
    local environment=$2
    
    # Base path for service secrets
    local secret_path="secret/data/${environment}/${service}"
    
    # Fetch all secrets for the service
    vault kv get -format=json "$secret_path" | jq -r '.data.data'
}

# Store secret in GitHub Actions output (masked)
set_secret_output() {
    local key=$1
    local value=$2
    
    # Mask the secret value
    echo "::add-mask::$value"
    
    # Set as output
    echo "${key}=${value}" >> $GITHUB_OUTPUT
}

# Fetch and export database credentials
fetch_database_credentials() {
    local service=$1
    local environment=$2
    
    local db_path="database/creds/${environment}-${service}"
    
    # Get dynamic database credentials
    local creds=$(vault read -format=json "$db_path")
    
    local username=$(echo "$creds" | jq -r '.data.username')
    local password=$(echo "$creds" | jq -r '.data.password')
    
    # Export as environment variables
    export DB_USERNAME="$username"
    export DB_PASSWORD="$password"
    
    # Set outputs for GitHub Actions
    set_secret_output "db_username" "$username"
    set_secret_output "db_password" "$password"
}

# Rotate secrets
rotate_secrets() {
    local service=$1
    local environment=$2
    
    echo "Rotating secrets for $service in $environment"
    
    # Rotate database passwords
    vault write -f "database/rotate-role/${environment}-${service}"
    
    # Rotate API keys
    local new_api_key=$(openssl rand -hex 32)
    vault kv put "secret/${environment}/${service}/api" \
        api_key="$new_api_key" \
        rotated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}

# Create Kubernetes secret from Vault
create_k8s_secret() {
    local service=$1
    local environment=$2
    local namespace=$3
    
    # Fetch secrets from Vault
    local secrets=$(fetch_secrets "$service" "$environment")
    
    # Create Kubernetes secret
    kubectl create secret generic "${service}-secrets" \
        --namespace="$namespace" \
        --from-literal=DATABASE_URL="postgresql://${DB_USERNAME}:${DB_PASSWORD}@postgres:5432/${service}_db" \
        --from-literal=JWT_SECRET="$(echo "$secrets" | jq -r '.jwt_secret')" \
        --from-literal=REDIS_URL="$(echo "$secrets" | jq -r '.redis_url')" \
        --from-literal=API_KEY="$(echo "$secrets" | jq -r '.api_key')" \
        --dry-run=client -o yaml | kubectl apply -f -
}

# Sync Vault secrets to environment
sync_vault_to_env() {
    local service=$1
    local environment=$2
    local output_file=${3:-".env.vault"}
    
    echo "# Vault secrets for $service in $environment" > "$output_file"
    echo "# Generated at $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$output_file"
    echo "" >> "$output_file"
    
    # Fetch secrets
    local secrets=$(fetch_secrets "$service" "$environment")
    
    # Write each secret to env file
    echo "$secrets" | jq -r 'to_entries | .[] | "\(.key | ascii_upcase)=\(.value)"' >> "$output_file"
    
    # Fetch database credentials
    fetch_database_credentials "$service" "$environment"
    echo "DATABASE_URL=postgresql://${DB_USERNAME}:${DB_PASSWORD}@postgres:5432/${service}_db" >> "$output_file"
}

# Validate Vault connectivity and permissions
validate_vault_access() {
    local service=$1
    local environment=$2
    
    echo "Validating Vault access for $service in $environment"
    
    # Check Vault token
    if ! vault token lookup > /dev/null 2>&1; then
        echo "ERROR: Invalid or missing Vault token"
        return 1
    fi
    
    # Check read permissions
    if ! vault kv get "secret/${environment}/${service}" > /dev/null 2>&1; then
        echo "ERROR: Cannot read secrets from secret/${environment}/${service}"
        return 1
    fi
    
    # Check database access
    if ! vault read "database/creds/${environment}-${service}" > /dev/null 2>&1; then
        echo "ERROR: Cannot read database credentials"
        return 1
    fi
    
    echo "Vault access validated successfully"
    return 0
}

# Initialize Vault policies for a service
init_vault_policies() {
    local service=$1
    
    # Create policy for CI/CD
    cat <<EOF | vault policy write "${service}-cicd" -
# CI/CD policy for ${service}
path "secret/data/+/${service}" {
  capabilities = ["read", "list"]
}

path "secret/metadata/+/${service}" {
  capabilities = ["list"]
}

path "database/creds/+-${service}" {
  capabilities = ["read"]
}

path "auth/jwt/login" {
  capabilities = ["create", "update"]
}
EOF

    # Create policy for runtime
    cat <<EOF | vault policy write "${service}-runtime" -
# Runtime policy for ${service}
path "secret/data/production/${service}" {
  capabilities = ["read"]
}

path "database/creds/production-${service}" {
  capabilities = ["read"]
}
EOF
}

# Main command processing
case "$1" in
    "authenticate")
        vault_authenticate "$2" "$3"
        ;;
    "fetch-secrets")
        fetch_secrets "$2" "$3"
        ;;
    "fetch-db-creds")
        fetch_database_credentials "$2" "$3"
        ;;
    "create-k8s-secret")
        create_k8s_secret "$2" "$3" "$4"
        ;;
    "rotate-secrets")
        rotate_secrets "$2" "$3"
        ;;
    "sync-env")
        sync_vault_to_env "$2" "$3" "$4"
        ;;
    "validate")
        validate_vault_access "$2" "$3"
        ;;
    "init-policies")
        init_vault_policies "$2"
        ;;
    *)
        echo "Usage: $0 {authenticate|fetch-secrets|fetch-db-creds|create-k8s-secret|rotate-secrets|sync-env|validate|init-policies} [args...]"
        exit 1
        ;;
esac