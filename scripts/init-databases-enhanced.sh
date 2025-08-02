#!/bin/bash
# Enhanced database initialization script with best practices
# This script creates multiple databases with proper extensions and schemas

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    local level=$1
    local message=$2
    local timestamp=$(date +'%Y-%m-%d %H:%M:%S')
    
    case $level in
        "ERROR")
            echo -e "${RED}[$timestamp] [ERROR] $message${NC}" >&2
            ;;
        "WARN")
            echo -e "${YELLOW}[$timestamp] [WARN] $message${NC}" >&2
            ;;
        "INFO")
            echo -e "${GREEN}[$timestamp] [INFO] $message${NC}"
            ;;
        "DEBUG")
            if [ "${DEBUG:-false}" = "true" ]; then
                echo -e "${BLUE}[$timestamp] [DEBUG] $message${NC}"
            fi
            ;;
    esac
}

# Database configuration
declare -A DATABASES=(
    ["auth_db"]="Authentication and authorization service"
    ["user_db"]="User management and profiles"
    ["gateway_db"]="API gateway configuration and routing"
)

# Extension configuration
EXTENSIONS=(
    "uuid-ossp"      # UUID generation
    "pgcrypto"       # Cryptographic functions
    "btree_gin"      # GIN index support
    "pg_trgm"        # Trigram matching for text search
    "pg_stat_statements"  # Query performance monitoring
)

# Schema configuration
SCHEMAS=(
    "application"    # Main application schema
    "audit"         # Audit logging schema
    "reporting"     # Reporting views and aggregates
)

# Create user with proper privileges
create_database_user() {
    local db_name=$1
    local db_user="${db_name}_user"
    local db_pass="${db_name}_pass"
    
    log "INFO" "Creating user '$db_user' for database '$db_name'"
    
    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
        -- Create user if it doesn't exist
        DO \$\$
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_user WHERE usename = '${db_user}') THEN
                CREATE USER ${db_user} WITH PASSWORD '${db_pass}';
                GRANT CONNECT ON DATABASE postgres TO ${db_user};
            ELSE
                -- Update password if user exists
                ALTER USER ${db_user} WITH PASSWORD '${db_pass}';
            END IF;
        END
        \$\$;
EOSQL
}

# Create database with extensions and schemas
create_enhanced_database() {
    local db_name=$1
    local db_description=$2
    local db_user="${db_name}_user"
    
    log "INFO" "Creating database '$db_name' - $db_description"
    
    # Create database if it doesn't exist
    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
        -- Check if database exists
        SELECT 'CREATE DATABASE $db_name'
        WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '$db_name')\gexec
        
        -- Grant privileges
        GRANT ALL PRIVILEGES ON DATABASE $db_name TO ${db_user};
        ALTER DATABASE $db_name OWNER TO ${db_user};
        
        -- Configure database
        ALTER DATABASE $db_name SET log_statement = 'mod';
        ALTER DATABASE $db_name SET log_min_duration_statement = 1000;
EOSQL
    
    # Connect to the new database and set up extensions and schemas
    log "INFO" "Setting up extensions and schemas for '$db_name'"
    
    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$db_name" <<-EOSQL
        -- Create extensions
        $(for ext in "${EXTENSIONS[@]}"; do
            echo "CREATE EXTENSION IF NOT EXISTS \"$ext\";"
        done)
        
        -- Create schemas
        $(for schema in "${SCHEMAS[@]}"; do
            echo "CREATE SCHEMA IF NOT EXISTS $schema;"
            echo "GRANT ALL ON SCHEMA $schema TO ${db_user};"
        done)
        
        -- Set search path
        ALTER DATABASE $db_name SET search_path TO application, public;
        
        -- Grant default privileges
        ALTER DEFAULT PRIVILEGES IN SCHEMA application 
            GRANT ALL ON TABLES TO ${db_user};
        ALTER DEFAULT PRIVILEGES IN SCHEMA application 
            GRANT ALL ON SEQUENCES TO ${db_user};
        ALTER DEFAULT PRIVILEGES IN SCHEMA application 
            GRANT ALL ON FUNCTIONS TO ${db_user};
        
        ALTER DEFAULT PRIVILEGES IN SCHEMA audit 
            GRANT ALL ON TABLES TO ${db_user};
        ALTER DEFAULT PRIVILEGES IN SCHEMA reporting 
            GRANT SELECT ON TABLES TO ${db_user};
        
        -- Create audit trigger function
        CREATE OR REPLACE FUNCTION audit.audit_trigger_function()
        RETURNS TRIGGER AS \$\$
        BEGIN
            IF TG_OP = 'INSERT' THEN
                INSERT INTO audit.audit_log(
                    table_name, operation, user_name, 
                    new_data, query, timestamp
                ) VALUES (
                    TG_TABLE_NAME, TG_OP, current_user,
                    row_to_json(NEW), current_query(), NOW()
                );
                RETURN NEW;
            ELSIF TG_OP = 'UPDATE' THEN
                INSERT INTO audit.audit_log(
                    table_name, operation, user_name,
                    old_data, new_data, query, timestamp
                ) VALUES (
                    TG_TABLE_NAME, TG_OP, current_user,
                    row_to_json(OLD), row_to_json(NEW), 
                    current_query(), NOW()
                );
                RETURN NEW;
            ELSIF TG_OP = 'DELETE' THEN
                INSERT INTO audit.audit_log(
                    table_name, operation, user_name,
                    old_data, query, timestamp
                ) VALUES (
                    TG_TABLE_NAME, TG_OP, current_user,
                    row_to_json(OLD), current_query(), NOW()
                );
                RETURN OLD;
            END IF;
            RETURN NULL;
        END;
        \$\$ LANGUAGE plpgsql;
        
        -- Create audit log table
        CREATE TABLE IF NOT EXISTS audit.audit_log (
            id BIGSERIAL PRIMARY KEY,
            table_name TEXT NOT NULL,
            operation TEXT NOT NULL,
            user_name TEXT NOT NULL,
            timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            old_data JSONB,
            new_data JSONB,
            query TEXT
        );
        
        -- Create indexes on audit log
        CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp 
            ON audit.audit_log(timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_audit_log_table_operation 
            ON audit.audit_log(table_name, operation);
        
        -- Grant permissions on audit log
        GRANT SELECT ON audit.audit_log TO ${db_user};
        
        -- Create performance monitoring views
        CREATE OR REPLACE VIEW reporting.slow_queries AS
        SELECT 
            query,
            calls,
            total_time,
            mean_time,
            max_time,
            stddev_time
        FROM pg_stat_statements 
        WHERE mean_time > 1000
        ORDER BY mean_time DESC;
        
        GRANT SELECT ON reporting.slow_queries TO ${db_user};
        
        -- Database initialization completed
        SELECT 'Database $db_name initialized successfully' as status;
EOSQL
    
    log "INFO" "Database '$db_name' created and configured successfully"
}

# Create read-only user for reporting
create_readonly_user() {
    local db_name=$1
    local readonly_user="${db_name}_readonly"
    local readonly_pass="${readonly_user}_pass"
    
    log "INFO" "Creating read-only user '$readonly_user' for database '$db_name'"
    
    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$db_name" <<-EOSQL
        -- Create read-only user
        DO \$\$
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_user WHERE usename = '${readonly_user}') THEN
                CREATE USER ${readonly_user} WITH PASSWORD '${readonly_pass}';
            END IF;
        END
        \$\$;
        
        -- Grant connect privilege
        GRANT CONNECT ON DATABASE $db_name TO ${readonly_user};
        
        -- Grant usage on schemas
        GRANT USAGE ON SCHEMA application, audit, reporting TO ${readonly_user};
        
        -- Grant select on all tables
        GRANT SELECT ON ALL TABLES IN SCHEMA application TO ${readonly_user};
        GRANT SELECT ON ALL TABLES IN SCHEMA audit TO ${readonly_user};
        GRANT SELECT ON ALL TABLES IN SCHEMA reporting TO ${readonly_user};
        
        -- Grant select on future tables
        ALTER DEFAULT PRIVILEGES IN SCHEMA application 
            GRANT SELECT ON TABLES TO ${readonly_user};
        ALTER DEFAULT PRIVILEGES IN SCHEMA audit 
            GRANT SELECT ON TABLES TO ${readonly_user};
        ALTER DEFAULT PRIVILEGES IN SCHEMA reporting 
            GRANT SELECT ON TABLES TO ${readonly_user};
EOSQL
}

# Verify database setup
verify_database() {
    local db_name=$1
    
    log "INFO" "Verifying database '$db_name' setup"
    
    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$db_name" <<-EOSQL
        -- Check extensions
        SELECT extname, extversion 
        FROM pg_extension 
        WHERE extname != 'plpgsql'
        ORDER BY extname;
        
        -- Check schemas
        SELECT nspname as schema_name
        FROM pg_namespace
        WHERE nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
        ORDER BY nspname;
        
        -- Check users and privileges
        SELECT 
            grantee,
            privilege_type,
            is_grantable
        FROM information_schema.schema_privileges
        WHERE schema_name IN ('application', 'audit', 'reporting')
        ORDER BY grantee, schema_name, privilege_type;
EOSQL
}

# Main execution
main() {
    log "INFO" "Starting enhanced database initialization"
    log "INFO" "PostgreSQL version: $(psql --version)"
    log "INFO" "Environment: ${ENVIRONMENT:-development}"
    
    # Check if multiple databases are configured
    if [ -z "${POSTGRES_MULTIPLE_DATABASES:-}" ]; then
        log "WARN" "POSTGRES_MULTIPLE_DATABASES not set, using default configuration"
        POSTGRES_MULTIPLE_DATABASES="auth_db,user_db,gateway_db"
    fi
    
    # Process each database
    for db_entry in $(echo $POSTGRES_MULTIPLE_DATABASES | tr ',' ' '); do
        # Extract database name (first part before colon if description provided)
        db_name=$(echo $db_entry | cut -d':' -f1)
        
        # Get description from our configuration or use default
        db_description="${DATABASES[$db_name]:-"Application database"}"
        
        # Create user first
        create_database_user "$db_name"
        
        # Create and configure database
        create_enhanced_database "$db_name" "$db_description"
        
        # Create read-only user
        create_readonly_user "$db_name"
        
        # Verify setup
        if [ "${VERIFY_SETUP:-true}" = "true" ]; then
            verify_database "$db_name"
        fi
        
        log "INFO" "Completed setup for database '$db_name'"
    done
    
    # Create shared infrastructure database if needed
    if [ "${CREATE_SHARED_DB:-false}" = "true" ]; then
        log "INFO" "Creating shared infrastructure database"
        create_database_user "shared_db"
        create_enhanced_database "shared_db" "Shared infrastructure (events, config)"
    fi
    
    log "INFO" "Enhanced database initialization completed successfully"
}

# Error handling
trap 'log "ERROR" "Database initialization failed at line $LINENO"' ERR

# Execute main function
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main "$@"
fi