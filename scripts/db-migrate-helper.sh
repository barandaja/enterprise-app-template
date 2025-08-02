#!/bin/bash
# Database migration helper script
# Provides utilities for managing Alembic migrations across services

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Available services
SERVICES=("auth-service" "user-service" "api-gateway")

# Usage information
usage() {
    cat << EOF
Database Migration Helper

Usage: $0 <command> [options]

Commands:
    create <service> <description>   Create a new migration
    upgrade <service> [target]       Upgrade database to target (default: head)
    downgrade <service> [target]     Downgrade database to target (default: -1)
    current <service>               Show current migration version
    history <service>               Show migration history
    validate <service>              Validate migration files
    seed <service> <environment>    Load seed data for environment
    backup <service>                Create database backup
    restore <service> <backup>      Restore from backup

Options:
    -h, --help                      Show this help message
    -e, --env <environment>         Set environment (default: development)
    -d, --dry-run                   Show SQL without executing

Examples:
    $0 create auth-service "add user preferences table"
    $0 upgrade user-service
    $0 seed auth-service development
    $0 backup auth-service

EOF
}

# Log function
log() {
    local level=$1
    local message=$2
    case $level in
        "INFO") echo -e "${GREEN}[INFO]${NC} $message" ;;
        "WARN") echo -e "${YELLOW}[WARN]${NC} $message" ;;
        "ERROR") echo -e "${RED}[ERROR]${NC} $message" >&2 ;;
    esac
}

# Validate service name
validate_service() {
    local service=$1
    if [[ ! " ${SERVICES[@]} " =~ " ${service} " ]]; then
        log "ERROR" "Invalid service: $service"
        log "INFO" "Available services: ${SERVICES[*]}"
        exit 1
    fi
}

# Get database URL for service
get_database_url() {
    local service=$1
    local db_name="${service//-service/}_db"
    local db_user="${db_name}_user"
    local db_pass="${db_name}_pass"
    local db_host="${DB_HOST:-localhost}"
    local db_port="${DB_PORT:-5432}"
    
    echo "postgresql://${db_user}:${db_pass}@${db_host}:${db_port}/${db_name}"
}

# Create new migration
create_migration() {
    local service=$1
    local description=$2
    
    validate_service "$service"
    
    if [ -z "$description" ]; then
        log "ERROR" "Description required for new migration"
        exit 1
    fi
    
    log "INFO" "Creating migration for $service: $description"
    
    cd "$PROJECT_ROOT/services/$service"
    
    # Generate migration
    alembic revision -m "$description"
    
    # Find the newly created migration file
    latest_migration=$(ls -t alembic/versions/*.py | head -1)
    
    log "INFO" "Created migration: $latest_migration"
    log "INFO" "Edit the migration file to add upgrade() and downgrade() logic"
}

# Upgrade database
upgrade_database() {
    local service=$1
    local target=${2:-head}
    
    validate_service "$service"
    
    log "INFO" "Upgrading $service database to: $target"
    
    cd "$PROJECT_ROOT/services/$service"
    
    # Set database URL
    export DATABASE_URL=$(get_database_url "$service")
    
    if [ "${DRY_RUN:-false}" = "true" ]; then
        log "INFO" "Dry run - showing SQL:"
        alembic upgrade $target --sql
    else
        # Show current version
        log "INFO" "Current version:"
        alembic current
        
        # Perform upgrade
        alembic upgrade $target
        
        # Show new version
        log "INFO" "New version:"
        alembic current
    fi
}

# Downgrade database
downgrade_database() {
    local service=$1
    local target=${2:--1}
    
    validate_service "$service"
    
    log "WARN" "Downgrading $service database to: $target"
    
    cd "$PROJECT_ROOT/services/$service"
    
    # Set database URL
    export DATABASE_URL=$(get_database_url "$service")
    
    if [ "${DRY_RUN:-false}" = "true" ]; then
        log "INFO" "Dry run - showing SQL:"
        alembic downgrade $target --sql
    else
        # Confirm downgrade
        read -p "Are you sure you want to downgrade? (y/N) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            alembic downgrade $target
            log "INFO" "Downgrade completed"
        else
            log "INFO" "Downgrade cancelled"
        fi
    fi
}

# Show current migration version
show_current() {
    local service=$1
    
    validate_service "$service"
    
    cd "$PROJECT_ROOT/services/$service"
    
    export DATABASE_URL=$(get_database_url "$service")
    
    log "INFO" "Current migration version for $service:"
    alembic current
}

# Show migration history
show_history() {
    local service=$1
    
    validate_service "$service"
    
    cd "$PROJECT_ROOT/services/$service"
    
    export DATABASE_URL=$(get_database_url "$service")
    
    log "INFO" "Migration history for $service:"
    alembic history --verbose
}

# Validate migrations
validate_migrations() {
    local service=$1
    
    validate_service "$service"
    
    log "INFO" "Validating migrations for $service"
    
    cd "$PROJECT_ROOT/services/$service"
    
    # Check Python syntax
    log "INFO" "Checking Python syntax..."
    python -m py_compile alembic/versions/*.py
    
    # Check for duplicate revision IDs
    log "INFO" "Checking for duplicate revision IDs..."
    duplicates=$(grep -h "^revision = " alembic/versions/*.py | sort | uniq -d)
    if [ -n "$duplicates" ]; then
        log "ERROR" "Duplicate revision IDs found:"
        echo "$duplicates"
        exit 1
    fi
    
    # Check migration chain
    export DATABASE_URL=$(get_database_url "$service")
    alembic check
    
    log "INFO" "All migrations valid"
}

# Load seed data
load_seed_data() {
    local service=$1
    local environment=$2
    
    validate_service "$service"
    
    if [ -z "$environment" ]; then
        log "ERROR" "Environment required for seeding"
        exit 1
    fi
    
    log "INFO" "Loading $environment seed data for $service"
    
    cd "$PROJECT_ROOT/services/$service"
    
    # Check if seed directory exists
    seed_dir="database/seeds/$environment"
    if [ ! -d "$seed_dir" ]; then
        log "WARN" "No seed data found for environment: $environment"
        return
    fi
    
    export DATABASE_URL=$(get_database_url "$service")
    
    # Load seed files in order
    for seed_file in "$seed_dir"/*.sql; do
        if [ -f "$seed_file" ]; then
            log "INFO" "Loading: $(basename "$seed_file")"
            psql "$DATABASE_URL" -f "$seed_file"
        fi
    done
    
    log "INFO" "Seed data loaded successfully"
}

# Backup database
backup_database() {
    local service=$1
    
    validate_service "$service"
    
    local db_name="${service//-service/}_db"
    local backup_dir="$PROJECT_ROOT/backups"
    local backup_file="$backup_dir/${db_name}_$(date +%Y%m%d_%H%M%S).sql"
    
    # Create backup directory
    mkdir -p "$backup_dir"
    
    log "INFO" "Creating backup for $service"
    
    DATABASE_URL=$(get_database_url "$service")
    
    # Create backup
    pg_dump "$DATABASE_URL" > "$backup_file"
    
    # Compress backup
    gzip "$backup_file"
    
    log "INFO" "Backup created: ${backup_file}.gz"
    log "INFO" "Size: $(du -h "${backup_file}.gz" | cut -f1)"
}

# Restore from backup
restore_database() {
    local service=$1
    local backup_file=$2
    
    validate_service "$service"
    
    if [ ! -f "$backup_file" ]; then
        log "ERROR" "Backup file not found: $backup_file"
        exit 1
    fi
    
    log "WARN" "Restoring $service from backup: $backup_file"
    
    # Confirm restore
    read -p "This will overwrite the current database. Continue? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log "INFO" "Restore cancelled"
        exit 0
    fi
    
    DATABASE_URL=$(get_database_url "$service")
    
    # Restore based on file type
    if [[ "$backup_file" == *.gz ]]; then
        gunzip -c "$backup_file" | psql "$DATABASE_URL"
    else
        psql "$DATABASE_URL" < "$backup_file"
    fi
    
    log "INFO" "Restore completed"
}

# Main command processing
main() {
    if [ $# -eq 0 ]; then
        usage
        exit 1
    fi
    
    COMMAND=$1
    shift
    
    # Parse options
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                exit 0
                ;;
            -e|--env)
                export ENVIRONMENT=$2
                shift 2
                ;;
            -d|--dry-run)
                export DRY_RUN=true
                shift
                ;;
            *)
                break
                ;;
        esac
    done
    
    # Execute command
    case $COMMAND in
        create)
            create_migration "$@"
            ;;
        upgrade)
            upgrade_database "$@"
            ;;
        downgrade)
            downgrade_database "$@"
            ;;
        current)
            show_current "$@"
            ;;
        history)
            show_history "$@"
            ;;
        validate)
            validate_migrations "$@"
            ;;
        seed)
            load_seed_data "$@"
            ;;
        backup)
            backup_database "$@"
            ;;
        restore)
            restore_database "$@"
            ;;
        *)
            log "ERROR" "Unknown command: $COMMAND"
            usage
            exit 1
            ;;
    esac
}

# Run main function
main "$@"