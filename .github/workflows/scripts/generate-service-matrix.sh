#!/bin/bash
# Generate service matrix from services-config.json

CONFIG_FILE=".github/workflows/services-config.json"

# Generate path filters for detect-changes job
generate_path_filters() {
    echo "# Auto-generated path filters from services-config.json"
    
    # Backend services
    jq -r '.services.backend[] | "\(.name):\n  - \"\(.path)/**\""' "$CONFIG_FILE"
    
    # Common dependencies
    echo "python-commons:"
    echo "  - 'shared/python-commons/**'"
    echo "infrastructure:"
    echo "  - 'infrastructure/**'"
    echo "  - '.github/workflows/**'"
}

# Generate service matrix for jobs
generate_service_matrix() {
    jq -c '[.services.backend[].name]' "$CONFIG_FILE"
}

# Generate service info for specific service
get_service_info() {
    local service=$1
    jq -r ".services.backend[] | select(.name==\"$service\")" "$CONFIG_FILE"
}

# Get service path
get_service_path() {
    local service=$1
    jq -r ".services.backend[] | select(.name==\"$service\") | .path" "$CONFIG_FILE"
}

# Get service port
get_service_port() {
    local service=$1
    jq -r ".services.backend[] | select(.name==\"$service\") | .port" "$CONFIG_FILE"
}

# Get service dependencies
get_service_dependencies() {
    local service=$1
    jq -r ".services.backend[] | select(.name==\"$service\") | .dependencies[]" "$CONFIG_FILE"
}

# Main command processing
case "$1" in
    "path-filters")
        generate_path_filters
        ;;
    "service-matrix")
        generate_service_matrix
        ;;
    "service-info")
        get_service_info "$2"
        ;;
    "service-path")
        get_service_path "$2"
        ;;
    "service-port")
        get_service_port "$2"
        ;;
    "service-dependencies")
        get_service_dependencies "$2"
        ;;
    *)
        echo "Usage: $0 {path-filters|service-matrix|service-info|service-path|service-port|service-dependencies} [service-name]"
        exit 1
        ;;
esac