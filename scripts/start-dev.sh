#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if Docker is running
check_docker() {
    if ! docker info >/dev/null 2>&1; then
        print_error "Docker is not running. Please start Docker and try again."
        exit 1
    fi
    print_success "Docker is running"
}

# Function to check if ports are available
check_ports() {
    local ports=("5432" "6379" "8000" "8001" "8002" "5173" "80" "5050" "8081")
    local unavailable_ports=()
    
    for port in "${ports[@]}"; do
        if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1; then
            unavailable_ports+=($port)
        fi
    done
    
    if [ ${#unavailable_ports[@]} -ne 0 ]; then
        print_warning "The following ports are already in use: ${unavailable_ports[*]}"
        print_warning "Services using these ports may conflict with the application"
        read -p "Do you want to continue anyway? (y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Function to build and start services
start_services() {
    print_status "Building and starting enterprise application..."
    
    # Build and start core services
    docker-compose up -d postgres redis
    
    print_status "Waiting for database and Redis to be ready..."
    sleep 10
    
    # Start backend services
    docker-compose up -d auth-service user-service api-gateway
    
    print_status "Waiting for backend services to be ready..."
    sleep 15
    
    # Start frontend and nginx
    docker-compose up -d frontend nginx
    
    print_success "All services started successfully!"
}

# Function to show service status
show_status() {
    print_status "Service Status:"
    docker-compose ps
    
    echo ""
    print_status "Application URLs:"
    echo "  Frontend: http://localhost (via nginx) or http://localhost:5173 (direct)"
    echo "  API Gateway: http://localhost:8000"
    echo "  Auth Service: http://localhost:8001"
    echo "  User Service: http://localhost:8002"
    echo "  Database: localhost:5432"
    echo "  Redis: localhost:6379"
    echo ""
    print_status "Admin Tools (optional):"
    echo "  PgAdmin: http://localhost:5050 (admin@enterprise.local / admin123)"
    echo "  Redis Commander: http://localhost:8081"
    echo ""
    print_status "To start admin tools, run: docker-compose --profile tools up -d"
}

# Function to check service health
check_health() {
    print_status "Checking service health..."
    
    local services=("http://localhost:8001/health" "http://localhost:8002/health" "http://localhost:8000/health")
    local max_attempts=30
    local attempt=1
    
    for service in "${services[@]}"; do
        while [ $attempt -le $max_attempts ]; do
            if curl -f -s "$service" >/dev/null 2>&1; then
                print_success "Service $service is healthy"
                break
            else
                if [ $attempt -eq $max_attempts ]; then
                    print_warning "Service $service is not responding after $max_attempts attempts"
                else
                    print_status "Waiting for $service to be ready... (attempt $attempt/$max_attempts)"
                    sleep 2
                fi
            fi
            ((attempt++))
        done
        attempt=1
    done
}

# Main execution
main() {
    echo "=========================================="
    echo "Enterprise Application Development Setup"
    echo "=========================================="
    echo ""
    
    print_status "Starting pre-flight checks..."
    check_docker
    check_ports
    
    echo ""
    start_services
    
    echo ""
    check_health
    
    echo ""
    show_status
    
    echo ""
    print_success "Development environment is ready!"
    print_status "To view logs: docker-compose logs -f [service-name]"
    print_status "To stop all services: docker-compose down"
    print_status "To restart a service: docker-compose restart [service-name]"
    print_status "To rebuild a service: docker-compose up -d --build [service-name]"
}

# Handle command line arguments
case "${1:-}" in
    "stop")
        print_status "Stopping all services..."
        docker-compose down
        print_success "All services stopped"
        ;;
    "restart")
        print_status "Restarting all services..."
        docker-compose restart
        print_success "All services restarted"
        ;;
    "logs")
        if [ -n "${2:-}" ]; then
            docker-compose logs -f "$2"
        else
            docker-compose logs -f
        fi
        ;;
    "status")
        show_status
        ;;
    "health")
        check_health
        ;;
    "clean")
        print_status "Cleaning up Docker resources..."
        docker-compose down -v
        docker system prune -f
        print_success "Cleanup completed"
        ;;
    "")
        main
        ;;
    *)
        echo "Usage: $0 [start|stop|restart|logs [service]|status|health|clean]"
        echo ""
        echo "Commands:"
        echo "  start (default) - Start the development environment"
        echo "  stop           - Stop all services"
        echo "  restart        - Restart all services"
        echo "  logs [service] - Show logs for all services or specific service"
        echo "  status         - Show service status and URLs"
        echo "  health         - Check service health"
        echo "  clean          - Stop services and clean up Docker resources"
        exit 1
        ;;
esac