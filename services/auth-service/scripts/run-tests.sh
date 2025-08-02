#!/bin/bash

# Auth Service Test Execution Script
# Comprehensive test runner with multiple execution modes

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
COVERAGE_THRESHOLD=90
PARALLEL_WORKERS="auto"

# Default values
RUN_UNIT=true
RUN_INTEGRATION=true
RUN_SECURITY=false
RUN_PERFORMANCE=false
RUN_COMPLIANCE=false
RUN_EDGE_CASES=false
COVERAGE_REPORT=true
PARALLEL=true
VERBOSE=false
FAIL_FAST=false
DOCKER_SERVICES=false

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

# Function to show usage
show_usage() {
    cat << EOF
Auth Service Test Runner

Usage: $0 [OPTIONS]

OPTIONS:
    -a, --all               Run all test suites
    -u, --unit              Run unit tests only (default: enabled)
    -i, --integration       Run integration tests only (default: enabled)
    -s, --security          Run security tests
    -p, --performance       Run performance tests
    -c, --compliance        Run compliance tests
    -e, --edge-cases        Run edge case tests
    
    --no-unit              Skip unit tests
    --no-integration       Skip integration tests
    --no-coverage          Skip coverage reporting
    --no-parallel          Disable parallel execution
    
    -v, --verbose          Verbose output
    -f, --fail-fast        Stop on first failure
    -d, --docker           Start Docker services automatically
    
    -t, --threshold N      Coverage threshold (default: 90)
    -w, --workers N        Number of parallel workers (default: auto)
    
    --smoke                Run smoke tests only
    --quick                Run quick tests (unit + integration, no slow tests)
    --ci                   CI mode (all tests except performance)
    
    -h, --help             Show this help message

EXAMPLES:
    $0                     # Run default tests (unit + integration)
    $0 --all               # Run all test suites
    $0 --security --compliance  # Run security and compliance tests
    $0 --quick --verbose   # Quick test run with verbose output
    $0 --ci                # CI pipeline mode
    $0 --smoke             # Smoke tests for quick validation

ENVIRONMENT VARIABLES:
    DATABASE_URL           Test database connection string
    REDIS_URL             Test Redis connection string
    SECRET_KEY            Test secret key
    TESTING               Set to 'true' for test mode
EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -a|--all)
                RUN_UNIT=true
                RUN_INTEGRATION=true
                RUN_SECURITY=true
                RUN_COMPLIANCE=true
                RUN_EDGE_CASES=true
                shift
                ;;
            -u|--unit)
                RUN_UNIT=true
                RUN_INTEGRATION=false
                shift
                ;;
            -i|--integration)
                RUN_INTEGRATION=true
                RUN_UNIT=false
                shift
                ;;
            -s|--security)
                RUN_SECURITY=true
                shift
                ;;
            -p|--performance)
                RUN_PERFORMANCE=true
                shift
                ;;
            -c|--compliance)
                RUN_COMPLIANCE=true
                shift
                ;;
            -e|--edge-cases)
                RUN_EDGE_CASES=true
                shift
                ;;
            --no-unit)
                RUN_UNIT=false
                shift
                ;;
            --no-integration)
                RUN_INTEGRATION=false
                shift
                ;;
            --no-coverage)
                COVERAGE_REPORT=false
                shift
                ;;
            --no-parallel)
                PARALLEL=false
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -f|--fail-fast)
                FAIL_FAST=true
                shift
                ;;
            -d|--docker)
                DOCKER_SERVICES=true
                shift
                ;;
            -t|--threshold)
                COVERAGE_THRESHOLD="$2"
                shift 2
                ;;
            -w|--workers)
                PARALLEL_WORKERS="$2"
                shift 2
                ;;
            --smoke)
                RUN_UNIT=true
                RUN_INTEGRATION=true
                RUN_SECURITY=false
                RUN_PERFORMANCE=false
                RUN_COMPLIANCE=false
                RUN_EDGE_CASES=false
                SMOKE_ONLY=true
                shift
                ;;
            --quick)
                RUN_UNIT=true
                RUN_INTEGRATION=true
                RUN_SECURITY=false
                RUN_PERFORMANCE=false
                RUN_COMPLIANCE=false
                RUN_EDGE_CASES=false
                QUICK_ONLY=true
                shift
                ;;
            --ci)
                RUN_UNIT=true
                RUN_INTEGRATION=true
                RUN_SECURITY=true
                RUN_COMPLIANCE=true
                RUN_EDGE_CASES=true
                RUN_PERFORMANCE=false  # Skip performance in CI
                CI_MODE=true
                shift
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
}

# Function to check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check if we're in the right directory
    if [[ ! -f "$PROJECT_DIR/pytest.ini" ]]; then
        print_error "pytest.ini not found. Please run from the auth-service directory."
        exit 1
    fi
    
    # Check Python version
    if ! python --version | grep -q "Python 3.11"; then
        print_warning "Python 3.11 recommended. Current version: $(python --version)"
    fi
    
    # Check if required packages are installed
    if ! python -c "import pytest" 2>/dev/null; then
        print_error "pytest not installed. Run: pip install -r requirements-test.txt"
        exit 1
    fi
    
    print_success "Prerequisites check passed"
}

# Function to set up environment
setup_environment() {
    print_status "Setting up test environment..."
    
    # Set default environment variables if not set
    export TESTING=${TESTING:-true}
    export ENVIRONMENT=${ENVIRONMENT:-testing}
    export SECRET_KEY=${SECRET_KEY:-test-secret-key}
    export DATABASE_URL=${DATABASE_URL:-postgresql+asyncpg://test:test@localhost:5432/test_authdb}
    export REDIS_URL=${REDIS_URL:-redis://localhost:6379/1}
    export RATE_LIMIT_ENABLED=${RATE_LIMIT_ENABLED:-false}
    export ENABLE_AUDIT_LOGGING=${ENABLE_AUDIT_LOGGING:-true}
    export ENABLE_DATA_ENCRYPTION=${ENABLE_DATA_ENCRYPTION:-false}
    
    print_success "Environment variables set"
}

# Function to start Docker services
start_docker_services() {
    if [[ "$DOCKER_SERVICES" == "true" ]]; then
        print_status "Starting Docker services..."
        
        # Check if Docker is available
        if ! command -v docker &> /dev/null; then
            print_error "Docker is not installed or not in PATH"
            exit 1
        fi
        
        # Start PostgreSQL
        print_status "Starting PostgreSQL..."
        docker run -d --name test-postgres \
            -e POSTGRES_PASSWORD=test \
            -e POSTGRES_USER=test \
            -e POSTGRES_DB=test_authdb \
            -p 5432:5432 \
            postgres:15 2>/dev/null || true
        
        # Start Redis
        print_status "Starting Redis..."
        docker run -d --name test-redis \
            -p 6379:6379 \
            redis:7-alpine 2>/dev/null || true
        
        # Wait for services to be ready
        print_status "Waiting for services to be ready..."
        sleep 10
        
        # Test connections
        if ! nc -z localhost 5432; then
            print_error "PostgreSQL is not ready"
            exit 1
        fi
        
        if ! nc -z localhost 6379; then
            print_error "Redis is not ready"
            exit 1
        fi
        
        print_success "Docker services started"
    fi
}

# Function to build pytest command
build_pytest_command() {
    local cmd="pytest"
    local markers=()
    local paths=()
    
    # Add paths based on selected test suites
    if [[ "$RUN_UNIT" == "true" ]]; then
        paths+=("tests/unit/")
        markers+=("unit")
    fi
    
    if [[ "$RUN_INTEGRATION" == "true" ]]; then
        paths+=("tests/integration/")
        markers+=("integration")
    fi
    
    if [[ "$RUN_SECURITY" == "true" ]]; then
        paths+=("tests/security/")
        markers+=("security")
    fi
    
    if [[ "$RUN_PERFORMANCE" == "true" ]]; then
        paths+=("tests/performance/")
        markers+=("performance")
    fi
    
    if [[ "$RUN_COMPLIANCE" == "true" ]]; then
        paths+=("tests/compliance/")
        markers+=("compliance")
    fi
    
    if [[ "$RUN_EDGE_CASES" == "true" ]]; then
        paths+=("tests/edge_cases/")
        markers+=("edge_case")
    fi
    
    # If no specific paths, run all
    if [[ ${#paths[@]} -eq 0 ]]; then
        paths=("tests/")
    fi
    
    # Add paths to command
    cmd="$cmd ${paths[*]}"
    
    # Add markers
    if [[ ${#markers[@]} -gt 0 ]]; then
        marker_expr=$(IFS=" or "; echo "${markers[*]}")
        cmd="$cmd -m \"$marker_expr\""
    fi
    
    # Add special mode filters
    if [[ "$SMOKE_ONLY" == "true" ]]; then
        cmd="$cmd -m smoke"
    elif [[ "$QUICK_ONLY" == "true" ]]; then
        cmd="$cmd -m \"not slow\""
    elif [[ "$CI_MODE" == "true" ]]; then
        cmd="$cmd -m \"not slow\""
    fi
    
    # Add coverage options
    if [[ "$COVERAGE_REPORT" == "true" ]]; then
        cmd="$cmd --cov=src"
        cmd="$cmd --cov-report=html:htmlcov"
        cmd="$cmd --cov-report=xml:coverage.xml"
        cmd="$cmd --cov-report=term-missing"
        cmd="$cmd --cov-fail-under=$COVERAGE_THRESHOLD"
    fi
    
    # Add parallel execution
    if [[ "$PARALLEL" == "true" ]]; then
        cmd="$cmd -n $PARALLEL_WORKERS"
    fi
    
    # Add verbosity
    if [[ "$VERBOSE" == "true" ]]; then
        cmd="$cmd -v"
    fi
    
    # Add fail fast
    if [[ "$FAIL_FAST" == "true" ]]; then
        cmd="$cmd -x"
    fi
    
    # Add other options
    cmd="$cmd --tb=short"
    cmd="$cmd --durations=10"
    cmd="$cmd --strict-markers"
    cmd="$cmd --json-report --json-report-file=test-report.json"
    
    echo "$cmd"
}

# Function to run tests
run_tests() {
    print_status "Starting test execution..."
    
    cd "$PROJECT_DIR"
    
    # Build and execute pytest command
    pytest_cmd=$(build_pytest_command)
    print_status "Running command: $pytest_cmd"
    
    # Execute tests
    if eval "$pytest_cmd"; then
        print_success "All tests passed!"
        return 0
    else
        print_error "Some tests failed!"
        return 1
    fi
}

# Function to generate test report
generate_report() {
    if [[ -f "test-report.json" ]]; then
        print_status "Generating test summary..."
        
        # Extract test statistics from JSON report
        if command -v jq &> /dev/null; then
            local total=$(jq '.summary.total' test-report.json)
            local passed=$(jq '.summary.passed' test-report.json)
            local failed=$(jq '.summary.failed' test-report.json)
            local skipped=$(jq '.summary.skipped' test-report.json)
            local duration=$(jq '.duration' test-report.json)
            
            echo ""
            echo "==============================================="
            echo "                TEST SUMMARY"
            echo "==============================================="
            echo "Total Tests:    $total"
            echo "Passed:         $passed"
            echo "Failed:         $failed"
            echo "Skipped:        $skipped"
            echo "Duration:       ${duration}s"
            echo "==============================================="
        fi
    fi
    
    # Show coverage report location
    if [[ "$COVERAGE_REPORT" == "true" && -d "htmlcov" ]]; then
        print_success "Coverage report generated: htmlcov/index.html"
    fi
}

# Function to cleanup
cleanup() {
    if [[ "$DOCKER_SERVICES" == "true" ]]; then
        print_status "Cleaning up Docker services..."
        docker stop test-postgres test-redis 2>/dev/null || true
        docker rm test-postgres test-redis 2>/dev/null || true
    fi
}

# Main execution
main() {
    # Set up trap for cleanup
    trap cleanup EXIT
    
    print_status "Auth Service Test Runner"
    print_status "========================"
    
    parse_args "$@"
    check_prerequisites
    setup_environment
    start_docker_services
    
    # Run tests and capture exit code
    if run_tests; then
        test_result=0
    else
        test_result=1
    fi
    
    generate_report
    
    # Final status
    if [[ $test_result -eq 0 ]]; then
        print_success "Test execution completed successfully!"
    else
        print_error "Test execution failed!"
    fi
    
    exit $test_result
}

# Execute main function if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi