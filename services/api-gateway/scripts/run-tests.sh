#!/bin/bash

# Comprehensive test runner script for API Gateway
# Provides different test execution modes and reporting options

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
TEST_TYPE="all"
VERBOSE=false
COVERAGE=true
PARALLEL=false
REPORT_FORMAT="terminal"
OUTPUT_DIR="test-reports"
MARKERS=""
TIMEOUT=300

# Function to display usage
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -t, --test-type TYPE     Test type to run (unit|integration|security|performance|compliance|websocket|edge_case|all)"
    echo "  -v, --verbose           Enable verbose output"
    echo "  -c, --coverage          Enable coverage reporting (default: true)"
    echo "  -p, --parallel          Run tests in parallel"
    echo "  -f, --format FORMAT     Report format (terminal|html|json|xml|all)"
    echo "  -o, --output DIR        Output directory for reports (default: test-reports)"
    echo "  -m, --markers MARKERS   Additional pytest markers"
    echo "  -s, --slow              Include slow tests"
    echo "  --timeout SECONDS       Test timeout in seconds (default: 300)"
    echo "  --no-coverage           Disable coverage reporting"
    echo "  --fail-fast             Stop on first failure"
    echo "  --lf                    Run only last failed tests"
    echo "  --clean                 Clean previous test reports"
    echo "  -h, --help              Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 -t unit -v                    # Run unit tests with verbose output"
    echo "  $0 -t security -f html           # Run security tests with HTML report"
    echo "  $0 -p -c                         # Run all tests in parallel with coverage"
    echo "  $0 -t performance -s             # Run performance tests including slow ones"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--test-type)
            TEST_TYPE="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -c|--coverage)
            COVERAGE=true
            shift
            ;;
        --no-coverage)
            COVERAGE=false
            shift
            ;;
        -p|--parallel)
            PARALLEL=true
            shift
            ;;
        -f|--format)
            REPORT_FORMAT="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -m|--markers)
            MARKERS="$2"
            shift 2
            ;;
        -s|--slow)
            MARKERS="$MARKERS slow"
            shift
            ;;
        --timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        --fail-fast)
            FAIL_FAST=true
            shift
            ;;
        --lf)
            LAST_FAILED=true
            shift
            ;;
        --clean)
            CLEAN=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Function to print colored output
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Function to check dependencies
check_dependencies() {
    print_status $BLUE "Checking dependencies..."
    
    # Check if pytest is installed
    if ! command -v pytest &> /dev/null; then
        print_status $RED "pytest is not installed. Please install test requirements:"
        echo "pip install -r requirements-test.txt"
        exit 1
    fi
    
    # Check if coverage is installed (if coverage is enabled)
    if [ "$COVERAGE" = true ] && ! command -v coverage &> /dev/null; then
        print_status $YELLOW "Warning: coverage not found. Installing..."
        pip install coverage pytest-cov
    fi
    
    print_status $GREEN "Dependencies check passed"
}

# Function to clean previous reports
clean_reports() {
    if [ "$CLEAN" = true ] || [ ! -d "$OUTPUT_DIR" ]; then
        print_status $BLUE "Cleaning previous test reports..."
        rm -rf "$OUTPUT_DIR"
        rm -rf htmlcov
        rm -rf .coverage
        rm -rf .pytest_cache
        rm -rf test-results.xml
        rm -rf coverage.xml
        print_status $GREEN "Reports cleaned"
    fi
}

# Function to create output directory
create_output_dir() {
    mkdir -p "$OUTPUT_DIR"
    mkdir -p "$OUTPUT_DIR/coverage"
    mkdir -p "$OUTPUT_DIR/html"
    mkdir -p "$OUTPUT_DIR/json"
    mkdir -p "$OUTPUT_DIR/xml"
}

# Function to build pytest command
build_pytest_command() {
    local cmd="pytest"
    
    # Test selection based on type
    case $TEST_TYPE in
        unit)
            cmd="$cmd tests/unit/"
            MARKERS="$MARKERS unit"
            ;;
        integration)
            cmd="$cmd tests/integration/"
            MARKERS="$MARKERS integration"
            ;;
        security)
            cmd="$cmd tests/security/"
            MARKERS="$MARKERS security"
            ;;
        performance)
            cmd="$cmd tests/performance/"
            MARKERS="$MARKERS performance"
            ;;
        compliance)
            cmd="$cmd tests/compliance/"
            MARKERS="$MARKERS compliance"
            ;;
        websocket)
            cmd="$cmd tests/websocket/"
            MARKERS="$MARKERS websocket"
            ;;
        edge_case)
            cmd="$cmd tests/edge_cases/"
            MARKERS="$MARKERS edge_case"
            ;;
        all)
            cmd="$cmd tests/"
            ;;
        *)
            print_status $RED "Invalid test type: $TEST_TYPE"
            usage
            exit 1
            ;;
    esac
    
    # Add markers
    if [ -n "$MARKERS" ]; then
        cmd="$cmd -m \"$MARKERS\""
    fi
    
    # Add verbose output
    if [ "$VERBOSE" = true ]; then
        cmd="$cmd -v"
    fi
    
    # Add parallel execution
    if [ "$PARALLEL" = true ]; then
        cmd="$cmd -n auto"
    fi
    
    # Add coverage
    if [ "$COVERAGE" = true ]; then
        cmd="$cmd --cov=src --cov-report=term-missing"
        
        # Add coverage reports based on format
        case $REPORT_FORMAT in
            html|all)
                cmd="$cmd --cov-report=html:$OUTPUT_DIR/coverage/html"
                ;;
        esac
        
        case $REPORT_FORMAT in
            xml|all)
                cmd="$cmd --cov-report=xml:$OUTPUT_DIR/coverage/coverage.xml"
                ;;
        esac
    fi
    
    # Add HTML report
    case $REPORT_FORMAT in
        html|all)
            cmd="$cmd --html=$OUTPUT_DIR/html/report.html --self-contained-html"
            ;;
    esac
    
    # Add JSON report
    case $REPORT_FORMAT in
        json|all)
            cmd="$cmd --json-report --json-report-file=$OUTPUT_DIR/json/report.json"
            ;;
    esac
    
    # Add XML report (JUnit format)
    case $REPORT_FORMAT in
        xml|all)
            cmd="$cmd --junit-xml=$OUTPUT_DIR/xml/results.xml"
            ;;
    esac
    
    # Add timeout
    cmd="$cmd --timeout=$TIMEOUT"
    
    # Add fail fast
    if [ "$FAIL_FAST" = true ]; then
        cmd="$cmd -x"
    fi
    
    # Add last failed
    if [ "$LAST_FAILED" = true ]; then
        cmd="$cmd --lf"
    fi
    
    echo "$cmd"
}

# Function to run tests
run_tests() {
    local pytest_cmd=$(build_pytest_command)
    
    print_status $BLUE "Running tests with command:"
    echo "$pytest_cmd"
    echo ""
    
    # Set environment variables for testing
    export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"
    export TESTING=true
    export ENVIRONMENT=test
    
    # Run the tests
    eval "$pytest_cmd"
    local exit_code=$?
    
    return $exit_code
}

# Function to generate summary report
generate_summary() {
    local exit_code=$1
    
    print_status $BLUE "Generating test summary..."
    
    echo "========================================="
    echo "API Gateway Test Summary"
    echo "========================================="
    echo "Test Type: $TEST_TYPE"
    echo "Coverage: $COVERAGE"
    echo "Parallel: $PARALLEL"
    echo "Report Format: $REPORT_FORMAT"
    echo "Output Directory: $OUTPUT_DIR"
    echo "Timeout: $TIMEOUT seconds"
    
    if [ -n "$MARKERS" ]; then
        echo "Markers: $MARKERS"
    fi
    
    echo ""
    
    if [ $exit_code -eq 0 ]; then
        print_status $GREEN "✅ All tests passed!"
    else
        print_status $RED "❌ Some tests failed (exit code: $exit_code)"
    fi
    
    echo ""
    echo "Reports generated in: $OUTPUT_DIR"
    
    # Show coverage summary if available
    if [ "$COVERAGE" = true ] && [ -f ".coverage" ]; then
        echo ""
        print_status $BLUE "Coverage Summary:"
        coverage report --show-missing | tail -n 10
    fi
    
    # Show available reports
    echo ""
    print_status $BLUE "Available Reports:"
    if [ -f "$OUTPUT_DIR/html/report.html" ]; then
        echo "  📊 HTML Report: $OUTPUT_DIR/html/report.html"
    fi
    if [ -f "$OUTPUT_DIR/coverage/html/index.html" ]; then
        echo "  📈 Coverage Report: $OUTPUT_DIR/coverage/html/index.html"
    fi
    if [ -f "$OUTPUT_DIR/json/report.json" ]; then
        echo "  📄 JSON Report: $OUTPUT_DIR/json/report.json"
    fi
    if [ -f "$OUTPUT_DIR/xml/results.xml" ]; then
        echo "  📋 XML Report: $OUTPUT_DIR/xml/results.xml"
    fi
}

# Function to open reports
open_reports() {
    if [ "$REPORT_FORMAT" = "html" ] || [ "$REPORT_FORMAT" = "all" ]; then
        if command -v open &> /dev/null; then  # macOS
            echo ""
            read -p "Open HTML report in browser? (y/n): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                open "$OUTPUT_DIR/html/report.html"
                if [ -f "$OUTPUT_DIR/coverage/html/index.html" ]; then
                    open "$OUTPUT_DIR/coverage/html/index.html"
                fi
            fi
        fi
    fi
}

# Main execution
main() {
    print_status $BLUE "🧪 API Gateway Test Runner"
    echo "========================================="
    
    check_dependencies
    clean_reports
    create_output_dir
    
    print_status $BLUE "Starting tests..."
    echo ""
    
    # Record start time
    start_time=$(date +%s)
    
    # Run tests
    run_tests
    exit_code=$?
    
    # Record end time
    end_time=$(date +%s)
    duration=$((end_time - start_time))
    
    echo ""
    print_status $BLUE "Tests completed in ${duration} seconds"
    
    generate_summary $exit_code
    open_reports
    
    exit $exit_code
}

# Run main function
main