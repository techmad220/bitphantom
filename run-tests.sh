#!/bin/bash

# Bit Phantom WAF - Automated Testing Suite
# This script runs comprehensive security tests against the WAF

set -e

echo "=========================================="
echo "   BIT PHANTOM WAF - AUTOMATED TESTING"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
WAF_PORT=${WAF_PORT:-3001}
TEST_MODE=${TEST_MODE:-full}
VERBOSE=${VERBOSE:-false}

# Check if WAF is running
check_waf() {
    echo -n "Checking if WAF is running on port $WAF_PORT... "
    if curl -s -o /dev/null -w "%{http_code}" http://localhost:$WAF_PORT/health | grep -q "200"; then
        echo -e "${GREEN}✓${NC}"
        return 0
    else
        echo -e "${RED}✗${NC}"
        echo "Please start the WAF first: npm start"
        exit 1
    fi
}

# Start WAF in test mode
start_waf() {
    echo "Starting WAF in paranoid mode..."
    cd /root/bit\ phantom
    WAF_MODE=paranoid npm start &
    WAF_PID=$!
    sleep 5
    echo "WAF started with PID: $WAF_PID"
}

# Run basic security tests
run_basic_tests() {
    echo ""
    echo "Running Basic Security Tests..."
    echo "================================"
    
    # XSS Tests
    echo -n "Testing XSS Protection... "
    response=$(curl -s -X POST http://localhost:$WAF_PORT/api/test \
        -H "Content-Type: application/json" \
        -d '{"data":"<script>alert(1)</script>"}' \
        -w "%{http_code}" -o /dev/null)
    
    if [ "$response" = "403" ]; then
        echo -e "${GREEN}✓ Blocked${NC}"
    else
        echo -e "${RED}✗ NOT BLOCKED (Status: $response)${NC}"
    fi
    
    # SQL Injection Tests
    echo -n "Testing SQL Injection Protection... "
    response=$(curl -s -X POST http://localhost:$WAF_PORT/api/login \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"admin' OR '1'='1\",\"password\":\"test\"}" \
        -w "%{http_code}" -o /dev/null)
    
    if [ "$response" = "403" ]; then
        echo -e "${GREEN}✓ Blocked${NC}"
    else
        echo -e "${RED}✗ NOT BLOCKED (Status: $response)${NC}"
    fi
    
    # Path Traversal Tests
    echo -n "Testing Path Traversal Protection... "
    response=$(curl -s -X GET "http://localhost:$WAF_PORT/api/file?path=../../../etc/passwd" \
        -w "%{http_code}" -o /dev/null)
    
    if [ "$response" = "403" ]; then
        echo -e "${GREEN}✓ Blocked${NC}"
    else
        echo -e "${RED}✗ NOT BLOCKED (Status: $response)${NC}"
    fi
    
    # Command Injection Tests
    echo -n "Testing Command Injection Protection... "
    response=$(curl -s -X POST http://localhost:$WAF_PORT/api/ping \
        -H "Content-Type: application/json" \
        -d '{"host":"google.com; cat /etc/passwd"}' \
        -w "%{http_code}" -o /dev/null)
    
    if [ "$response" = "403" ]; then
        echo -e "${GREEN}✓ Blocked${NC}"
    else
        echo -e "${RED}✗ NOT BLOCKED (Status: $response)${NC}"
    fi
}

# Run advanced tests
run_advanced_tests() {
    echo ""
    echo "Running Advanced Attack Tests..."
    echo "================================"
    
    # XXE Test
    echo -n "Testing XXE Protection... "
    response=$(curl -s -X POST http://localhost:$WAF_PORT/api/xml \
        -H "Content-Type: application/xml" \
        -d '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>' \
        -w "%{http_code}" -o /dev/null)
    
    if [ "$response" = "403" ]; then
        echo -e "${GREEN}✓ Blocked${NC}"
    else
        echo -e "${RED}✗ NOT BLOCKED (Status: $response)${NC}"
    fi
    
    # SSRF Test
    echo -n "Testing SSRF Protection... "
    response=$(curl -s -X POST http://localhost:$WAF_PORT/api/webhook \
        -H "Content-Type: application/json" \
        -d '{"url":"http://169.254.169.254/latest/meta-data"}' \
        -w "%{http_code}" -o /dev/null)
    
    if [ "$response" = "403" ]; then
        echo -e "${GREEN}✓ Blocked${NC}"
    else
        echo -e "${RED}✗ NOT BLOCKED (Status: $response)${NC}"
    fi
    
    # JWT None Algorithm
    echo -n "Testing JWT Attack Protection... "
    response=$(curl -s -X GET http://localhost:$WAF_PORT/api/admin \
        -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4ifQ." \
        -w "%{http_code}" -o /dev/null)
    
    if [ "$response" = "403" ]; then
        echo -e "${GREEN}✓ Blocked${NC}"
    else
        echo -e "${RED}✗ NOT BLOCKED (Status: $response)${NC}"
    fi
    
    # Prototype Pollution
    echo -n "Testing Prototype Pollution Protection... "
    response=$(curl -s -X POST http://localhost:$WAF_PORT/api/data \
        -H "Content-Type: application/json" \
        -d '{"__proto__":{"isAdmin":true}}' \
        -w "%{http_code}" -o /dev/null)
    
    if [ "$response" = "403" ]; then
        echo -e "${GREEN}✓ Blocked${NC}"
    else
        echo -e "${RED}✗ NOT BLOCKED (Status: $response)${NC}"
    fi
}

# Run evasion tests
run_evasion_tests() {
    echo ""
    echo "Running Evasion Technique Tests..."
    echo "================================"
    
    # Double URL Encoding
    echo -n "Testing Double URL Encoding Detection... "
    response=$(curl -s -X POST http://localhost:$WAF_PORT/api/test \
        -H "Content-Type: application/json" \
        -d '{"data":"%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E"}' \
        -w "%{http_code}" -o /dev/null)
    
    if [ "$response" = "403" ]; then
        echo -e "${GREEN}✓ Blocked${NC}"
    else
        echo -e "${RED}✗ NOT BLOCKED (Status: $response)${NC}"
    fi
    
    # Case Manipulation
    echo -n "Testing Case Manipulation Detection... "
    response=$(curl -s -X POST http://localhost:$WAF_PORT/api/test \
        -H "Content-Type: application/json" \
        -d '{"data":"<ScRiPt>alert(1)</sCrIpT>"}' \
        -w "%{http_code}" -o /dev/null)
    
    if [ "$response" = "403" ]; then
        echo -e "${GREEN}✓ Blocked${NC}"
    else
        echo -e "${RED}✗ NOT BLOCKED (Status: $response)${NC}"
    fi
    
    # Unicode Encoding
    echo -n "Testing Unicode Encoding Detection... "
    response=$(curl -s -X POST http://localhost:$WAF_PORT/api/test \
        -H "Content-Type: application/json" \
        -d '{"data":"\\u003cscript\\u003ealert(1)\\u003c/script\\u003e"}' \
        -w "%{http_code}" -o /dev/null)
    
    if [ "$response" = "403" ]; then
        echo -e "${GREEN}✓ Blocked${NC}"
    else
        echo -e "${RED}✗ NOT BLOCKED (Status: $response)${NC}"
    fi
}

# Run rate limiting tests
run_rate_limit_tests() {
    echo ""
    echo "Running Rate Limiting Tests..."
    echo "================================"
    
    echo -n "Testing rate limiting (sending 150 requests)... "
    
    blocked_count=0
    for i in {1..150}; do
        response=$(curl -s -X GET http://localhost:$WAF_PORT/api/data \
            -w "%{http_code}" -o /dev/null)
        
        if [ "$response" = "429" ] || [ "$response" = "403" ]; then
            blocked_count=$((blocked_count + 1))
        fi
    done
    
    if [ $blocked_count -gt 40 ]; then
        echo -e "${GREEN}✓ Rate limiting working (blocked $blocked_count/150)${NC}"
    else
        echo -e "${RED}✗ Rate limiting weak (blocked only $blocked_count/150)${NC}"
    fi
}

# Run bot detection tests
run_bot_tests() {
    echo ""
    echo "Running Bot Detection Tests..."
    echo "================================"
    
    # Missing User-Agent
    echo -n "Testing missing User-Agent detection... "
    response=$(curl -s -X GET http://localhost:$WAF_PORT/api/test \
        -H "User-Agent:" \
        -w "%{http_code}" -o /dev/null)
    
    if [ "$response" = "403" ]; then
        echo -e "${GREEN}✓ Blocked${NC}"
    else
        echo -e "${YELLOW}⚠ Not blocked (may be intentional)${NC}"
    fi
    
    # Known Bot User-Agent
    echo -n "Testing bot User-Agent detection... "
    response=$(curl -s -X GET http://localhost:$WAF_PORT/api/test \
        -H "User-Agent: sqlmap/1.0" \
        -w "%{http_code}" -o /dev/null)
    
    if [ "$response" = "403" ]; then
        echo -e "${GREEN}✓ Blocked${NC}"
    else
        echo -e "${RED}✗ NOT BLOCKED${NC}"
    fi
    
    # Automated Tool Headers
    echo -n "Testing automated tool detection... "
    response=$(curl -s -X GET http://localhost:$WAF_PORT/api/test \
        -H "X-Selenium: 1" \
        -H "User-Agent: Puppeteer" \
        -w "%{http_code}" -o /dev/null)
    
    if [ "$response" = "403" ]; then
        echo -e "${GREEN}✓ Blocked${NC}"
    else
        echo -e "${RED}✗ NOT BLOCKED${NC}"
    fi
}

# Run full automated test suite
run_full_suite() {
    echo ""
    echo "Running Full Automated Test Suite..."
    echo "================================"
    echo "This will run 1000+ tests and may take several minutes..."
    echo ""
    
    cd /root/bit\ phantom
    node tests/automated-pentest.js
}

# Performance benchmark
run_performance_test() {
    echo ""
    echo "Running Performance Benchmark..."
    echo "================================"
    
    echo "Testing response time with WAF enabled..."
    
    total_time=0
    requests=100
    
    for i in $(seq 1 $requests); do
        time_ms=$(curl -s -o /dev/null -w "%{time_total}" http://localhost:$WAF_PORT/api/test)
        total_time=$(echo "$total_time + $time_ms" | bc)
    done
    
    avg_time=$(echo "scale=3; $total_time / $requests * 1000" | bc)
    echo "Average response time: ${avg_time}ms"
    
    if (( $(echo "$avg_time < 50" | bc -l) )); then
        echo -e "${GREEN}✓ Excellent performance (<50ms)${NC}"
    elif (( $(echo "$avg_time < 100" | bc -l) )); then
        echo -e "${YELLOW}⚠ Good performance (<100ms)${NC}"
    else
        echo -e "${RED}✗ Performance needs optimization (>100ms)${NC}"
    fi
}

# Memory usage check
check_memory() {
    echo ""
    echo "Checking Memory Usage..."
    echo "================================"
    
    # Get WAF process memory
    if [ -n "$WAF_PID" ]; then
        mem_usage=$(ps -o rss= -p $WAF_PID | awk '{print $1/1024 " MB"}')
        echo "WAF Memory Usage: $mem_usage"
        
        mem_mb=$(ps -o rss= -p $WAF_PID | awk '{print $1/1024}')
        if (( $(echo "$mem_mb < 500" | bc -l) )); then
            echo -e "${GREEN}✓ Within target (<500MB)${NC}"
        elif (( $(echo "$mem_mb < 1000" | bc -l) )); then
            echo -e "${YELLOW}⚠ Acceptable (<1GB)${NC}"
        else
            echo -e "${RED}✗ Exceeds target (>1GB)${NC}"
        fi
    fi
}

# Generate test report
generate_report() {
    echo ""
    echo "=========================================="
    echo "           TEST REPORT SUMMARY"
    echo "=========================================="
    
    report_file="/root/bit phantom/test-results/report-$(date +%Y%m%d-%H%M%S).txt"
    mkdir -p /root/bit\ phantom/test-results
    
    {
        echo "Bit Phantom WAF Test Report"
        echo "Generated: $(date)"
        echo ""
        echo "Test Categories:"
        echo "- Basic Security: XSS, SQLi, Path Traversal, Command Injection"
        echo "- Advanced: XXE, SSRF, JWT, Prototype Pollution"
        echo "- Evasion: Encoding, Case Manipulation, Unicode"
        echo "- Rate Limiting: Burst protection"
        echo "- Bot Detection: User-Agent, Automation tools"
        echo ""
        echo "Results saved to: $report_file"
    } | tee "$report_file"
    
    echo ""
    echo -e "${GREEN}Report saved to: $report_file${NC}"
}

# Main execution
main() {
    case "$TEST_MODE" in
        basic)
            check_waf
            run_basic_tests
            ;;
        advanced)
            check_waf
            run_advanced_tests
            ;;
        evasion)
            check_waf
            run_evasion_tests
            ;;
        rate)
            check_waf
            run_rate_limit_tests
            ;;
        bot)
            check_waf
            run_bot_tests
            ;;
        performance)
            check_waf
            run_performance_test
            check_memory
            ;;
        full)
            check_waf
            run_basic_tests
            run_advanced_tests
            run_evasion_tests
            run_rate_limit_tests
            run_bot_tests
            run_performance_test
            check_memory
            generate_report
            ;;
        suite)
            check_waf
            run_full_suite
            ;;
        *)
            echo "Usage: $0"
            echo "Environment variables:"
            echo "  TEST_MODE=[basic|advanced|evasion|rate|bot|performance|full|suite]"
            echo "  WAF_PORT=3001"
            echo "  VERBOSE=false"
            echo ""
            echo "Example: TEST_MODE=full ./run-tests.sh"
            exit 1
            ;;
    esac
}

# Cleanup on exit
cleanup() {
    if [ -n "$WAF_PID" ]; then
        echo ""
        echo "Stopping WAF..."
        kill $WAF_PID 2>/dev/null || true
    fi
}

trap cleanup EXIT

# Run main
main

echo ""
echo "=========================================="
echo "         TESTING COMPLETE"
echo "=========================================="