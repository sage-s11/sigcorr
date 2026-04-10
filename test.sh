#!/bin/bash
#
# SigCorr Test Runner
# Generates test pcaps and validates detection
#

set -e

cd "$(dirname "$0")"

echo "════════════════════════════════════════════════════════════"
echo " SigCorr Test Suite"
echo "════════════════════════════════════════════════════════════"
echo

# Check JAR exists
if [ ! -f "target/sigcorr-0.1.0-all.jar" ]; then
    echo "Building SigCorr..."
    mvn clean package -DskipTests -q
fi

# Generate test pcaps
echo "[1/3] Generating test pcaps..."
cd test-pcaps
python3 generate_ss7_attack_pcaps.py 2>/dev/null || {
    echo "ERROR: pcap generator failed"
    exit 1
}
cd ..
echo

# Run tests
echo "[2/3] Running attack detection tests..."
echo

PASSED=0
FAILED=0

test_pcap() {
    local pcap="$1"
    local expected="$2"
    local name="$3"
    
    if [ ! -f "test-pcaps/$pcap" ]; then
        echo "  [SKIP] $name - file not found"
        return
    fi
    
    output=$(java -jar target/sigcorr-0.1.0-all.jar analyze "test-pcaps/$pcap" 2>&1)
    
    if echo "$output" | grep -q "$expected"; then
        echo "  [PASS] $name"
        PASSED=$((PASSED + 1))
    else
        echo "  [FAIL] $name - expected $expected"
        FAILED=$((FAILED + 1))
    fi
}

# Attack pattern tests
test_pcap "ss7_location_tracking.pcap" "ATK-001" "ATK-001: Silent Location Tracking"
test_pcap "ss7_interception_setup.pcap" "ATK-002" "ATK-002: Interception Setup"
test_pcap "full_multi_protocol_attack.pcap" "ATK-001" "ATK-001+003: Multi-Protocol Attack"
test_pcap "atk011_sms_interception.pcap" "ATK-011" "ATK-011: SMS Interception"
test_pcap "atk014_auth_harvesting.pcap" "ATK-014" "ATK-014: Auth Harvesting"
test_pcap "atk021_imsi_catcher.pcap" "ATK-021" "ATK-021: IMSI Catcher"
test_pcap "atk006_subscriber_dos.pcap" "ATK-006" "ATK-006: Subscriber DoS"
test_pcap "cross_protocol_auth_downgrade.pcap" "ATK-005" "ATK-005: Auth Downgrade"

# Negative test (no alerts expected)
echo
echo "  Negative tests:"
output=$(java -jar target/sigcorr-0.1.0-all.jar analyze "test-pcaps/normal_traffic.pcap" 2>&1)
if echo "$output" | grep -q "No attack patterns detected"; then
    echo "  [PASS] Normal traffic - no false positives"
    PASSED=$((PASSED + 1))
else
    echo "  [FAIL] Normal traffic - unexpected alerts"
    FAILED=$((FAILED + 1))
fi

echo
echo "[3/3] Summary"
echo "════════════════════════════════════════════════════════════"
echo "  Passed: $PASSED"
echo "  Failed: $FAILED"
echo

if [ $FAILED -gt 0 ]; then
    echo "SOME TESTS FAILED"
    exit 1
else
    echo "ALL TESTS PASSED ✓"
fi
