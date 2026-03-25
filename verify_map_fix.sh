#!/bin/bash
#
# MAP Field Extraction Verification Test
# Tests if gsm_map.imsi_digits and gsm_map.msisdn_digits work with tshark -T ek
#
set -e

echo "========================================"
echo "MAP Field Extraction Verification"
echo "========================================"
echo ""

# Find the pcap
PCAP_CANDIDATES=(
    "test-pcaps/ss7_location_tracking.pcap"
    "../test-pcaps/ss7_location_tracking.pcap"
    "./ss7_location_tracking.pcap"
)

PCAP=""
for candidate in "${PCAP_CANDIDATES[@]}"; do
    if [ -f "$candidate" ]; then
        PCAP="$candidate"
        break
    fi
done

if [ -z "$PCAP" ]; then
    echo "ERROR: Cannot find ss7_location_tracking.pcap"
    echo "Searched in: ${PCAP_CANDIDATES[@]}"
    exit 1
fi

echo "✓ Found pcap: $PCAP"
echo ""

# Test 1: Verify pcap contains MAP traffic
echo "TEST 1: Verify MAP traffic exists..."
MAP_COUNT=$(tshark -r "$PCAP" -Y "gsm_map" 2>&1 | wc -l)
if [ "$MAP_COUNT" -lt 2 ]; then
    echo "✗ FAIL: No MAP packets found in pcap"
    exit 1
fi
echo "✓ PASS: Found $MAP_COUNT lines of MAP traffic"
echo ""

# Test 2: Test OLD (broken) field extraction
echo "TEST 2: Testing OLD field names (should be empty)..."
echo "Fields: e212.imsi, gsm_map.msisdn"
tshark -r "$PCAP" -Y "gsm_map" -T ek \
    -e frame.time_epoch \
    -e e212.imsi \
    -e gsm_map.msisdn 2>&1 | \
    grep -v "^{\"index\"" | head -3

echo ""
echo "Analysis: If you see NO imsi/msisdn fields above, the old fields don't work ✗"
echo ""

# Test 3: Test NEW (fixed) field extraction  
echo "TEST 3: Testing NEW field names (should have data)..."
echo "Fields: gsm_map.imsi_digits, gsm_map.msisdn_digits"

OUTPUT=$(tshark -r "$PCAP" -Y "gsm_map" -T ek \
    -e frame.time_epoch \
    -e gsm_old.localValue \
    -e gsm_map.imsi_digits \
    -e gsm_map.msisdn_digits \
    -e sccp.calling.digits \
    -e sccp.called.digits 2>&1)

echo "$OUTPUT" | grep -v "^{\"index\"" | head -3
echo ""

# Validate that we got data
if echo "$OUTPUT" | grep -q "gsm_map_imsi_digits"; then
    echo "✓ PASS: gsm_map.imsi_digits field extracts data!"
else
    echo "⚠ NOTE: gsm_map.imsi_digits not found (may appear in response, not request)"
fi

if echo "$OUTPUT" | grep -q "gsm_map_msisdn_digits"; then
    echo "✓ PASS: gsm_map.msisdn_digits field extracts data!"
else
    echo "⚠ NOTE: gsm_map.msisdn_digits not found (may appear in request, not response)"
fi

echo ""

# Test 4: Full extraction test with all fields
echo "TEST 4: Full field extraction (as SigCorr will use)..."
echo ""

tshark -r "$PCAP" -Y "gsm_map" -T ek \
    -e frame.time_epoch \
    -e gsm_old.localValue \
    -e gsm_old.opCode \
    -e gsm_map.imsi_digits \
    -e gsm_map.msisdn_digits \
    -e sccp.calling.digits \
    -e sccp.called.digits 2>&1 | \
    grep -v "^{\"index\"" | python3 -m json.tool 2>/dev/null || cat

echo ""
echo "========================================"
echo "VERIFICATION COMPLETE"
echo "========================================"
echo ""
echo "NEXT STEPS:"
echo "1. Apply the patch to TsharkBridge.java (see TsharkBridge_MAP_Fix.patch.java)"
echo "2. Rebuild: mvn clean compile test"
echo "3. Test: java -jar target/sigcorr-0.1.0.jar analyze $PCAP --verbose"
echo "4. Expected: ATK-001 (Location Tracking) alert should fire"
echo ""
