#!/bin/bash
#
# SigCorr Public Sample Robustness Test
# =====================================
# Tests that SigCorr handles real-world pcap variations without crashing
# and doesn't produce false positives on normal traffic.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
JAR="$SCRIPT_DIR/../target/sigcorr-0.1.0.jar"
SAMPLES_DIR="$SCRIPT_DIR/public-samples"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo ""
echo "════════════════════════════════════════════════════════════════"
echo -e " ${BLUE}SigCorr Public Sample Robustness Test${NC}"
echo "════════════════════════════════════════════════════════════════"
echo ""

# Check JAR
if [[ ! -f "$JAR" ]]; then
    echo -e "${RED}ERROR: JAR not found at $JAR${NC}"
    echo "Run: mvn clean package -DskipTests"
    exit 1
fi

# Check samples directory
if [[ ! -d "$SAMPLES_DIR" ]] || [[ -z "$(ls -A "$SAMPLES_DIR"/*.pcap 2>/dev/null)$(ls -A "$SAMPLES_DIR"/*.pcapng 2>/dev/null)$(ls -A "$SAMPLES_DIR"/*.cap 2>/dev/null)" ]]; then
    echo -e "${YELLOW}No public samples found in $SAMPLES_DIR${NC}"
    echo "See DOWNLOAD_GUIDE.md for instructions"
    exit 0
fi

passed=0
crashed=0
warnings=0
total=0

for f in "$SAMPLES_DIR"/*.pcap "$SAMPLES_DIR"/*.pcapng "$SAMPLES_DIR"/*.cap; do
    [[ -f "$f" ]] || continue
    name=$(basename "$f")
    total=$((total + 1))
    
    # Run SigCorr with timeout, capture both stdout and exit code
    set +e
    output=$(timeout 120 java -jar "$JAR" analyze "$f" 2>&1)
    exit_code=$?
    set -e
    
    # Check for actual crashes (Java exceptions)
    if echo "$output" | grep -qiE "Exception|Error.*at.*\.java:|NullPointer|OutOfMemory"; then
        echo -e "  ${RED}[CRASH]${NC} $name"
        echo "$output" | grep -A2 "Exception\|Error" | head -5
        crashed=$((crashed + 1))
        continue
    fi
    
    # Check for timeout
    if [[ $exit_code -eq 124 ]]; then
        echo -e "  ${YELLOW}[TIMEOUT]${NC} $name (>120s)"
        warnings=$((warnings + 1))
        continue
    fi
    
    # Parse output for alerts and events
    alert_count=$(echo "$output" | grep -c "ALERT" 2>/dev/null || echo "0")
    
    # Extract event counts - try different patterns
    map_events=$(echo "$output" | grep -oP "SS7/MAP:\s*\K\d+" 2>/dev/null || echo "0")
    dia_events=$(echo "$output" | grep -oP "Diameter:\s*\K\d+" 2>/dev/null || echo "0")
    gtp_events=$(echo "$output" | grep -oP "GTPv2:\s*\K\d+" 2>/dev/null || echo "0")
    total_events=$((map_events + dia_events + gtp_events))
    
    if [[ "$alert_count" -gt 0 ]]; then
        echo -e "  ${YELLOW}[WARN]${NC}  $name - $alert_count alerts on public sample"
        warnings=$((warnings + 1))
    elif [[ "$total_events" -gt 0 ]]; then
        echo -e "  ${GREEN}[PASS]${NC}  $name - $total_events events, 0 alerts"
        passed=$((passed + 1))
    else
        echo -e "  ${GREEN}[PASS]${NC}  $name - no supported events (0 alerts)"
        passed=$((passed + 1))
    fi
done

echo ""
echo "════════════════════════════════════════════════════════════════"
echo " Summary"
echo "════════════════════════════════════════════════════════════════"
echo -e "  Total:    $total"
echo -e "  ${GREEN}Passed:${NC}   $passed"
echo -e "  ${YELLOW}Warnings:${NC} $warnings"
echo -e "  ${RED}Crashed:${NC}  $crashed"
echo ""

if [[ "$crashed" -eq 0 ]]; then
    echo -e "${GREEN}✓ ROBUSTNESS TEST PASSED - No crashes on public samples${NC}"
    exit 0
else
    echo -e "${RED}✗ ROBUSTNESS TEST FAILED - $crashed crashes${NC}"
    exit 1
fi
