#!/bin/bash
#
# SigCorr Real-World PCAP Test Suite
# Downloads sample pcaps from Wireshark wiki and tests SigCorr against them
#

set -e

PCAP_DIR="./real-world-pcaps"
SIGCORR_JAR="../target/sigcorr-0.1.0.jar"

echo "=============================================="
echo "SigCorr Real-World PCAP Test Suite"
echo "=============================================="
echo

# Create directory
mkdir -p "$PCAP_DIR"
cd "$PCAP_DIR"

# ============================================================================
# WIRESHARK WIKI SAMPLE PCAPS
# ============================================================================

echo "[1/4] Downloading Wireshark sample pcaps..."
echo

# GSM MAP with USSD
if [ ! -f gsm_map_with_ussd_string.pcap ]; then
    echo "  Downloading gsm_map_with_ussd_string.pcap..."
    wget -q "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/gsm_map_with_ussd_string.pcap" -O gsm_map_with_ussd_string.pcap 2>/dev/null || echo "  (download failed)"
fi

# CAMEL pcap
if [ ! -f camel.pcap ]; then
    echo "  Downloading camel.pcap..."
    wget -q "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/camel.pcap" -O camel.pcap 2>/dev/null || echo "  (download failed)"
fi

# CAMEL2 pcap
if [ ! -f camel2.pcap ]; then
    echo "  Downloading camel2.pcap..."
    wget -q "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/camel2.pcap" -O camel2.pcap 2>/dev/null || echo "  (download failed)"
fi

# ISUP pcap
if [ ! -f isup.cap ]; then
    echo "  Downloading isup.cap..."
    wget -q "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/isup.cap" -O isup.cap 2>/dev/null || echo "  (download failed)"
fi

# Packlog example (Cisco SS7)
if [ ! -f packlog-example.cap ]; then
    echo "  Downloading packlog-example.cap..."
    wget -q "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/packlog-example.cap" -O packlog-example.cap 2>/dev/null || echo "  (download failed)"
fi

# Japan TCAP
if [ ! -f japan_tcap_over_m2pa.pcap ]; then
    echo "  Downloading japan_tcap_over_m2pa.pcap..."
    wget -q "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/japan_tcap_over_m2pa.pcap" -O japan_tcap_over_m2pa.pcap 2>/dev/null || echo "  (download failed)"
fi

# ANSI TCAP
if [ ! -f ansi_tcap_over_itu_sccp_over_mtp3_over_mtp2.pcap ]; then
    echo "  Downloading ansi_tcap_over_itu_sccp_over_mtp3_over_mtp2.pcap..."
    wget -q "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/ansi_tcap_over_itu_sccp_over_mtp3_over_mtp2.pcap" -O ansi_tcap_over_itu_sccp_over_mtp3_over_mtp2.pcap 2>/dev/null || echo "  (download failed)"
fi

# ANSI MAP WIN
if [ ! -f ansi_map_win.pcap ]; then
    echo "  Downloading ansi_map_win.pcap..."
    wget -q "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/ansi_map_win.pcap" -O ansi_map_win.pcap 2>/dev/null || echo "  (download failed)"
fi

# Diameter
if [ ! -f diameter.cap ]; then
    echo "  Downloading diameter.cap..."
    wget -q "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/diameter.cap" -O diameter.cap 2>/dev/null || echo "  (download failed)"
fi

# GTPv2
if [ ! -f gtpv2.pcap ]; then
    echo "  Downloading gtpv2.pcap..."
    wget -q "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/gtp_v2.pcap" -O gtpv2.pcap 2>/dev/null || echo "  (download failed)"
fi

echo
echo "[2/4] Listing downloaded pcaps..."
echo
ls -la *.pcap *.cap 2>/dev/null || echo "No pcaps found"

echo
echo "[3/4] Checking pcap contents with tshark..."
echo

for f in *.pcap *.cap; do
    if [ -f "$f" ]; then
        echo "=== $f ==="
        echo "  Packets: $(tshark -r "$f" 2>/dev/null | wc -l)"
        echo "  Protocols: $(tshark -r "$f" -T fields -e frame.protocols 2>/dev/null | sort -u | head -5)"
        echo
    fi
done

echo
echo "[4/4] Running SigCorr analysis..."
echo

cd ..

for f in "$PCAP_DIR"/*.pcap "$PCAP_DIR"/*.cap; do
    if [ -f "$f" ]; then
        echo "════════════════════════════════════════════════════════════"
        echo "TESTING: $(basename $f)"
        echo "════════════════════════════════════════════════════════════"
        
        # Run SigCorr
        java -jar "$SIGCORR_JAR" analyze "$f" 2>&1 || echo "  (analysis failed or no events detected)"
        
        echo
    fi
done

echo
echo "=============================================="
echo "Test Suite Complete"
echo "=============================================="
