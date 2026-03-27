#!/bin/bash
#
# Download real SS7/Diameter/GTP pcaps from Wireshark wiki
# These are protocol-correct samples (not attack traffic, but real encoding)
#

PCAP_DIR="test-pcaps/wireshark-samples"
mkdir -p "$PCAP_DIR"
cd "$PCAP_DIR"

echo "Downloading Wireshark sample pcaps..."
echo

# Direct URLs from Wireshark wiki attachments
SAMPLES=(
    "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/gsm_map_with_ussd_string.pcap|gsm_map_ussd.pcap|GSM MAP USSD"
    "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/camel.pcap|camel.pcap|CAMEL call"
    "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/camel2.pcap|camel2.pcap|CAMEL call 2"
    "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/packlog-example.cap|packlog.cap|Cisco SS7 packlog"
    "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/isup.cap|isup.cap|ISUP signaling"
    "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/diameter.cap|diameter.cap|Diameter"
)

for entry in "${SAMPLES[@]}"; do
    IFS='|' read -r url filename desc <<< "$entry"
    if [ ! -f "$filename" ] || [ ! -s "$filename" ]; then
        echo -n "  Downloading $desc... "
        if curl -sL "$url" -o "$filename" 2>/dev/null && [ -s "$filename" ]; then
            echo "✓ $(ls -lh "$filename" | awk '{print $5}')"
        else
            echo "✗ failed"
            rm -f "$filename"
        fi
    else
        echo "  Already have: $filename"
    fi
done

echo
echo "Downloaded files:"
ls -la *.pcap *.cap 2>/dev/null || echo "  (none)"

echo
echo "Test with SigCorr:"
echo "  for f in $PCAP_DIR/*.pcap $PCAP_DIR/*.cap; do"
echo "    echo \"=== \$(basename \$f) ===\""
echo "    java -jar target/sigcorr-0.1.0.jar analyze \"\$f\" 2>&1 | tail -20"
echo "  done"
