#!/bin/bash
#
# SigCorr SS7/MAP Pipeline Complete Integration Script
# 
set -e

echo "================================================"
echo "SigCorr SS7/MAP Pipeline Integration"
echo "================================================"
echo ""

# Check we're in the right directory
if [ ! -f "pom.xml" ]; then
    echo "ERROR: Not in SigCorr project directory"
    exit 1
fi

echo "[1/5] Backing up TsharkBridge.java..."
cp src/main/java/io/sigcorr/ingest/tshark/TsharkBridge.java \
   src/main/java/io/sigcorr/ingest/tshark/TsharkBridge.java.backup-$(date +%Y%m%d-%H%M%S)
echo "✓ Backup created"
echo ""

echo "[2/5] Applying attacker GT normalization fix..."
sed -i '
/subscriber = SubscriberIdentity\.fromMsisdn(callingGt);/ {
    c\
            String attackerGt = null;\
            if (callingGt != null && callingGt.startsWith("49")) {\
                attackerGt = callingGt;\
            } else if (calledGt != null && calledGt.startsWith("49")) {\
                attackerGt = calledGt;\
            } else {\
                attackerGt = callingGt != null ? callingGt : calledGt;\
            }\
            subscriber = SubscriberIdentity.fromMsisdn(attackerGt);
}
' src/main/java/io/sigcorr/ingest/tshark/TsharkBridge.java

echo "✓ Fix applied"
echo ""

echo "[3/5] Verifying..."
grep -A5 "attackerGt = " src/main/java/io/sigcorr/ingest/tshark/TsharkBridge.java | head -8
echo ""

echo "[4/5] Rebuilding..."
mvn clean package -DskipTests -q
echo "✓ Build complete"
echo ""

echo "[5/5] Testing..."
java -jar target/sigcorr-0.1.0.jar analyze test-pcaps/ss7_location_tracking.pcap --verbose

echo ""
echo "================================================"
echo "Done!"
echo "================================================"
