# Getting Started with SigCorr

## Installation

### Option 1: Docker (fastest)

```bash
git clone https://github.com/sage-s11/sigcorr.git
cd sigcorr
docker build -t sigcorr .
docker run --rm -v $(pwd):/data sigcorr analyze /data/test-pcaps/ss7_location_tracking.pcap
```

### Option 2: Build from source

**Prerequisites:** Java 17+, Maven 3.8+, tshark 3.6+

```bash
git clone https://github.com/sage-s11/sigcorr.git
cd sigcorr
mvn clean package -DskipTests -q
java -jar target/sigcorr-0.1.0-all.jar analyze test-pcaps/ss7_location_tracking.pcap
```

## Your First Analysis

### Single file

```bash
java -jar target/sigcorr-0.1.0-all.jar analyze capture.pcap
```

### Batch (entire directory)

```bash
java -jar target/sigcorr-0.1.0-all.jar analyze ./captures/
```

### Output formats

```bash
# Console (default)
java -jar target/sigcorr-0.1.0-all.jar analyze capture.pcap

# JSON (for scripting, SIEM import)
java -jar target/sigcorr-0.1.0-all.jar analyze capture.pcap --json

# CSV (for Excel, pandas)
java -jar target/sigcorr-0.1.0-all.jar analyze capture.pcap --csv

# Quiet mode (suppress banner, clean output)
java -jar target/sigcorr-0.1.0-all.jar analyze capture.pcap -q --json
```

### Evidence export

SigCorr can extract the specific packets that triggered an alert into separate pcap files:

```bash
java -jar target/sigcorr-0.1.0-all.jar analyze capture.pcap --export-evidence
# Evidence pcaps saved to ./evidence/
```

## Understanding the Output

A typical alert looks like:

```
ALERT[HIGH] ATK-001 | Silent Location Tracking | subscriber=IMSI:234101234567890 | confidence=89% | events=2 | cross-protocol=false | duration=3000ms
```

- **Severity** (CRITICAL/HIGH/MEDIUM) — How dangerous the attack is if successful
- **Pattern ID** — Maps to the [attack pattern catalog](../attacks/)
- **Subscriber** — The targeted IMSI or MSISDN
- **Confidence** — How certain SigCorr is that this is a real attack (not normal traffic)
- **Cross-protocol** — Whether the attack spans multiple protocol families
- **Duration** — Time between first and last event in the attack chain

## Running the Demo

SigCorr includes a built-in demo with synthetic attack scenarios:

```bash
java -jar target/sigcorr-0.1.0-all.jar demo
```

This generates 7 attack scenarios and 1 legitimate traffic scenario, showing SigCorr's detection capabilities without needing real pcap files.

## Listing All Patterns

```bash
java -jar target/sigcorr-0.1.0-all.jar patterns
```

Shows all 22 detection patterns with their steps, temporal windows, and MITRE ATT&CK mappings.

## Next Steps

- Read the [attack pattern documentation](../attacks/) for details on each detection
- Configure SigCorr via [sigcorr-config.yaml](configuration.md)
- Set up [Docker deployment](docker.md) for production use
- Check the [MITRE ATT&CK mapping](../../ATTACK_MAPPING.md) for threat framework integration
