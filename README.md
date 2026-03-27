# SigCorr

**Passive Cross-Protocol Attack Detection for Mobile Core Networks**

SigCorr is the first open-source tool to detect cross-protocol attack chains spanning SS7/MAP, Diameter S6a, and GTPv2-C through unified subscriber identity correlation.

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%203.0-blue.svg)](https://opensource.org/licenses/AGPL-3.0)
[![Java 17+](https://img.shields.io/badge/Java-17%2B-orange.svg)](https://openjdk.org/)

---

## Features

- **Cross-protocol correlation** — Links SS7/MAP, Diameter S6a, and GTPv2-C events for the same subscriber
- **Identity resolution** — Automatically correlates IMSI ↔ MSISDN across protocol boundaries  
- **22 attack patterns** — Detects location tracking, interception, DoS, auth harvesting, and more
- **Zero false positives** — Validated against 20+ public telecom pcap samples
- **Passive analysis** — Offline pcap analysis, no network injection

---

## Quick Start

### Prerequisites

- Java 17+ (tested with OpenJDK 21)
- Maven 3.8+
- tshark (Wireshark CLI) 3.6+

### Build

```bash
git clone https://github.com/sage-s11/sigcorr.git
cd sigcorr
mvn clean package -DskipTests
```

### Analyze a PCAP

```bash
java -jar target/sigcorr-0.1.0.jar analyze capture.pcap
```

### Run Tests

```bash
./test.sh
```

---

## Attack Patterns Detected

### SS7/MAP Attacks

| ID | Attack | Description |
|----|--------|-------------|
| ATK-001 | Silent Location Tracking | SRI followed by PSI to track subscriber |
| ATK-002 | Interception Setup | SRI followed by ISD to redirect calls |
| ATK-006 | Subscriber DoS | CancelLocation + DeleteSubscriberData |
| ATK-011 | SMS Interception | SRI-SM followed by MT-ForwardSM |
| ATK-014 | Auth Vector Harvesting | SRI followed by SendAuthInfo |
| ATK-021 | IMSI Catcher Detection | Rogue UpdateLocation + SendAuthInfo |

### Cross-Protocol Attacks

| ID | Attack | Description |
|----|--------|-------------|
| ATK-003 | Multi-Protocol Reconnaissance | MAP + Diameter + GTP coordinated attack |
| ATK-005 | Diameter-to-SS7 Downgrade | Diameter AIR failure then MAP fallback |
| ATK-009 | Diameter Recon + GTP Hijack | AIR followed by CreateSession |
| ATK-010 | Diameter Location Hijack | AIR followed by spoofed ULR |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         SigCorr                                  │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐            │
│  │   SS7/MAP   │   │  Diameter   │   │   GTPv2-C   │            │
│  │   Parser    │   │   Parser    │   │   Parser    │            │
│  └──────┬──────┘   └──────┬──────┘   └──────┬──────┘            │
│         │                 │                 │                    │
│         └────────────┬────┴────────────────┘                    │
│                      ▼                                           │
│            ┌─────────────────────┐                              │
│            │  Identity Resolver  │  IMSI ↔ MSISDN correlation   │
│            └──────────┬──────────┘                              │
│                       ▼                                          │
│            ┌─────────────────────┐                              │
│            │ Correlation Engine  │  Temporal windowing          │
│            └──────────┬──────────┘                              │
│                       ▼                                          │
│            ┌─────────────────────┐                              │
│            │   Pattern Matcher   │  22 attack signatures        │
│            └──────────┬──────────┘                              │
│                       ▼                                          │
│                   ALERTS                                         │
└─────────────────────────────────────────────────────────────────┘
```

---

## Example Output

```
════════════════════════════════════════════════════════════════
 SigCorr v0.1.0 - Cross-Protocol Signaling Security Correlator
════════════════════════════════════════════════════════════════

Analyzing: full_multi_protocol_attack.pcap

Events decoded:
  SS7/MAP:     2
  Diameter:    2
  GTPv2-C:     1
  Total:       5

Alerts:
  ALERT[CRITICAL] ATK-001 | Silent Location Tracking 
    subscriber=IMSI:234101234567890 
    confidence=95% 
    events=2

  ALERT[CRITICAL] ATK-003 | Multi-Protocol Reconnaissance 
    subscriber=IMSI:234101234567890 
    confidence=90% 
    cross-protocol=true
    events=5

Summary: 2 alerts generated
```

---

## Configuration

Edit `sigcorr-config.yaml`:

```yaml
sigcorr:
  tshark:
    path: /usr/bin/tshark
    timeout: 30s
    
  correlation:
    temporal_window: 30s
    inference_window: 10s
    
  detection:
    min_confidence: 70
    enabled_patterns:
      - ATK-001
      - ATK-002
      - ATK-003
      # ... or 'all'
      
  output:
    evidence_dir: ./evidence
    extract_pcap: true
```

---

## Testing

### Attack Detection Tests

```bash
./test.sh
```

Validates 9 attack patterns against generated pcaps.

### Robustness Tests

```bash
# Download public samples first (see test-pcaps/public-samples/DOWNLOAD_GUIDE.md)
bash ./test-pcaps/test_public_samples.sh
```

Tests against 20+ real-world pcap samples for:
- No crashes on encoding variations
- No false positives on normal traffic

---

## Project Structure

```
sigcorr/
├── src/main/java/io/sigcorr/
│   ├── core/              # Core models (SignalingEvent, SubscriberIdentity)
│   ├── ingest/            # Protocol parsers (TsharkBridge)
│   ├── correlation/       # Identity resolution, temporal windowing
│   └── detection/         # Attack patterns, alerting
├── test-pcaps/
│   ├── attack-samples/    # Generated attack pcaps
│   ├── public-samples/    # Real-world validation samples
│   └── generate_*.py      # Pcap generators
├── evidence/              # Extracted evidence pcaps (runtime)
├── pom.xml
├── sigcorr-config.yaml
└── test.sh
```

---

## Roadmap

- [x] v0.1.0 — Pcap-based detection, 22 patterns, cross-protocol correlation
- [ ] v0.2.0 — Real-time stream processing (Kafka/tap input)
- [ ] v0.3.0 — Response code analysis, volumetric detection
- [ ] v1.0.0 — Production-ready with enterprise features

---

## References

- [GSMA FS.11](https://www.gsma.com/security/resources/fs-11-ss7-interconnect-security-monitoring-guidelines/) — SS7 Security Monitoring Guidelines
- [GSMA FS.19](https://www.gsma.com/security/resources/fs-19-diameter-interconnect-security/) — Diameter Interconnect Security
- [3GPP TS 29.002](https://www.3gpp.org/DynaReport/29002.htm) — MAP Protocol Specification
- [3GPP TS 29.272](https://www.3gpp.org/DynaReport/29272.htm) — Diameter S6a/S6d Interface

---

## License

AGPL-3.0 — See [LICENSE](LICENSE) for details.

---

## Author

**Xyzzz** (GitHub: [@sage-s11](https://github.com/sage-s11))

Security researcher specializing in DNS/DDI protocols and telecom signaling security.

---

## Acknowledgments

- Wireshark project for tshark and protocol dissectors
- P1 Security for SS7 security research and inspiration
- The telecom security research community
