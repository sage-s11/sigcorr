# SigCorr

**Passive Cross-Protocol Attack Detection for Mobile Core Networks**

SigCorr is the first open-source tool to detect cross-protocol attack chains spanning SS7/MAP, Diameter S6a, and GTPv2-C through unified subscriber identity correlation.

[![CI](https://github.com/sage-s11/sigcorr/actions/workflows/ci.yml/badge.svg)](https://github.com/sage-s11/sigcorr/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%203.0-blue.svg)](https://opensource.org/licenses/AGPL-3.0)
[![Java 17+](https://img.shields.io/badge/Java-17%2B-orange.svg)](https://openjdk.org/)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED.svg)](https://github.com/sage-s11/sigcorr/blob/main/Dockerfile)
[![MITRE ATT\&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-mapped-red.svg)](ATTACK_MAPPING.md)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.19439509.svg)](https://doi.org/10.5281/zenodo.19439509)

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

| ID      | Attack                    | Description                                  |
|---------|---------------------------|----------------------------------------------|
| ATK-001 | Silent Location Tracking  | SRI followed by PSI to track subscriber      |
| ATK-002 | Interception Setup        | SRI followed by ISD to redirect calls        |
| ATK-006 | Subscriber DoS            | CancelLocation + DeleteSubscriberData        |
| ATK-011 | SMS Interception          | SRI-SM followed by MT-ForwardSM              |
| ATK-014 | Auth Vector Harvesting    | SRI followed by SendAuthInfo                 |
| ATK-021 | IMSI Catcher Detection    | Rogue UpdateLocation + SendAuthInfo          |

### Cross-Protocol Attacks

| ID      | Attack                       | Description                                  |
|---------|------------------------------|----------------------------------------------|
| ATK-003 | Multi-Protocol Reconnaissance| MAP + Diameter + GTP coordinated attack      |
| ATK-005 | Diameter-to-SS7 Downgrade   | Diameter AIR failure then MAP fallback       |
| ATK-009 | Diameter Recon + GTP Hijack  | AIR followed by CreateSession                |
| ATK-010 | Diameter Location Hijack     | AIR followed by spoofed ULR                  |

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

## Contributing

Contributions are welcome! Whether it's bug reports, new attack pattern ideas, protocol support, or documentation improvements — all help is appreciated.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-attack-pattern`)
3. Commit your changes (`git commit -m 'Add ATK-022: new pattern'`)
4. Push to the branch (`git push origin feature/new-attack-pattern`)
5. Open a Pull Request

Please make sure `./test.sh` passes before submitting.

---

## License

SigCorr is released under the **GNU Affero General Public License v3.0 (AGPL-3.0)**.

This means you are free to use, modify, and distribute SigCorr, including in commercial environments. If you modify SigCorr and make it available over a network (e.g., as a hosted service), you must release your modifications under the same license.

See [LICENSE](LICENSE) for the full text.

### Commercial Licensing

If the AGPL does not work for your use case — for example, if you want to embed SigCorr into a proprietary product or offer it as part of a commercial service without the AGPL's source-sharing requirements — a **commercial license** is available.

Contact **Shreyas S** at [shrey.sneh650@gmail.com](mailto:shrey.sneh650@gmail.com) or open a [GitHub Issue](https://github.com/sage-s11/sigcorr/issues) tagged `licensing` to discuss.

---

## Citing SigCorr

If you use SigCorr in academic research, please cite:

```bibtex
@software{sigcorr2025,
  author    = {Shreyas S},
  title     = {SigCorr: Passive Cross-Protocol Attack Detection for Mobile Core Networks},
  year      = {2025},
  url       = {https://github.com/sage-s11/sigcorr},
  doi       = {10.5281/zenodo.19439509}
}
```

---

## References

- [GSMA FS.11](https://www.gsma.com/security/resources/fs-11-ss7-interconnect-security-monitoring-guidelines/) — SS7 Security Monitoring Guidelines
- [GSMA FS.19](https://www.gsma.com/security/resources/fs-19-diameter-interconnect-security/) — Diameter Interconnect Security
- [3GPP TS 29.002](https://www.3gpp.org/DynaReport/29002.htm) — MAP Protocol Specification
- [3GPP TS 29.272](https://www.3gpp.org/DynaReport/29272.htm) — Diameter S6a/S6d Interface

---

## Author

**Shreyas S** (GitHub: [@sage-s11](https://github.com/sage-s11))
