# SigCorr — Passive Cross-Interface Telecom Signaling Security Correlator

The first open-source tool that correlates security events across SS7/MAP, Diameter S6a, and GTPv2-C protocol interfaces to detect multi-step attacks invisible to single-protocol monitors.

## Quick Start

```bash
# Build
mvn clean package -q

# Run demo (synthetic attack scenarios)
mvn exec:java -Dexec.args="demo"

# Analyze a real pcap file (requires tshark)
mvn exec:java -Dexec.args="analyze capture.pcap"

# Or use the fat JAR directly
java -jar target/sigcorr-0.1.0.jar demo
java -jar target/sigcorr-0.1.0.jar analyze capture.pcap --verbose

# Run tests
mvn test

# List detection patterns
java -jar target/sigcorr-0.1.0.jar patterns
```

## What It Does

Telecom signaling attacks (location tracking, call interception, subscriber DoS) span multiple protocol interfaces. An attacker queries routing info via SS7 MAP, then redirects calls via Diameter, then establishes a data session via GTP-C. Each step looks normal on its own interface. SigCorr correlates across all three.

### Detection Catalog

| ID | Attack | Severity | Protocols | Steps |
|---|---|---|---|---|
| ATK-001 | Silent Location Tracking | HIGH | MAP | SRI → PSI |
| ATK-002 | Interception Setup | CRITICAL | MAP + Diameter | SRI → ISD → ULR |
| ATK-003 | Tracking + Session Hijack | CRITICAL | MAP + GTP | SRI → Create-Session |
| ATK-004 | IMSI Harvesting | MEDIUM | MAP | SRI → SRI |
| ATK-005 | Auth Downgrade | HIGH | Diameter + MAP | AIR → SendAuthInfo |
| ATK-006 | Subscriber DoS | HIGH | MAP | Cancel → Delete |
| ATK-007 | Call Forwarding Intercept | CRITICAL | MAP | RegisterSS → ActivateSS |
| ATK-008 | Cross-Protocol Recon | HIGH | MAP + Diameter | SRI → AIR |

## Architecture

```
pcap file → tshark (JSON decode) → TsharkBridge → Normalized SignalingEvents
    → IdentityResolver (learns IMSI↔MSISDN from signaling)
        → TemporalWindow (per-subscriber event grouping)
            → PatternMatcher (8 attack pattern definitions)
                → SecurityAlerts (with confidence scoring)
```

### Key Design Decision: tshark Bridge

Instead of reimplementing Wireshark's protocol dissectors, SigCorr uses `tshark -T ek` to decode pcap files into structured JSON, then maps the fields to its internal event model. This gives us Wireshark-quality protocol decoding for free.

## Requirements

- Java 17+
- Maven 3.8+
- tshark (for pcap analysis): `sudo apt install tshark`

## Options

```
sigcorr <command> [options]

Commands:
  demo                  Run synthetic attack scenarios
  analyze <pcap>        Analyze pcap file via tshark
  patterns              List detection patterns
  version               Show version

Options:
  --verbose, -v         Debug output with event details
  --quiet, -q           Suppress banner and info
  --json                JSON output
```

## References

- 3GPP TS 29.002 — MAP Protocol
- 3GPP TS 29.272 — Diameter S6a/S6d
- 3GPP TS 29.274 — GTPv2-C
- GSMA IR.82 — SS7 Security Monitoring
- GSMA FS.11 — SS7/Diameter Interconnect Security

## License

MIT
