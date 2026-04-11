# SigCorr Documentation

## Attack Pattern Reference

Detailed documentation for each attack pattern detected by SigCorr. Each page explains the attack chain, protocol flow, detection logic, and references.

### SS7/MAP Attacks

| ID | Attack | Severity | Doc |
|----|--------|----------|-----|
| ATK-001 | [Silent Location Tracking](attacks/ATK-001.md) | HIGH | Protocol: SRI → PSI |
| ATK-002 | [Interception Setup](attacks/ATK-002.md) | CRITICAL | Protocol: SRI → ISD |
| ATK-006 | [Subscriber DoS](attacks/ATK-006.md) | HIGH | Protocol: CancelLocation → DeleteSubscriberData |
| ATK-011 | [SMS Interception](attacks/ATK-011.md) | CRITICAL | Protocol: SRI-SM → MT-ForwardSM |
| ATK-014 | [Auth Vector Harvesting](attacks/ATK-014.md) | HIGH | Protocol: SRI → SendAuthInfo |
| ATK-021 | [IMSI Catcher Detection](attacks/ATK-021.md) | CRITICAL | Protocol: UpdateLocation → SendAuthInfo |

### Cross-Protocol Attacks

| ID | Attack | Severity | Doc |
|----|--------|----------|-----|
| ATK-003 | [Multi-Protocol Reconnaissance](attacks/ATK-003.md) | CRITICAL | Protocol: MAP + Diameter + GTP |
| ATK-005 | [Diameter-to-SS7 Downgrade](attacks/ATK-005.md) | HIGH | Protocol: Diameter AIR → MAP fallback |
| ATK-009 | [Diameter Recon + GTP Hijack](attacks/ATK-009.md) | CRITICAL | Protocol: AIR → CreateSession |
| ATK-010 | [Diameter Location Hijack](attacks/ATK-010.md) | CRITICAL | Protocol: AIR → spoofed ULR |

## Guides

- [Getting Started](guides/getting-started.md) — Install, build, and run your first analysis
- [Configuration](guides/configuration.md) — Tune detection thresholds, whitelisting, and output
- [Docker Deployment](guides/docker.md) — Run SigCorr in a container
- [Writing Custom Patterns](guides/custom-patterns.md) — Extend SigCorr with your own detection rules
- [MITRE ATT&CK Mapping](../ATTACK_MAPPING.md) — Full mapping to ATT&CK and FiGHT frameworks

## Architecture

- [Pipeline Overview](architecture/pipeline.md) — How pcap → events → correlation → alerts works
- [Identity Resolution](architecture/identity-resolution.md) — IMSI ↔ MSISDN cross-protocol linking
- [Temporal Windowing](architecture/temporal-windowing.md) — How event sequences are matched
