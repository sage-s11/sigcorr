# MITRE ATT&CK Mapping

SigCorr attack patterns mapped to [MITRE ATT&CK for Mobile](https://attack.mitre.org/matrices/mobile/) and [MITRE FiGHT](https://fight.mitre.org/) (5G threat framework).

## SS7/MAP Attacks

| SigCorr ID | Attack | MITRE ATT&CK | MITRE FiGHT | Tactic |
|------------|--------|---------------|--------------|--------|
| ATK-001 | Silent Location Tracking | [T1430](https://attack.mitre.org/techniques/T1430/) — Location Tracking | FGT1040 — Location tracking | Collection |
| ATK-002 | Interception Setup | [T1638](https://attack.mitre.org/techniques/T1638/) — Adversary-in-the-Middle | FGT1557 — Adversary-in-the-middle | Collection |
| ATK-006 | Subscriber DoS | [T1464](https://attack.mitre.org/techniques/T1464/) — Network Denial of Service | FGT5012 — Subscriber profile manipulation | Impact |
| ATK-011 | SMS Interception | [T1412](https://attack.mitre.org/techniques/T1412/) — Capture SMS Messages | FGT1040.002 — SS7 exploitation | Collection |
| ATK-014 | Auth Vector Harvesting | [T1056](https://attack.mitre.org/techniques/T1056/) — Input Capture | FGT5019 — Retrieve UE subscription data | Credential Access |
| ATK-021 | IMSI Catcher Detection | [T1430](https://attack.mitre.org/techniques/T1430/) — Location Tracking | FGT5004 — Fake base station | Collection, Initial Access |

## Cross-Protocol Attacks

| SigCorr ID | Attack | MITRE ATT&CK | MITRE FiGHT | Tactic |
|------------|--------|---------------|--------------|--------|
| ATK-003 | Multi-Protocol Reconnaissance | [T1422](https://attack.mitre.org/techniques/T1422/) — System Network Configuration Discovery | FGT5012 — Subscriber profile manipulation | Discovery |
| ATK-005 | Diameter-to-SS7 Downgrade | [T1562](https://attack.mitre.org/techniques/T1562/) — Impair Defenses | FGT5029 — Diameter signaling exploitation | Defense Evasion |
| ATK-009 | Diameter Recon + GTP Hijack | [T1557](https://attack.mitre.org/techniques/T1557/) — Adversary-in-the-Middle | FGT5029 + FGT1557 | Lateral Movement |
| ATK-010 | Diameter Location Hijack | [T1430](https://attack.mitre.org/techniques/T1430/) — Location Tracking | FGT5029 — Diameter signaling exploitation | Collection |

## GSMA Reference Mapping

| SigCorr ID | GSMA FS.11 Category | GSMA FS.19 Category |
|------------|---------------------|---------------------|
| ATK-001 | Cat 1 — Location Tracking | — |
| ATK-002 | Cat 2 — Interception | — |
| ATK-003 | Cat 1 + Cat 2 (cross-protocol) | Cat A — Unauthorized info retrieval |
| ATK-005 | — | Cat C — Protocol downgrade |
| ATK-006 | Cat 3 — Denial of Service | — |
| ATK-009 | — | Cat A + GTP abuse |
| ATK-010 | — | Cat B — Location manipulation |
| ATK-011 | Cat 2 — SMS Interception | — |
| ATK-014 | Cat 2 — Info harvesting | — |
| ATK-021 | Cat 1 — IMSI catching | — |

## Usage with SigCorr

SigCorr includes ATT&CK technique IDs in JSON output:

```bash
java -jar sigcorr.jar analyze capture.pcap --format json
```

```json
{
  "alert": {
    "id": "ATK-001",
    "name": "Silent Location Tracking",
    "mitre_attack": ["T1430"],
    "mitre_fight": ["FGT1040"],
    "tactic": "Collection",
    "confidence": 95
  }
}
```
