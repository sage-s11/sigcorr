# SigCorr Attack Pattern Mapping — 5G Extensions (v0.2)
---

## 5G Attack Patterns (ATK-022 – ATK-027)

### ATK-022: Bidding-Down Attack (5G→Legacy Forced Handover)

| Field | Value |
|---|---|
| **Severity** | HIGH |
| **Cross-Protocol** | Yes (5G NAS → SS7/MAP) |
| **Attack Chain** | DeregistrationRequest(NW) → MAP UpdateLocation |
| **Temporal Window** | 120 seconds |
| **MITRE ATT&CK** | T1562.001 (Impair Defenses: Disable/Modify Tools) |
| **MITRE FiGHT** | FGT1600.501 (Forced Handover) |
| **GSMA** | FS.37 (GTP Security), FS.11 (SS7 Monitoring) |
| **3GPP** | TS 33.501 §6.7 (Inter-RAT security) |
| **Description** | Subscriber forcibly deregistered from 5G, then same IMSI appears on legacy SS7/MAP network where protections are weaker. Enables IMSI catching, call interception, and location tracking. |

### ATK-023: NAS Replay / Manipulation

| Field | Value |
|---|---|
| **Severity** | HIGH |
| **Cross-Protocol** | No (5G NAS only) |
| **Attack Chain** | SecurityModeCommand(null cipher) → SecurityModeReject |
| **Temporal Window** | 10 seconds |
| **MITRE ATT&CK** | T1557 (Adversary-in-the-Middle) |
| **MITRE FiGHT** | FGT1557 (NAS Manipulation) |
| **3GPP** | TS 33.501 §5.5.2 (NAS replay protection) |
| **Description** | Rogue gNB attempts security downgrade by sending SecurityModeCommand with null ciphering (5G-EA0). UE rejection confirms manipulation attempt. Also detects duplicate RegistrationRequests and unsolicited IdentityRequests. |

### ATK-024: NGAP Handover Hijack

| Field | Value |
|---|---|
| **Severity** | CRITICAL |
| **Cross-Protocol** | Yes (NGAP → GTPv2-C) |
| **Attack Chain** | HandoverRequired → GTP ModifyBearerRequest |
| **Temporal Window** | 30 seconds |
| **MITRE ATT&CK** | T1557 (Adversary-in-the-Middle) |
| **MITRE FiGHT** | FGT1599 (Rogue Base Station) |
| **GSMA** | FS.37 §5.4 (GTP tunnel manipulation) |
| **3GPP** | TS 38.413 (NGAP), TS 29.274 (GTPv2-C) |
| **Description** | Suspicious handover to unrecognized gNB followed by GTP tunnel modification redirecting user-plane traffic through attacker-controlled endpoint. |

### ATK-025: PFCP Session Hijack

| Field | Value |
|---|---|
| **Severity** | CRITICAL |
| **Cross-Protocol** | No (PFCP / N4 interface) |
| **Attack Chain** | SessionEstablishmentReq → SessionModificationReq (changed F-TEID) |
| **Temporal Window** | 60 seconds |
| **MITRE ATT&CK** | T1565 (Data Manipulation) |
| **MITRE FiGHT** | FGT5012 (User Plane Manipulation) |
| **3GPP** | TS 29.244 §5.2.3 (PFCP session modification) |
| **Description** | Unauthorized modification of UPF forwarding rules via PFCP. Source IP of modification differs from original session establishment, or F-TEID changes to external address. Enables mass traffic interception. |

### ATK-026: 5G-to-Legacy Downgrade Chain (3-Protocol)

| Field | Value |
|---|---|
| **Severity** | CRITICAL |
| **Cross-Protocol** | Yes (5G NAS → Diameter S6a → SS7/MAP) |
| **Attack Chain** | DeregistrationRequest(NW) → Diameter CLR → MAP SRI |
| **Temporal Window** | 300 seconds |
| **MITRE ATT&CK** | T1562.001, T1557 |
| **MITRE FiGHT** | FGT1600.501 (Forced Handover), FGT1040 (Protocol Downgrade) |
| **GSMA** | FS.11, FS.19, FS.37 |
| **3GPP** | TS 33.501, TS 29.272, TS 29.002 |
| **Description** | Full cross-generation attack chain spanning all three protocol generations. Subscriber deregistered from 5G, falls to 4G (Diameter CancelLocation), then attacked via SS7 MAP. **Only detectable by cross-protocol correlation** — single-protocol tools miss this entirely. This is SigCorr's signature detection capability. |

### ATK-027: Cross-Generation Reconnaissance

| Field | Value |
|---|---|
| **Severity** | HIGH |
| **Cross-Protocol** | Yes (5G NAS → SS7/MAP) |
| **Attack Chain** | IdentityRequest → MAP SendRoutingInfo |
| **Temporal Window** | 180 seconds |
| **MITRE ATT&CK** | T1592 (Gather Victim Host Information) |
| **MITRE FiGHT** | FGT1040.001 (SUPI Catching) |
| **GSMA** | FS.11 §4.3 (SRI-based reconnaissance) |
| **3GPP** | TS 24.501, TS 29.002 |
| **Description** | Attacker probes subscriber identity via 5G NAS IdentityRequest, then pivots to SS7 MAP to extract location and routing information that 5G protections would otherwise conceal. |

---

## Coverage Summary (v0.2)

| Generation | Protocol | Patterns | IDs |
|---|---|---|---|
| 2G/3G | SS7/MAP | 8 | ATK-001, 002, 006, 011, 014, 021, + variants |
| 4G LTE | Diameter S6a | 4 | ATK-003, 005, 009, 010 |
| 4G LTE | GTPv2-C | 3 | ATK-003, 009, 024 |
| 5G SA | 5G NAS | 5 | ATK-022, 023, 026, 027, + variants |
| 5G SA | NGAP | 1 | ATK-024 |
| 5G SA | PFCP | 1 | ATK-025 |
| **Cross-generation** | **Multi** | **4** | **ATK-022, 024, 026, 027** |

**Total: 28 attack patterns** (22 existing + 6 new 5G patterns)

---

## Protocol Coverage by Generation

```
┌─────────┬──────────────────────────────────────────────────────┐
│ 2G/3G   │ SS7/MAP (SRI, PSI, ISD, CL, SRI-SM, SAI, UL)       │
├─────────┼──────────────────────────────────────────────────────┤
│ 4G LTE  │ Diameter S6a (AIR, ULR, CLR, IDR)                   │
│         │ GTPv2-C (CreateSession, ModifyBearer, DeleteSession) │
├─────────┼──────────────────────────────────────────────────────┤
│ 5G NSA  │ Diameter S6a + GTPv2-C (same as 4G)                 │
├─────────┼──────────────────────────────────────────────────────┤
│ 5G SA   │ 5G NAS (Registration, Deregistration, Auth, SMC)    │
│ (NEW)   │ NGAP (Handover, UEContext, PDUSession)               │
│         │ PFCP (SessionEstablish, Modify, Delete, Report)      │
└─────────┴──────────────────────────────────────────────────────┘

Cross-protocol correlation:  SS7 ↔ Diameter ↔ GTP ↔ 5G NAS ↔ NGAP ↔ PFCP
Identity chain:              MSISDN ↔ IMSI ↔ SUPI ↔ SUCI ↔ 5G-GUTI
```
