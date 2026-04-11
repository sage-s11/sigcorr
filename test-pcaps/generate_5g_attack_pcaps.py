#!/usr/bin/env python3
"""
SigCorr 5G Test PCAP Generator
Generates synthetic pcap files for testing 5G attack pattern detection.

Uses scapy to create pcap files containing:
  - 5G NAS messages (Registration, Deregistration, Auth, SecurityMode, Identity)
  - NGAP messages (HandoverRequired, InitialUEMessage)
  - PFCP messages (SessionEstablishment, SessionModification)
  - Cross-generation attack chains (5G NAS + Diameter + SS7 combined)

Requirements: pip install scapy

Usage: python generate_5g_attack_pcaps.py [output_dir]
"""

import sys
import os
import struct
import time
from scapy.all import (
    Ether, IP, UDP, TCP, SCTP, SCTPChunkData,
    Raw, wrpcap, conf
)

OUTPUT_DIR = sys.argv[1] if len(sys.argv) > 1 else "./test-pcaps"

# ═══════════════════════════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════════════════════════

AMF_IP = "10.0.0.10"
GNB_IP = "10.0.0.20"
SMF_IP = "10.0.0.30"
UPF_IP = "10.0.0.40"
ROGUE_GNB_IP = "10.99.99.1"
ATTACKER_IP = "10.99.99.99"

# Well-known ports
NGAP_PORT = 38412      # SCTP port for NGAP
PFCP_PORT = 8805       # UDP port for PFCP
GTP_C_PORT = 2123      # UDP port for GTPv2-C
DIAMETER_PORT = 3868    # TCP port for Diameter

# Test subscriber identity
TEST_IMSI = "234101234567890"
TEST_SUPI = f"imsi-{TEST_IMSI}"

# ═══════════════════════════════════════════════════════════════════
# 5G NAS Message Builders (simplified payloads)
# Per 3GPP TS 24.501 — just enough structure for tshark to decode
# ═══════════════════════════════════════════════════════════════════

def nas_5g_mm_header(msg_type, security_header=0):
    """Build 5GMM NAS header: EPD(0x7e) + Security Header + Message Type"""
    return bytes([
        0x7e,                    # Extended Protocol Discriminator: 5GMM
        security_header & 0x0f,  # Security header type
        msg_type & 0xff          # Message type
    ])

def nas_5g_sm_header(msg_type, pdu_session_id=1):
    """Build 5GSM NAS header: EPD(0x2e) + PDU Session ID + PTI + Message Type"""
    return bytes([
        0x2e,                    # Extended Protocol Discriminator: 5GSM
        pdu_session_id & 0xff,   # PDU session identity
        0x01,                    # Procedure transaction identity
        msg_type & 0xff          # Message type
    ])

def build_5gs_mobile_identity_supi(imsi_str):
    """Build 5GS Mobile Identity IE with SUPI (IMSI format)"""
    # Type: SUPI (0x01), SUPI format: IMSI (0x01)
    digits = [int(d) for d in imsi_str]
    # BCD encoding: pairs of digits, nibble-swapped
    bcd = []
    for i in range(0, len(digits), 2):
        if i + 1 < len(digits):
            bcd.append((digits[i+1] << 4) | digits[i])
        else:
            bcd.append(0xf0 | digits[i])

    identity_type = 0x01  # SUPI
    supi_format = 0x00    # IMSI
    header = bytes([identity_type | (supi_format << 4)])
    return header + bytes(bcd)

def build_5gs_mobile_identity_suci(imsi_str):
    """Build 5GS Mobile Identity IE with SUCI (null scheme = cleartext)"""
    # SUCI with null scheme (scheme 0x00) = MSIN in cleartext
    mcc = imsi_str[0:3]
    mnc = imsi_str[3:5]
    msin = imsi_str[5:]

    identity_type = 0x01  # SUCI
    # Simplified: just enough for tshark to decode
    suci_header = bytes([
        0x01,                               # Type: SUCI
        int(mcc[0]) | (int(mcc[1]) << 4),   # MCC digit 1,2
        int(mcc[2]) | (int(mnc[0]) << 4),   # MCC digit 3, MNC digit 1
        int(mnc[1]) | (0xf0),               # MNC digit 2, filler
        0x00, 0x00,                          # Routing indicator
        0x00,                                # Protection scheme: null
        0x00,                                # Home network public key ID
    ])
    # MSIN in cleartext BCD
    msin_bytes = bytes([int(d) for d in msin])
    return suci_header + msin_bytes

# ═══════════════════════════════════════════════════════════════════
# 5G NAS Registration Request
# ═══════════════════════════════════════════════════════════════════

def make_nas_registration_request(src_ip, dst_ip, imsi):
    """5G NAS Registration Request (message type 0x41)"""
    nas_payload = (
        nas_5g_mm_header(0x41) +            # RegistrationRequest
        bytes([0x01]) +                      # Registration type: initial
        build_5gs_mobile_identity_supi(imsi)
    )
    return IP(src=src_ip, dst=dst_ip) / \
           TCP(sport=12345, dport=38412) / \
           Raw(load=nas_payload)

# ═══════════════════════════════════════════════════════════════════
# 5G NAS Deregistration Request (Network-initiated) — for ATK-022, 026
# ═══════════════════════════════════════════════════════════════════

def make_nas_deregistration_nw(src_ip, dst_ip, imsi):
    """5G NAS Deregistration Request from network (message type 0x46)"""
    nas_payload = (
        nas_5g_mm_header(0x46) +            # DeregistrationRequest (NW)
        bytes([0x01]) +                      # De-registration type
        build_5gs_mobile_identity_supi(imsi)
    )
    return IP(src=src_ip, dst=dst_ip) / \
           TCP(sport=38412, dport=12345) / \
           Raw(load=nas_payload)

# ═══════════════════════════════════════════════════════════════════
# 5G NAS Security Mode Command (null cipher) — for ATK-023
# ═══════════════════════════════════════════════════════════════════

def make_nas_security_mode_command(src_ip, dst_ip, cipher_algo=0, integ_algo=2):
    """5G NAS SecurityModeCommand (message type 0x5d)"""
    nas_payload = (
        nas_5g_mm_header(0x5d, security_header=0) +
        bytes([
            (integ_algo << 4) | cipher_algo,  # NAS security algorithms
            0x00,                              # NAS key set identifier
            0xe0,                              # Replayed UE security capabilities
            0xe0, 0x00, 0x00,
        ])
    )
    return IP(src=src_ip, dst=dst_ip) / \
           TCP(sport=38412, dport=12345) / \
           Raw(load=nas_payload)

def make_nas_security_mode_reject(src_ip, dst_ip):
    """5G NAS SecurityModeReject (message type 0x5f)"""
    nas_payload = (
        nas_5g_mm_header(0x5f) +
        bytes([0x18])                         # Cause: UE security capabilities mismatch
    )
    return IP(src=src_ip, dst=dst_ip) / \
           TCP(sport=12345, dport=38412) / \
           Raw(load=nas_payload)

# ═══════════════════════════════════════════════════════════════════
# 5G NAS Identity Request — for ATK-027
# ═══════════════════════════════════════════════════════════════════

def make_nas_identity_request(src_ip, dst_ip, id_type=0x01):
    """5G NAS IdentityRequest (message type 0x5b)"""
    nas_payload = (
        nas_5g_mm_header(0x5b) +
        bytes([id_type])                     # Identity type: 0x01=SUCI, 0x03=IMEI
    )
    return IP(src=src_ip, dst=dst_ip) / \
           TCP(sport=38412, dport=12345) / \
           Raw(load=nas_payload)

# ═══════════════════════════════════════════════════════════════════
# PFCP Messages — for ATK-025
# ═══════════════════════════════════════════════════════════════════

def pfcp_header(msg_type, seid=0, seq=1):
    """PFCP message header (3GPP TS 29.244)"""
    version = 1
    flags = 0x20 | (0x01 if seid else 0x00)  # Version 1, SEID flag
    if seid:
        return struct.pack("!BBH Q I",
            (version << 5) | flags,
            msg_type,
            24,              # Message length (placeholder)
            seid,
            seq << 8         # Sequence number (24-bit) + spare
        )
    else:
        return struct.pack("!BBH I",
            (version << 5) | flags,
            msg_type,
            8,
            seq << 8
        )

def make_pfcp_session_establishment(src_ip, dst_ip, seid=0xDEADBEEF):
    """PFCP Session Establishment Request (type 50)"""
    payload = pfcp_header(50, seid=seid, seq=1)
    return IP(src=src_ip, dst=dst_ip) / \
           UDP(sport=PFCP_PORT, dport=PFCP_PORT) / \
           Raw(load=payload)

def make_pfcp_session_modification(src_ip, dst_ip, seid=0xDEADBEEF):
    """PFCP Session Modification Request (type 52)"""
    payload = pfcp_header(52, seid=seid, seq=2)
    return IP(src=src_ip, dst=dst_ip) / \
           UDP(sport=PFCP_PORT, dport=PFCP_PORT) / \
           Raw(load=payload)

# ═══════════════════════════════════════════════════════════════════
# Scenario Generators
# ═══════════════════════════════════════════════════════════════════

def generate_atk022_bidding_down():
    """ATK-022: 5G NAS deregistration → SS7 MAP UpdateLocation"""
    packets = [
        make_nas_deregistration_nw(AMF_IP, GNB_IP, TEST_IMSI),
        # SS7 MAP UpdateLocation would follow (from existing generator)
    ]
    return packets

def generate_atk023_nas_manipulation():
    """ATK-023: SecurityModeCommand(null cipher) → SecurityModeReject"""
    packets = [
        make_nas_security_mode_command(AMF_IP, GNB_IP, cipher_algo=0, integ_algo=0),
        make_nas_security_mode_reject(GNB_IP, AMF_IP),
    ]
    return packets

def generate_atk025_pfcp_hijack():
    """ATK-025: PFCP SessionEstablishment → rogue SessionModification"""
    seid = 0x00000000DEADBEEF
    packets = [
        make_pfcp_session_establishment(SMF_IP, UPF_IP, seid=seid),
        # Modification from DIFFERENT source (attacker)
        make_pfcp_session_modification(ATTACKER_IP, UPF_IP, seid=seid),
    ]
    return packets

def generate_atk027_cross_gen_recon():
    """ATK-027: 5G NAS IdentityRequest (no SS7 in this pcap — would be separate)"""
    packets = [
        make_nas_identity_request(AMF_IP, GNB_IP, id_type=0x01),
        # SS7 MAP SRI would follow in a separate/combined pcap
    ]
    return packets

def generate_5g_registration_normal():
    """Normal 5G registration (no attack — for false-positive testing)"""
    packets = [
        make_nas_registration_request(GNB_IP, AMF_IP, TEST_IMSI),
        make_nas_security_mode_command(AMF_IP, GNB_IP, cipher_algo=1, integ_algo=2),
        # Normal: UE accepts (SecurityModeComplete would follow)
    ]
    return packets

# ═══════════════════════════════════════════════════════════════════
# Main — Generate all test pcaps
# ═══════════════════════════════════════════════════════════════════

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    scenarios = {
        "5g_bidding_down_atk022.pcap": generate_atk022_bidding_down(),
        "5g_nas_manipulation_atk023.pcap": generate_atk023_nas_manipulation(),
        "5g_pfcp_hijack_atk025.pcap": generate_atk025_pfcp_hijack(),
        "5g_cross_gen_recon_atk027.pcap": generate_atk027_cross_gen_recon(),
        "5g_normal_registration.pcap": generate_5g_registration_normal(),
    }

    for filename, packets in scenarios.items():
        path = os.path.join(OUTPUT_DIR, filename)
        # Add Ethernet headers for pcap compatibility
        eth_packets = [Ether() / pkt for pkt in packets]
        wrpcap(path, eth_packets)
        print(f"  Generated: {path} ({len(packets)} packets)")

    print(f"\n  Total: {len(scenarios)} pcap files generated in {OUTPUT_DIR}/")
    print("  Use with: java -jar target/sigcorr-0.2.0-all.jar analyze <pcap>")

if __name__ == "__main__":
    main()
