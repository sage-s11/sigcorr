#!/usr/bin/env python3
"""
Generate attack pcap files for SigCorr validation.

Uses raw byte construction + Wireshark's text2pcap tool.
No Scapy dependency — works in any environment with Python 3 and tshark/text2pcap.

Generates pcap files containing real protocol-encoded attack sequences:
1. Diameter S6a: Authentication-Information-Request (cmd 316) + Update-Location-Request (cmd 318)
2. GTPv2-C: Create-Session-Request (type 32) with IMSI/MSISDN

These are fed to tshark for decoding, then to SigCorr for correlation and detection.
"""

import struct
import subprocess
import os
import sys
import time

OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))

# ════════════════════════════════════════════════════════════
#  Diameter message builder
# ════════════════════════════════════════════════════════════

def build_diameter_avp(code, flags, data, vendor_id=None):
    """Build a single Diameter AVP."""
    if vendor_id is not None:
        flags |= 0x80  # Vendor-specific bit
        header = struct.pack("!IBI", code, flags, 12 + len(data)) 
        # Fix: AVP length field is 3 bytes, packed with flags
        avp_flags_length = (flags << 24) | (12 + len(data))
        header = struct.pack("!II", code, avp_flags_length) + struct.pack("!I", vendor_id)
    else:
        avp_flags_length = (flags << 24) | (8 + len(data))
        header = struct.pack("!II", code, avp_flags_length)
    
    avp = header + data
    # Pad to 4-byte boundary
    pad_len = (4 - (len(avp) % 4)) % 4
    avp += b'\x00' * pad_len
    return avp

def build_diameter_message(cmd_code, app_id, hop_id, end_id, is_request, avps_bytes):
    """Build a complete Diameter message."""
    flags = 0x80 if is_request else 0x00  # R flag
    flags |= 0x40  # P (proxiable) flag
    
    msg_len = 20 + len(avps_bytes)
    
    header = struct.pack("!I", (1 << 24) | msg_len)  # Version 1 + length
    header += struct.pack("!I", (flags << 24) | cmd_code)  # Flags + command code
    header += struct.pack("!I", app_id)
    header += struct.pack("!I", hop_id)
    header += struct.pack("!I", end_id)
    
    return header + avps_bytes

def build_diameter_s6a_air(imsi, origin_host, origin_realm, dest_realm, hop_id=0x11111111):
    """Build Diameter S6a Authentication-Information-Request (cmd 316)."""
    avps = b''
    avps += build_diameter_avp(263, 0x40, b"session-air-001;" + origin_host.encode())  # Session-Id
    avps += build_diameter_avp(264, 0x40, origin_host.encode())  # Origin-Host
    avps += build_diameter_avp(296, 0x40, origin_realm.encode())  # Origin-Realm
    avps += build_diameter_avp(283, 0x40, dest_realm.encode())  # Destination-Realm
    avps += build_diameter_avp(1, 0x40, imsi.encode())  # User-Name (IMSI)
    avps += build_diameter_avp(277, 0x40, struct.pack("!I", 1))  # Auth-Session-State
    
    return build_diameter_message(316, 16777251, hop_id, 0xAAAA0001, True, avps)

def build_diameter_s6a_ulr(imsi, origin_host, origin_realm, dest_realm, hop_id=0x22222222):
    """Build Diameter S6a Update-Location-Request (cmd 318)."""
    avps = b''
    avps += build_diameter_avp(263, 0x40, b"session-ulr-001;" + origin_host.encode())  # Session-Id
    avps += build_diameter_avp(264, 0x40, origin_host.encode())  # Origin-Host
    avps += build_diameter_avp(296, 0x40, origin_realm.encode())  # Origin-Realm
    avps += build_diameter_avp(283, 0x40, dest_realm.encode())  # Destination-Realm
    avps += build_diameter_avp(1, 0x40, imsi.encode())  # User-Name (IMSI)
    avps += build_diameter_avp(277, 0x40, struct.pack("!I", 1))  # Auth-Session-State
    
    return build_diameter_message(318, 16777251, hop_id, 0xAAAA0002, True, avps)

# ════════════════════════════════════════════════════════════
#  GTPv2-C message builder
# ════════════════════════════════════════════════════════════

def encode_tbcd(digits):
    """Encode a digit string in TBCD (Telephony BCD) format."""
    result = bytearray()
    for i in range(0, len(digits), 2):
        low = int(digits[i])
        high = int(digits[i+1]) if i+1 < len(digits) else 0x0F
        result.append((high << 4) | low)
    return bytes(result)

def build_gtpv2_ie(ie_type, instance, data):
    """Build a GTPv2-C Information Element."""
    return struct.pack("!BHB", ie_type, len(data), instance) + data

def build_gtpv2_create_session(imsi, msisdn, teid=1, seq=1):
    """Build GTPv2-C Create-Session-Request (type 32)."""
    ies = b''
    
    # IMSI IE (type 1)
    imsi_tbcd = encode_tbcd(imsi)
    ies += build_gtpv2_ie(1, 0, imsi_tbcd)
    
    # MSISDN IE (type 76)
    msisdn_tbcd = encode_tbcd(msisdn)
    ies += build_gtpv2_ie(76, 0, msisdn_tbcd)
    
    # RAT Type IE (type 82) — EUTRAN = 6
    ies += build_gtpv2_ie(82, 0, bytes([6]))
    
    # Serving Network IE (type 83) — MCC=234, MNC=10
    ies += build_gtpv2_ie(83, 0, bytes([0x42, 0xF0, 0x01]))
    
    # APN IE (type 71) — "internet"
    apn = bytes([8]) + b'internet'
    ies += build_gtpv2_ie(71, 0, apn)
    
    # Header: version=2, T=1, msg_type=32
    msg_len = len(ies) + 4  # +4 for seq+spare after TEID
    header = struct.pack("!BBHI", 0x48, 32, msg_len, teid)
    header += struct.pack("!I", (seq << 8))  # seq (3 bytes) + spare (1 byte)
    
    return header + ies

# ════════════════════════════════════════════════════════════
#  TCP/IP wrapping for Diameter
# ════════════════════════════════════════════════════════════

def wrap_in_tcp_ip(payload, src_ip, dst_ip, src_port, dst_port, seq_num=1000):
    """Wrap payload in IP + TCP headers for pcap writing."""
    # TCP header (20 bytes, no options)
    tcp_header = struct.pack("!HHIIBBHHH",
        src_port, dst_port,
        seq_num, 0,          # seq, ack
        0x50, 0x18,          # data offset (5 words) + flags (PSH+ACK)
        65535, 0, 0)         # window, checksum (0=let pcap handle), urgent
    
    total_len = 20 + 20 + len(payload)  # IP + TCP + payload
    
    # IP header (20 bytes)
    ip_header = struct.pack("!BBHHHBBH4s4s",
        0x45, 0,             # version/ihl, dscp
        total_len, 0x1234,   # total length, identification
        0x4000, 64, 6,       # flags+offset, ttl, protocol (TCP)
        0,                   # checksum (0)
        bytes(int(x) for x in src_ip.split('.')),
        bytes(int(x) for x in dst_ip.split('.')))
    
    return ip_header + tcp_header + payload

def wrap_in_udp_ip(payload, src_ip, dst_ip, src_port, dst_port):
    """Wrap payload in IP + UDP headers."""
    udp_len = 8 + len(payload)
    udp_header = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
    
    total_len = 20 + udp_len
    ip_header = struct.pack("!BBHHHBBH4s4s",
        0x45, 0,
        total_len, 0x5678,
        0x4000, 64, 17,      # protocol 17 = UDP
        0,
        bytes(int(x) for x in src_ip.split('.')),
        bytes(int(x) for x in dst_ip.split('.')))
    
    return ip_header + udp_header + payload

# ════════════════════════════════════════════════════════════
#  Pcap file writer (libpcap format)
# ════════════════════════════════════════════════════════════

def write_pcap(filename, packets_with_timestamps):
    """
    Write packets to pcap file.
    packets_with_timestamps: list of (timestamp_epoch, raw_bytes) tuples
    """
    PCAP_MAGIC = 0xa1b2c3d4
    LINKTYPE_RAW = 101       # Raw IP (no Ethernet header)
    LINKTYPE_ETHERNET = 1
    
    with open(filename, 'wb') as f:
        # Global header
        f.write(struct.pack("!IHHiIII",
            PCAP_MAGIC,
            2, 4,            # version
            0,               # timezone
            0,               # sigfigs
            65535,           # snaplen
            LINKTYPE_ETHERNET))  # Use Ethernet
        
        for ts, raw_ip_data in packets_with_timestamps:
            ts_sec = int(ts)
            ts_usec = int((ts - ts_sec) * 1000000)
            
            # Wrap in Ethernet header (14 bytes)
            eth_header = bytes([
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  # dst MAC
                0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,  # src MAC
                0x08, 0x00                             # EtherType: IPv4
            ])
            
            frame = eth_header + raw_ip_data
            
            # Packet header
            f.write(struct.pack("!IIII",
                ts_sec, ts_usec,
                len(frame), len(frame)))
            f.write(frame)

# ════════════════════════════════════════════════════════════
#  Attack scenario generators
# ════════════════════════════════════════════════════════════

def generate_diameter_attack_pcap():
    """
    Generate Diameter S6a attack: AIR followed by ULR from same attacker.
    This models ATK-008 (Cross-Protocol Recon) if combined with MAP,
    or standalone Diameter reconnaissance.
    
    Target: IMSI 234101234567890
    Attacker: mme01.attacker.com (10.99.0.1)
    Home HSS: hss.home-net.com (10.1.0.1)
    """
    imsi = "234101234567890"
    attacker_host = "mme01.attacker.com"
    attacker_realm = "attacker.com"
    home_realm = "home-net.com"
    
    packets = []
    base_time = 1700000000.0  # Fixed epoch for reproducibility
    
    # Packet 1: AIR (Authentication-Information-Request)
    air = build_diameter_s6a_air(imsi, attacker_host, attacker_realm, home_realm)
    air_ip = wrap_in_tcp_ip(air, "10.99.0.1", "10.1.0.1", 3868, 3868, seq_num=1000)
    packets.append((base_time, air_ip))
    
    # Packet 2: ULR (Update-Location-Request) — 5 seconds later
    ulr = build_diameter_s6a_ulr(imsi, attacker_host, attacker_realm, home_realm)
    ulr_ip = wrap_in_tcp_ip(ulr, "10.99.0.1", "10.1.0.1", 3868, 3868, seq_num=2000)
    packets.append((base_time + 5.0, ulr_ip))
    
    # Packet 3: Second AIR for different IMSI — 10 seconds later
    air2 = build_diameter_s6a_air("234109876543210", attacker_host, attacker_realm, home_realm, hop_id=0x33333333)
    air2_ip = wrap_in_tcp_ip(air2, "10.99.0.1", "10.1.0.1", 3868, 3868, seq_num=3000)
    packets.append((base_time + 10.0, air2_ip))
    
    outfile = os.path.join(OUTPUT_DIR, "diameter_s6a_attack.pcap")
    write_pcap(outfile, packets)
    print(f"[+] Written {len(packets)} Diameter S6a packets to {outfile}")
    return outfile

def generate_gtpv2_attack_pcap():
    """
    Generate GTPv2-C attack: Create-Session-Request with target IMSI.
    When combined with prior MAP SRI, this models ATK-003 (Tracking + Session).
    
    Target: IMSI 234101234567890, MSISDN 447712345678
    """
    packets = []
    base_time = 1700000060.0  # 60 seconds after Diameter attack
    
    # Create-Session-Request
    csr = build_gtpv2_create_session("234101234567890", "447712345678", teid=1, seq=1)
    csr_ip = wrap_in_udp_ip(csr, "10.99.0.1", "10.1.0.2", 2123, 2123)
    packets.append((base_time, csr_ip))
    
    # Second Create-Session for different subscriber
    csr2 = build_gtpv2_create_session("234109876543210", "447798765432", teid=2, seq=2)
    csr2_ip = wrap_in_udp_ip(csr2, "10.99.0.1", "10.1.0.2", 2123, 2123)
    packets.append((base_time + 3.0, csr2_ip))
    
    outfile = os.path.join(OUTPUT_DIR, "gtpv2_attack.pcap")
    write_pcap(outfile, packets)
    print(f"[+] Written {len(packets)} GTPv2-C packets to {outfile}")
    return outfile

def generate_combined_attack_pcap():
    """
    Generate a combined multi-protocol attack scenario:
    
    Timeline:
      T+0s:   Diameter AIR for IMSI 234101234567890 (recon)
      T+5s:   Diameter ULR for same IMSI (location update — re-registration)
      T+60s:  GTPv2-C Create-Session for same IMSI (session hijack)
    
    This should trigger ATK-003 (Tracking + Session Correlation) via
    the Diameter→GTP cross-protocol pattern when both are correlated
    by IMSI through the identity resolver.
    """
    imsi = "234101234567890"
    msisdn = "447712345678"
    attacker_host = "mme01.attacker.com"
    attacker_realm = "attacker.com"
    home_realm = "home-net.com"
    
    packets = []
    base_time = 1700000000.0
    
    # Phase 1: Diameter S6a reconnaissance
    air = build_diameter_s6a_air(imsi, attacker_host, attacker_realm, home_realm)
    packets.append((base_time, wrap_in_tcp_ip(air, "10.99.0.1", "10.1.0.1", 3868, 3868, 1000)))
    
    ulr = build_diameter_s6a_ulr(imsi, attacker_host, attacker_realm, home_realm)
    packets.append((base_time + 5.0, wrap_in_tcp_ip(ulr, "10.99.0.1", "10.1.0.1", 3868, 3868, 2000)))
    
    # Phase 2: GTPv2-C session establishment (60s later)
    csr = build_gtpv2_create_session(imsi, msisdn, teid=1, seq=1)
    packets.append((base_time + 60.0, wrap_in_udp_ip(csr, "10.99.0.1", "10.1.0.2", 2123, 2123)))
    
    outfile = os.path.join(OUTPUT_DIR, "combined_dia_gtp_attack.pcap")
    write_pcap(outfile, packets)
    print(f"[+] Written {len(packets)} combined Diameter+GTP packets to {outfile}")
    return outfile

# ════════════════════════════════════════════════════════════
#  Main
# ════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("SigCorr Attack Pcap Generator")
    print("=" * 50)
    print()
    
    f1 = generate_diameter_attack_pcap()
    f2 = generate_gtpv2_attack_pcap()
    f3 = generate_combined_attack_pcap()
    
    print()
    print("Verify with tshark:")
    print(f"  tshark -r {f1} -V")
    print(f"  tshark -r {f2} -V")
    print(f"  tshark -r {f3} -V")
    print()
    print("Test with SigCorr:")
    print(f"  java -jar target/sigcorr-0.1.0.jar analyze {f1} --verbose")
    print(f"  java -jar target/sigcorr-0.1.0.jar analyze {f2} --verbose")
    print(f"  java -jar target/sigcorr-0.1.0.jar analyze {f3} --verbose")
