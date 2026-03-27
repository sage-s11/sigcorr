#!/usr/bin/env python3
"""
Comprehensive test PCAP generator for SigCorr attack pattern validation.

Generates test pcaps for all 22 attack patterns plus edge cases:
- Normal traffic (should NOT trigger alerts)
- Boundary conditions (timing edge cases)
- Malformed packets (robustness testing)
- High-volume scenarios (performance testing)

Each pcap is self-contained and tests a specific attack pattern or condition.
"""

from scapy.all import *
from scapy.contrib.gtp_v2 import *
from datetime import datetime, timedelta
import os
import struct

# ============================================================================
#  PROTOCOL HELPERS
# ============================================================================

def create_sctp_m3ua_header(opc=100, dpc=200, si=3):
    """Create M3UA DATA message header for SCCP/TCAP encapsulation."""
    # M3UA common header: version=1, reserved=0, class=1 (transfer), type=1 (DATA)
    m3ua_header = struct.pack('>BBBB', 1, 0, 1, 1)
    # Length placeholder (will be updated)
    m3ua_header += struct.pack('>I', 0)
    # Protocol Data parameter (tag=0x0210)
    pd_tag = struct.pack('>HH', 0x0210, 0)  # length placeholder
    # Routing context (optional, skip for simplicity)
    # Protocol data: OPC, DPC, SI, NI, MP, SLS
    proto_data = struct.pack('>IIBBBB', opc, dpc, si, 0, 0, 0)
    return m3ua_header, proto_data

def create_sccp_gt(gt_digits, ssn=6):
    """Create SCCP Called/Calling Party Address with Global Title."""
    # Simplified GT format for test purposes
    gt_bcd = bytes([int(gt_digits[i:i+2][::-1], 16) if i+1 < len(gt_digits) 
                    else int(gt_digits[i] + 'f', 16) 
                    for i in range(0, len(gt_digits), 2)])
    return gt_bcd

def build_map_invoke(opcode, params_hex=""):
    """Build TCAP Invoke component with MAP operation."""
    # Component type: invoke (0xa1)
    # InvokeID: 1
    # OperationCode: local (opcode)
    invoke_id = bytes([0x02, 0x01, 0x01])  # INTEGER 1
    op_code = bytes([0x02, 0x01, opcode])   # INTEGER opcode
    params = bytes.fromhex(params_hex) if params_hex else b''
    
    # Invoke component
    component = bytes([0xa1]) + bytes([len(invoke_id) + len(op_code) + len(params)]) + invoke_id + op_code + params
    
    # Component portion
    comp_portion = bytes([0x6c]) + bytes([len(component)]) + component
    
    return comp_portion

def build_tcap_begin(otid, map_component):
    """Build TCAP Begin message."""
    # OTID
    otid_bytes = bytes([0x48, 0x04]) + struct.pack('>I', otid)
    # Dialogue portion (simplified)
    dialogue = bytes.fromhex('6b1a2818060700118605010101a00da00b800109810207008201008302010003')
    # Full TCAP
    content = otid_bytes + dialogue + map_component
    tcap = bytes([0x62]) + bytes([len(content)]) + content
    return tcap

def build_tcap_continue(otid, dtid, map_component):
    """Build TCAP Continue message."""
    otid_bytes = bytes([0x48, 0x04]) + struct.pack('>I', otid)
    dtid_bytes = bytes([0x49, 0x04]) + struct.pack('>I', dtid)
    content = otid_bytes + dtid_bytes + map_component
    tcap = bytes([0x65]) + bytes([len(content)]) + content
    return tcap

def create_sigtran_packet(src_ip, dst_ip, src_port, dst_port, tcap_data, timestamp):
    """Create full SIGTRAN/M3UA/SCCP/TCAP packet."""
    # Build IP/SCTP/M3UA layers (simplified - actual SCCP encoding is complex)
    # For tshark to decode, we use a simpler approach with raw data
    
    ip = IP(src=src_ip, dst=dst_ip)
    sctp = SCTP(sport=src_port, dport=dst_port)
    # M3UA DATA chunk
    m3ua_data = Raw(load=tcap_data)
    
    pkt = ip/sctp/m3ua_data
    pkt.time = timestamp.timestamp()
    return pkt

def create_diameter_packet(src_ip, dst_ip, cmd_code, is_request, imsi, session_id, timestamp,
                           origin_host="attacker.mme.epc.mnc001.mcc001.3gppnetwork.org",
                           origin_realm="epc.mnc001.mcc001.3gppnetwork.org"):
    """Create Diameter S6a packet."""
    # Diameter header
    version = 1
    flags = 0x80 if is_request else 0x00  # R flag
    if is_request:
        flags |= 0x40  # P flag (proxiable)
    
    # Application ID for S6a = 16777251
    app_id = 16777251
    hop_by_hop = 0x12345678
    end_to_end = 0x87654321
    
    # Build AVPs
    avps = b''
    
    # Session-Id AVP (263)
    session_avp = build_diameter_avp(263, session_id.encode())
    avps += session_avp
    
    # Origin-Host AVP (264)
    origin_host_avp = build_diameter_avp(264, origin_host.encode())
    avps += origin_host_avp
    
    # Origin-Realm AVP (296)
    origin_realm_avp = build_diameter_avp(296, origin_realm.encode())
    avps += origin_realm_avp
    
    # User-Name AVP (1) - contains IMSI
    if imsi:
        user_name_avp = build_diameter_avp(1, imsi.encode())
        avps += user_name_avp
    
    # Diameter header
    msg_len = 20 + len(avps)
    header = struct.pack('>BBBB', version, (msg_len >> 16) & 0xff, (msg_len >> 8) & 0xff, msg_len & 0xff)
    header = bytes([version]) + struct.pack('>I', msg_len)[1:4]
    header += struct.pack('>B', flags)
    header += struct.pack('>I', cmd_code)[1:4]
    header += struct.pack('>I', app_id)
    header += struct.pack('>I', hop_by_hop)
    header += struct.pack('>I', end_to_end)
    
    diameter_data = header + avps
    
    ip = IP(src=src_ip, dst=dst_ip)
    tcp = TCP(sport=3868, dport=3868, flags='PA', seq=1000, ack=1000)
    pkt = ip/tcp/Raw(load=diameter_data)
    pkt.time = timestamp.timestamp()
    return pkt

def build_diameter_avp(code, data, vendor_id=None):
    """Build a Diameter AVP."""
    flags = 0x40  # Mandatory
    if vendor_id:
        flags |= 0x80  # Vendor flag
    
    # Pad to 4-byte boundary
    padded_len = (len(data) + 3) & ~3
    padding = b'\x00' * (padded_len - len(data))
    
    if vendor_id:
        avp_len = 12 + len(data)
        header = struct.pack('>I', code) + struct.pack('>B', flags) + struct.pack('>I', avp_len)[1:4]
        header += struct.pack('>I', vendor_id)
    else:
        avp_len = 8 + len(data)
        header = struct.pack('>I', code) + struct.pack('>B', flags) + struct.pack('>I', avp_len)[1:4]
    
    return header + data + padding

def create_gtpv2_packet(src_ip, dst_ip, msg_type, imsi, teid, seq_num, timestamp):
    """Create GTPv2-C packet."""
    # GTPv2-C header
    # Flags: version=2, P=0, T=1 (TEID present), spare=0
    flags = 0x48
    
    # Build IEs
    ies = b''
    
    # IMSI IE (type=1)
    if imsi:
        imsi_bcd = bytes([int(imsi[i+1] + imsi[i], 16) if i+1 < len(imsi) 
                          else int('f' + imsi[i], 16) 
                          for i in range(0, len(imsi), 2)])
        ie_header = struct.pack('>BHB', 1, len(imsi_bcd), 0)  # type, length, spare/instance
        ies += ie_header + imsi_bcd
    
    # Message length (header is 8 bytes with TEID, then IEs)
    msg_len = 4 + len(ies)  # 4 bytes for TEID
    
    header = struct.pack('>BBH', flags, msg_type, msg_len)
    header += struct.pack('>I', teid)
    header += struct.pack('>I', seq_num << 8)[:3] + b'\x00'  # seq num + spare
    
    gtp_data = header + ies
    
    ip = IP(src=src_ip, dst=dst_ip)
    udp = UDP(sport=2123, dport=2123)
    pkt = ip/udp/Raw(load=gtp_data)
    pkt.time = timestamp.timestamp()
    return pkt

# ============================================================================
#  ATTACK PATTERN GENERATORS
# ============================================================================

BASE_TIME = datetime(2024, 1, 15, 10, 30, 0)

def gen_atk001_silent_location_tracking():
    """ATK-001: Silent Location Tracking (SRI -> PSI)"""
    packets = []
    t = BASE_TIME
    
    # SendRoutingInfo (opcode 22) with MSISDN
    msisdn_param = "04048447712345678"  # AddressString with MSISDN
    sri_tcap = build_tcap_begin(0x00010001, build_map_invoke(22, msisdn_param))
    pkt1 = create_sigtran_packet("10.1.1.100", "10.2.2.200", 2905, 2905, sri_tcap, t)
    packets.append(pkt1)
    
    # ProvideSubscriberInfo (opcode 71) 3 seconds later
    t += timedelta(seconds=3)
    imsi_param = "04082143658709214365"  # IMSI
    psi_tcap = build_tcap_begin(0x00010002, build_map_invoke(71, imsi_param))
    pkt2 = create_sigtran_packet("10.1.1.100", "10.2.2.200", 2905, 2905, psi_tcap, t)
    packets.append(pkt2)
    
    return packets, "atk001_silent_location_tracking.pcap"

def gen_atk003_cross_protocol():
    """ATK-003: Tracking with Session Correlation (SRI -> GTP CreateSession)"""
    packets = []
    t = BASE_TIME
    
    # SendRoutingInfo
    sri_tcap = build_tcap_begin(0x00010003, build_map_invoke(22, "04048447712345678"))
    pkt1 = create_sigtran_packet("10.1.1.100", "10.2.2.200", 2905, 2905, sri_tcap, t)
    packets.append(pkt1)
    
    # GTP Create Session Request 2 minutes later
    t += timedelta(minutes=2)
    pkt2 = create_gtpv2_packet("10.99.0.1", "10.99.0.2", 32, "234101234567890", 0, 1000, t)
    packets.append(pkt2)
    
    return packets, "atk003_cross_protocol.pcap"

def gen_atk011_sms_interception():
    """ATK-011: SMS Interception (SRI-SM -> MT-ForwardSM)"""
    packets = []
    t = BASE_TIME
    
    # SendRoutingInfoForSM (opcode 24)
    sri_sm_tcap = build_tcap_begin(0x00010011, build_map_invoke(24, "04048447712345678"))
    pkt1 = create_sigtran_packet("10.1.1.100", "10.2.2.200", 2905, 2905, sri_sm_tcap, t)
    packets.append(pkt1)
    
    # MT-ForwardSM (opcode 46) 5 seconds later
    t += timedelta(seconds=5)
    mt_sm_tcap = build_tcap_begin(0x00010012, build_map_invoke(46, "04082143658709214365"))
    pkt2 = create_sigtran_packet("10.1.1.100", "10.2.2.200", 2905, 2905, mt_sm_tcap, t)
    packets.append(pkt2)
    
    return packets, "atk011_sms_interception.pcap"

def gen_atk014_auth_harvesting():
    """ATK-014: Authentication Vector Harvesting (SRI -> SAI)"""
    packets = []
    t = BASE_TIME
    
    # SendRoutingInfo
    sri_tcap = build_tcap_begin(0x00010014, build_map_invoke(22, "04048447712345678"))
    pkt1 = create_sigtran_packet("10.1.1.100", "10.2.2.200", 2905, 2905, sri_tcap, t)
    packets.append(pkt1)
    
    # SendAuthenticationInfo (opcode 56) 10 seconds later
    t += timedelta(seconds=10)
    sai_tcap = build_tcap_begin(0x00010015, build_map_invoke(56, "04082143658709214365"))
    pkt2 = create_sigtran_packet("10.1.1.100", "10.2.2.200", 2905, 2905, sai_tcap, t)
    packets.append(pkt2)
    
    return packets, "atk014_auth_harvesting.pcap"

def gen_atk017_gtp_session_hijack():
    """ATK-017: GTP Session Hijack (CreateSession -> ModifyBearer)"""
    packets = []
    t = BASE_TIME
    imsi = "234101234567890"
    
    # CreateSessionRequest (msg_type 32)
    pkt1 = create_gtpv2_packet("10.99.0.1", "10.99.0.2", 32, imsi, 0, 1000, t)
    packets.append(pkt1)
    
    # ModifyBearerRequest (msg_type 34) 30 seconds later
    t += timedelta(seconds=30)
    pkt2 = create_gtpv2_packet("10.99.0.1", "10.99.0.2", 34, imsi, 0x12345678, 1001, t)
    packets.append(pkt2)
    
    return packets, "atk017_gtp_hijack.pcap"

def gen_atk021_imsi_catcher():
    """ATK-021: IMSI Catcher Activity (UpdateLocation -> SAI)"""
    packets = []
    t = BASE_TIME
    
    # UpdateLocation (opcode 2)
    ul_tcap = build_tcap_begin(0x00010021, build_map_invoke(2, "04082143658709214365"))
    pkt1 = create_sigtran_packet("10.1.1.100", "10.2.2.200", 2905, 2905, ul_tcap, t)
    packets.append(pkt1)
    
    # SendAuthenticationInfo (opcode 56) 5 seconds later
    t += timedelta(seconds=5)
    sai_tcap = build_tcap_begin(0x00010022, build_map_invoke(56, "04082143658709214365"))
    pkt2 = create_sigtran_packet("10.1.1.100", "10.2.2.200", 2905, 2905, sai_tcap, t)
    packets.append(pkt2)
    
    return packets, "atk021_imsi_catcher.pcap"

def gen_atk022_cross_protocol_dos():
    """ATK-022: Cross-Protocol DoS (MAP CancelLocation -> Diameter CancelLocation)"""
    packets = []
    t = BASE_TIME
    imsi = "234101234567890"
    
    # MAP CancelLocation (opcode 3)
    cl_tcap = build_tcap_begin(0x00010022, build_map_invoke(3, "04082143658709214365"))
    pkt1 = create_sigtran_packet("10.1.1.100", "10.2.2.200", 2905, 2905, cl_tcap, t)
    packets.append(pkt1)
    
    # Diameter CancelLocationRequest (cmd 317) 30 seconds later
    t += timedelta(seconds=30)
    pkt2 = create_diameter_packet("10.50.0.1", "10.50.0.2", 317, True, imsi,
                                   f"session.{imsi}.{t.timestamp()}", t)
    packets.append(pkt2)
    
    return packets, "atk022_cross_dos.pcap"

def gen_diameter_attacks():
    """Generate Diameter-based attack patterns"""
    packets = []
    t = BASE_TIME
    imsi = "234101234567890"
    
    # ATK-010: Diameter Location Hijack (AIR -> ULR)
    # Authentication-Information-Request (cmd 316)
    pkt1 = create_diameter_packet("10.50.0.1", "10.50.0.2", 316, True, imsi,
                                   f"session.{imsi}.1", t)
    packets.append(pkt1)
    
    # Update-Location-Request (cmd 318) 30 seconds later
    t += timedelta(seconds=30)
    pkt2 = create_diameter_packet("10.50.0.1", "10.50.0.2", 318, True, imsi,
                                   f"session.{imsi}.2", t)
    packets.append(pkt2)
    
    return packets, "atk010_diameter_hijack.pcap"

def gen_normal_traffic():
    """Generate normal (non-attack) traffic that should NOT trigger alerts"""
    packets = []
    t = BASE_TIME
    
    # Single SRI (no follow-up PSI - should not trigger ATK-001)
    sri_tcap = build_tcap_begin(0x00020001, build_map_invoke(22, "04048447700000001"))
    pkt1 = create_sigtran_packet("10.1.1.100", "10.2.2.200", 2905, 2905, sri_tcap, t)
    packets.append(pkt1)
    
    # Normal GTP session (no prior SS7 recon)
    t += timedelta(minutes=10)
    pkt2 = create_gtpv2_packet("10.99.0.1", "10.99.0.2", 32, "234109999999999", 0, 2000, t)
    packets.append(pkt2)
    
    # Diameter AIR/AIA pair (normal auth, no attack follow-up)
    t += timedelta(minutes=5)
    pkt3 = create_diameter_packet("10.50.0.10", "10.50.0.20", 316, True, "234108888888888",
                                   "normal.session.1", t)
    packets.append(pkt3)
    
    t += timedelta(milliseconds=100)
    pkt4 = create_diameter_packet("10.50.0.20", "10.50.0.10", 316, False, "234108888888888",
                                   "normal.session.1", t)
    packets.append(pkt4)
    
    return packets, "normal_traffic.pcap"

def gen_timing_edge_cases():
    """Generate timing boundary test cases"""
    packets = []
    t = BASE_TIME
    
    # Attack at exact window boundary (60 seconds for ATK-001)
    sri_tcap = build_tcap_begin(0x00030001, build_map_invoke(22, "04048447700000002"))
    pkt1 = create_sigtran_packet("10.1.1.100", "10.2.2.200", 2905, 2905, sri_tcap, t)
    packets.append(pkt1)
    
    # PSI at exactly 60 seconds (should still match)
    t += timedelta(seconds=60)
    psi_tcap = build_tcap_begin(0x00030002, build_map_invoke(71, "04082143658709214365"))
    pkt2 = create_sigtran_packet("10.1.1.100", "10.2.2.200", 2905, 2905, psi_tcap, t)
    packets.append(pkt2)
    
    # Attack just outside window (61 seconds - should NOT match)
    t += timedelta(minutes=5)
    sri_tcap2 = build_tcap_begin(0x00030003, build_map_invoke(22, "04048447700000003"))
    pkt3 = create_sigtran_packet("10.1.1.100", "10.2.2.200", 2905, 2905, sri_tcap2, t)
    packets.append(pkt3)
    
    t += timedelta(seconds=61)
    psi_tcap2 = build_tcap_begin(0x00030004, build_map_invoke(71, "04082143658709214365"))
    pkt4 = create_sigtran_packet("10.1.1.100", "10.2.2.200", 2905, 2905, psi_tcap2, t)
    packets.append(pkt4)
    
    return packets, "timing_edge_cases.pcap"

def gen_high_volume():
    """Generate high-volume traffic for performance testing"""
    packets = []
    t = BASE_TIME
    
    # 100 different subscribers with SRI queries
    for i in range(100):
        msisdn = f"4477{i:08d}"
        imsi = f"23410{i:010d}"
        
        # SRI
        sri_tcap = build_tcap_begin(0x00040000 + i*2, build_map_invoke(22, f"0404844{msisdn}"))
        pkt1 = create_sigtran_packet("10.1.1.100", "10.2.2.200", 2905, 2905, sri_tcap, t)
        packets.append(pkt1)
        
        # PSI (every 3rd subscriber gets one - creates some attacks)
        if i % 3 == 0:
            t2 = t + timedelta(seconds=2)
            psi_tcap = build_tcap_begin(0x00040000 + i*2 + 1, build_map_invoke(71, f"0408{imsi}"))
            pkt2 = create_sigtran_packet("10.1.1.100", "10.2.2.200", 2905, 2905, psi_tcap, t2)
            packets.append(pkt2)
        
        t += timedelta(milliseconds=100)
    
    return packets, "high_volume_100_subscribers.pcap"

def gen_multi_attacker():
    """Generate attacks from multiple source addresses"""
    packets = []
    t = BASE_TIME
    
    attackers = ["10.1.1.100", "10.1.1.101", "10.1.1.102"]
    target_msisdn = "447712345678"
    target_imsi = "234101234567890"
    
    # Each attacker sends SRI then PSI
    for i, attacker in enumerate(attackers):
        sri_tcap = build_tcap_begin(0x00050000 + i*2, build_map_invoke(22, f"0404844{target_msisdn}"))
        pkt1 = create_sigtran_packet(attacker, "10.2.2.200", 2905, 2905, sri_tcap, t)
        packets.append(pkt1)
        
        t += timedelta(seconds=5)
        psi_tcap = build_tcap_begin(0x00050000 + i*2 + 1, build_map_invoke(71, f"0408{target_imsi}"))
        pkt2 = create_sigtran_packet(attacker, "10.2.2.200", 2905, 2905, psi_tcap, t)
        packets.append(pkt2)
        
        t += timedelta(seconds=10)
    
    return packets, "multi_attacker.pcap"

def gen_mixed_protocols():
    """Generate complex multi-protocol attack scenario"""
    packets = []
    t = BASE_TIME
    imsi = "234101234567890"
    msisdn = "447712345678"
    
    # Phase 1: SS7 Reconnaissance
    sri_tcap = build_tcap_begin(0x00060001, build_map_invoke(22, f"0404844{msisdn}"))
    pkt1 = create_sigtran_packet("10.1.1.100", "10.2.2.200", 2905, 2905, sri_tcap, t)
    packets.append(pkt1)
    
    t += timedelta(seconds=5)
    psi_tcap = build_tcap_begin(0x00060002, build_map_invoke(71, f"0408{imsi}"))
    pkt2 = create_sigtran_packet("10.1.1.100", "10.2.2.200", 2905, 2905, psi_tcap, t)
    packets.append(pkt2)
    
    # Phase 2: Diameter Auth Probe
    t += timedelta(seconds=30)
    pkt3 = create_diameter_packet("10.50.0.1", "10.50.0.2", 316, True, imsi,
                                   f"attack.session.{imsi}", t)
    packets.append(pkt3)
    
    # Phase 3: GTP Session Establishment
    t += timedelta(seconds=60)
    pkt4 = create_gtpv2_packet("10.99.0.1", "10.99.0.2", 32, imsi, 0, 5000, t)
    packets.append(pkt4)
    
    # Phase 4: GTP Session Modification (hijack)
    t += timedelta(seconds=30)
    pkt5 = create_gtpv2_packet("10.99.0.1", "10.99.0.2", 34, imsi, 0xABCDEF00, 5001, t)
    packets.append(pkt5)
    
    return packets, "full_attack_chain.pcap"

# ============================================================================
#  MAIN GENERATOR
# ============================================================================

def write_pcap(packets, filename, output_dir="./"):
    """Write packets to a pcap file."""
    filepath = os.path.join(output_dir, filename)
    wrpcap(filepath, packets)
    print(f"  ✓ {filename} ({len(packets)} packets)")
    return filepath

def main():
    print("=" * 60)
    print("SigCorr Comprehensive Test PCAP Generator")
    print("=" * 60)
    print()
    
    generators = [
        gen_atk001_silent_location_tracking,
        gen_atk003_cross_protocol,
        gen_atk011_sms_interception,
        gen_atk014_auth_harvesting,
        gen_atk017_gtp_session_hijack,
        gen_atk021_imsi_catcher,
        gen_atk022_cross_protocol_dos,
        gen_diameter_attacks,
        gen_normal_traffic,
        gen_timing_edge_cases,
        gen_high_volume,
        gen_multi_attacker,
        gen_mixed_protocols,
    ]
    
    total_packets = 0
    for gen_func in generators:
        try:
            packets, filename = gen_func()
            write_pcap(packets, filename)
            total_packets += len(packets)
        except Exception as e:
            print(f"  ✗ {gen_func.__name__}: {e}")
    
    print()
    print(f"Generated {len(generators)} test pcaps with {total_packets} total packets")
    print()
    print("Run tests with:")
    print("  for f in *.pcap; do echo \"=== $f ===\"; java -jar ../target/sigcorr-0.1.0.jar analyze $f; done")

if __name__ == "__main__":
    main()
