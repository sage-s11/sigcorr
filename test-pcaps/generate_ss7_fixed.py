#!/usr/bin/env python3
"""
SS7/MAP Attack Pcap Generator for SigCorr Validation

Generates pcap files containing properly encoded SS7/MAP attack sequences
that tshark decodes as real GSM MAP messages. The protocol stack:

  Ethernet → IP → SCTP → M3UA (DATA) → MTP3 → SCCP (UDT) → TCAP → MAP

Attack scenarios generated:
  1. ATK-001: Silent Location Tracking — SRI (opcode 22) → PSI (opcode 71)
  2. ATK-002: Interception Setup — SRI (opcode 22) → ISD (opcode 7)
  3. Combined with Diameter for cross-protocol ATK-005/ATK-008

Encoding references:
  - SCTP: RFC 4960
  - M3UA: RFC 4666
  - MTP3: ITU-T Q.704
  - SCCP: ITU-T Q.713
  - TCAP: ITU-T Q.773
  - MAP: 3GPP TS 29.002 (ASN.1 BER encoding)
"""

import struct
import os
import sys

OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))

# ════════════════════════════════════════════════════════════
#  TBCD / BER encoding helpers
# ════════════════════════════════════════════════════════════

def encode_tbcd(digits):
    """Encode digit string in TBCD (Telephony BCD) — nibble-swapped."""
    result = bytearray()
    for i in range(0, len(digits), 2):
        low = int(digits[i])
        high = int(digits[i+1]) if i+1 < len(digits) else 0x0F
        result.append((high << 4) | low)
    return bytes(result)

def ber_tag_length(tag, data):
    """Wrap data with BER tag and length."""
    length = len(data)
    if length < 0x80:
        return bytes([tag, length]) + data
    elif length < 0x100:
        return bytes([tag, 0x81, length]) + data
    else:
        return bytes([tag, 0x82, (length >> 8) & 0xFF, length & 0xFF]) + data

def ber_integer(tag, value):
    """Encode a BER INTEGER."""
    if value < 0x80:
        return bytes([tag, 1, value])
    elif value < 0x8000:
        return bytes([tag, 2, (value >> 8) & 0xFF, value & 0xFF])
    else:
        return bytes([tag, 3, (value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF])

def encode_isdn_address(digits, noa=0x91):
    """
    Encode ISDN-AddressString (MSISDN / Global Title).
    First byte: extension + nature of address + numbering plan
    Remaining: TBCD digits
    noa=0x91: international number, ISDN/telephony plan
    """
    return bytes([noa]) + encode_tbcd(digits)

def encode_imsi_tbcd(imsi):
    """Encode IMSI as TBCD OCTET STRING."""
    return encode_tbcd(imsi)

# ════════════════════════════════════════════════════════════
#  MAP operation builders (BER-encoded)
# ════════════════════════════════════════════════════════════

def build_map_sri_invoke(invoke_id, msisdn):
    """
    Build MAP SendRoutingInfo Invoke (opcode 22).
    
    TCAP Invoke {
      invokeID INTEGER,
      opCode  localValue INTEGER (22),
      argument SEQUENCE {
        msisdn [0] ISDN-AddressString,
        interrogationType [3] ENUMERATED (basicCall=0)
      }
    }
    """
    # Operation code: localValue 22 (SendRoutingInfo)
    opcode = ber_integer(0x02, 22)
    
    # Argument: SEQUENCE containing MSISDN
    msisdn_encoded = encode_isdn_address(msisdn)
    # MSISDN as context [0] OCTET STRING
    msisdn_tlv = ber_tag_length(0x80, msisdn_encoded)
    # Interrogation type [3] ENUMERATED = 0 (basicCall)
    interrog_type = bytes([0x83, 0x01, 0x00])
    
    argument = ber_tag_length(0x30, msisdn_tlv + interrog_type)
    
    # Invoke: invokeID + opCode + argument
    invoke_id_ber = ber_integer(0x02, invoke_id)
    invoke_body = invoke_id_ber + opcode + argument
    
    # TCAP Invoke component [1] (tag 0xA1)
    return ber_tag_length(0xA1, invoke_body)

def build_map_psi_invoke(invoke_id, imsi):
    """
    Build MAP ProvideSubscriberInfo Invoke (opcode 71).
    
    Argument: SEQUENCE {
      imsi [0] IMSI,
      requestedInfo [1] SEQUENCE { locationInformation [0] NULL }
    }
    """
    opcode = ber_integer(0x02, 71)
    
    # IMSI as OCTET STRING
    imsi_encoded = encode_imsi_tbcd(imsi)
    imsi_tlv = ber_tag_length(0x80, imsi_encoded)  # CONTEXT [0] IMPLICIT
    
    # RequestedInfo: requesting location
    location_null = bytes([0x80, 0x00])  # [0] NULL (locationInformation)
    requested_info = ber_tag_length(0xA1, location_null)
    
    argument = ber_tag_length(0x30, imsi_tlv + requested_info)
    
    invoke_id_ber = ber_integer(0x02, invoke_id)
    invoke_body = invoke_id_ber + opcode + argument
    
    return ber_tag_length(0xA1, invoke_body)

def build_map_isd_invoke(invoke_id, imsi, forwarding_msisdn=None):
    """
    Build MAP InsertSubscriberData Invoke (opcode 7).
    
    Argument: SEQUENCE {
      imsi [0] IMSI,
      msisdn [1] ISDN-AddressString (optional — the forwarding target)
    }
    """
    opcode = ber_integer(0x02, 7)
    
    imsi_encoded = encode_imsi_tbcd(imsi)
    imsi_tlv = ber_tag_length(0x80, imsi_encoded)  # CONTEXT [0] IMPLICIT
    
    arg_data = imsi_tlv
    if forwarding_msisdn:
        fwd_encoded = encode_isdn_address(forwarding_msisdn)
        arg_data += ber_tag_length(0x81, fwd_encoded)
    
    argument = ber_tag_length(0x30, arg_data)
    
    invoke_id_ber = ber_integer(0x02, invoke_id)
    invoke_body = invoke_id_ber + opcode + argument
    
    return ber_tag_length(0xA1, invoke_body)

def build_map_send_auth_info_invoke(invoke_id, imsi):
    """
    Build MAP SendAuthenticationInfo Invoke (opcode 56).
    
    Argument: SEQUENCE { imsi IMSI }
    """
    opcode = ber_integer(0x02, 56)
    
    imsi_encoded = encode_imsi_tbcd(imsi)
    imsi_tlv = ber_tag_length(0x80, imsi_encoded)  # CONTEXT [0] IMPLICIT
    
    argument = ber_tag_length(0x30, imsi_tlv)
    
    invoke_id_ber = ber_integer(0x02, invoke_id)
    invoke_body = invoke_id_ber + opcode + argument
    
    return ber_tag_length(0xA1, invoke_body)

# ════════════════════════════════════════════════════════════
#  TCAP layer
# ════════════════════════════════════════════════════════════

def build_tcap_begin(transaction_id, map_component, app_context_oid=None):
    """
    Build TCAP BEGIN message wrapping a MAP component.
    
    begin [APPLICATION 2] SEQUENCE {
      otid OCTET STRING (4 bytes),
      dialoguePortion (optional — for MAP context),
      components SEQUENCE OF Component
    }
    """
    # Source Transaction ID
    otid = ber_tag_length(0x48, struct.pack("!I", transaction_id))
    
    # Dialogue portion with MAP application context (simplified)
    dialogue = b''
    if app_context_oid:
        dialogue = build_dialogue_portion(app_context_oid)
    
    # Component portion: SEQUENCE OF Component
    components = ber_tag_length(0x6C, map_component)
    
    # TCAP BEGIN [APPLICATION 2] = tag 0x62
    begin_body = otid + dialogue + components
    return ber_tag_length(0x62, begin_body)

def build_dialogue_portion(context_oid_bytes):
    """Build TCAP dialogue portion with application context."""
    # This encodes the MAP dialogue as seen in the reference pcap
    # OID for dialogue: 0.0.17.773.1.1.1
    dialogue_oid = bytes([0x06, 0x07, 0x00, 0x11, 0x86, 0x05, 0x01, 0x01, 0x01])
    
    # Protocol version
    proto_version = bytes([0x80, 0x02, 0x07, 0x80])
    
    # Application context name
    acn = ber_tag_length(0xA1, ber_tag_length(0x06, context_oid_bytes))
    
    # dialogueRequest
    dialogue_request = ber_tag_length(0xA0, proto_version + acn)
    
    # External wrapper
    external = ber_tag_length(0x28, dialogue_oid + dialogue_request)
    
    # Dialogue portion [APPLICATION 11] = 0x6B
    return ber_tag_length(0x6B, external)

# ════════════════════════════════════════════════════════════
#  SCCP layer (Unitdata)
# ════════════════════════════════════════════════════════════

def encode_sccp_gt(digits, ssn=6, noa=0x04):
    """
    Encode SCCP Global Title (GT format 0100).
    Address indicator + SSN + GT(translation type, numbering plan, encoding, NAI, digits)
    """
    # Address indicator: GT=0100, SSN present, no PC
    addr_indicator = 0x12  # GT indicator=4, SSN=1, PC=0
    
    # BCD encode the digits
    bcd = encode_tbcd(digits)
    num_digits = len(digits)
    
    # Encoding scheme: 1=BCD odd, 2=BCD even
    encoding = 0x01 if num_digits % 2 == 1 else 0x02
    numbering_plan = 0x01  # ISDN
    
    np_es = (numbering_plan << 4) | encoding
    
    # GT: translation_type(1) + np_es(1) + noa(1) + digits
    gt = bytes([0x00, np_es, noa]) + bcd
    
    return bytes([addr_indicator, ssn]) + gt

def build_sccp_udt(called_digits, calling_digits, tcap_data,
                   called_ssn=147, calling_ssn=6):
    """
    Build SCCP Unitdata (UDT) message.
    Message type 0x09, class 0, called addr, calling addr, data
    """
    called_addr = encode_sccp_gt(called_digits, called_ssn)
    calling_addr = encode_sccp_gt(calling_digits, calling_ssn)
    
    # Calculate pointer offsets
    ptr_called = 3  # 3 bytes for the 3 pointers
    ptr_calling = ptr_called + 1 + len(called_addr)  # +1 for length byte
    ptr_data = ptr_calling + 1 + len(calling_addr)
    
    # Pointers are relative to their own position
    msg = bytes([0x09])  # Message type: UDT
    msg += bytes([0x00])  # Protocol class: 0
    msg += bytes([ptr_called - 2, ptr_calling - 1, ptr_data])  # Pointers (simplified)
    
    # Actually, SCCP UDT pointers work differently. Let me use the correct encoding:
    # Pointer to called = offset from pointer1 position to called addr
    # Pointer to calling = offset from pointer2 position to calling addr
    # Pointer to data = offset from pointer3 position to data
    
    called_with_len = bytes([len(called_addr)]) + called_addr
    calling_with_len = bytes([len(calling_addr)]) + calling_addr
    data_with_len = bytes([len(tcap_data)]) + tcap_data
    
    # Three pointers
    p1 = 3  # pointer to called party (from p1 position)
    p2 = p1 + len(called_with_len)  # from p2 position: adjust
    p3 = p2 + len(calling_with_len) - 1
    
    # Simpler: just compute correctly
    # p1 is at offset 2 (after msgtype + class), points to called
    # p2 is at offset 3, points to calling
    # p3 is at offset 4, points to data
    # called starts at offset 5
    # calling starts at offset 5 + len(called_with_len)
    # data starts at offset 5 + len(called_with_len) + len(calling_with_len)
    
    p1_val = 3  # from position of p1 (offset 2) to called (offset 5) = 3
    p2_val = 2 + len(called_with_len)  # from p2 (offset 3) to calling
    p3_val = 1 + len(called_with_len) + len(calling_with_len)  # from p3 to data
    
    result = bytes([0x09, 0x00, p1_val, p2_val, p3_val])
    result += called_with_len + calling_with_len + data_with_len
    
    return result

# ════════════════════════════════════════════════════════════
#  MTP3 layer
# ════════════════════════════════════════════════════════════

def build_mtp3(service_indicator, dpc, opc, sls, sccp_data):
    """
    Build MTP3 header (ITU format, 5 bytes routing label).
    SIO (1 byte): network indicator (2b) + spare (2b) + service indicator (4b)
    Routing label (4 bytes): DPC(14b) + OPC(14b) + SLS(4b)
    """
    # SIO: national network (0x80) + SCCP (0x03)
    sio = 0x83  # NI=10 (national), SI=0011 (SCCP)
    
    # Routing label (ITU): 4 bytes = DPC(14) + OPC(14) + SLS(4)
    # Packed as little-endian for ITU
    rl = (dpc & 0x3FFF) | ((opc & 0x3FFF) << 14) | ((sls & 0x0F) << 28)
    rl_bytes = struct.pack("<I", rl)
    
    return bytes([sio]) + rl_bytes + sccp_data

# ════════════════════════════════════════════════════════════
#  M3UA layer
# ════════════════════════════════════════════════════════════

def build_m3ua_data(opc, dpc, si, mtp3_and_sccp_data):
    """
    Build M3UA DATA message (Transfer message).
    
    M3UA header: Version(1) + Reserved(1) + Message Class(1) + Message Type(1) + Length(4)
    Followed by Protocol Data parameter containing MTP3 payload.
    """
    # Protocol Data parameter (tag 0x0210)
    # Contains: OPC(4) + DPC(4) + SI(1) + NI(1) + MP(1) + SLS(1) + user data
    proto_data_value = struct.pack("!IIBBBB",
        opc, dpc,
        si,    # Service Indicator (3 = SCCP)
        2,     # Network Indicator (national)
        0,     # Message Priority
        0      # Signalling Link Selection
    ) + mtp3_and_sccp_data
    
    # Pad to 4-byte boundary
    pad = (4 - len(proto_data_value) % 4) % 4
    proto_data_padded = proto_data_value + (b'\x00' * pad)
    
    # Parameter: Tag(2) + Length(2) + Value
    param_length = 4 + len(proto_data_value)  # tag+len+value (unpadded length in header)
    proto_data_param = struct.pack("!HH", 0x0210, param_length) + proto_data_padded
    
    # M3UA header
    msg_length = 8 + len(proto_data_param)
    m3ua_header = struct.pack("!BBBBI",
        1,     # Version
        0,     # Reserved
        1,     # Message Class: Transfer (1)
        1,     # Message Type: DATA (1)
        msg_length  # Explicitly pack as 4-byte int
    )
    
    # Repack header correctly (8 bytes)
    m3ua_header = bytes([1, 0, 1, 1]) + struct.pack("!I", msg_length)
    
    return m3ua_header + proto_data_param

# ════════════════════════════════════════════════════════════
#  SCTP layer
# ════════════════════════════════════════════════════════════

def build_sctp_data_chunk(payload, stream_id=0, stream_seq=0, ppid=3):
    """
    Build SCTP DATA chunk.
    Type(1) + Flags(1) + Length(2) + TSN(4) + StreamID(2) + StreamSeq(2) + PPID(4) + data
    PPID=3 for M3UA
    """
    chunk_length = 16 + len(payload)
    chunk = struct.pack("!BBHIHHI",
        0,          # Chunk Type: DATA
        0x03,       # Flags: B+E (beginning + ending — single fragment)
        chunk_length,
        1,          # TSN
        stream_id,
        stream_seq,
        ppid
    ) + payload
    
    # Pad to 4-byte boundary
    pad = (4 - len(chunk) % 4) % 4
    return chunk + (b'\x00' * pad)

def build_sctp_packet(src_port, dst_port, vtag, chunks):
    """
    Build SCTP packet header.
    SrcPort(2) + DstPort(2) + VTag(4) + Checksum(4) + chunks
    """
    header = struct.pack("!HHII",
        src_port, dst_port,
        vtag,
        0  # Checksum (0 — wireshark will show as incorrect but still decodes)
    )
    return header + chunks

# ════════════════════════════════════════════════════════════
#  IP + Ethernet wrappers
# ════════════════════════════════════════════════════════════

def wrap_in_ip(payload, src_ip, dst_ip, protocol=132):
    """Wrap in IPv4 header. Protocol 132 = SCTP."""
    total_len = 20 + len(payload)
    return struct.pack("!BBHHHBBH4s4s",
        0x45, 0x00,
        total_len, 0x1234,
        0x0000, 0xFF, protocol,
        0x0000,
        bytes(int(x) for x in src_ip.split('.')),
        bytes(int(x) for x in dst_ip.split('.'))) + payload

def wrap_ethernet(ip_packet):
    """Wrap in Ethernet II header."""
    return (bytes([0x02, 0x02, 0x02, 0x02, 0x02, 0x02,   # dst MAC
                   0x01, 0x01, 0x01, 0x01, 0x01, 0x01,   # src MAC
                   0x08, 0x00])                            # EtherType: IPv4
            + ip_packet)

# ════════════════════════════════════════════════════════════
#  Pcap writer
# ════════════════════════════════════════════════════════════

def write_pcap(filename, packets):
    """Write packets as pcap. packets = [(timestamp, ethernet_frame), ...]"""
    with open(filename, 'wb') as f:
        # Global header (big-endian)
        f.write(struct.pack("!IHHiIII",
            0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))  # linktype=1 (Ethernet)
        
        for ts, frame in packets:
            ts_sec = int(ts)
            ts_usec = int((ts - ts_sec) * 1000000)
            f.write(struct.pack("!IIII", ts_sec, ts_usec, len(frame), len(frame)))
            f.write(frame)

# ════════════════════════════════════════════════════════════
#  Full packet builder: MAP operation → Ethernet frame
# ════════════════════════════════════════════════════════════

def build_ss7_map_packet(map_component, calling_gt, called_gt,
                          src_ip="10.0.0.1", dst_ip="10.0.0.2",
                          opc=9283, dpc=9444, transaction_id=0x2F3B4602,
                          called_ssn=6, calling_ssn=147,
                          stream_seq=0):
    """
    Build a complete Ethernet frame containing an SS7/MAP message.
    Stack: Ethernet → IP → SCTP → M3UA DATA → SCCP UDT → TCAP BEGIN → MAP
    """
    # TCAP: wrap MAP component in TCAP BEGIN
    tcap = build_tcap_begin(transaction_id, map_component)
    
    # SCCP: Unitdata with called/calling GTs
    sccp = build_sccp_udt(called_gt, calling_gt, tcap,
                          called_ssn=called_ssn, calling_ssn=calling_ssn)
    
    # M3UA: DATA containing SCCP
    m3ua = build_m3ua_data(opc, dpc, 3, sccp)  # SI=3 for SCCP
    
    # SCTP: DATA chunk with PPID=3 (M3UA)
    sctp_chunk = build_sctp_data_chunk(m3ua, stream_seq=stream_seq)
    sctp = build_sctp_packet(2905, 2905, 0, sctp_chunk)  # M3UA default port
    
    # IP + Ethernet
    ip = wrap_in_ip(sctp, src_ip, dst_ip, protocol=132)
    return wrap_ethernet(ip)

# ════════════════════════════════════════════════════════════
#  Attack scenario generators
# ════════════════════════════════════════════════════════════

def generate_location_tracking_pcap():
    """
    ATK-001: Silent Location Tracking
    
    Step 1: MAP SendRoutingInfo (opcode 22) — queries MSISDN to get IMSI
    Step 2: MAP ProvideSubscriberInfo (opcode 71) — queries IMSI to get Cell-ID
    
    Both from the same foreign GT (attacker), targeting the same subscriber.
    """
    target_msisdn = "447712345678"
    target_imsi = "234101234567890"
    attacker_gt = "491720000000"  # Foreign GT (Germany)
    home_gt = "441234567890"      # Home HLR GT (UK)
    
    packets = []
    base_time = 1700001000.0
    
    # Step 1: SendRoutingInfo (MSISDN query)
    sri = build_map_sri_invoke(1, target_msisdn)
    frame1 = build_ss7_map_packet(sri, attacker_gt, home_gt,
                                   src_ip="10.0.0.1", dst_ip="10.0.0.2",
                                   opc=100, dpc=200, transaction_id=0x00010001,
                                   calling_ssn=147, called_ssn=6,
                                   stream_seq=0)
    packets.append((base_time, frame1))
    
    # Step 2: ProvideSubscriberInfo (location query) — 3 seconds later
    psi = build_map_psi_invoke(2, target_imsi)
    frame2 = build_ss7_map_packet(psi, attacker_gt, home_gt,
                                   src_ip="10.0.0.1", dst_ip="10.0.0.2",
                                   opc=100, dpc=200, transaction_id=0x00010002,
                                   calling_ssn=147, called_ssn=6,
                                   stream_seq=1)
    packets.append((base_time + 3.0, frame2))
    
    outfile = os.path.join(OUTPUT_DIR, "ss7_location_tracking.pcap")
    write_pcap(outfile, packets)
    print(f"[+] ATK-001 Location Tracking: {outfile}")
    print(f"    SRI(MSISDN={target_msisdn}) → PSI(IMSI={target_imsi})")
    print(f"    Attacker GT: {attacker_gt}")
    return outfile

def generate_interception_setup_pcap():
    """
    ATK-002: Interception Setup
    
    Step 1: MAP SendRoutingInfo (opcode 22) — discover routing
    Step 2: MAP InsertSubscriberData (opcode 7) — redirect to attacker MSC
    
    Both from the same foreign GT.
    """
    target_msisdn = "447798765432"
    target_imsi = "234109876543210"
    attacker_gt = "491720000000"
    home_gt = "441234567890"
    attacker_msisdn = "491720000099"  # Attacker's forwarding number
    
    packets = []
    base_time = 1700002000.0
    
    # Step 1: SRI
    sri = build_map_sri_invoke(1, target_msisdn)
    frame1 = build_ss7_map_packet(sri, attacker_gt, home_gt,
                                   opc=100, dpc=200, transaction_id=0x00020001,
                                   stream_seq=0)
    packets.append((base_time, frame1))
    
    # Step 2: ISD — 5 seconds later
    isd = build_map_isd_invoke(2, target_imsi, attacker_msisdn)
    frame2 = build_ss7_map_packet(isd, attacker_gt, home_gt,
                                   opc=100, dpc=200, transaction_id=0x00020002,
                                   stream_seq=1)
    packets.append((base_time + 5.0, frame2))
    
    outfile = os.path.join(OUTPUT_DIR, "ss7_interception_setup.pcap")
    write_pcap(outfile, packets)
    print(f"[+] ATK-002 Interception Setup: {outfile}")
    print(f"    SRI(MSISDN={target_msisdn}) → ISD(IMSI={target_imsi}, fwd={attacker_msisdn})")
    return outfile

def generate_auth_downgrade_pcap():
    """
    ATK-005: Diameter-to-SS7 Authentication Downgrade
    
    Step 1: Diameter AIR (cmd 316) — rejected by HSS
    Step 2: MAP SendAuthenticationInfo (opcode 56) — fallback to legacy SS7
    
    Cross-protocol: Diameter then SS7/MAP for the same IMSI.
    """
    target_imsi = "234101234567890"
    attacker_gt = "491720000000"
    home_gt = "441234567890"
    
    packets = []
    base_time = 1700003000.0
    
    # Step 1: Diameter AIR
    from generate_attack_pcaps import build_diameter_s6a_air, wrap_in_tcp_ip
    air = build_diameter_s6a_air(target_imsi, "mme01.attacker.com", "attacker.com", "home-net.com")
    air_frame = (bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                        0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0x08, 0x00])
                 + wrap_in_tcp_ip(air, "10.99.0.1", "10.1.0.1", 3868, 3868))
    packets.append((base_time, air_frame))
    
    # Step 2: MAP SendAuthInfo — 8 seconds later (SS7 fallback)
    sai = build_map_send_auth_info_invoke(1, target_imsi)
    frame2 = build_ss7_map_packet(sai, attacker_gt, home_gt,
                                   opc=100, dpc=200, transaction_id=0x00030001,
                                   stream_seq=0)
    packets.append((base_time + 8.0, frame2))
    
    outfile = os.path.join(OUTPUT_DIR, "cross_protocol_auth_downgrade.pcap")
    write_pcap(outfile, packets)
    print(f"[+] ATK-005 Auth Downgrade: {outfile}")
    print(f"    Diameter AIR(IMSI={target_imsi}) → MAP SendAuthInfo(IMSI={target_imsi})")
    return outfile

def generate_full_attack_scenario_pcap():
    """
    Combined multi-protocol attack scenario:
    
    T+0s:    MAP SRI for MSISDN 447712345678 (reconnaissance)
    T+3s:    MAP PSI for IMSI 234101234567890 (location tracking)
    T+60s:   Diameter AIR for same IMSI (auth probe)
    T+65s:   Diameter ULR for same IMSI (re-registration)
    T+120s:  GTPv2-C Create-Session for same IMSI (session hijack)
    
    Should trigger: ATK-001, ATK-009, ATK-010 at minimum.
    """
    target_msisdn = "447712345678"
    target_imsi = "234101234567890"
    attacker_gt = "491720000000"
    home_gt = "441234567890"
    
    packets = []
    base_time = 1700004000.0
    
    # T+0: MAP SRI
    sri = build_map_sri_invoke(1, target_msisdn)
    packets.append((base_time,
        build_ss7_map_packet(sri, attacker_gt, home_gt,
                             opc=100, dpc=200, transaction_id=0x00040001, stream_seq=0)))
    
    # T+3: MAP PSI
    psi = build_map_psi_invoke(2, target_imsi)
    packets.append((base_time + 3.0,
        build_ss7_map_packet(psi, attacker_gt, home_gt,
                             opc=100, dpc=200, transaction_id=0x00040002, stream_seq=1)))
    
    # T+60: Diameter AIR
    from generate_attack_pcaps import build_diameter_s6a_air, build_diameter_s6a_ulr, wrap_in_tcp_ip, wrap_in_udp_ip, build_gtpv2_create_session
    
    air = build_diameter_s6a_air(target_imsi, "mme01.attacker.com", "attacker.com", "home-net.com")
    packets.append((base_time + 60.0,
        bytes([0x00,0x11,0x22,0x33,0x44,0x55, 0x66,0x77,0x88,0x99,0xAA,0xBB, 0x08,0x00])
        + wrap_in_tcp_ip(air, "10.99.0.1", "10.1.0.1", 3868, 3868)))
    
    # T+65: Diameter ULR
    ulr = build_diameter_s6a_ulr(target_imsi, "mme01.attacker.com", "attacker.com", "home-net.com")
    packets.append((base_time + 65.0,
        bytes([0x00,0x11,0x22,0x33,0x44,0x55, 0x66,0x77,0x88,0x99,0xAA,0xBB, 0x08,0x00])
        + wrap_in_tcp_ip(ulr, "10.99.0.1", "10.1.0.1", 3868, 3868, seq_num=2000)))
    
    # T+120: GTPv2-C Create-Session
    csr = build_gtpv2_create_session(target_imsi, target_msisdn)
    packets.append((base_time + 120.0,
        bytes([0x00,0x11,0x22,0x33,0x44,0x55, 0x66,0x77,0x88,0x99,0xAA,0xBB, 0x08,0x00])
        + wrap_in_udp_ip(csr, "10.99.0.1", "10.1.0.2", 2123, 2123)))
    
    outfile = os.path.join(OUTPUT_DIR, "full_multi_protocol_attack.pcap")
    write_pcap(outfile, packets)
    print(f"[+] Full Multi-Protocol Attack: {outfile}")
    print(f"    MAP SRI → MAP PSI → Diameter AIR → Diameter ULR → GTP CreateSession")
    print(f"    Target: IMSI={target_imsi}, MSISDN={target_msisdn}")
    return outfile

# ════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("SigCorr SS7/MAP Attack Pcap Generator")
    print("=" * 50)
    print()
    
    f1 = generate_location_tracking_pcap()
    print()
    f2 = generate_interception_setup_pcap()
    print()
    
    # Cross-protocol attacks need the Diameter/GTP generator
    try:
        f3 = generate_auth_downgrade_pcap()
        print()
        f4 = generate_full_attack_scenario_pcap()
        print()
    except ImportError:
        print("\n[!] Skipping cross-protocol pcaps (need generate_attack_pcaps.py in same dir)")
        f3 = f4 = None
    
    print()
    print("Verify with tshark:")
    for f in [f1, f2, f3, f4]:
        if f:
            print(f"  tshark -r {os.path.basename(f)} -V | head -60")
    
    print()
    print("Test with SigCorr:")
    for f in [f1, f2, f3, f4]:
        if f:
            print(f"  java -jar target/sigcorr-0.1.0.jar analyze test-pcaps/{os.path.basename(f)} --verbose")
