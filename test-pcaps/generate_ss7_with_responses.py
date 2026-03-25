#!/usr/bin/env python3
"""
SS7/MAP Attack Pcap Generator with Response Packets - COMPLETE IMPLEMENTATION

Generates realistic SS7/MAP traffic with INVOKE (request) + RETURN RESULT (response) pairs.
This enables proper IMSI extraction and subscriber-based correlation.

Protocol stack: Ethernet → IP → SCTP → M3UA → MTP3 → SCCP → TCAP → MAP

Response packets added:
  - SendRoutingInfo RESPONSE: contains IMSI (mapped from MSISDN)
  - ProvideSubscriberInfo RESPONSE: contains location data (Cell-ID, LAC)
  - InsertSubscriberData RESPONSE: success acknowledgment
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
#  MAP REQUEST builders (INVOKE)
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
    opcode = ber_integer(0x02, 22)
    
    # Argument: SEQUENCE containing MSISDN
    msisdn_encoded = encode_isdn_address(msisdn)
    msisdn_tlv = ber_tag_length(0x80, msisdn_encoded)  # [0] CONTEXT
    interrog_type = bytes([0x83, 0x01, 0x00])  # [3] ENUMERATED = basicCall
    
    argument = ber_tag_length(0x30, msisdn_tlv + interrog_type)
    
    invoke_id_ber = ber_integer(0x02, invoke_id)
    invoke_body = invoke_id_ber + opcode + argument
    
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
    
    # IMSI as CONTEXT [0] IMPLICIT OCTET STRING
    imsi_encoded = encode_imsi_tbcd(imsi)
    imsi_tlv = ber_tag_length(0x80, imsi_encoded)  # [0] CONTEXT - FIXED
    
    # RequestedInfo: requesting location
    location_null = bytes([0x80, 0x00])  # [0] NULL
    requested_info = ber_tag_length(0xA1, location_null)  # [1] SEQUENCE
    
    argument = ber_tag_length(0x30, imsi_tlv + requested_info)
    
    invoke_id_ber = ber_integer(0x02, invoke_id)
    invoke_body = invoke_id_ber + opcode + argument
    
    return ber_tag_length(0xA1, invoke_body)

def build_map_isd_invoke(invoke_id, imsi, forwarding_msisdn=None):
    """
    Build MAP InsertSubscriberData Invoke (opcode 7).
    
    Argument: SEQUENCE {
      imsi [0] IMSI,
      msisdn [1] ISDN-AddressString (optional)
    }
    """
    opcode = ber_integer(0x02, 7)
    
    imsi_encoded = encode_imsi_tbcd(imsi)
    imsi_tlv = ber_tag_length(0x80, imsi_encoded)  # [0] CONTEXT - FIXED
    
    arg_data = imsi_tlv
    if forwarding_msisdn:
        fwd_encoded = encode_isdn_address(forwarding_msisdn)
        arg_data += ber_tag_length(0x81, fwd_encoded)  # [1] CONTEXT
    
    argument = ber_tag_length(0x30, arg_data)
    
    invoke_id_ber = ber_integer(0x02, invoke_id)
    invoke_body = invoke_id_ber + opcode + argument
    
    return ber_tag_length(0xA1, invoke_body)

# ════════════════════════════════════════════════════════════
#  MAP RESPONSE builders (RETURN RESULT)
# ════════════════════════════════════════════════════════════

def build_map_sri_return_result(invoke_id, imsi, msc_number="441234999999"):
    """
    Build MAP SendRoutingInfo Return Result (response to opcode 22).
    
    TCAP ReturnResult {
      invokeID INTEGER,
      resultretres SEQUENCE {
        opCode localValue INTEGER (22),
        result SEQUENCE {
          imsi OCTET STRING,
          extendedRoutingInfo ExtendedRoutingInfo (optional)
        }
      }
    }
    
    This response contains the IMSI that was looked up from the MSISDN.
    """
    # IMSI as UNIVERSAL OCTET STRING (tag 0x04) - Wireshark expects this
    imsi_encoded = encode_imsi_tbcd(imsi)
    imsi_tlv = ber_tag_length(0x04, imsi_encoded)  # OCTET STRING
    
    # Routing info: roamingNumber (simplified - just return MSC address)
    roaming_number = encode_isdn_address(msc_number)
    routing_tlv = ber_tag_length(0x80, roaming_number)  # [0] roamingNumber
    routing_info = ber_tag_length(0xA9, routing_tlv)  # [9] routingInfo
    
    # Result SEQUENCE
    result_seq = ber_tag_length(0x30, imsi_tlv + routing_info)
    
    # Operation code
    opcode = ber_integer(0x02, 22)
    
    # resultretres SEQUENCE
    resultretres = ber_tag_length(0x30, opcode + result_seq)
    
    # ReturnResult component
    invoke_id_ber = ber_integer(0x02, invoke_id)
    return_result_body = invoke_id_ber + resultretres
    
    # TCAP ReturnResult [2] = tag 0xA2
    return ber_tag_length(0xA2, return_result_body)

def build_map_psi_return_result(invoke_id, cell_id=0x1234, lac=0x5678):
    """
    Build MAP ProvideSubscriberInfo Return Result (response to opcode 71).
    
    TCAP ReturnResult {
      invokeID INTEGER,
      resultretres SEQUENCE {
        opCode localValue INTEGER (71),
        result SEQUENCE {
          subscriberInfo SEQUENCE {
            locationInformation [0] SEQUENCE {
              cellGlobalIdOrServiceAreaIdFixedLength [0] OCTET STRING (7 bytes),
              locationAreaCode OCTET STRING (2 bytes)
            }
          }
        }
      }
    }
    
    This response contains location data (Cell-ID, LAC).
    """
    # Cell Global ID (simplified): MCC(234) + MNC(10) + LAC + Cell-ID
    # Format: 3 bytes (MCC+MNC in TBCD) + 2 bytes LAC + 2 bytes Cell-ID
    mcc_mnc = encode_tbcd("23410")  # MCC=234, MNC=10
    cell_global_id = mcc_mnc + struct.pack("!HH", lac, cell_id)
    
    # Pad to 7 bytes if needed
    while len(cell_global_id) < 7:
        cell_global_id += b'\x00'
    
    cell_id_tlv = ber_tag_length(0x80, cell_global_id[:7])  # [0] cellGlobalId
    
    # LocationInformation [0] SEQUENCE
    location_info = ber_tag_length(0xA0, cell_id_tlv)
    
    # SubscriberInfo SEQUENCE
    subscriber_info = ber_tag_length(0x30, location_info)
    
    # Result SEQUENCE
    result_seq = ber_tag_length(0x30, subscriber_info)
    
    # Operation code
    opcode = ber_integer(0x02, 71)
    
    # resultretres SEQUENCE
    resultretres = ber_tag_length(0x30, opcode + result_seq)
    
    # ReturnResult component
    invoke_id_ber = ber_integer(0x02, invoke_id)
    return_result_body = invoke_id_ber + resultretres
    
    # TCAP ReturnResult [2] = tag 0xA2
    return ber_tag_length(0xA2, return_result_body)

def build_map_isd_return_result(invoke_id):
    """
    Build MAP InsertSubscriberData Return Result (response to opcode 7).
    
    Simple success acknowledgment - no result data needed.
    """
    # Operation code
    opcode = ber_integer(0x02, 7)
    
    # Empty result (success)
    result_seq = ber_tag_length(0x30, b'')
    
    # resultretres SEQUENCE
    resultretres = ber_tag_length(0x30, opcode + result_seq)
    
    # ReturnResult component
    invoke_id_ber = ber_integer(0x02, invoke_id)
    return_result_body = invoke_id_ber + resultretres
    
    # TCAP ReturnResult [2] = tag 0xA2
    return ber_tag_length(0xA2, return_result_body)

# ════════════════════════════════════════════════════════════
#  TCAP layer
# ════════════════════════════════════════════════════════════

def build_tcap_begin(transaction_id, map_component):
    """
    Build TCAP BEGIN message wrapping a MAP Invoke component.
    
    begin [APPLICATION 2] SEQUENCE {
      otid OCTET STRING (4 bytes),
      components SEQUENCE OF Component
    }
    """
    # Source Transaction ID
    otid = ber_tag_length(0x48, struct.pack("!I", transaction_id))
    
    # Component portion
    components = ber_tag_length(0x6C, map_component)
    
    # TCAP BEGIN [APPLICATION 2] = tag 0x62
    begin_body = otid + components
    return ber_tag_length(0x62, begin_body)

def build_tcap_end(transaction_id, map_component):
    """
    Build TCAP END message wrapping a MAP ReturnResult component.
    
    end [APPLICATION 4] SEQUENCE {
      dtid OCTET STRING (4 bytes),
      components SEQUENCE OF Component
    }
    """
    # Destination Transaction ID
    dtid = ber_tag_length(0x49, struct.pack("!I", transaction_id))
    
    # Component portion
    components = ber_tag_length(0x6C, map_component)
    
    # TCAP END [APPLICATION 4] = tag 0x64
    end_body = dtid + components
    return ber_tag_length(0x64, end_body)

# ════════════════════════════════════════════════════════════
#  SCCP layer (Unitdata)
# ════════════════════════════════════════════════════════════

def encode_sccp_gt(digits, ssn=6, noa=0x04):
    """Encode SCCP Global Title (GT format 0100)."""
    addr_indicator = 0x12  # GT indicator=4, SSN=1, PC=0
    
    bcd = encode_tbcd(digits)
    num_digits = len(digits)
    
    encoding = 0x01 if num_digits % 2 == 1 else 0x02
    numbering_plan = 0x01  # ISDN
    
    np_es = (numbering_plan << 4) | encoding
    
    gt = bytes([0x00, np_es, noa]) + bcd
    
    return bytes([addr_indicator, ssn]) + gt

def build_sccp_udt(called_digits, calling_digits, tcap_data,
                   called_ssn=147, calling_ssn=6):
    """Build SCCP Unitdata (UDT) message."""
    called_addr = encode_sccp_gt(called_digits, called_ssn)
    calling_addr = encode_sccp_gt(calling_digits, calling_ssn)
    
    called_with_len = bytes([len(called_addr)]) + called_addr
    calling_with_len = bytes([len(calling_addr)]) + calling_addr
    data_with_len = bytes([len(tcap_data)]) + tcap_data
    
    p1_val = 3
    p2_val = 2 + len(called_with_len)
    p3_val = 1 + len(called_with_len) + len(calling_with_len)
    
    result = bytes([0x09, 0x00, p1_val, p2_val, p3_val])
    result += called_with_len + calling_with_len + data_with_len
    
    return result

# ════════════════════════════════════════════════════════════
#  MTP3, M3UA, SCTP layers (unchanged from original)
# ════════════════════════════════════════════════════════════

def build_m3ua_data(opc, dpc, si, mtp3_and_sccp_data):
    """Build M3UA DATA message."""
    proto_data_value = struct.pack("!IIBBBB",
        opc, dpc, si, 2, 0, 0
    ) + mtp3_and_sccp_data
    
    pad = (4 - len(proto_data_value) % 4) % 4
    proto_data_padded = proto_data_value + (b'\x00' * pad)
    
    param_length = 4 + len(proto_data_value)
    proto_data_param = struct.pack("!HH", 0x0210, param_length) + proto_data_padded
    
    msg_length = 8 + len(proto_data_param)
    m3ua_header = bytes([1, 0, 1, 1]) + struct.pack("!I", msg_length)
    
    return m3ua_header + proto_data_param

def build_sctp_data_chunk(payload, stream_id=0, stream_seq=0, ppid=3):
    """Build SCTP DATA chunk."""
    chunk_length = 16 + len(payload)
    chunk = struct.pack("!BBHIHHI",
        0, 0x03, chunk_length, 1, stream_id, stream_seq, ppid
    ) + payload
    
    pad = (4 - len(chunk) % 4) % 4
    return chunk + (b'\x00' * pad)

def build_sctp_packet(src_port, dst_port, vtag, chunks):
    """Build SCTP packet header."""
    header = struct.pack("!HHII", src_port, dst_port, vtag, 0)
    return header + chunks

def wrap_in_ip(payload, src_ip, dst_ip, protocol=132):
    """Wrap in IPv4 header."""
    total_len = 20 + len(payload)
    return struct.pack("!BBHHHBBH4s4s",
        0x45, 0x00, total_len, 0x1234, 0x0000, 0xFF, protocol, 0x0000,
        bytes(int(x) for x in src_ip.split('.')),
        bytes(int(x) for x in dst_ip.split('.'))) + payload

def wrap_ethernet(ip_packet):
    """Wrap in Ethernet II header."""
    return (bytes([0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                   0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                   0x08, 0x00]) + ip_packet)

# ════════════════════════════════════════════════════════════
#  Pcap writer
# ════════════════════════════════════════════════════════════

def write_pcap(filename, packets):
    """Write packets as pcap."""
    with open(filename, 'wb') as f:
        f.write(struct.pack("!IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        
        for ts, frame in packets:
            ts_sec = int(ts)
            ts_usec = int((ts - ts_sec) * 1000000)
            f.write(struct.pack("!IIII", ts_sec, ts_usec, len(frame), len(frame)))
            f.write(frame)

# ════════════════════════════════════════════════════════════
#  Packet builder helper
# ════════════════════════════════════════════════════════════

def build_ss7_map_packet(tcap_message, calling_gt, called_gt,
                          src_ip="10.0.0.1", dst_ip="10.0.0.2",
                          opc=9283, dpc=9444,
                          called_ssn=6, calling_ssn=147,
                          stream_seq=0):
    """Build complete Ethernet frame containing SS7/MAP message."""
    sccp = build_sccp_udt(called_gt, calling_gt, tcap_message,
                          called_ssn=called_ssn, calling_ssn=calling_ssn)
    m3ua = build_m3ua_data(opc, dpc, 3, sccp)
    sctp_chunk = build_sctp_data_chunk(m3ua, stream_seq=stream_seq)
    sctp = build_sctp_packet(2905, 2905, 0, sctp_chunk)
    ip = wrap_in_ip(sctp, src_ip, dst_ip, protocol=132)
    return wrap_ethernet(ip)

# ════════════════════════════════════════════════════════════
#  Attack scenario generators WITH RESPONSES
# ════════════════════════════════════════════════════════════

def generate_location_tracking_pcap():
    """
    ATK-001: Silent Location Tracking WITH RESPONSES
    
    Packet 1: SRI Invoke (MSISDN query)
    Packet 2: SRI Return Result (IMSI response) ← NEW
    Packet 3: PSI Invoke (location query with IMSI)
    Packet 4: PSI Return Result (Cell-ID response) ← NEW
    """
    target_msisdn = "447712345678"
    target_imsi = "234101234567890"
    attacker_gt = "491720000000"
    home_gt = "441234567890"
    
    packets = []
    base_time = 1700001000.0
    transaction_id = 0x00010001
    
    # Packet 1: SRI Invoke (attacker → home network)
    sri_invoke = build_map_sri_invoke(1, target_msisdn)
    tcap_begin = build_tcap_begin(transaction_id, sri_invoke)
    frame1 = build_ss7_map_packet(tcap_begin, attacker_gt, home_gt,
                                   src_ip="10.0.0.1", dst_ip="10.0.0.2",
                                   opc=100, dpc=200,
                                   calling_ssn=147, called_ssn=6,
                                   stream_seq=0)
    packets.append((base_time, frame1))
    
    # Packet 2: SRI Return Result (home network → attacker) - 0.5s later
    sri_response = build_map_sri_return_result(1, target_imsi)
    tcap_end = build_tcap_end(transaction_id, sri_response)
    frame2 = build_ss7_map_packet(tcap_end, home_gt, attacker_gt,
                                   src_ip="10.0.0.2", dst_ip="10.0.0.1",
                                   opc=200, dpc=100,
                                   calling_ssn=6, called_ssn=147,
                                   stream_seq=1)
    packets.append((base_time + 0.5, frame2))
    
    # Packet 3: PSI Invoke (attacker → home network) - 2.5s after response
    transaction_id2 = 0x00010002
    psi_invoke = build_map_psi_invoke(2, target_imsi)
    tcap_begin2 = build_tcap_begin(transaction_id2, psi_invoke)
    frame3 = build_ss7_map_packet(tcap_begin2, attacker_gt, home_gt,
                                   src_ip="10.0.0.1", dst_ip="10.0.0.2",
                                   opc=100, dpc=200,
                                   calling_ssn=147, called_ssn=6,
                                   stream_seq=2)
    packets.append((base_time + 3.0, frame3))
    
    # Packet 4: PSI Return Result (home network → attacker) - 0.3s later
    psi_response = build_map_psi_return_result(2, cell_id=0x1A2B, lac=0x5678)
    tcap_end2 = build_tcap_end(transaction_id2, psi_response)
    frame4 = build_ss7_map_packet(tcap_end2, home_gt, attacker_gt,
                                   src_ip="10.0.0.2", dst_ip="10.0.0.1",
                                   opc=200, dpc=100,
                                   calling_ssn=6, called_ssn=147,
                                   stream_seq=3)
    packets.append((base_time + 3.3, frame4))
    
    outfile = os.path.join(OUTPUT_DIR, "ss7_location_tracking.pcap")
    write_pcap(outfile, packets)
    print(f"[+] ATK-001 Location Tracking: {outfile}")
    print(f"    4 packets: SRI invoke/response + PSI invoke/response")
    print(f"    MSISDN={target_msisdn} → IMSI={target_imsi}")
    print(f"    Attacker GT: {attacker_gt}")
    return outfile

def generate_interception_setup_pcap():
    """
    ATK-002: Interception Setup WITH RESPONSES
    
    Packet 1: SRI Invoke
    Packet 2: SRI Return Result (IMSI)
    Packet 3: ISD Invoke (call forwarding)
    Packet 4: ISD Return Result (success)
    """
    target_msisdn = "447798765432"
    target_imsi = "234109876543210"
    attacker_gt = "491720000000"
    home_gt = "441234567890"
    attacker_msisdn = "491720000099"
    
    packets = []
    base_time = 1700002000.0
    
    # Packet 1: SRI Invoke
    transaction_id = 0x00020001
    sri_invoke = build_map_sri_invoke(1, target_msisdn)
    tcap_begin = build_tcap_begin(transaction_id, sri_invoke)
    frame1 = build_ss7_map_packet(tcap_begin, attacker_gt, home_gt,
                                   opc=100, dpc=200, stream_seq=0)
    packets.append((base_time, frame1))
    
    # Packet 2: SRI Return Result
    sri_response = build_map_sri_return_result(1, target_imsi)
    tcap_end = build_tcap_end(transaction_id, sri_response)
    frame2 = build_ss7_map_packet(tcap_end, home_gt, attacker_gt,
                                   opc=200, dpc=100, stream_seq=1)
    packets.append((base_time + 0.4, frame2))
    
    # Packet 3: ISD Invoke - 5s later
    transaction_id2 = 0x00020002
    isd_invoke = build_map_isd_invoke(2, target_imsi, attacker_msisdn)
    tcap_begin2 = build_tcap_begin(transaction_id2, isd_invoke)
    frame3 = build_ss7_map_packet(tcap_begin2, attacker_gt, home_gt,
                                   opc=100, dpc=200, stream_seq=2)
    packets.append((base_time + 5.0, frame3))
    
    # Packet 4: ISD Return Result
    isd_response = build_map_isd_return_result(2)
    tcap_end2 = build_tcap_end(transaction_id2, isd_response)
    frame4 = build_ss7_map_packet(tcap_end2, home_gt, attacker_gt,
                                   opc=200, dpc=100, stream_seq=3)
    packets.append((base_time + 5.3, frame4))
    
    outfile = os.path.join(OUTPUT_DIR, "ss7_interception_setup.pcap")
    write_pcap(outfile, packets)
    print(f"[+] ATK-002 Interception Setup: {outfile}")
    print(f"    4 packets: SRI + ISD with responses")
    print(f"    Target: IMSI={target_imsi}, Forward to: {attacker_msisdn}")
    return outfile

# ════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("SigCorr SS7/MAP Attack Pcap Generator (WITH RESPONSES)")
    print("=" * 60)
    print()
    
    f1 = generate_location_tracking_pcap()
    print()
    f2 = generate_interception_setup_pcap()
    print()
    
    print("Verify IMSI extraction:")
    print(f"  tshark -r {os.path.basename(f1)} -Y 'gsm_map' -T fields \\")
    print(f"    -e frame.number -e gsm_old.localValue -e gsm_map.imsi -e e164.msisdn")
    print()
    print("Test with SigCorr:")
    print(f"  java -jar target/sigcorr-0.1.0.jar analyze test-pcaps/{os.path.basename(f1)} --verbose")
