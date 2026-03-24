#!/usr/bin/env python3
"""
Generate test pcap files with SS7/MAP, Diameter, and GTPv2-C traffic.
These are used to validate SigCorr's tshark bridge against real protocol data.
"""
from scapy.all import *
from scapy.contrib.diameter import *
from scapy.contrib.gtp_v2 import *
import struct, os

OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))

# ════════════════════════════════════════════════════════════
#  Diameter S6a — Authentication-Information-Request/Answer
# ════════════════════════════════════════════════════════════

def generate_diameter_pcap():
    """Generate Diameter S6a AIR + AIA messages."""
    pkts = []
    
    # AIR: Authentication-Information-Request (cmd=318, app=16777251)
    # We build raw Diameter since scapy's contrib may vary
    air = (
        IP(src="10.0.0.1", dst="10.0.0.2") /
        TCP(sport=3868, dport=3868) /
        DiamG(
            version=1,
            msg_len=0,  # Will be auto-calculated
            flags=0xC0,  # Request + Proxiable
            cmd_code=318,
            app_id=16777251,
            hop_by_hop_id=0x11111111,
            end_to_end_id=0x22222222,
            avp_list=[
                AVP(avpCode=263, avpFlags=0x40, avpData=DiameterString(val="session-001;10.0.0.1")),  # Session-Id
                AVP(avpCode=264, avpFlags=0x40, avpData=DiameterString(val="mme01.attacker.com")),  # Origin-Host
                AVP(avpCode=296, avpFlags=0x40, avpData=DiameterString(val="attacker.com")),  # Origin-Realm
                AVP(avpCode=283, avpFlags=0x40, avpData=DiameterString(val="home-network.com")),  # Destination-Realm
                AVP(avpCode=1, avpFlags=0x40, avpData=DiameterString(val="234101234567890")),  # User-Name (IMSI)
            ]
        )
    )
    pkts.append(air)

    # ULR: Update-Location-Request (cmd=316)
    ulr = (
        IP(src="10.0.0.1", dst="10.0.0.2") /
        TCP(sport=3868, dport=3868) /
        DiamG(
            version=1,
            msg_len=0,
            flags=0xC0,
            cmd_code=316,
            app_id=16777251,
            hop_by_hop_id=0x33333333,
            end_to_end_id=0x44444444,
            avp_list=[
                AVP(avpCode=263, avpFlags=0x40, avpData=DiameterString(val="session-002;10.0.0.1")),
                AVP(avpCode=264, avpFlags=0x40, avpData=DiameterString(val="mme01.attacker.com")),
                AVP(avpCode=296, avpFlags=0x40, avpData=DiameterString(val="attacker.com")),
                AVP(avpCode=283, avpFlags=0x40, avpData=DiameterString(val="home-network.com")),
                AVP(avpCode=1, avpFlags=0x40, avpData=DiameterString(val="234101234567890")),
            ]
        )
    )
    pkts.append(ulr)

    outfile = os.path.join(OUTPUT_DIR, "diameter_s6a_test.pcap")
    wrpcap(outfile, pkts)
    print(f"Written {len(pkts)} Diameter packets to {outfile}")
    return outfile


# ════════════════════════════════════════════════════════════
#  GTPv2-C — Create Session Request
# ════════════════════════════════════════════════════════════

def generate_gtpv2_pcap():
    """Generate GTPv2-C Create-Session-Request with IMSI."""
    pkts = []

    # IMSI 234101234567890 in TBCD: 32 14 10 32 54 76 98 F0
    imsi_tbcd = bytes([0x32, 0x14, 0x10, 0x32, 0x54, 0x76, 0x98, 0xF0])

    # Create Session Request (type=32)
    gtp_create = (
        IP(src="10.1.0.1", dst="10.1.0.2") /
        UDP(sport=2123, dport=2123) /
        GTPHeader(version=2, P=0, T=1, MP=0, TEID=0x00000001,
                  gtp_type=32, seq=1) /
        IE_IMSI(ietype=1, length=8, IMSI="234101234567890") /
        IE_MSISDN(ietype=76, length=6, digits="447712345678") /
        IE_APN(ietype=71, length=14, APN="internet.test") /
        IE_RATType(ietype=82, length=1, RAT_type=6)
    )
    pkts.append(gtp_create)

    # Create Session Response (type=33) 
    gtp_response = (
        IP(src="10.1.0.2", dst="10.1.0.1") /
        UDP(sport=2123, dport=2123) /
        GTPHeader(version=2, P=0, T=1, MP=0, TEID=0x00000002,
                  gtp_type=33, seq=1) /
        IE_Cause(ietype=2, length=2, Cause=16)  # Request Accepted
    )
    pkts.append(gtp_response)

    # Delete Session Request (type=36)
    gtp_delete = (
        IP(src="10.1.0.1", dst="10.1.0.2") /
        UDP(sport=2123, dport=2123) /
        GTPHeader(version=2, P=0, T=1, MP=0, TEID=0x00000001,
                  gtp_type=36, seq=2) /
        IE_IMSI(ietype=1, length=8, IMSI="234101234567890")
    )
    pkts.append(gtp_delete)

    outfile = os.path.join(OUTPUT_DIR, "gtpv2_test.pcap")
    wrpcap(outfile, pkts)
    print(f"Written {len(pkts)} GTPv2-C packets to {outfile}")
    return outfile


# ════════════════════════════════════════════════════════════
#  Main
# ════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("Generating test pcaps for SigCorr validation...\n")
    
    try:
        f1 = generate_diameter_pcap()
    except Exception as e:
        print(f"Diameter generation failed: {e}")
        f1 = None

    try:
        f2 = generate_gtpv2_pcap()
    except Exception as e:
        print(f"GTPv2 generation failed: {e}")
        f2 = None

    print("\nDone. Now verify with tshark:")
    if f1: print(f"  tshark -r {f1} -V | head -50")
    if f2: print(f"  tshark -r {f2} -V | head -50")
    print(f"\nThen test with SigCorr:")
    if f1: print(f"  java -jar target/sigcorr-0.1.0.jar analyze {f1} --verbose")
    if f2: print(f"  java -jar target/sigcorr-0.1.0.jar analyze {f2} --verbose")
