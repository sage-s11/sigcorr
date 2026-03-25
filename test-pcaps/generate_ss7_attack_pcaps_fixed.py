#!/usr/bin/env python3
"""
Fixed SS7/MAP Attack Pcap Generator - BER encoding corrected
"""

import struct
import os
import sys

# Copy the original file first
original = 'test-pcaps/generate_ss7_attack_pcaps.py'
if os.path.exists(original):
    with open(original, 'r') as f:
        original_content = f.read()
else:
    print("Error: Cannot find generate_ss7_attack_pcaps.py")
    sys.exit(1)

# Apply the fix: Change IMSI encoding from OCTET STRING to CONTEXT [0]
fixed_content = original_content.replace(
    'imsi_tlv = ber_tag_length(0x04, imsi_encoded)',
    'imsi_tlv = ber_tag_length(0x80, imsi_encoded)  # CONTEXT [0] IMPLICIT'
)

# Write fixed version
with open('test-pcaps/generate_ss7_fixed.py', 'w') as f:
    f.write(fixed_content)

print("[+] Created fixed generator: test-pcaps/generate_ss7_fixed.py")
print("[+] Changes:")
print("    - IMSI encoding: 0x04 → 0x80 (CONTEXT [0] IMPLICIT)")
print("\nRun: python3 test-pcaps/generate_ss7_fixed.py")
