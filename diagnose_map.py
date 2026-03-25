#!/usr/bin/env python3
"""
Diagnose SS7/MAP field extraction from tshark
Finds the correct field names for IMSI/MSISDN in MAP messages
"""

import subprocess
import json
import sys

def run_tshark(pcap_path, display_filter, fields):
    """Run tshark with specified fields and return parsed output"""
    cmd = [
        'tshark', '-r', pcap_path,
        '-Y', display_filter,
        '-T', 'ek',
    ]
    for field in fields:
        cmd.extend(['-e', field])
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        lines = [line for line in result.stdout.split('\n') if line.strip() and not line.startswith('{"index"')]
        return [json.loads(line) for line in lines if line.startswith('{')]
    except Exception as e:
        print(f"Error running tshark: {e}", file=sys.stderr)
        return []

def get_all_gsm_map_fields(pcap_path):
    """Get all gsm_map.* and e212.* fields from first packet"""
    cmd = [
        'tshark', '-r', pcap_path,
        '-Y', 'gsm_map',
        '-T', 'pdml',
        '-c', '1'  # Just first packet
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    fields = set()
    
    for line in result.stdout.split('\n'):
        if 'field name=' in line and ('gsm_map' in line or 'e212' in line or 'e164' in line):
            # Extract field name from: <field name="gsm_map.xxx" ...>
            start = line.find('name="') + 6
            end = line.find('"', start)
            if start > 5 and end > start:
                field_name = line[start:end]
                if field_name.startswith(('gsm_map', 'e212', 'e164')):
                    fields.add(field_name)
    
    return sorted(fields)

def main():
    # Check if pcap exists
    pcap_paths = [
        '/mnt/user-data/uploads/ss7_location_tracking.pcap',
        'test-pcaps/ss7_location_tracking.pcap',
        'ss7_location_tracking.pcap'
    ]
    
    pcap_path = None
    for path in pcap_paths:
        try:
            subprocess.run(['test', '-f', path], check=True, capture_output=True)
            pcap_path = path
            break
        except:
            continue
    
    if not pcap_path:
        print("ERROR: Cannot find ss7_location_tracking.pcap", file=sys.stderr)
        sys.exit(1)
    
    print("=== SS7/MAP Field Diagnostics ===\n")
    print(f"PCAP: {pcap_path}\n")
    
    # Step 1: Find all gsm_map/e212 fields
    print("STEP 1: Discovering all GSM MAP fields in pcap...")
    all_fields = get_all_gsm_map_fields(pcap_path)
    print(f"Found {len(all_fields)} unique fields:")
    for field in all_fields[:50]:  # Limit output
        print(f"  - {field}")
    if len(all_fields) > 50:
        print(f"  ... and {len(all_fields) - 50} more")
    print()
    
    # Step 2: Test specific extraction candidates
    print("STEP 2: Testing IMSI extraction candidates...")
    imsi_candidates = [
        'e212.imsi',
        'gsm_map.imsi',
        'gsm_map.imsi_digits', 
        'e212.imsi.digits',
        'gsm_old.imsi',
        'gsm_map.sm_rp_da.sm_rp_da_imsi_digits',
    ]
    
    for field in imsi_candidates:
        packets = run_tshark(pcap_path, 'gsm_map', [field])
        if packets and 'layers' in packets[0]:
            layers = packets[0]['layers']
            # Clean field name for JSON key
            json_key = field.replace('.', '_')
            if json_key in layers and layers[json_key]:
                print(f"  ✓ {field}: {layers[json_key]}")
            else:
                print(f"  ✗ {field}: (empty)")
        else:
            print(f"  ✗ {field}: (no data)")
    print()
    
    # Step 3: Test MSISDN extraction
    print("STEP 3: Testing MSISDN extraction candidates...")
    msisdn_candidates = [
        'gsm_map.msisdn',
        'gsm_map.msisdn_digits',
        'e164.msisdn',
        'gsm_old.msisdn',
        'gsm_map.sm_rp_oa.sm_rp_oa_msisdn_digits',
    ]
    
    for field in msisdn_candidates:
        packets = run_tshark(pcap_path, 'gsm_map', [field])
        if packets and 'layers' in packets[0]:
            layers = packets[0]['layers']
            json_key = field.replace('.', '_')
            if json_key in layers and layers[json_key]:
                print(f"  ✓ {field}: {layers[json_key]}")
            else:
                print(f"  ✗ {field}: (empty)")
        else:
            print(f"  ✗ {field}: (no data)")
    print()
    
    # Step 4: Show actual EK output with working fields
    print("STEP 4: Current EK output with known working fields...")
    packets = run_tshark(pcap_path, 'gsm_map', [
        'frame.time_epoch',
        'gsm_old.localValue',
        'gsm_old.opCode',
        'sccp.calling.digits',
        'sccp.called.digits'
    ])
    
    for i, pkt in enumerate(packets[:3], 1):
        print(f"Packet {i}:")
        if 'layers' in pkt:
            print(json.dumps(pkt['layers'], indent=2))
        print()

if __name__ == '__main__':
    main()
