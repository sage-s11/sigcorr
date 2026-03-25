#!/usr/bin/env python3
"""
MAP PCAP Analyzer
Analyzes SS7/MAP pcaps to show what data is available for correlation.
Helps debug field extraction and validate pcap generation.
"""

import subprocess
import json
import sys
from collections import defaultdict
from datetime import datetime

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def run_tshark_ek(pcap_path, fields):
    """Extract fields using tshark -T ek"""
    cmd = ['tshark', '-r', pcap_path, '-Y', 'gsm_map', '-T', 'ek']
    for field in fields:
        cmd.extend(['-e', field])
    
    result = subprocess.run(cmd, capture_output=True, text=True, stderr=subprocess.DEVNULL)
    
    events = []
    for line in result.stdout.split('\n'):
        if line.strip() and not line.startswith('{"index"'):
            try:
                events.append(json.loads(line))
            except:
                pass
    
    return events

def analyze_map_pcap(pcap_path):
    """Comprehensive MAP pcap analysis"""
    
    print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}")
    print(f"{Colors.HEADER}MAP PCAP ANALYSIS{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}")
    print(f"PCAP: {pcap_path}\n")
    
    # Define field extraction sets
    fields_old = [
        'frame.time_epoch',
        'gsm_old.localValue',
        'gsm_old.opCode',
        'e212.imsi',              # OLD (broken)
        'gsm_map.msisdn',         # OLD (broken)
        'sccp.calling.digits',
        'sccp.called.digits'
    ]
    
    fields_new = [
        'frame.time_epoch',
        'gsm_old.localValue',
        'gsm_old.opCode',
        'gsm_map.imsi_digits',    # NEW (fixed)
        'gsm_map.msisdn_digits',  # NEW (fixed)
        'sccp.calling.digits',
        'sccp.called.digits'
    ]
    
    # Extract with both field sets
    print(f"{Colors.OKBLUE}Extracting with OLD field names...{Colors.ENDC}")
    events_old = run_tshark_ek(pcap_path, fields_old)
    
    print(f"{Colors.OKBLUE}Extracting with NEW field names...{Colors.ENDC}")
    events_new = run_tshark_ek(pcap_path, fields_new)
    
    print(f"\n{Colors.OKGREEN}✓ Extracted {len(events_new)} MAP events{Colors.ENDC}\n")
    
    # Analyze operation distribution
    print(f"{Colors.HEADER}OPERATION DISTRIBUTION{Colors.ENDC}")
    print("-" * 70)
    
    op_codes = {
        '22': 'SendRoutingInfo (SRI)',
        '71': 'ProvideSubscriberInfo (PSI)',
        '2': 'UpdateLocation',
        '7': 'InsertSubscriberData',
        '46': 'SendAuthenticationInfo'
    }
    
    op_counts = defaultdict(int)
    for event in events_new:
        layers = event.get('layers', {})
        op = layers.get('gsm_old_localValue', [None])[0] if 'gsm_old_localValue' in layers else None
        if op:
            op_counts[op] += 1
    
    for op_code, count in sorted(op_counts.items()):
        op_name = op_codes.get(op_code, f'Unknown ({op_code})')
        print(f"  {op_name:40s} {count:3d} packets")
    
    print()
    
    # Compare OLD vs NEW extraction
    print(f"{Colors.HEADER}FIELD EXTRACTION COMPARISON{Colors.ENDC}")
    print("-" * 70)
    
    def count_populated_fields(events, field_name):
        count = 0
        for event in events:
            layers = event.get('layers', {})
            json_key = field_name.replace('.', '_')
            if json_key in layers and layers[json_key]:
                count += 1
        return count
    
    print(f"\n{'Field':<30s} {'OLD':<15s} {'NEW':<15s} {'Status':<10s}")
    print("-" * 70)
    
    comparisons = [
        ('IMSI', 'e212_imsi', 'gsm_map_imsi_digits'),
        ('MSISDN', 'gsm_map_msisdn', 'gsm_map_msisdn_digits'),
        ('SCCP Calling', 'sccp_calling_digits', 'sccp_calling_digits'),
        ('SCCP Called', 'sccp_called_digits', 'sccp_called_digits'),
        ('Operation', 'gsm_old_localValue', 'gsm_old_localValue')
    ]
    
    for label, old_field, new_field in comparisons:
        old_count = count_populated_fields(events_old, old_field)
        new_count = count_populated_fields(events_new, new_field)
        
        if new_count > old_count:
            status = f"{Colors.OKGREEN}✓ FIXED{Colors.ENDC}"
        elif new_count == old_count and new_count > 0:
            status = f"{Colors.OKGREEN}✓ OK{Colors.ENDC}"
        elif new_count == 0 and old_count == 0:
            status = f"{Colors.WARNING}⚠ EMPTY{Colors.ENDC}"
        else:
            status = f"{Colors.FAIL}✗ BROKEN{Colors.ENDC}"
        
        print(f"{label:<30s} {old_count:>3d}/{len(events_old):<10d} {new_count:>3d}/{len(events_new):<10d} {status}")
    
    print()
    
    # Show sample events
    print(f"{Colors.HEADER}SAMPLE EVENTS (NEW EXTRACTION){Colors.ENDC}")
    print("-" * 70)
    
    for i, event in enumerate(events_new[:3], 1):
        layers = event.get('layers', {})
        
        timestamp = layers.get('frame_time_epoch', ['unknown'])[0]
        op_code = layers.get('gsm_old_localValue', ['?'])[0]
        op_name = op_codes.get(op_code, f'Op {op_code}')
        imsi = layers.get('gsm_map_imsi_digits', [None])[0]
        msisdn = layers.get('gsm_map_msisdn_digits', [None])[0]
        sccp_calling = layers.get('sccp_calling_digits', [None])[0]
        sccp_called = layers.get('sccp_called_digits', [None])[0]
        
        print(f"\n{Colors.OKCYAN}Event {i}: {op_name}{Colors.ENDC}")
        print(f"  Timestamp:     {timestamp}")
        print(f"  IMSI:          {imsi if imsi else '(not present)'}")
        print(f"  MSISDN:        {msisdn if msisdn else '(not present)'}")
        print(f"  SCCP Calling:  {sccp_calling if sccp_calling else '(not present)'}")
        print(f"  SCCP Called:   {sccp_called if sccp_called else '(not present)'}")
    
    print()
    
    # Correlation potential
    print(f"{Colors.HEADER}CORRELATION ANALYSIS{Colors.ENDC}")
    print("-" * 70)
    
    # Count events with identity fields
    imsi_count = count_populated_fields(events_new, 'gsm_map_imsi_digits')
    msisdn_count = count_populated_fields(events_new, 'gsm_map_msisdn_digits')
    
    print(f"Events with IMSI:   {imsi_count}/{len(events_new)}")
    print(f"Events with MSISDN: {msisdn_count}/{len(events_new)}")
    
    # Extract unique identities
    imsis = set()
    msisdns = set()
    for event in events_new:
        layers = event.get('layers', {})
        if 'gsm_map_imsi_digits' in layers:
            imsi = layers['gsm_map_imsi_digits'][0]
            if imsi:
                imsis.add(imsi)
        if 'gsm_map_msisdn_digits' in layers:
            msisdn = layers['gsm_map_msisdn_digits'][0]
            if msisdn:
                msisdns.add(msisdn)
    
    print(f"\nUnique subscribers:")
    print(f"  Distinct IMSIs:   {len(imsis)}")
    print(f"  Distinct MSISDNs: {len(msisdns)}")
    
    if imsis:
        print(f"\n  IMSIs: {', '.join(sorted(imsis))}")
    if msisdns:
        print(f"  MSISDNs: {', '.join(sorted(msisdns))}")
    
    print()
    
    # Attack pattern potential
    print(f"{Colors.HEADER}ATTACK PATTERN DETECTION POTENTIAL{Colors.ENDC}")
    print("-" * 70)
    
    # Check for SRI → PSI sequence (ATK-001: Location Tracking)
    sri_count = op_counts.get('22', 0)
    psi_count = op_counts.get('71', 0)
    
    print(f"\nATK-001: Silent Location Tracking")
    print(f"  SendRoutingInfo (SRI):         {sri_count} events")
    print(f"  ProvideSubscriberInfo (PSI):   {psi_count} events")
    
    if sri_count > 0 and psi_count > 0:
        print(f"  {Colors.OKGREEN}✓ Pattern detectable{Colors.ENDC}")
    else:
        print(f"  {Colors.WARNING}⚠ Insufficient events for pattern{Colors.ENDC}")
    
    print()
    
    # Summary
    print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}")
    print(f"{Colors.HEADER}SUMMARY{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}")
    
    if imsi_count > 0 or msisdn_count > 0:
        print(f"{Colors.OKGREEN}✓ Identity extraction: WORKING{Colors.ENDC}")
        print(f"{Colors.OKGREEN}✓ Ready for correlation engine{Colors.ENDC}")
    else:
        print(f"{Colors.FAIL}✗ Identity extraction: FAILED{Colors.ENDC}")
        print(f"{Colors.FAIL}✗ Cannot correlate without IMSI/MSISDN{Colors.ENDC}")
    
    if sri_count > 0 and psi_count > 0:
        print(f"{Colors.OKGREEN}✓ Attack patterns: DETECTABLE{Colors.ENDC}")
    else:
        print(f"{Colors.WARNING}⚠ Attack patterns: LIMITED{Colors.ENDC}")
    
    print()

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <pcap_file>")
        print(f"\nExample: {sys.argv[0]} test-pcaps/ss7_location_tracking.pcap")
        sys.exit(1)
    
    pcap_path = sys.argv[1]
    
    try:
        analyze_map_pcap(pcap_path)
    except FileNotFoundError:
        print(f"{Colors.FAIL}Error: tshark not found. Please install wireshark/tshark.{Colors.ENDC}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.FAIL}Error analyzing pcap: {e}{Colors.ENDC}")
        sys.exit(1)

if __name__ == '__main__':
    main()
