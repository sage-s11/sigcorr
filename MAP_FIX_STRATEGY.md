SS7/MAP Field Extraction Fix Strategy
======================================

PROBLEM ANALYSIS
----------------
From your tshark -T ek output:
```
{"timestamp":"1700001000000","layers":{
  "frame_time_epoch":["1700001000.000000000"],
  "gsm_old_localValue":["22"],  ← SendRoutingInfo (SRI)
  "gsm_old_opCode":["0"],
  "sccp_calling_digits":["491720000000"],
  "sccp_called_digits":["441234567890"]
}}
```

Key observations:
1. SCCP addresses (calling/called digits) ARE extracted ✓
2. Operation codes (localValue=22 for SRI, 71 for PSI) ARE extracted ✓  
3. IMSI/MSISDN fields are MISSING ✗

ROOT CAUSE
----------
SS7/MAP operations encode IMSI/MSISDN as OPERATION-SPECIFIC PARAMETERS.
Tshark exposes these with operation-specific field names:

SendRoutingInfo (op=22):
  - Input: gsm_map.msisdn (the target MSISDN being queried)
  - Output: gsm_map.imsi (the resolved IMSI in response)

ProvideSubscriberInfo (op=71):
  - Input: gsm_map.imsi (the target IMSI being queried)
  - Output: location data (cell-id, etc.)

SOLUTION OPTIONS
----------------

Option 1: Use Wireshark Display Filter Fields (RECOMMENDED)
- Wireshark has "convenience fields" that work across operations
- Field: gsm_map.imsi_digits extracts IMSI from ANY operation that carries it
- Field: gsm_map.msisdn_digits extracts MSISDN from ANY operation
- These are DISPLAY FILTER fields, not protocol fields

Option 2: Extract from PDML then Convert to JSON
- Use tshark -T pdml to get XML with full nested structure
- Parse XML to extract operation-specific parameters
- More complex but gives access to ALL fields

Option 3: Operation-Specific Field Mapping
- Map gsm_old.localValue → expected parameter field names
- SendRoutingInfo (22) → extract gsm_map.sendRoutingInfo.msisdn
- ProvideSubscriberInfo (71) → extract gsm_map.provideSubscriberInfo.imsi
- Requires maintaining operation→field mappings

RECOMMENDED FIX
---------------
Use Option 1 with these field names in tshark -T ek extraction:

Current (broken):
  -e e212.imsi 
  -e gsm_map.msisdn

Fixed (working):
  -e gsm_map.imsi_digits     ← Works across all MAP operations
  -e gsm_map.msisdn_digits   ← Works across all MAP operations

VERIFICATION TEST
-----------------
Run this to test if the fix works:

tshark -r test-pcaps/ss7_location_tracking.pcap \
  -Y "gsm_map" \
  -T ek \
  -e frame.time_epoch \
  -e gsm_old.localValue \
  -e gsm_map.imsi_digits \
  -e gsm_map.msisdn_digits \
  -e sccp.calling.digits \
  -e sccp.called.digits

Expected output:
{"timestamp":"...","layers":{
  "frame_time_epoch":["1700001000.000000000"],
  "gsm_old_localValue":["22"],
  "gsm_map_msisdn_digits":["447712345678"],  ← NOW EXTRACTED
  "sccp_calling_digits":["491720000000"],
  "sccp_called_digits":["441234567890"]
}}

TSHARKBRIDGE.JAVA FIX
---------------------
Update the field extraction list in TsharkBridge.java:

OLD:
  private static final String[] TSHARK_FIELDS = {
      "frame.time_epoch",
      "gsm_old.localValue",
      "gsm_old.opCode", 
      "e212.imsi",              ← REMOVE (doesn't work)
      "gsm_map.msisdn",         ← REMOVE (doesn't work)
      "sccp.calling.digits",
      "sccp.called.digits"
  };

NEW:
  private static final String[] TSHARK_FIELDS = {
      "frame.time_epoch",
      "gsm_old.localValue",
      "gsm_old.opCode",
      "gsm_map.imsi_digits",    ← ADD (works across ops)
      "gsm_map.msisdn_digits",  ← ADD (works across ops)  
      "sccp.calling.digits",
      "sccp.called.digits"
  };

JSON KEY MAPPING
----------------
Tshark converts field names to JSON keys by replacing dots with underscores:
  gsm_map.imsi_digits → gsm_map_imsi_digits
  gsm_map.msisdn_digits → gsm_map_msisdn_digits

Update parseEvent() to read these keys:
  String imsi = getField(layers, "gsm_map_imsi_digits");
  String msisdn = getField(layers, "gsm_map_msisdn_digits");

IMPLEMENTATION CHECKLIST
------------------------
[ ] Update TSHARK_FIELDS array with _digits field names
[ ] Update parseEvent() to read new JSON keys
[ ] Run mvn test to verify existing tests still pass
[ ] Generate fresh MAP pcaps if needed
[ ] Test end-to-end: pcap → tshark → bridge → events → alerts
[ ] Validate ATK-001 (Location Tracking) fires on MAP pcaps
