/**
 * TSHARKBRIDGE.JAVA - SS7/MAP FIELD EXTRACTION FIX
 * 
 * This patch fixes IMSI/MSISDN extraction from SS7/MAP pcaps.
 * 
 * ROOT CAUSE: Using protocol-specific fields (e212.imsi, gsm_map.msisdn)
 * which don't work with tshark -T ek for MAP operations.
 * 
 * SOLUTION: Use Wireshark display filter convenience fields:
 *   - gsm_map.imsi_digits (works across all MAP operations)
 *   - gsm_map.msisdn_digits (works across all MAP operations)
 */

// ============================================================================
// SECTION 1: Update Field Extraction Array
// ============================================================================

// FIND THIS in TsharkBridge.java (around line 40-50):
private static final String[] TSHARK_FIELDS = {
    "frame.time_epoch",
    "gsm_old.localValue",
    "gsm_old.opCode",
    "e212.imsi",              // ← BROKEN: doesn't extract from MAP operations
    "gsm_map.msisdn",         // ← BROKEN: doesn't extract from MAP operations
    "sccp.calling.digits",
    "sccp.called.digits",
    // Diameter fields...
    "diameter.cmd.code",
    // GTP fields...
    "gtpv2.message_type"
};

// REPLACE WITH:
private static final String[] TSHARK_FIELDS = {
    "frame.time_epoch",
    "gsm_old.localValue",
    "gsm_old.opCode",
    "gsm_map.imsi_digits",    // ✓ FIXED: works across all MAP operations
    "gsm_map.msisdn_digits",  // ✓ FIXED: works across all MAP operations
    "sccp.calling.digits",
    "sccp.called.digits",
    // Diameter fields...
    "diameter.cmd.code",
    "diameter.Session-Id",
    "diameter.User-Name",
    "diameter.Origin-Host",
    "diameter.Destination-Host",
    // GTP fields...
    "gtpv2.message_type",
    "gtpv2.imsi",
    "gtpv2.msisdn",
    "gtpv2.bearer_context"
};

// ============================================================================
// SECTION 2: Update parseEvent() Method
// ============================================================================

// FIND THIS in parseEvent() method (around line 150-200):
private SignalingEvent parseEvent(JsonNode eventJson) {
    JsonNode layers = eventJson.get("layers");
    if (layers == null) return null;
    
    // Extract common fields
    String timestamp = getField(layers, "frame_time_epoch");
    
    // Extract SS7/MAP fields
    String imsi = getField(layers, "e212_imsi");           // ← BROKEN
    String msisdn = getField(layers, "gsm_map_msisdn");    // ← BROKEN
    String sccpCalling = getField(layers, "sccp_calling_digits");
    String sccpCalled = getField(layers, "sccp_called_digits");
    String mapOperation = getField(layers, "gsm_old_localValue");
    
    // Extract Diameter fields
    String diameterCmd = getField(layers, "diameter_cmd_code");
    // ...
}

// REPLACE WITH:
private SignalingEvent parseEvent(JsonNode eventJson) {
    JsonNode layers = eventJson.get("layers");
    if (layers == null) return null;
    
    // Extract timestamp
    String timestamp = getField(layers, "frame_time_epoch");
    
    // Extract SS7/MAP fields (FIXED field names)
    String imsi = getField(layers, "gsm_map_imsi_digits");     // ✓ FIXED
    String msisdn = getField(layers, "gsm_map_msisdn_digits"); // ✓ FIXED
    String sccpCalling = getField(layers, "sccp_calling_digits");
    String sccpCalled = getField(layers, "sccp_called_digits");
    String mapOperation = getField(layers, "gsm_old_localValue");
    String mapOpCode = getField(layers, "gsm_old_opCode");
    
    // Extract Diameter fields
    String diameterCmd = getField(layers, "diameter_cmd_code");
    String sessionId = getField(layers, "diameter_Session_Id");
    String username = getField(layers, "diameter_User_Name");
    String originHost = getField(layers, "diameter_Origin_Host");
    String destHost = getField(layers, "diameter_Destination_Host");
    
    // Extract GTP fields
    String gtpMsgType = getField(layers, "gtpv2_message_type");
    String gtpImsi = getField(layers, "gtpv2_imsi");
    String gtpMsisdn = getField(layers, "gtpv2_msisdn");
    
    // Determine protocol and build event
    // ... rest of method stays the same
}

// ============================================================================
// SECTION 3: Enhanced getField() Helper (Optional but Recommended)
// ============================================================================

// CURRENT getField() (around line 300):
private String getField(JsonNode layers, String fieldName) {
    JsonNode field = layers.get(fieldName);
    if (field == null || field.isNull()) return null;
    if (field.isArray() && field.size() > 0) {
        return field.get(0).asText();
    }
    return field.asText();
}

// ENHANCED VERSION (handles multiple array formats):
private String getField(JsonNode layers, String fieldName) {
    JsonNode field = layers.get(fieldName);
    if (field == null || field.isNull()) return null;
    
    // tshark -T ek can return:
    // 1. String: "value"
    // 2. Array: ["value"]  
    // 3. Array: ["value1", "value2"] ← take first
    if (field.isArray()) {
        if (field.size() == 0) return null;
        JsonNode first = field.get(0);
        return first != null && !first.isNull() ? first.asText() : null;
    }
    
    return field.asText();
}

// ============================================================================
// SECTION 4: Testing the Fix
// ============================================================================

/*
VALIDATION COMMANDS:

1. Test tshark extraction directly:
   tshark -r test-pcaps/ss7_location_tracking.pcap \
     -Y "gsm_map" -T ek \
     -e frame.time_epoch \
     -e gsm_old.localValue \
     -e gsm_map.imsi_digits \
     -e gsm_map.msisdn_digits \
     -e sccp.calling.digits \
     -e sccp.called.digits

   Expected: You should see gsm_map_imsi_digits and gsm_map_msisdn_digits
   populated in the JSON output

2. Rebuild SigCorr:
   mvn clean compile test

3. Run against MAP pcap:
   java -jar target/sigcorr-0.1.0.jar analyze test-pcaps/ss7_location_tracking.pcap --verbose

4. Expected output:
   [INFO] Parsed 4 events from pcap
   [INFO] Events: 2x MAP_SEND_ROUTING_INFO, 2x MAP_PROVIDE_SUBSCRIBER_INFO
   [ALERT] ATK-001: Silent Location Tracking
   [ALERT]   Subscriber: IMSI:234101234567890
   [ALERT]   Pattern: SRI → PSI within 30s
   [ALERT]   Confidence: 95%
*/

// ============================================================================
// ADDITIONAL NOTES
// ============================================================================

/*
WHY THIS FIX WORKS:
------------------
1. gsm_map.imsi_digits is a Wireshark DISPLAY FILTER field that extracts
   IMSI from ANY MAP operation that contains it (SRI response, PSI request,
   InsertSubscriberData, etc.)

2. gsm_map.msisdn_digits similarly extracts MSISDN from any operation

3. These are NOT protocol fields (gsm_map.sendRoutingInfo.msisdn) but 
   convenience fields that Wireshark's dissector populates automatically

4. tshark -T ek can extract these display filter fields just like protocol
   fields, and they appear in the JSON with dots→underscores conversion

FIELD NAME REFERENCE:
--------------------
Tshark Field               → JSON Key in EK Output
-------------------          ----------------------
gsm_map.imsi_digits       → gsm_map_imsi_digits
gsm_map.msisdn_digits     → gsm_map_msisdn_digits  
sccp.calling.digits       → sccp_calling_digits
sccp.called.digits        → sccp_called_digits
gsm_old.localValue        → gsm_old_localValue
gsm_old.opCode            → gsm_old_opCode

CROSS-PROTOCOL CORRELATION:
--------------------------
Once MAP extraction works, you can correlate:
  1. MAP SendRoutingInfo → learns IMSI from MSISDN
  2. Diameter AIR → queries same IMSI  
  3. GTP CreateSession → same IMSI establishes data session

All three events will share correlation key "IMSI:234101234567890"
enabling ATK-009 (Cross-Protocol Reconnaissance) detection.
*/
