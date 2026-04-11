/*
 * SigCorr - Cross-Protocol Signaling Security Correlator
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * 5G Protocol Parser Extension (v0.2)
 *
 * Adds tshark-based parsing for:
 *   - 5G NAS (nas-5gs)  — UE ↔ AMF mobility/session management
 *   - NGAP (ngap)       — gNB ↔ AMF N2 interface
 *   - PFCP (pfcp)       — SMF ↔ UPF N4 session management
 *
 * INTEGRATION NOTE:
 *   Merge these parsing methods into your existing TsharkBridge.java.
 *   The tshark JSON field extraction follows the same pattern as
 *   existing SS7/MAP, Diameter, and GTPv2-C parsers.
 */
package io.sigcorr.ingest.tshark;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import io.sigcorr.core.model.ProtocolInterface;
import io.sigcorr.core.model.SignalingOperation;
import io.sigcorr.core.event.SignalingEvent;
import io.sigcorr.core.event.NetworkNode;
import io.sigcorr.core.identity.SubscriberIdentity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Parses 5G protocol events from pcap files using tshark JSON output.
 *
 * <p>Tshark fields extracted per protocol:
 * <ul>
 *   <li>5G NAS: nas_5gs.mm.message_type, nas_5gs.mm.5gs_mobile_id (SUPI/SUCI/5G-GUTI)</li>
 *   <li>NGAP: ngap.procedureCode, ngap.ran_ue_ngap_id, ngap.amf_ue_ngap_id</li>
 *   <li>PFCP: pfcp.msg_type, pfcp.seid (session endpoint identifier)</li>
 * </ul>
 */
public class TsharkBridge5G {

    private static final Logger log = LoggerFactory.getLogger(TsharkBridge5G.class);

    // ═══════════════════════════════════════════════════════════════
    // Tshark field names for 5G protocols
    // ═══════════════════════════════════════════════════════════════

    // 5G NAS fields
    private static final String NAS5G_MSG_TYPE = "nas_5gs.mm.message_type";
    private static final String NAS5G_SM_MSG_TYPE = "nas_5gs.sm.message_type";
    private static final String NAS5G_MOBILE_ID = "nas_5gs.mm.5gs_mobile_id";
    private static final String NAS5G_MOBILE_ID_TYPE = "nas_5gs.mm.type_id";
    private static final String NAS5G_SUPI = "nas_5gs.mm.supi";
    private static final String NAS5G_SUCI = "nas_5gs.mm.suci";
    private static final String NAS5G_5G_GUTI = "nas_5gs.mm.5g_guti";
    private static final String NAS5G_IMEI = "nas_5gs.mm.imeisv";
    private static final String NAS5G_SEC_ALGO_CIPHER = "nas_5gs.mm.nas_sec_algo_enc";
    private static final String NAS5G_SEC_ALGO_INTEG = "nas_5gs.mm.nas_sec_algo_ip";

    // NGAP fields
    private static final String NGAP_PROCEDURE_CODE = "ngap.procedureCode";
    private static final String NGAP_RAN_UE_ID = "ngap.RAN_UE_NGAP_ID";
    private static final String NGAP_AMF_UE_ID = "ngap.AMF_UE_NGAP_ID";
    private static final String NGAP_CAUSE = "ngap.Cause";
    private static final String NGAP_NAS_PDU = "ngap.NAS_PDU";
    private static final String NGAP_GLOBAL_GNB_ID = "ngap.GlobalGNB_ID";
    private static final String NGAP_TAC = "ngap.TAC";
    private static final String NGAP_HANDOVER_TYPE = "ngap.HandoverType";
    private static final String NGAP_TARGET_ID = "ngap.TargetID";

    // PFCP fields
    private static final String PFCP_MSG_TYPE = "pfcp.msg_type";
    private static final String PFCP_SEID = "pfcp.seid";
    private static final String PFCP_SEQ_NUM = "pfcp.seq_no";
    private static final String PFCP_NODE_ID = "pfcp.node_id_ipv4";
    private static final String PFCP_F_TEID = "pfcp.f_teid_ipv4";
    private static final String PFCP_UE_IP = "pfcp.ue_ip_addr_ipv4";
    private static final String PFCP_OUTER_HEADER = "pfcp.outer_hdr_desc";

    // Common
    private static final String FRAME_TIME = "frame.time_epoch";
    private static final String IP_SRC = "ip.src";
    private static final String IP_DST = "ip.dst";

    // ═══════════════════════════════════════════════════════════════
    // 5G NAS message type mappings (from 3GPP TS 24.501 Table 8.2.1)
    // ═══════════════════════════════════════════════════════════════

    private static final Map<String, SignalingOperation> NAS5G_MM_TYPE_MAP = new HashMap<>();
    static {
        // 5GMM (5GS Mobility Management) message types
        NAS5G_MM_TYPE_MAP.put("0x41", SignalingOperation.NAS_5G_REGISTRATION_REQUEST);
        NAS5G_MM_TYPE_MAP.put("0x42", SignalingOperation.NAS_5G_REGISTRATION_ACCEPT);
        NAS5G_MM_TYPE_MAP.put("0x43", SignalingOperation.NAS_5G_REGISTRATION_REJECT);
        NAS5G_MM_TYPE_MAP.put("0x44", SignalingOperation.NAS_5G_REGISTRATION_COMPLETE);
        NAS5G_MM_TYPE_MAP.put("0x45", SignalingOperation.NAS_5G_DEREGISTRATION_REQUEST_UE);
        NAS5G_MM_TYPE_MAP.put("0x46", SignalingOperation.NAS_5G_DEREGISTRATION_REQUEST_NW);
        NAS5G_MM_TYPE_MAP.put("0x47", SignalingOperation.NAS_5G_DEREGISTRATION_ACCEPT);
        NAS5G_MM_TYPE_MAP.put("0x56", SignalingOperation.NAS_5G_AUTH_REQUEST);
        NAS5G_MM_TYPE_MAP.put("0x57", SignalingOperation.NAS_5G_AUTH_RESPONSE);
        NAS5G_MM_TYPE_MAP.put("0x58", SignalingOperation.NAS_5G_AUTH_REJECT);
        NAS5G_MM_TYPE_MAP.put("0x59", SignalingOperation.NAS_5G_AUTH_FAILURE);
        NAS5G_MM_TYPE_MAP.put("0x5b", SignalingOperation.NAS_5G_IDENTITY_REQUEST);
        NAS5G_MM_TYPE_MAP.put("0x5c", SignalingOperation.NAS_5G_IDENTITY_RESPONSE);
        NAS5G_MM_TYPE_MAP.put("0x5d", SignalingOperation.NAS_5G_SECURITY_MODE_COMMAND);
        NAS5G_MM_TYPE_MAP.put("0x5e", SignalingOperation.NAS_5G_SECURITY_MODE_COMPLETE);
        NAS5G_MM_TYPE_MAP.put("0x5f", SignalingOperation.NAS_5G_SECURITY_MODE_REJECT);
        NAS5G_MM_TYPE_MAP.put("0x4c", SignalingOperation.NAS_5G_SERVICE_REQUEST);

        // Also accept decimal forms (tshark sometimes outputs these)
        NAS5G_MM_TYPE_MAP.put("65", SignalingOperation.NAS_5G_REGISTRATION_REQUEST);
        NAS5G_MM_TYPE_MAP.put("66", SignalingOperation.NAS_5G_REGISTRATION_ACCEPT);
        NAS5G_MM_TYPE_MAP.put("67", SignalingOperation.NAS_5G_REGISTRATION_REJECT);
        NAS5G_MM_TYPE_MAP.put("68", SignalingOperation.NAS_5G_REGISTRATION_COMPLETE);
        NAS5G_MM_TYPE_MAP.put("69", SignalingOperation.NAS_5G_DEREGISTRATION_REQUEST_UE);
        NAS5G_MM_TYPE_MAP.put("70", SignalingOperation.NAS_5G_DEREGISTRATION_REQUEST_NW);
        NAS5G_MM_TYPE_MAP.put("71", SignalingOperation.NAS_5G_DEREGISTRATION_ACCEPT);
        NAS5G_MM_TYPE_MAP.put("86", SignalingOperation.NAS_5G_AUTH_REQUEST);
        NAS5G_MM_TYPE_MAP.put("87", SignalingOperation.NAS_5G_AUTH_RESPONSE);
        NAS5G_MM_TYPE_MAP.put("88", SignalingOperation.NAS_5G_AUTH_REJECT);
        NAS5G_MM_TYPE_MAP.put("89", SignalingOperation.NAS_5G_AUTH_FAILURE);
        NAS5G_MM_TYPE_MAP.put("91", SignalingOperation.NAS_5G_IDENTITY_REQUEST);
        NAS5G_MM_TYPE_MAP.put("92", SignalingOperation.NAS_5G_IDENTITY_RESPONSE);
        NAS5G_MM_TYPE_MAP.put("93", SignalingOperation.NAS_5G_SECURITY_MODE_COMMAND);
        NAS5G_MM_TYPE_MAP.put("94", SignalingOperation.NAS_5G_SECURITY_MODE_COMPLETE);
        NAS5G_MM_TYPE_MAP.put("95", SignalingOperation.NAS_5G_SECURITY_MODE_REJECT);
        NAS5G_MM_TYPE_MAP.put("76", SignalingOperation.NAS_5G_SERVICE_REQUEST);
    }

    // 5GSM (5GS Session Management) message types
    private static final Map<String, SignalingOperation> NAS5G_SM_TYPE_MAP = new HashMap<>();
    static {
        NAS5G_SM_TYPE_MAP.put("0xc1", SignalingOperation.NAS_5G_PDU_SESSION_ESTABLISHMENT_REQ);
        NAS5G_SM_TYPE_MAP.put("0xc9", SignalingOperation.NAS_5G_PDU_SESSION_MODIFICATION_REQ);
        NAS5G_SM_TYPE_MAP.put("0xd1", SignalingOperation.NAS_5G_PDU_SESSION_RELEASE_REQUEST);
        // Decimal forms
        NAS5G_SM_TYPE_MAP.put("193", SignalingOperation.NAS_5G_PDU_SESSION_ESTABLISHMENT_REQ);
        NAS5G_SM_TYPE_MAP.put("201", SignalingOperation.NAS_5G_PDU_SESSION_MODIFICATION_REQ);
        NAS5G_SM_TYPE_MAP.put("209", SignalingOperation.NAS_5G_PDU_SESSION_RELEASE_REQUEST);
    }

    // ═══════════════════════════════════════════════════════════════
    // NGAP procedure code mappings (from 3GPP TS 38.413)
    // ═══════════════════════════════════════════════════════════════

    private static final Map<String, SignalingOperation> NGAP_PROC_MAP = new HashMap<>();
    static {
        NGAP_PROC_MAP.put("15", SignalingOperation.NGAP_INITIAL_UE_MESSAGE);
        NGAP_PROC_MAP.put("14", SignalingOperation.NGAP_INITIAL_CONTEXT_SETUP_REQ);
        NGAP_PROC_MAP.put("41", SignalingOperation.NGAP_UE_CONTEXT_RELEASE_COMMAND);
        NGAP_PROC_MAP.put("42", SignalingOperation.NGAP_UE_CONTEXT_RELEASE_REQUEST);
        NGAP_PROC_MAP.put("0", SignalingOperation.NGAP_HANDOVER_REQUIRED);
        NGAP_PROC_MAP.put("1", SignalingOperation.NGAP_HANDOVER_REQUEST);
        NGAP_PROC_MAP.put("3", SignalingOperation.NGAP_HANDOVER_NOTIFY);
        NGAP_PROC_MAP.put("12", SignalingOperation.NGAP_PATH_SWITCH_REQUEST);
        NGAP_PROC_MAP.put("21", SignalingOperation.NGAP_NG_SETUP_REQUEST);
        NGAP_PROC_MAP.put("25", SignalingOperation.NGAP_DOWNLINK_NAS_TRANSPORT);
        NGAP_PROC_MAP.put("46", SignalingOperation.NGAP_UPLINK_NAS_TRANSPORT);
        NGAP_PROC_MAP.put("5", SignalingOperation.NGAP_PAGING);
        NGAP_PROC_MAP.put("26", SignalingOperation.NGAP_PDU_SESSION_RESOURCE_SETUP_REQ);
        NGAP_PROC_MAP.put("27", SignalingOperation.NGAP_PDU_SESSION_RESOURCE_RELEASE_CMD);
        NGAP_PROC_MAP.put("28", SignalingOperation.NGAP_PDU_SESSION_RESOURCE_MODIFY_REQ);
    }

    // ═══════════════════════════════════════════════════════════════
    // PFCP message type mappings (from 3GPP TS 29.244)
    // ═══════════════════════════════════════════════════════════════

    private static final Map<String, SignalingOperation> PFCP_TYPE_MAP = new HashMap<>();
    static {
        PFCP_TYPE_MAP.put("1", SignalingOperation.PFCP_HEARTBEAT_REQ);
        PFCP_TYPE_MAP.put("2", SignalingOperation.PFCP_HEARTBEAT_RSP);
        PFCP_TYPE_MAP.put("5", SignalingOperation.PFCP_ASSOCIATION_SETUP_REQ);
        PFCP_TYPE_MAP.put("6", SignalingOperation.PFCP_ASSOCIATION_SETUP_RSP);
        PFCP_TYPE_MAP.put("50", SignalingOperation.PFCP_SESSION_ESTABLISHMENT_REQ);
        PFCP_TYPE_MAP.put("51", SignalingOperation.PFCP_SESSION_ESTABLISHMENT_RSP);
        PFCP_TYPE_MAP.put("52", SignalingOperation.PFCP_SESSION_MODIFICATION_REQ);
        PFCP_TYPE_MAP.put("53", SignalingOperation.PFCP_SESSION_MODIFICATION_RSP);
        PFCP_TYPE_MAP.put("54", SignalingOperation.PFCP_SESSION_DELETION_REQ);
        PFCP_TYPE_MAP.put("55", SignalingOperation.PFCP_SESSION_DELETION_RSP);
        PFCP_TYPE_MAP.put("56", SignalingOperation.PFCP_SESSION_REPORT_REQ);
        PFCP_TYPE_MAP.put("57", SignalingOperation.PFCP_SESSION_REPORT_RSP);
    }

    // ═══════════════════════════════════════════════════════════════
    // Tshark invocation — 5G protocol field extraction
    // ═══════════════════════════════════════════════════════════════

    /**
     * Build the tshark command for extracting 5G protocol fields from a pcap.
     *
     * @param pcapPath path to the pcap file
     * @param tsharkPath path to tshark binary (default: /usr/bin/tshark)
     * @return full command as string list
     */
    public static List<String> buildTsharkCommand(Path pcapPath, String tsharkPath) {
        // Combined display filter: any 5G protocol
        String displayFilter = "nas-5gs || ngap || pfcp";

        // Fields to extract (superset for all three protocols)
        List<String> fields = List.of(
            FRAME_TIME, IP_SRC, IP_DST,
            // 5G NAS
            NAS5G_MSG_TYPE, NAS5G_SM_MSG_TYPE, NAS5G_MOBILE_ID,
            NAS5G_MOBILE_ID_TYPE, NAS5G_SUPI, NAS5G_SUCI, NAS5G_5G_GUTI,
            NAS5G_SEC_ALGO_CIPHER, NAS5G_SEC_ALGO_INTEG,
            // NGAP
            NGAP_PROCEDURE_CODE, NGAP_RAN_UE_ID, NGAP_AMF_UE_ID,
            NGAP_CAUSE, NGAP_GLOBAL_GNB_ID, NGAP_TAC,
            NGAP_HANDOVER_TYPE, NGAP_TARGET_ID,
            // PFCP
            PFCP_MSG_TYPE, PFCP_SEID, PFCP_SEQ_NUM,
            PFCP_NODE_ID, PFCP_F_TEID, PFCP_UE_IP
        );

        List<String> cmd = new ArrayList<>();
        cmd.add(tsharkPath != null ? tsharkPath : "tshark");
        cmd.add("-r");
        cmd.add(pcapPath.toString());
        cmd.add("-Y");
        cmd.add(displayFilter);
        cmd.add("-T");
        cmd.add("json");

        // Add field extraction flags
        for (String field : fields) {
            cmd.add("-e");
            cmd.add(field);
        }

        return cmd;
    }

    /**
     * Parse a single tshark JSON packet object into a SignalingEvent.
     * Determines the protocol type and extracts relevant fields.
     *
     * @param packetLayers the "_source.layers" JSON object from tshark output
     * @return parsed SignalingEvent, or empty if packet is not a recognized 5G operation
     */
    public static Optional<SignalingEvent> parsePacket(JsonObject packetLayers) {
        // Try each protocol in priority order
        // 5G NAS first (most specific), then NGAP, then PFCP

        Optional<SignalingEvent> event = tryParse5gNas(packetLayers);
        if (event.isPresent()) return event;

        event = tryParseNgap(packetLayers);
        if (event.isPresent()) return event;

        event = tryParsePfcp(packetLayers);
        return event;
    }

    // ── 5G NAS parsing ────────────────────────────────────────────

    private static Optional<SignalingEvent> tryParse5gNas(JsonObject layers) {
        // Check for 5GMM (Mobility Management) message
        String mmType = extractField(layers, NAS5G_MSG_TYPE);
        String smType = extractField(layers, NAS5G_SM_MSG_TYPE);

        SignalingOperation operation = null;

        if (mmType != null) {
            operation = NAS5G_MM_TYPE_MAP.get(mmType.toLowerCase());
        }
        if (operation == null && smType != null) {
            operation = NAS5G_SM_TYPE_MAP.get(smType.toLowerCase());
        }

        if (operation == null) return Optional.empty();

        // Extract subscriber identity
        String subscriberId = extractNas5gIdentity(layers);
        String timestamp = extractField(layers, FRAME_TIME);
        String srcIp = extractField(layers, IP_SRC);
        String dstIp = extractField(layers, IP_DST);

        // Extract security algorithm info (for SecurityModeCommand detection)
        Map<String, String> metadata = new HashMap<>();
        String cipherAlgo = extractField(layers, NAS5G_SEC_ALGO_CIPHER);
        String integAlgo = extractField(layers, NAS5G_SEC_ALGO_INTEG);
        if (cipherAlgo != null) metadata.put("cipher_algo", cipherAlgo);
        if (integAlgo != null) metadata.put("integrity_algo", integAlgo);

        SignalingEvent event = buildEvent(
            ProtocolInterface.FIVEG_NAS,
            operation,
            subscriberId,
            parseTimestamp(timestamp),
            srcIp,
            dstIp,
            metadata
        );

        return Optional.of(event);
    }

    /**
     * Extract the best available 5G subscriber identity from NAS fields.
     * Priority: SUPI > SUCI > 5G-GUTI > mobile_id
     */
    private static String extractNas5gIdentity(JsonObject layers) {
        String supi = extractField(layers, NAS5G_SUPI);
        if (supi != null && !supi.isBlank()) return supi;

        String suci = extractField(layers, NAS5G_SUCI);
        if (suci != null && !suci.isBlank()) return suci;

        String guti = extractField(layers, NAS5G_5G_GUTI);
        if (guti != null && !guti.isBlank()) return guti;

        String mobileId = extractField(layers, NAS5G_MOBILE_ID);
        if (mobileId != null && !mobileId.isBlank()) return mobileId;

        return null;
    }

    // ── NGAP parsing ──────────────────────────────────────────────

    private static Optional<SignalingEvent> tryParseNgap(JsonObject layers) {
        String procCode = extractField(layers, NGAP_PROCEDURE_CODE);
        if (procCode == null) return Optional.empty();

        SignalingOperation operation = NGAP_PROC_MAP.get(procCode);
        if (operation == null) return Optional.empty();

        String timestamp = extractField(layers, FRAME_TIME);
        String srcIp = extractField(layers, IP_SRC);
        String dstIp = extractField(layers, IP_DST);

        // NGAP doesn't directly carry subscriber identity — it uses
        // RAN-UE-NGAP-ID / AMF-UE-NGAP-ID as session identifiers.
        // The actual SUPI/IMSI is in the embedded NAS PDU.
        String ranUeId = extractField(layers, NGAP_RAN_UE_ID);
        String amfUeId = extractField(layers, NGAP_AMF_UE_ID);

        // Use AMF-UE-NGAP-ID as the correlation key for NGAP
        // (AMF assigns this and it's stable for the UE context)
        String subscriberId = amfUeId != null ? "ngap-amf-" + amfUeId : null;

        Map<String, String> metadata = new HashMap<>();
        if (ranUeId != null) metadata.put("ran_ue_ngap_id", ranUeId);
        if (amfUeId != null) metadata.put("amf_ue_ngap_id", amfUeId);
        String gnbId = extractField(layers, NGAP_GLOBAL_GNB_ID);
        if (gnbId != null) metadata.put("gnb_id", gnbId);
        String tac = extractField(layers, NGAP_TAC);
        if (tac != null) metadata.put("tac", tac);
        String handoverType = extractField(layers, NGAP_HANDOVER_TYPE);
        if (handoverType != null) metadata.put("handover_type", handoverType);
        String targetId = extractField(layers, NGAP_TARGET_ID);
        if (targetId != null) metadata.put("target_id", targetId);
        String cause = extractField(layers, NGAP_CAUSE);
        if (cause != null) metadata.put("cause", cause);

        SignalingEvent event = buildEvent(
            ProtocolInterface.NGAP,
            operation,
            subscriberId,
            parseTimestamp(timestamp),
            srcIp,
            dstIp,
            metadata
        );

        return Optional.of(event);
    }

    // ── PFCP parsing ──────────────────────────────────────────────

    private static Optional<SignalingEvent> tryParsePfcp(JsonObject layers) {
        String msgType = extractField(layers, PFCP_MSG_TYPE);
        if (msgType == null) return Optional.empty();

        SignalingOperation operation = PFCP_TYPE_MAP.get(msgType);
        if (operation == null) return Optional.empty();

        String timestamp = extractField(layers, FRAME_TIME);
        String srcIp = extractField(layers, IP_SRC);
        String dstIp = extractField(layers, IP_DST);

        // PFCP uses SEID (Session Endpoint Identifier) as the session key
        String seid = extractField(layers, PFCP_SEID);
        String subscriberId = seid != null ? "pfcp-seid-" + seid : null;

        Map<String, String> metadata = new HashMap<>();
        if (seid != null) metadata.put("seid", seid);
        String nodeId = extractField(layers, PFCP_NODE_ID);
        if (nodeId != null) metadata.put("node_id", nodeId);
        String fTeid = extractField(layers, PFCP_F_TEID);
        if (fTeid != null) metadata.put("f_teid", fTeid);
        String ueIp = extractField(layers, PFCP_UE_IP);
        if (ueIp != null) metadata.put("ue_ip", ueIp);
        String seqNum = extractField(layers, PFCP_SEQ_NUM);
        if (seqNum != null) metadata.put("seq_num", seqNum);

        SignalingEvent event = buildEvent(
            ProtocolInterface.PFCP,
            operation,
            subscriberId,
            parseTimestamp(timestamp),
            srcIp,
            dstIp,
            metadata
        );

        return Optional.of(event);
    }

    
    /**
     * Build a SignalingEvent using the existing builder pattern.
     */
    private static SignalingEvent buildEvent(
            ProtocolInterface protocol, SignalingOperation operation,
            String subscriberId, Instant timestamp,
            String srcIp, String dstIp,
            Map<String, String> metadata) {

        SubscriberIdentity sub;
        if (subscriberId != null && subscriberId.matches("\\d{14,15}")) {
            sub = SubscriberIdentity.fromImsi(subscriberId);
        } else if (subscriberId != null && subscriberId.matches("\\d{7,15}")) {
            sub = SubscriberIdentity.fromMsisdn(subscriberId);
        } else if (subscriberId != null) {
            String stripped = subscriberId.toLowerCase().startsWith("imsi-")
                ? subscriberId.substring(5) : null;
            if (stripped != null && stripped.matches("\\d{14,15}")) {
                sub = SubscriberIdentity.fromImsi(stripped);
            } else {
                sub = SubscriberIdentity.fromImsi(subscriberId);
            }
        } else {
            sub = SubscriberIdentity.fromImsi("000000000000000");
        }

        SignalingEvent.Builder builder = SignalingEvent.builder()
            .timestamp(timestamp != null ? timestamp : Instant.now())
            .protocolInterface(protocol)
            .operation(operation)
            .subscriber(sub);

        if (metadata != null) builder.parameters(metadata);
        if (srcIp != null) builder.sourceNode(new NetworkNode(NetworkNode.NodeType.IP_ADDRESS, srcIp));
        if (dstIp != null) builder.destinationNode(new NetworkNode(NetworkNode.NodeType.IP_ADDRESS, dstIp));

        return builder.build();
    }

    // ── Utility methods ───────────────────────────────────────────

    /**
     * Extract a field value from tshark JSON layers.
     * Handles both direct string values and single-element arrays.
     */
    private static String extractField(JsonObject layers, String fieldName) {
        JsonElement element = layers.get(fieldName);
        if (element == null) return null;

        if (element.isJsonArray()) {
            JsonArray arr = element.getAsJsonArray();
            if (arr.size() > 0 && !arr.get(0).isJsonNull()) {
                return arr.get(0).getAsString();
            }
            return null;
        }

        if (element.isJsonPrimitive()) {
            return element.getAsString();
        }

        return null;
    }

    /**
     * Parse epoch timestamp string from tshark output.
     */
    private static Instant parseTimestamp(String epochStr) {
        if (epochStr == null) return Instant.now();
        try {
            double epoch = Double.parseDouble(epochStr);
            long seconds = (long) epoch;
            long nanos = (long) ((epoch - seconds) * 1_000_000_000);
            return Instant.ofEpochSecond(seconds, nanos);
        } catch (NumberFormatException e) {
            return Instant.now();
        }
    }
}
