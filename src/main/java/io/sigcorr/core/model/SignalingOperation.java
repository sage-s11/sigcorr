package io.sigcorr.core.model;

/**
 * Enumeration of all signaling operations tracked by SigCorr.
 *
 * Each operation maps to a specific protocol message that may be part
 * of an attack chain. Operations are grouped by protocol interface.
 *
 * Operation codes reference:
 * - MAP: 3GPP TS 29.002 (MAP operation codes)
 * - Diameter: 3GPP TS 29.272 (S6a/S6d command codes)
 * - GTPv2-C: 3GPP TS 29.274 (GTPv2-C message types)
 */
public enum SignalingOperation {

    // === SS7 MAP Operations (3GPP TS 29.002) ===

    /** MAP opcode 22 - Returns IMSI and routing info for a given MSISDN */
    MAP_SEND_ROUTING_INFO(ProtocolInterface.SS7_MAP, 22,
            "SendRoutingInfo", OperationCategory.RECONNAISSANCE),

    /** MAP opcode 70 - Returns IMSI for a given MSISDN (packet domain) */
    MAP_SEND_ROUTING_INFO_GPRS(ProtocolInterface.SS7_MAP, 70,
            "SendRoutingInfoForGprs", OperationCategory.RECONNAISSANCE),

    /** MAP opcode 71 - Returns subscriber location (Cell-ID/LAC) */
    MAP_PROVIDE_SUBSCRIBER_INFO(ProtocolInterface.SS7_MAP, 71,
            "ProvideSubscriberInfo", OperationCategory.TRACKING),

    /** MAP opcode 83 - Returns subscriber location (LCS) */
    MAP_PROVIDE_SUBSCRIBER_LOCATION(ProtocolInterface.SS7_MAP, 83,
            "ProvideSubscriberLocation", OperationCategory.TRACKING),

    /** MAP opcode 7 - Modifies subscriber profile in HLR */
    MAP_INSERT_SUBSCRIBER_DATA(ProtocolInterface.SS7_MAP, 7,
            "InsertSubscriberData", OperationCategory.MANIPULATION),

    /** MAP opcode 8 - Deletes subscriber data from HLR */
    MAP_DELETE_SUBSCRIBER_DATA(ProtocolInterface.SS7_MAP, 8,
            "DeleteSubscriberData", OperationCategory.MANIPULATION),

    /** MAP opcode 2 - Updates subscriber location in HLR */
    MAP_UPDATE_LOCATION(ProtocolInterface.SS7_MAP, 2,
            "UpdateLocation", OperationCategory.MANIPULATION),

    /** MAP opcode 3 - Cancels subscriber location in VLR */
    MAP_CANCEL_LOCATION(ProtocolInterface.SS7_MAP, 3,
            "CancelLocation", OperationCategory.MANIPULATION),

    /** MAP opcode 56 - Retrieves authentication vectors from HLR */
    MAP_SEND_AUTH_INFO(ProtocolInterface.SS7_MAP, 56,
            "SendAuthenticationInfo", OperationCategory.INTERCEPTION),

    /** MAP opcode 10 - Registers call forwarding (SS registration) */
    MAP_REGISTER_SS(ProtocolInterface.SS7_MAP, 10,
            "RegisterSS", OperationCategory.INTERCEPTION),

    /** MAP opcode 12 - Activates supplementary service */
    MAP_ACTIVATE_SS(ProtocolInterface.SS7_MAP, 12,
            "ActivateSS", OperationCategory.INTERCEPTION),

    /** MAP opcode 73 - Sends USSD to subscriber */
    MAP_PROCESS_UNSTRUCTURED_SS(ProtocolInterface.SS7_MAP, 73,
            "ProcessUnstructuredSS-Request", OperationCategory.RECONNAISSANCE),

    // === Diameter S6a Operations (3GPP TS 29.272) ===

    /** Diameter cmd 316 - MME requests subscriber authentication vectors from HSS */
    DIA_AUTH_INFO_REQUEST(ProtocolInterface.DIAMETER_S6A, 316,
            "Authentication-Information-Request", OperationCategory.INTERCEPTION),

    /** Diameter cmd 316 - HSS responds with authentication vectors */
    DIA_AUTH_INFO_ANSWER(ProtocolInterface.DIAMETER_S6A, 316,
            "Authentication-Information-Answer", OperationCategory.INTERCEPTION),

    /** Diameter cmd 318 - MME registers subscriber location with HSS */
    DIA_UPDATE_LOCATION_REQUEST(ProtocolInterface.DIAMETER_S6A, 318,
            "Update-Location-Request", OperationCategory.MANIPULATION),

    /** Diameter cmd 318 - HSS responds with subscriber profile */
    DIA_UPDATE_LOCATION_ANSWER(ProtocolInterface.DIAMETER_S6A, 318,
            "Update-Location-Answer", OperationCategory.MANIPULATION),

    /** Diameter cmd 317 - HSS cancels subscriber location in MME */
    DIA_CANCEL_LOCATION_REQUEST(ProtocolInterface.DIAMETER_S6A, 317,
            "Cancel-Location-Request", OperationCategory.MANIPULATION),

    /** Diameter cmd 321 - HSS pushes subscriber data to MME */
    DIA_INSERT_SUBSCRIBER_DATA_REQUEST(ProtocolInterface.DIAMETER_S6A, 321,
            "Insert-Subscriber-Data-Request", OperationCategory.MANIPULATION),

    /** Diameter cmd 320 - HSS deletes subscriber data from MME */
    DIA_DELETE_SUBSCRIBER_DATA_REQUEST(ProtocolInterface.DIAMETER_S6A, 320,
            "Delete-Subscriber-Data-Request", OperationCategory.MANIPULATION),

    /** Diameter cmd 8388622 - Notify request */
    DIA_NOTIFY_REQUEST(ProtocolInterface.DIAMETER_S6A, 8388622,
            "Notify-Request", OperationCategory.RECONNAISSANCE),

    // === GTPv2-C Operations (3GPP TS 29.274) ===

    /** GTPv2-C type 32 - Creates bearer session */
    GTP_CREATE_SESSION_REQUEST(ProtocolInterface.GTPC_V2, 32,
            "Create-Session-Request", OperationCategory.SESSION),

    /** GTPv2-C type 33 - Create session response */
    GTP_CREATE_SESSION_RESPONSE(ProtocolInterface.GTPC_V2, 33,
            "Create-Session-Response", OperationCategory.SESSION),

    /** GTPv2-C type 36 - Deletes bearer session */
    GTP_DELETE_SESSION_REQUEST(ProtocolInterface.GTPC_V2, 36,
            "Delete-Session-Request", OperationCategory.SESSION),

    /** GTPv2-C type 34 - Modifies existing bearer */
    GTP_MODIFY_BEARER_REQUEST(ProtocolInterface.GTPC_V2, 34,
            "Modify-Bearer-Request", OperationCategory.SESSION),

    /** GTPv2-C type 170 - Downlink data notification */
    GTP_DOWNLINK_DATA_NOTIFICATION(ProtocolInterface.GTPC_V2, 170,
            "Downlink-Data-Notification", OperationCategory.SESSION);

    private final ProtocolInterface protocolInterface;
    private final int operationCode;
    private final String displayName;
    private final OperationCategory category;

    SignalingOperation(ProtocolInterface protocolInterface, int operationCode,
                       String displayName, OperationCategory category) {
        this.protocolInterface = protocolInterface;
        this.operationCode = operationCode;
        this.displayName = displayName;
        this.category = category;
    }

    public ProtocolInterface getProtocolInterface() { return protocolInterface; }
    public int getOperationCode() { return operationCode; }
    public String getDisplayName() { return displayName; }
    public OperationCategory getCategory() { return category; }

    /**
     * Categories of signaling operations from a security perspective.
     */
    public enum OperationCategory {
        /** Information gathering - querying subscriber identity/routing */
        RECONNAISSANCE,
        /** Location determination - getting subscriber position */
        TRACKING,
        /** Profile/routing modification - altering subscriber state */
        MANIPULATION,
        /** Authentication/key material - enabling eavesdropping */
        INTERCEPTION,
        /** Data session management - bearer/tunnel operations */
        SESSION
    }

    /**
     * Look up a MAP operation by its operation code.
     */
    public static SignalingOperation fromMapOpcode(int opcode) {
        // MAP v1/v2 opcode aliases
        if (opcode == 59) opcode = 73; // processUnstructuredSS v1 → v2

        for (SignalingOperation op : values()) {
            if (op.protocolInterface.getFamily() == ProtocolInterface.ProtocolFamily.SS7
                    && op.operationCode == opcode) {
                return op;
            }
        }
        return null;
    }

    /**
     * Look up a Diameter operation by command code and request flag.
     */
    public static SignalingOperation fromDiameterCommand(int commandCode, boolean isRequest) {
        for (SignalingOperation op : values()) {
            if (op.protocolInterface.getFamily() == ProtocolInterface.ProtocolFamily.DIAMETER
                    && op.operationCode == commandCode) {
                // Simple heuristic: requests end with "Request", answers with "Answer"
                boolean opIsRequest = op.displayName.contains("Request");
                if (opIsRequest == isRequest) {
                    return op;
                }
            }
        }
        return null;
    }

    /**
     * Look up a GTPv2-C operation by message type.
     */
    public static SignalingOperation fromGtpMessageType(int messageType) {
        for (SignalingOperation op : values()) {
            if (op.protocolInterface.getFamily() == ProtocolInterface.ProtocolFamily.GTP
                    && op.operationCode == messageType) {
                return op;
            }
        }
        return null;
    }
}
