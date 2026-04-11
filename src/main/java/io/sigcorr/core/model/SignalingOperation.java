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

    /** MAP opcode 46 - Sends SMS via signaling (MT-ForwardSM) */
    MAP_MT_FORWARD_SM(ProtocolInterface.SS7_MAP, 46,
            "MT-ForwardSM", OperationCategory.INTERCEPTION),

    /** MAP opcode 45 - Sends SMS via signaling (MO-ForwardSM) */
    MAP_MO_FORWARD_SM(ProtocolInterface.SS7_MAP, 45,
            "MO-ForwardSM", OperationCategory.INTERCEPTION),

    /** MAP opcode 24 - Routes SMS for delivery */
    MAP_SEND_ROUTING_INFO_FOR_SM(ProtocolInterface.SS7_MAP, 24,
            "SendRoutingInfoForSM", OperationCategory.RECONNAISSANCE),

    /** MAP opcode 44 - Reports SM delivery status */
    MAP_REPORT_SM_DELIVERY_STATUS(ProtocolInterface.SS7_MAP, 44,
            "ReportSM-DeliveryStatus", OperationCategory.RECONNAISSANCE),

    /** MAP opcode 63 - Ready for SM (triggers SMS delivery) */
    MAP_READY_FOR_SM(ProtocolInterface.SS7_MAP, 63,
            "ReadyForSM", OperationCategory.MANIPULATION),

    /** MAP opcode 66 - Sends IMSI (subscriber identity response) */
    MAP_SEND_IMSI(ProtocolInterface.SS7_MAP, 66,
            "SendIMSI", OperationCategory.RECONNAISSANCE),

    /** MAP opcode 5 - Reset (clears subscriber data) */
    MAP_RESET(ProtocolInterface.SS7_MAP, 5,
            "Reset", OperationCategory.MANIPULATION),

    /** MAP opcode 4 - Purge MS (removes subscriber from VLR) */
    MAP_PURGE_MS(ProtocolInterface.SS7_MAP, 4,
            "PurgeMS", OperationCategory.MANIPULATION),

    /** MAP opcode 13 - Deactivates supplementary service */
    MAP_DEACTIVATE_SS(ProtocolInterface.SS7_MAP, 13,
            "DeactivateSS", OperationCategory.INTERCEPTION),

    /** MAP opcode 11 - Erases supplementary service */
    MAP_ERASE_SS(ProtocolInterface.SS7_MAP, 11,
            "EraseSS", OperationCategory.INTERCEPTION),

    /** MAP opcode 14 - Interrogates supplementary service status */
    MAP_INTERROGATE_SS(ProtocolInterface.SS7_MAP, 14,
            "InterrogateSS", OperationCategory.RECONNAISSANCE),

    /** MAP opcode 6 - Restore data (restores subscriber data after reset) */
    MAP_RESTORE_DATA(ProtocolInterface.SS7_MAP, 6,
            "RestoreData", OperationCategory.MANIPULATION),

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
            "Downlink-Data-Notification", OperationCategory.SESSION),

    // === 5G NAS Operations (3GPP TS 24.501) — v0.2 ===
    NAS_5G_REGISTRATION_REQUEST(ProtocolInterface.FIVEG_NAS, 0x41, "RegistrationRequest", OperationCategory.RECONNAISSANCE),
    NAS_5G_REGISTRATION_ACCEPT(ProtocolInterface.FIVEG_NAS, 0x42, "RegistrationAccept", OperationCategory.RECONNAISSANCE),
    NAS_5G_REGISTRATION_REJECT(ProtocolInterface.FIVEG_NAS, 0x43, "RegistrationReject", OperationCategory.MANIPULATION),
    NAS_5G_REGISTRATION_COMPLETE(ProtocolInterface.FIVEG_NAS, 0x44, "RegistrationComplete", OperationCategory.RECONNAISSANCE),
    NAS_5G_DEREGISTRATION_REQUEST_UE(ProtocolInterface.FIVEG_NAS, 0x45, "DeregistrationRequestUE", OperationCategory.MANIPULATION),
    NAS_5G_DEREGISTRATION_REQUEST_NW(ProtocolInterface.FIVEG_NAS, 0x46, "DeregistrationRequestNW", OperationCategory.MANIPULATION),
    NAS_5G_DEREGISTRATION_ACCEPT(ProtocolInterface.FIVEG_NAS, 0x47, "DeregistrationAccept", OperationCategory.MANIPULATION),
    NAS_5G_AUTH_REQUEST(ProtocolInterface.FIVEG_NAS, 0x56, "AuthenticationRequest", OperationCategory.INTERCEPTION),
    NAS_5G_AUTH_RESPONSE(ProtocolInterface.FIVEG_NAS, 0x57, "AuthenticationResponse", OperationCategory.INTERCEPTION),
    NAS_5G_AUTH_REJECT(ProtocolInterface.FIVEG_NAS, 0x58, "AuthenticationReject", OperationCategory.INTERCEPTION),
    NAS_5G_AUTH_FAILURE(ProtocolInterface.FIVEG_NAS, 0x59, "AuthenticationFailure", OperationCategory.INTERCEPTION),
    NAS_5G_IDENTITY_REQUEST(ProtocolInterface.FIVEG_NAS, 0x5b, "IdentityRequest", OperationCategory.RECONNAISSANCE),
    NAS_5G_IDENTITY_RESPONSE(ProtocolInterface.FIVEG_NAS, 0x5c, "IdentityResponse", OperationCategory.RECONNAISSANCE),
    NAS_5G_SECURITY_MODE_COMMAND(ProtocolInterface.FIVEG_NAS, 0x5d, "SecurityModeCommand", OperationCategory.INTERCEPTION),
    NAS_5G_SECURITY_MODE_COMPLETE(ProtocolInterface.FIVEG_NAS, 0x5e, "SecurityModeComplete", OperationCategory.INTERCEPTION),
    NAS_5G_SECURITY_MODE_REJECT(ProtocolInterface.FIVEG_NAS, 0x5f, "SecurityModeReject", OperationCategory.INTERCEPTION),
    NAS_5G_SERVICE_REQUEST(ProtocolInterface.FIVEG_NAS, 0x4c, "ServiceRequest", OperationCategory.RECONNAISSANCE),
    NAS_5G_PDU_SESSION_ESTABLISHMENT_REQ(ProtocolInterface.FIVEG_NAS, 0xc1, "PDUSessionEstablishmentRequest", OperationCategory.MANIPULATION),
    NAS_5G_PDU_SESSION_MODIFICATION_REQ(ProtocolInterface.FIVEG_NAS, 0xc9, "PDUSessionModificationRequest", OperationCategory.MANIPULATION),
    NAS_5G_PDU_SESSION_RELEASE_REQUEST(ProtocolInterface.FIVEG_NAS, 0xd1, "PDUSessionReleaseRequest", OperationCategory.MANIPULATION),
    NAS_5G_AUTHENTICATION_REQUEST(ProtocolInterface.FIVEG_NAS, 0x56, "AuthenticationRequest", OperationCategory.INTERCEPTION),		

    // === NGAP Operations (3GPP TS 38.413) — v0.2 ===
    NGAP_INITIAL_UE_MESSAGE(ProtocolInterface.NGAP, 15, "InitialUEMessage", OperationCategory.RECONNAISSANCE),
    NGAP_INITIAL_CONTEXT_SETUP_REQ(ProtocolInterface.NGAP, 14, "InitialContextSetupRequest", OperationCategory.MANIPULATION),
    NGAP_UE_CONTEXT_RELEASE_COMMAND(ProtocolInterface.NGAP, 41, "UEContextReleaseCommand", OperationCategory.MANIPULATION),
    NGAP_UE_CONTEXT_RELEASE_REQUEST(ProtocolInterface.NGAP, 42, "UEContextReleaseRequest", OperationCategory.MANIPULATION),
    NGAP_HANDOVER_REQUIRED(ProtocolInterface.NGAP, 0, "HandoverRequired", OperationCategory.MANIPULATION),
    NGAP_HANDOVER_REQUEST(ProtocolInterface.NGAP, 1, "HandoverRequest", OperationCategory.MANIPULATION),
    NGAP_HANDOVER_NOTIFY(ProtocolInterface.NGAP, 3, "HandoverNotify", OperationCategory.MANIPULATION),
    NGAP_PATH_SWITCH_REQUEST(ProtocolInterface.NGAP, 12, "PathSwitchRequest", OperationCategory.MANIPULATION),
    NGAP_NG_SETUP_REQUEST(ProtocolInterface.NGAP, 21, "NGSetupRequest", OperationCategory.RECONNAISSANCE),
    NGAP_DOWNLINK_NAS_TRANSPORT(ProtocolInterface.NGAP, 25, "DownlinkNASTransport", OperationCategory.INTERCEPTION),
    NGAP_UPLINK_NAS_TRANSPORT(ProtocolInterface.NGAP, 46, "UplinkNASTransport", OperationCategory.INTERCEPTION),
    NGAP_PAGING(ProtocolInterface.NGAP, 5, "Paging", OperationCategory.TRACKING),
    NGAP_PDU_SESSION_RESOURCE_SETUP_REQ(ProtocolInterface.NGAP, 26, "PDUSessionResourceSetupRequest", OperationCategory.MANIPULATION),
    NGAP_PDU_SESSION_RESOURCE_RELEASE_CMD(ProtocolInterface.NGAP, 27, "PDUSessionResourceReleaseCommand", OperationCategory.MANIPULATION),
    NGAP_PDU_SESSION_RESOURCE_MODIFY_REQ(ProtocolInterface.NGAP, 28, "PDUSessionResourceModifyRequest", OperationCategory.MANIPULATION),

    // === PFCP Operations (3GPP TS 29.244) — v0.2 ===
    PFCP_HEARTBEAT_REQ(ProtocolInterface.PFCP, 1, "HeartbeatRequest", OperationCategory.RECONNAISSANCE),
    PFCP_HEARTBEAT_RSP(ProtocolInterface.PFCP, 2, "HeartbeatResponse", OperationCategory.RECONNAISSANCE),
    PFCP_ASSOCIATION_SETUP_REQ(ProtocolInterface.PFCP, 5, "AssociationSetupRequest", OperationCategory.RECONNAISSANCE),
    PFCP_ASSOCIATION_SETUP_RSP(ProtocolInterface.PFCP, 6, "AssociationSetupResponse", OperationCategory.RECONNAISSANCE),
    PFCP_SESSION_ESTABLISHMENT_REQ(ProtocolInterface.PFCP, 50, "SessionEstablishmentRequest", OperationCategory.MANIPULATION),
    PFCP_SESSION_ESTABLISHMENT_RSP(ProtocolInterface.PFCP, 51, "SessionEstablishmentResponse", OperationCategory.MANIPULATION),
    PFCP_SESSION_MODIFICATION_REQ(ProtocolInterface.PFCP, 52, "SessionModificationRequest", OperationCategory.MANIPULATION),
    PFCP_SESSION_MODIFICATION_RSP(ProtocolInterface.PFCP, 53, "SessionModificationResponse", OperationCategory.MANIPULATION),
    PFCP_SESSION_DELETION_REQ(ProtocolInterface.PFCP, 54, "SessionDeletionRequest", OperationCategory.MANIPULATION),
    PFCP_SESSION_DELETION_RSP(ProtocolInterface.PFCP, 55, "SessionDeletionResponse", OperationCategory.MANIPULATION),
    PFCP_SESSION_REPORT_REQ(ProtocolInterface.PFCP, 56, "SessionReportRequest", OperationCategory.MANIPULATION),
    PFCP_SESSION_REPORT_RSP(ProtocolInterface.PFCP, 57, "SessionReportResponse", OperationCategory.MANIPULATION);

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

    /**
     * Look up a 5G NAS Mobility Management operation by message type string.
     * Accepts both hex ("0x41") and decimal ("65") forms from tshark.
     */
    public static SignalingOperation fromNas5gMmType(String typeStr) {
        if (typeStr == null) return null;
        int code = parse5gTypeCode(typeStr);
        if (code < 0) return null;
        for (SignalingOperation op : values()) {
            if (op.protocolInterface == ProtocolInterface.FIVEG_NAS
                    && op.operationCode == code
                    && !op.name().contains("PDU_SESSION")) {
                return op;
            }
        }
        return null;
    }

    /**
     * Look up a 5G NAS Session Management operation by message type string.
     * Accepts both hex ("0xc1") and decimal ("193") forms from tshark.
     */
    public static SignalingOperation fromNas5gSmType(String typeStr) {
        if (typeStr == null) return null;
        int code = parse5gTypeCode(typeStr);
        if (code < 0) return null;
        for (SignalingOperation op : values()) {
            if (op.protocolInterface == ProtocolInterface.FIVEG_NAS
                    && op.operationCode == code
                    && op.name().contains("PDU_SESSION")) {
                return op;
            }
        }
        return null;
    }

    /**
     * Look up an NGAP operation by procedure code string.
     */
    public static SignalingOperation fromNgapProcedureCode(String codeStr) {
        if (codeStr == null) return null;
        int code;
        try { code = Integer.parseInt(codeStr.trim()); }
        catch (NumberFormatException e) { return null; }
        for (SignalingOperation op : values()) {
            if (op.protocolInterface == ProtocolInterface.NGAP
                    && op.operationCode == code) {
                return op;
            }
        }
        return null;
    }

    /**
     * Look up a PFCP operation by message type string.
     */
    public static SignalingOperation fromPfcpMsgType(String typeStr) {
        if (typeStr == null) return null;
        int code;
        try { code = Integer.parseInt(typeStr.trim()); }
        catch (NumberFormatException e) { return null; }
        for (SignalingOperation op : values()) {
            if (op.protocolInterface == ProtocolInterface.PFCP
                    && op.operationCode == code) {
                return op;
            }
        }
        return null;
    }

    /**
     * Parse a 5G NAS type code from hex or decimal string.
     * tshark outputs "0x41" or "65" depending on version.
     */
    private static int parse5gTypeCode(String typeStr) {
        typeStr = typeStr.trim().toLowerCase();
        try {
            if (typeStr.startsWith("0x")) {
                return Integer.parseInt(typeStr.substring(2), 16);
            }
            return Integer.parseInt(typeStr);
        } catch (NumberFormatException e) {
            return -1;
        }

    }
}
