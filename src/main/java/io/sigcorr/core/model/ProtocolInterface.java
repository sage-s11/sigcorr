package io.sigcorr.core.model;

/**
 * Signaling protocol interfaces monitored by SigCorr.
 *
 * Each interface carries different signaling operations in telecom networks:
 * - SS7_MAP: Mobile Application Part over SS7 (legacy 2G/3G signaling)
 * - DIAMETER_S6A: Diameter S6a interface between MME and HSS (4G/LTE authentication)
 * - DIAMETER_S6D: Diameter S6d interface (SGSN to HSS in combined 3G/4G)
 * - GTPC_V2: GTP Control Plane v2 (bearer/session management in 4G)
 * - SS7_CAMEL: CAMEL Application Part (intelligent network triggers)
 * - SS7_ISUP: ISDN User Part (call setup signaling)
 */
public enum ProtocolInterface {

    SS7_MAP("SS7/MAP", "Mobile Application Part", ProtocolFamily.SS7),
    SS7_CAMEL("SS7/CAMEL", "CAMEL Application Part", ProtocolFamily.SS7),
    SS7_ISUP("SS7/ISUP", "ISDN User Part", ProtocolFamily.SS7),
    DIAMETER_S6A("Diameter/S6a", "MME to HSS", ProtocolFamily.DIAMETER),
    DIAMETER_S6D("Diameter/S6d", "SGSN to HSS", ProtocolFamily.DIAMETER),
    DIAMETER_SWX("Diameter/SWx", "Non-3GPP AAA to HSS", ProtocolFamily.DIAMETER),
    GTPC_V2("GTPv2-C", "GTP Control Plane v2", ProtocolFamily.GTP);

    private final String displayName;
    private final String description;
    private final ProtocolFamily family;

    ProtocolInterface(String displayName, String description, ProtocolFamily family) {
        this.displayName = displayName;
        this.description = description;
        this.family = family;
    }

    public String getDisplayName() { return displayName; }
    public String getDescription() { return description; }
    public ProtocolFamily getFamily() { return family; }

    public enum ProtocolFamily {
        SS7, DIAMETER, GTP
    }
}
