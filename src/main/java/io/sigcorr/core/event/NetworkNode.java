package io.sigcorr.core.event;

import java.util.Objects;

/**
 * Represents a signaling network node (MSC, HLR, MME, SGW, etc.).
 *
 * Nodes are identified differently across protocols:
 * - SS7: Global Title (GT) — an E.164 address used for SCCP routing
 * - Diameter: Origin-Host / Origin-Realm — FQDN-based identifiers
 * - GTP-C: F-TEID — IP address + TEID (Tunnel Endpoint Identifier)
 *
 * For correlation, what matters is whether two events originate from
 * the same node (or an unexpected node). A foreign GT sending MAP queries
 * about domestic subscribers is a classic SS7 attack indicator.
 */
public final class NetworkNode {

    private final NodeType type;
    private final String identifier;
    private final String realm;   // Diameter realm or MCC+MNC derived network

    public NetworkNode(NodeType type, String identifier, String realm) {
        this.type = Objects.requireNonNull(type);
        this.identifier = Objects.requireNonNull(identifier);
        this.realm = realm;
    }

    public NetworkNode(NodeType type, String identifier) {
        this(type, identifier, null);
    }

    /**
     * Create from SS7 Global Title.
     */
    public static NetworkNode fromGlobalTitle(String gt) {
        return new NetworkNode(NodeType.GLOBAL_TITLE, normalizeGT(gt));
    }

    /**
     * Create from Diameter Origin-Host.
     */
    public static NetworkNode fromDiameterHost(String host, String realm) {
        return new NetworkNode(NodeType.DIAMETER_HOST, host, realm);
    }

    /**
     * Create from GTP-C peer address.
     */
    public static NetworkNode fromGtpPeer(String ipAddress) {
        return new NetworkNode(NodeType.GTP_PEER, ipAddress);
    }

    public NodeType getType() { return type; }
    public String getIdentifier() { return identifier; }
    public String getRealm() { return realm; }

    /**
     * Determine if this node appears to be from a foreign (non-home) network.
     * Used in attack detection: legitimate queries from home network nodes
     * vs suspicious queries from foreign nodes.
     *
     * @param homeNetworkIdentifiers identifiers (GTs, realms) belonging to home network
     */
    public boolean isForeign(java.util.Set<String> homeNetworkIdentifiers) {
        if (homeNetworkIdentifiers.contains(identifier)) return false;
        if (realm != null && homeNetworkIdentifiers.contains(realm)) return false;
        return true;
    }

    private static String normalizeGT(String gt) {
        // Strip any formatting, keep only digits and leading '+'
        return gt.replaceAll("[^0-9+]", "");
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        NetworkNode that = (NetworkNode) o;
        return type == that.type && Objects.equals(identifier, that.identifier);
    }

    @Override
    public int hashCode() {
        return Objects.hash(type, identifier);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(type.getPrefix()).append(":").append(identifier);
        if (realm != null) sb.append("@").append(realm);
        return sb.toString();
    }

    public enum NodeType {
        GLOBAL_TITLE("GT"),
        DIAMETER_HOST("DIA"),
        GTP_PEER("GTP"),
        UNKNOWN("UNK");

        private final String prefix;

        NodeType(String prefix) { this.prefix = prefix; }
        public String getPrefix() { return prefix; }
    }
}
