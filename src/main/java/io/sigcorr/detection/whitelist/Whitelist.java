package io.sigcorr.detection.whitelist;

import io.sigcorr.core.event.NetworkNode;
import io.sigcorr.core.event.SignalingEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * Whitelist for trusted network relationships.
 * 
 * In telecom signaling, many queries that look suspicious are actually
 * legitimate roaming/interconnect traffic. For example:
 * - A roaming partner's HLR querying your subscriber's location
 * - SMS interworking platforms sending routing queries
 * - Legitimate hubbing providers relaying traffic
 *
 * The whitelist allows operators to define:
 * 1. Trusted GT pairs: specific source→destination relationships
 * 2. Home network prefixes: GT prefixes belonging to the home network
 * 3. Trusted foreign networks: partner networks (by GT prefix)
 *
 * Events matching whitelist rules are flagged so alerts can be suppressed
 * or downgraded in severity.
 */
public class Whitelist {

    private static final Logger log = LoggerFactory.getLogger(Whitelist.class);

    private final boolean enabled;
    private final Set<String> trustedGtPairs;        // "sourceGT->destGT" format
    private final Set<String> trustedGts;            // single GTs trusted in any direction
    private final List<String> homeNetworkPrefixes;  // GT prefixes for home network
    private final List<String> trustedForeignPrefixes; // GT prefixes for trusted partners

    private Whitelist(boolean enabled,
                      Set<String> trustedGtPairs,
                      Set<String> trustedGts,
                      List<String> homeNetworkPrefixes,
                      List<String> trustedForeignPrefixes) {
        this.enabled = enabled;
        this.trustedGtPairs = trustedGtPairs;
        this.trustedGts = trustedGts;
        this.homeNetworkPrefixes = homeNetworkPrefixes;
        this.trustedForeignPrefixes = trustedForeignPrefixes;
    }

    /**
     * Create a whitelist from configuration lists.
     */
    public static Whitelist fromConfig(boolean enabled,
                                        List<String> gtPairs,
                                        List<String> homePrefixes) {
        Set<String> pairs = new HashSet<>();
        Set<String> singles = new HashSet<>();
        
        for (String entry : gtPairs) {
            entry = entry.trim();
            if (entry.contains("->")) {
                pairs.add(normalizeGtPair(entry));
            } else if (!entry.isEmpty()) {
                singles.add(normalizeGt(entry));
            }
        }
        
        return new Whitelist(enabled, pairs, singles, homePrefixes, Collections.emptyList());
    }

    /**
     * Create an empty (disabled) whitelist.
     */
    public static Whitelist disabled() {
        return new Whitelist(false, 
                Collections.emptySet(), 
                Collections.emptySet(),
                Collections.emptyList(),
                Collections.emptyList());
    }

    /**
     * Check if an event involves only trusted/home network nodes.
     * 
     * @return true if this event should be considered trusted (whitelist match)
     */
    public boolean isTrusted(SignalingEvent event) {
        if (!enabled) return false;

        NetworkNode source = event.getSourceNode();
        NetworkNode dest = event.getDestinationNode();
        
        String sourceGt = source != null ? normalizeGt(source.getIdentifier()) : null;
        String destGt = dest != null ? normalizeGt(dest.getIdentifier()) : null;

        // Check explicit GT pair whitelist
        if (sourceGt != null && destGt != null) {
            String pair = sourceGt + "->" + destGt;
            if (trustedGtPairs.contains(pair)) {
                log.debug("Whitelist match: trusted GT pair {}", pair);
                return true;
            }
        }

        // Check single GT whitelist
        if (sourceGt != null && trustedGts.contains(sourceGt)) {
            log.debug("Whitelist match: trusted source GT {}", sourceGt);
            return true;
        }
        if (destGt != null && trustedGts.contains(destGt)) {
            log.debug("Whitelist match: trusted destination GT {}", destGt);
            return true;
        }

        // Check home network prefixes (traffic within home network is trusted)
        if (isHomeNetwork(sourceGt) && isHomeNetwork(destGt)) {
            log.debug("Whitelist match: home network traffic {} -> {}", sourceGt, destGt);
            return true;
        }

        return false;
    }

    /**
     * Check if a GT belongs to the home network.
     */
    public boolean isHomeNetwork(String gt) {
        if (gt == null || homeNetworkPrefixes.isEmpty()) return false;
        String normalized = normalizeGt(gt);
        for (String prefix : homeNetworkPrefixes) {
            if (normalized.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if a GT belongs to a foreign (non-home) network.
     */
    public boolean isForeignNetwork(String gt) {
        if (gt == null) return false;
        return !isHomeNetwork(gt);
    }

    /**
     * Get a human-readable reason why an event matched the whitelist.
     * Returns null if no match.
     */
    public String getMatchReason(SignalingEvent event) {
        if (!enabled) return null;

        NetworkNode source = event.getSourceNode();
        NetworkNode dest = event.getDestinationNode();
        
        String sourceGt = source != null ? normalizeGt(source.getIdentifier()) : null;
        String destGt = dest != null ? normalizeGt(dest.getIdentifier()) : null;

        if (sourceGt != null && destGt != null) {
            String pair = sourceGt + "->" + destGt;
            if (trustedGtPairs.contains(pair)) {
                return "Trusted GT pair: " + pair;
            }
        }

        if (sourceGt != null && trustedGts.contains(sourceGt)) {
            return "Trusted source GT: " + sourceGt;
        }
        if (destGt != null && trustedGts.contains(destGt)) {
            return "Trusted destination GT: " + destGt;
        }

        if (isHomeNetwork(sourceGt) && isHomeNetwork(destGt)) {
            return "Home network traffic";
        }

        return null;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public int getTrustedPairCount() {
        return trustedGtPairs.size() + trustedGts.size();
    }

    private static String normalizeGt(String gt) {
        if (gt == null) return null;
        // Keep only digits, strip +
        return gt.replaceAll("[^0-9]", "");
    }

    private static String normalizeGtPair(String pair) {
        String[] parts = pair.split("->");
        if (parts.length != 2) return pair;
        return normalizeGt(parts[0]) + "->" + normalizeGt(parts[1]);
    }
}
