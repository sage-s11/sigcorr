package io.sigcorr.core.identity;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Resolves and tracks subscriber identity mappings across protocol interfaces.
 *
 * In telecom signaling, the same subscriber may be referenced by IMSI in one message
 * and MSISDN in another. The IdentityResolver learns these mappings from observed
 * signaling traffic (e.g., MAP SendRoutingInfo reveals MSISDN→IMSI mapping) and
 * uses them to correlate events that would otherwise appear unrelated.
 *
 * This is a critical component: without identity resolution, an attacker who queries
 * by MSISDN on SS7 and by IMSI on Diameter would generate events that appear to
 * target different subscribers.
 */
public class IdentityResolver {

    private static final Logger log = LoggerFactory.getLogger(IdentityResolver.class);

    // Bidirectional mapping: IMSI ↔ MSISDN
    private final Map<String, String> imsiToMsisdn = new ConcurrentHashMap<>();
    private final Map<String, String> msisdnToImsi = new ConcurrentHashMap<>();

    // Unified identity store: correlation key → merged identity
    private final Map<String, SubscriberIdentity> identityStore = new ConcurrentHashMap<>();

    /**
     * Register a learned IMSI ↔ MSISDN mapping.
     * Called when signaling reveals the association (e.g., SRI response).
     */
    public void registerMapping(String imsi, String msisdn) {
        // Check for conflicts (possible IMSI catch / identity spoofing)
        String existingMsisdn = imsiToMsisdn.get(imsi);
        String existingImsi = msisdnToImsi.get(msisdn);

        if (existingMsisdn != null && !existingMsisdn.equals(msisdn)) {
            log.warn("IMSI {} previously mapped to MSISDN {}, now mapped to {} — possible identity conflict",
                    imsi, existingMsisdn, msisdn);
        }
        if (existingImsi != null && !existingImsi.equals(imsi)) {
            log.warn("MSISDN {} previously mapped to IMSI {}, now mapped to {} — possible identity conflict",
                    msisdn, existingImsi, imsi);
        }

        imsiToMsisdn.put(imsi, msisdn);
        msisdnToImsi.put(msisdn, imsi);

        // Store unified identity
        SubscriberIdentity unified = SubscriberIdentity.fromBoth(imsi, msisdn);
        identityStore.put("IMSI:" + imsi, unified);
        identityStore.put("MSISDN:" + msisdn, unified);

        log.debug("Registered mapping: IMSI={} ↔ MSISDN={}", imsi, msisdn);
    }

    /**
     * Resolve the best known identity for a given IMSI.
     * May return an enriched identity with MSISDN if the mapping is known.
     */
    public SubscriberIdentity resolveByImsi(String imsi) {
        SubscriberIdentity stored = identityStore.get("IMSI:" + imsi);
        if (stored != null) return stored;
        return SubscriberIdentity.fromImsi(imsi);
    }

    /**
     * Resolve the best known identity for a given MSISDN.
     * May return an enriched identity with IMSI if the mapping is known.
     */
    public SubscriberIdentity resolveByMsisdn(String msisdn) {
        SubscriberIdentity stored = identityStore.get("MSISDN:" + msisdn);
        if (stored != null) return stored;
        return SubscriberIdentity.fromMsisdn(msisdn);
    }

    /**
     * Get the canonical correlation key for a subscriber, resolving
     * MSISDN to IMSI if the mapping is known (IMSI is preferred as
     * it's globally unique and not subject to number portability).
     */
    public String getCorrelationKey(SubscriberIdentity identity) {
        // If we have IMSI, use it directly
        if (identity.hasImsi()) {
            return "IMSI:" + identity.getImsi().get();
        }

        // Try to resolve MSISDN → IMSI
        String msisdn = identity.getMsisdn().orElseThrow();
        String resolvedImsi = msisdnToImsi.get(msisdn);
        if (resolvedImsi != null) {
            return "IMSI:" + resolvedImsi;
        }

        // Fall back to MSISDN
        return "MSISDN:" + msisdn;
    }

    /**
     * Look up IMSI by MSISDN.
     */
    public Optional<String> lookupImsi(String msisdn) {
        return Optional.ofNullable(msisdnToImsi.get(msisdn));
    }

    /**
     * Look up MSISDN by IMSI.
     */
    public Optional<String> lookupMsisdn(String imsi) {
        return Optional.ofNullable(imsiToMsisdn.get(imsi));
    }

    /**
     * Number of known IMSI ↔ MSISDN mappings.
     */
    public int getMappingCount() {
        return imsiToMsisdn.size();
    }

    /**
     * Clear all learned mappings.
     */
    public void clear() {
        imsiToMsisdn.clear();
        msisdnToImsi.clear();
        identityStore.clear();
    }
}
