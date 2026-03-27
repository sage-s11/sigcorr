package io.sigcorr.core.identity;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Resolves and tracks subscriber identity mappings across protocol interfaces.
 *
 * In telecom signaling, the same subscriber may be referenced by IMSI in one message
 * and MSISDN in another. The IdentityResolver learns these mappings from observed
 * signaling traffic (e.g., MAP SendRoutingInfo reveals MSISDN->IMSI mapping) and
 * uses them to correlate events that would otherwise appear unrelated.
 *
 * This is a critical component: without identity resolution, an attacker who queries
 * by MSISDN on SS7 and by IMSI on Diameter would generate events that appear to
 * target different subscribers.
 *
 * TEMPORAL INFERENCE: When events with only IMSI or only MSISDN arrive within a
 * configurable time window from the same source network context, the resolver
 * infers they belong to the same subscriber. This handles the common case where
 * MAP SRI (MSISDN) is followed by MAP PSI (IMSI) targeting the same victim.
 */
public class IdentityResolver {

    private static final Logger log = LoggerFactory.getLogger(IdentityResolver.class);

    /** Default window for temporal identity inference */
    public static final Duration DEFAULT_INFERENCE_WINDOW = Duration.ofSeconds(10);

    // Bidirectional mapping: IMSI <-> MSISDN
    private final Map<String, String> imsiToMsisdn = new ConcurrentHashMap<>();
    private final Map<String, String> msisdnToImsi = new ConcurrentHashMap<>();

    // Unified identity store: correlation key -> merged identity
    private final Map<String, SubscriberIdentity> identityStore = new ConcurrentHashMap<>();

    // Pending partial identities for temporal inference
    // Key: source node identifier (or "unknown"), Value: list of pending partials
    private final Map<String, List<PendingIdentity>> pendingBySource = new ConcurrentHashMap<>();

    // Configurable inference window
    private Duration inferenceWindow = DEFAULT_INFERENCE_WINDOW;

    /**
     * A partial identity waiting for a temporal match.
     * When an event has only IMSI or only MSISDN, we store it here briefly.
     * If an event with the complementary identifier arrives within the window
     * from the same source, we infer they're the same subscriber.
     */
    private record PendingIdentity(
            String imsi,
            String msisdn,
            Instant timestamp,
            String sourceNode
    ) {
        boolean hasImsi() { return imsi != null; }
        boolean hasMsisdn() { return msisdn != null; }
    }

    /**
     * Set the temporal inference window.
     * Events with partial identities (IMSI-only or MSISDN-only) within this window
     * from the same source are inferred to be the same subscriber.
     */
    public void setInferenceWindow(Duration window) {
        this.inferenceWindow = window;
    }

    public Duration getInferenceWindow() {
        return inferenceWindow;
    }

    /**
     * Register a learned IMSI <-> MSISDN mapping.
     * Called when signaling reveals the association (e.g., SRI response).
     */
    public void registerMapping(String imsi, String msisdn) {
        registerMappingInternal(imsi, msisdn, false);
    }

    /**
     * Internal mapping registration with inference flag for logging.
     */
    private void registerMappingInternal(String imsi, String msisdn, boolean inferred) {
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

        if (inferred) {
            log.info("INFERRED mapping via temporal correlation: IMSI={} <-> MSISDN={}", imsi, msisdn);
        } else {
            log.info("Registered mapping: IMSI={} <-> MSISDN={}", imsi, msisdn);
        }
    }

    /**
     * Register a partial identity and attempt temporal inference.
     *
     * When an event has only IMSI or only MSISDN, this method:
     * 1. Checks if there's a pending partial with the complementary identifier
     *    from the same source within the inference window
     * 2. If found, infers the mapping and registers it
     * 3. If not found, stores this as a pending partial for future matching
     *
     * @param imsi      IMSI from the event (may be null)
     * @param msisdn    MSISDN from the event (may be null)
     * @param timestamp Event timestamp
     * @param sourceNode Source network node identifier (may be null)
     * @return true if a new mapping was inferred, false otherwise
     */
    public boolean tryTemporalInference(String imsi, String msisdn, Instant timestamp, String sourceNode) {
        log.debug("tryTemporalInference: imsi={}, msisdn={}, source={}, time={}", imsi, msisdn, sourceNode, timestamp);
        
        // If we already have both, use direct registration
        if (imsi != null && msisdn != null) {
            // Check if this is a new mapping
            boolean isNew = !imsi.equals(msisdnToImsi.get(msisdn));
            registerMapping(imsi, msisdn);
            log.debug("Direct mapping (both present): isNew={}", isNew);
            return isNew;
        }

        // If we have neither, nothing to do
        if (imsi == null && msisdn == null) {
            log.debug("No identifiers present, skipping");
            return false;
        }

        // Check if we already know this mapping
        if (imsi != null && imsiToMsisdn.containsKey(imsi)) {
            log.debug("IMSI {} already mapped to {}", imsi, imsiToMsisdn.get(imsi));
            return false; // Already mapped
        }
        if (msisdn != null && msisdnToImsi.containsKey(msisdn)) {
            log.debug("MSISDN {} already mapped to {}", msisdn, msisdnToImsi.get(msisdn));
            return false; // Already mapped
        }

        String sourceKey = sourceNode != null ? sourceNode : "unknown";
        Instant cutoff = timestamp.minus(inferenceWindow);
        
        log.debug("Looking for temporal match: sourceKey={}, cutoff={}", sourceKey, cutoff);

        // Get or create pending list for this source
        List<PendingIdentity> pendingList = pendingBySource.computeIfAbsent(
                sourceKey, k -> new ArrayList<>());

        synchronized (pendingList) {
            log.debug("Pending list for source {}: {} entries", sourceKey, pendingList.size());
            
            // Clean up expired entries and look for a match
            Iterator<PendingIdentity> iter = pendingList.iterator();
            PendingIdentity match = null;

            while (iter.hasNext()) {
                PendingIdentity pending = iter.next();
                log.debug("  Checking pending: imsi={}, msisdn={}, time={}", 
                    pending.imsi(), pending.msisdn(), pending.timestamp());

                // Remove expired entries
                if (pending.timestamp().isBefore(cutoff)) {
                    log.debug("  -> Expired, removing");
                    iter.remove();
                    continue;
                }

                // Look for complementary match
                if (imsi != null && pending.hasMsisdn() && !pending.hasImsi()) {
                    // We have IMSI, pending has MSISDN — match!
                    log.debug("  -> MATCH! We have IMSI, pending has MSISDN");
                    match = pending;
                    iter.remove();
                    break;
                }
                if (msisdn != null && pending.hasImsi() && !pending.hasMsisdn()) {
                    // We have MSISDN, pending has IMSI — match!
                    log.debug("  -> MATCH! We have MSISDN, pending has IMSI");
                    match = pending;
                    iter.remove();
                    break;
                }
                log.debug("  -> No match");
            }

            if (match != null) {
                // Found a match — infer the mapping
                String inferredImsi = imsi != null ? imsi : match.imsi();
                String inferredMsisdn = msisdn != null ? msisdn : match.msisdn();
                log.info("TEMPORAL INFERENCE SUCCESS: IMSI={} <-> MSISDN={}", inferredImsi, inferredMsisdn);
                registerMappingInternal(inferredImsi, inferredMsisdn, true);
                return true;
            }

            // No match found — store as pending
            pendingList.add(new PendingIdentity(imsi, msisdn, timestamp, sourceKey));
            log.debug("Stored as pending. List now has {} entries", pendingList.size());
        }

        return false;
    }

    /**
     * Get the number of pending partial identities awaiting inference.
     */
    public int getPendingCount() {
        return pendingBySource.values().stream()
                .mapToInt(List::size)
                .sum();
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

        // Try to resolve MSISDN -> IMSI
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
     * Number of known IMSI <-> MSISDN mappings.
     */
    public int getMappingCount() {
        return imsiToMsisdn.size();
    }

    /**
     * Clear all learned mappings and pending identities.
     */
    public void clear() {
        imsiToMsisdn.clear();
        msisdnToImsi.clear();
        identityStore.clear();
        pendingBySource.clear();
    }
}
