/*
 * SigCorr - Cross-Protocol Signaling Security Correlator
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * 5G Identity Resolution Extension (v0.2)
 *
 * Extends the existing IdentityResolver to support:
 *   - SUPI (Subscription Permanent Identifier) — 5G equivalent of IMSI
 *   - SUCI (Subscription Concealed Identifier) — encrypted SUPI
 *   - 5GS-TMSI / 5G-GUTI — temporary identifiers in 5G
 *   - Cross-generation correlation: SUPI ↔ IMSI ↔ MSISDN
 *
 * INTEGRATION NOTE:
 *   Merge these methods into your existing IdentityResolver.java.
 *   The SUPI format is "imsi-<MCC><MNC><MSIN>" per 3GPP TS 23.003,
 *   so SUPI→IMSI extraction is straightforward string parsing.
 */
package io.sigcorr.core.identity;

import io.sigcorr.core.model.ProtocolInterface;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Resolves and correlates subscriber identities across 2G–5G protocol boundaries.
 *
 * <p>Identity mappings maintained:
 * <ul>
 *   <li>IMSI ↔ MSISDN (existing, from SS7/MAP and Diameter)</li>
 *   <li>SUPI ↔ IMSI (new, 5G SA — typically SUPI = "imsi-" + IMSI digits)</li>
 *   <li>SUCI → SUPI (new, one-way — SUCI is the concealed form)</li>
 *   <li>5G-GUTI ↔ SUPI (new, temporary identifier mapping)</li>
 * </ul>
 */
public class IdentityResolver5G {

    private static final Logger log = LoggerFactory.getLogger(IdentityResolver5G.class);

    /** SUPI → IMSI mapping (typically trivial: strip "imsi-" prefix) */
    private final Map<String, String> supiToImsi = new ConcurrentHashMap<>();

    /** IMSI → SUPI reverse mapping */
    private final Map<String, String> imsiToSupi = new ConcurrentHashMap<>();

    /** SUCI → SUPI mapping (populated when network decrypts SUCI) */
    private final Map<String, String> suciToSupi = new ConcurrentHashMap<>();

    /** 5G-GUTI → SUPI mapping (temporary identifier resolution) */
    private final Map<String, String> gutiToSupi = new ConcurrentHashMap<>();

    /** SUPI → 5G-GUTI reverse mapping */
    private final Map<String, String> supiToGuti = new ConcurrentHashMap<>();

    // ── Reference to existing resolver for IMSI ↔ MSISDN lookups ──
    // In actual integration, these methods would be added directly to IdentityResolver.java
    // rather than in a separate class. Kept separate here for clean merge.

    /**
     * Register a SUPI observed in 5G NAS signaling.
     * Automatically extracts and maps the underlying IMSI.
     *
     * @param supi SUPI string, e.g. "imsi-234101234567890" or raw digits
     */
    public void registerSupi(String supi) {
        if (supi == null || supi.isBlank()) return;

        String normalized = normalizeSupi(supi);
        String imsi = extractImsiFromSupi(normalized);

        if (imsi != null) {
            supiToImsi.put(normalized, imsi);
            imsiToSupi.put(imsi, normalized);
            log.debug("Registered SUPI→IMSI mapping: {} → {}", normalized, imsi);
        }
    }

    /**
     * Register a SUCI→SUPI mapping observed during 5G authentication.
     * The network decrypts SUCI to obtain SUPI; we capture that association.
     *
     * @param suci the concealed identifier from RegistrationRequest
     * @param supi the revealed permanent identifier
     */
    public void registerSuciMapping(String suci, String supi) {
        if (suci == null || supi == null) return;

        String normalizedSupi = normalizeSupi(supi);
        suciToSupi.put(suci, normalizedSupi);
        registerSupi(normalizedSupi);
        log.debug("Registered SUCI→SUPI mapping: {} → {}", suci, normalizedSupi);
    }

    /**
     * Register a 5G-GUTI↔SUPI mapping from RegistrationAccept or similar.
     *
     * @param guti 5G-GUTI string
     * @param supi associated SUPI
     */
    public void registerGutiMapping(String guti, String supi) {
        if (guti == null || supi == null) return;

        String normalizedSupi = normalizeSupi(supi);
        gutiToSupi.put(guti, normalizedSupi);
        supiToGuti.put(normalizedSupi, guti);
        registerSupi(normalizedSupi);
        log.debug("Registered 5G-GUTI→SUPI mapping: {} → {}", guti, normalizedSupi);
    }

    /**
     * Resolve any 5G identifier to its canonical IMSI.
     * Handles SUPI, SUCI, 5G-GUTI, and raw IMSI pass-through.
     *
     * @param identifier the 5G identifier string
     * @return resolved IMSI, or empty if unresolvable
     */
    public Optional<String> resolveToImsi(String identifier) {
        if (identifier == null || identifier.isBlank()) return Optional.empty();

        // Direct IMSI (15-digit numeric string)
        if (identifier.matches("\\d{14,15}")) {
            return Optional.of(identifier);
        }

        // SUPI format: "imsi-<digits>" or "nai-<user@realm>"
        if (identifier.toLowerCase().startsWith("imsi-")) {
            String imsi = extractImsiFromSupi(identifier);
            return Optional.ofNullable(imsi);
        }

        // Check SUPI map
        if (supiToImsi.containsKey(identifier)) {
            return Optional.of(supiToImsi.get(identifier));
        }

        // Check SUCI map (SUCI → SUPI → IMSI)
        if (suciToSupi.containsKey(identifier)) {
            String supi = suciToSupi.get(identifier);
            return Optional.ofNullable(supiToImsi.get(supi));
        }

        // Check 5G-GUTI map (GUTI → SUPI → IMSI)
        if (gutiToSupi.containsKey(identifier)) {
            String supi = gutiToSupi.get(identifier);
            return Optional.ofNullable(supiToImsi.get(supi));
        }

        return Optional.empty();
    }

    /**
     * Resolve an IMSI (from legacy protocols) to its 5G SUPI.
     * Enables cross-generation correlation: SS7 IMSI → 5G SUPI.
     *
     * @param imsi the legacy IMSI
     * @return SUPI if known, else generates canonical form "imsi-{IMSI}"
     */
    public String resolveImsiToSupi(String imsi) {
        if (imsi == null) return null;
        return imsiToSupi.getOrDefault(imsi, "imsi-" + imsi);
    }

    /**
     * Check if two identifiers (from any generation) refer to the same subscriber.
     * This is the core cross-generation correlation method.
     *
     * @param id1 first identifier (IMSI, SUPI, SUCI, GUTI, MSISDN)
     * @param id2 second identifier
     * @return true if both resolve to the same subscriber
     */
    public boolean isSameSubscriber(String id1, String id2) {
        Optional<String> imsi1 = resolveToImsi(id1);
        Optional<String> imsi2 = resolveToImsi(id2);

        if (imsi1.isPresent() && imsi2.isPresent()) {
            return imsi1.get().equals(imsi2.get());
        }
        return false;
    }

    /**
     * Get the count of known SUPI→IMSI mappings.
     */
    public int getSupiMappingCount() {
        return supiToImsi.size();
    }

    /**
     * Get all known SUPIs.
     */
    public Set<String> getKnownSupis() {
        return supiToImsi.keySet();
    }

    // ── Internal helpers ──────────────────────────────────────────

    /**
     * Normalize SUPI to lowercase canonical form.
     * Per 3GPP TS 23.003: SUPI containing IMSI = "imsi-{MCC}{MNC}{MSIN}"
     */
    private String normalizeSupi(String supi) {
        if (supi == null) return null;
        String trimmed = supi.trim();

        // If it's raw digits (legacy IMSI format), prefix with "imsi-"
        if (trimmed.matches("\\d{14,15}")) {
            return "imsi-" + trimmed;
        }

        return trimmed.toLowerCase();
    }

    /**
     * Extract the IMSI digit string from a SUPI.
     * SUPI format for IMSI-based: "imsi-{MCC}{MNC}{MSIN}"
     *
     * @param supi normalized SUPI string
     * @return IMSI digits, or null if not IMSI-based SUPI
     */
    private String extractImsiFromSupi(String supi) {
        if (supi == null) return null;

        String lower = supi.toLowerCase().trim();
        if (lower.startsWith("imsi-")) {
            String digits = lower.substring(5);
            if (digits.matches("\\d{14,15}")) {
                return digits;
            }
        }

        // Raw digits (already an IMSI)
        if (lower.matches("\\d{14,15}")) {
            return lower;
        }

        // NAI-based SUPI (e.g., "nai-user@realm") — cannot extract IMSI
        if (lower.startsWith("nai-")) {
            log.debug("NAI-based SUPI cannot be resolved to IMSI: {}", supi);
            return null;
        }

        return null;
    }
}
