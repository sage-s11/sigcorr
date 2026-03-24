package io.sigcorr.core.identity;

import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Represents a telecom subscriber identity used for cross-interface correlation.
 *
 * The fundamental insight of SigCorr is that attacks spanning multiple protocol
 * interfaces target the SAME subscriber. The subscriber identity (IMSI and/or MSISDN)
 * is the join key that links events across SS7, Diameter, and GTP-C.
 *
 * IMSI (International Mobile Subscriber Identity): 15-digit identifier stored on SIM.
 *   Format: MCC (3 digits) + MNC (2-3 digits) + MSIN (9-10 digits)
 *
 * MSISDN (Mobile Station International Subscriber Directory Number): The phone number.
 *   Format: CC (1-3 digits) + NDC + SN (up to 15 digits total)
 *
 * Not all signaling messages contain both identifiers. MAP SendRoutingInfo uses MSISDN
 * as input and returns IMSI. The identity resolver maintains the IMSI↔MSISDN mapping
 * learned from observed signaling.
 */
public final class SubscriberIdentity {

    private static final Pattern IMSI_PATTERN = Pattern.compile("^\\d{14,15}$");
    private static final Pattern MSISDN_PATTERN = Pattern.compile("^\\d{7,15}$");

    private final String imsi;
    private final String msisdn;

    private SubscriberIdentity(String imsi, String msisdn) {
        this.imsi = imsi;
        this.msisdn = msisdn;
    }

    /**
     * Create identity from IMSI only.
     */
    public static SubscriberIdentity fromImsi(String imsi) {
        validateImsi(imsi);
        return new SubscriberIdentity(imsi, null);
    }

    /**
     * Create identity from MSISDN only.
     */
    public static SubscriberIdentity fromMsisdn(String msisdn) {
        validateMsisdn(msisdn);
        return new SubscriberIdentity(null, msisdn);
    }

    /**
     * Create identity from both IMSI and MSISDN.
     */
    public static SubscriberIdentity fromBoth(String imsi, String msisdn) {
        validateImsi(imsi);
        validateMsisdn(msisdn);
        return new SubscriberIdentity(imsi, msisdn);
    }

    /**
     * Create identity from whichever identifiers are available.
     * At least one must be non-null.
     */
    public static SubscriberIdentity of(String imsi, String msisdn) {
        if (imsi == null && msisdn == null) {
            throw new IllegalArgumentException("At least one of IMSI or MSISDN must be provided");
        }
        if (imsi != null) validateImsi(imsi);
        if (msisdn != null) validateMsisdn(msisdn);
        return new SubscriberIdentity(imsi, msisdn);
    }

    public Optional<String> getImsi() { return Optional.ofNullable(imsi); }
    public Optional<String> getMsisdn() { return Optional.ofNullable(msisdn); }
    public boolean hasImsi() { return imsi != null; }
    public boolean hasMsisdn() { return msisdn != null; }

    /**
     * Extract MCC (Mobile Country Code) from IMSI.
     * First 3 digits of IMSI.
     */
    public Optional<String> getMcc() {
        return getImsi().map(i -> i.substring(0, 3));
    }

    /**
     * Extract MNC (Mobile Network Code) from IMSI.
     * Digits 4-5 or 4-6 of IMSI (2 or 3 digit MNC).
     * Uses 2-digit MNC by default; caller should use MCC-specific lookup for accuracy.
     */
    public Optional<String> getMnc(int mncLength) {
        if (mncLength != 2 && mncLength != 3) {
            throw new IllegalArgumentException("MNC length must be 2 or 3");
        }
        return getImsi().map(i -> i.substring(3, 3 + mncLength));
    }

    /**
     * Merge two identities that are known to represent the same subscriber.
     * This happens when we learn the IMSI↔MSISDN mapping from signaling.
     * For example, MAP SendRoutingInfo contains MSISDN in the request and
     * IMSI in the response — we merge them.
     */
    public SubscriberIdentity merge(SubscriberIdentity other) {
        String mergedImsi = this.imsi != null ? this.imsi : other.imsi;
        String mergedMsisdn = this.msisdn != null ? this.msisdn : other.msisdn;

        // Conflict check: if both have IMSI, they must match
        if (this.imsi != null && other.imsi != null && !this.imsi.equals(other.imsi)) {
            throw new IdentityConflictException(
                    "IMSI conflict: " + this.imsi + " vs " + other.imsi);
        }
        if (this.msisdn != null && other.msisdn != null && !this.msisdn.equals(other.msisdn)) {
            throw new IdentityConflictException(
                    "MSISDN conflict: " + this.msisdn + " vs " + other.msisdn);
        }

        return new SubscriberIdentity(mergedImsi, mergedMsisdn);
    }

    /**
     * Returns the best available identifier for correlation.
     * Prefers IMSI (globally unique) over MSISDN (can be ported).
     */
    public String getCorrelationKey() {
        if (imsi != null) return "IMSI:" + imsi;
        return "MSISDN:" + msisdn;
    }

    /**
     * Check if this identity could match another (overlapping identifiers).
     */
    public boolean couldMatch(SubscriberIdentity other) {
        if (this.imsi != null && other.imsi != null) {
            return this.imsi.equals(other.imsi);
        }
        if (this.msisdn != null && other.msisdn != null) {
            return this.msisdn.equals(other.msisdn);
        }
        // Can't determine — no overlapping identifier types
        return false;
    }

    private static void validateImsi(String imsi) {
        if (imsi == null || !IMSI_PATTERN.matcher(imsi).matches()) {
            throw new IllegalArgumentException(
                    "Invalid IMSI (must be 14-15 digits): " + imsi);
        }
    }

    private static void validateMsisdn(String msisdn) {
        if (msisdn == null || !MSISDN_PATTERN.matcher(msisdn).matches()) {
            throw new IllegalArgumentException(
                    "Invalid MSISDN (must be 7-15 digits): " + msisdn);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SubscriberIdentity that = (SubscriberIdentity) o;
        return Objects.equals(imsi, that.imsi) && Objects.equals(msisdn, that.msisdn);
    }

    @Override
    public int hashCode() {
        return Objects.hash(imsi, msisdn);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("Subscriber[");
        if (imsi != null) sb.append("IMSI=").append(imsi);
        if (imsi != null && msisdn != null) sb.append(", ");
        if (msisdn != null) sb.append("MSISDN=").append(msisdn);
        sb.append("]");
        return sb.toString();
    }

    /**
     * Thrown when merging two identities reveals conflicting data,
     * which itself may indicate an attack (identity spoofing).
     */
    public static class IdentityConflictException extends RuntimeException {
        public IdentityConflictException(String message) {
            super(message);
        }
    }
}
