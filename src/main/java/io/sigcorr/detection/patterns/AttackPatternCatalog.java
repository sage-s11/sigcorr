package io.sigcorr.detection.patterns;

import io.sigcorr.core.model.SignalingOperation;

import java.time.Duration;
import java.util.*;

/**
 * Catalog of known cross-interface attack patterns.
 *
 * These patterns are derived from published telecom security research:
 * - ENEA AdaptiveMobile threat reports
 * - GSMA IR.82 (SS7 Security Monitoring Guidelines)
 * - GSMA FS.11 (SS7/Diameter Interconnect Security)
 * - SRLabs "Locating Mobile Phones using SS7" (2014)
 * - Positive Technologies "SS7 Vulnerabilities and Attack Exposure" reports
 *
 * Each pattern represents a documented multi-step attack that requires
 * cross-interface correlation to detect reliably.
 */
public final class AttackPatternCatalog {

    private AttackPatternCatalog() {} // No instances

    /**
     * ATTACK 9: Diameter Reconnaissance + GTP Session Hijack
     *
     * Cross-protocol: Diameter AIR (authentication probe) followed by
     * GTP-C Create-Session targeting the same IMSI. The attacker probes
     * the subscriber via Diameter, then establishes a data session via GTP.
     */
    public static AttackPattern diameterReconWithSession() {
        return AttackPattern.builder()
                .patternId("ATK-009")
                .name("Diameter Recon + GTP Session Hijack")
                .description("Diameter Authentication-Information-Request probes subscriber, "
                        + "followed by GTP-C Create-Session-Request for the same IMSI. "
                        + "Cross-protocol reconnaissance leading to session establishment.")
                .severity(AttackPattern.Severity.CRITICAL)
                .maxWindow(Duration.ofMinutes(5))
                .requireSameSource(false)
                .mitreTechniques(Set.of("T1430", "T1565"))
                .addStep(1, SignalingOperation.DIA_AUTH_INFO_REQUEST)
                .addStep(2, SignalingOperation.GTP_CREATE_SESSION_REQUEST)
                .build();
    }

    /**
     * ATTACK 10: Diameter Location Hijack
     *
     * Diameter AIR followed by ULR — the attacker probes authentication
     * then re-registers the subscriber to their own MME.
     */
    public static AttackPattern diameterLocationHijack() {
        return AttackPattern.builder()
                .patternId("ATK-010")
                .name("Diameter Location Hijack")
                .description("Diameter Authentication-Information-Request followed by "
                        + "Update-Location-Request for the same IMSI from the same origin. "
                        + "The attacker probes auth vectors then re-registers the subscriber.")
                .severity(AttackPattern.Severity.CRITICAL)
                .maxWindow(Duration.ofSeconds(120))
                .requireSameSource(true)
                .mitreTechniques(Set.of("T1636"))
                .addStep(1, SignalingOperation.DIA_AUTH_INFO_REQUEST)
                .addStep(2, SignalingOperation.DIA_UPDATE_LOCATION_REQUEST)
                .build();
    }

    /**
     * Get all built-in attack patterns.
     */
    public static List<AttackPattern> getAllPatterns() {
        return List.of(
                silentLocationTracking(),
                interceptionSetup(),
                trackingWithSessionCorrelation(),
                imsiHarvestingSweep(),
                diameterSpoofWithSs7Fallback(),
                subscriberDenialOfService(),
                callInterceptionViaForwarding(),
                crossProtocolReconnaissance(),
                diameterReconWithSession(),
                diameterLocationHijack()
        );
    }

    /**
     * ATTACK 1: Silent Location Tracking
     *
     * The attacker queries the network to locate a subscriber without their knowledge.
     * Step 1: SendRoutingInfo reveals MSISDN→IMSI mapping and serving MSC/VLR
     * Step 2: ProvideSubscriberInfo reveals Cell-ID (physical location)
     *
     * Cross-interface variant adds Diameter ULR to re-register and trigger paging.
     *
     * GSMA category: Location Tracking
     * MITRE: T1430 (Location Tracking)
     */
    public static AttackPattern silentLocationTracking() {
        return AttackPattern.builder()
                .patternId("ATK-001")
                .name("Silent Location Tracking")
                .description("Attacker queries subscriber location across MAP interfaces. " +
                        "SendRoutingInfo maps MSISDN to IMSI and serving node, " +
                        "followed by ProvideSubscriberInfo to obtain Cell-ID. " +
                        "This reveals the subscriber's physical location without any " +
                        "notification or consent.")
                .severity(AttackPattern.Severity.HIGH)
                .maxWindow(Duration.ofSeconds(60))
                .requireSameSource(true)
                .mitreTechniques(Set.of("T1430"))
                .addStep(1, SignalingOperation.MAP_SEND_ROUTING_INFO)
                .addStep(2, SignalingOperation.MAP_PROVIDE_SUBSCRIBER_INFO)
                .build();
    }

    /**
     * ATTACK 2: Interception Setup (Call/SMS Redirect)
     *
     * The attacker modifies the subscriber's profile to redirect calls/SMS.
     * Step 1: SendRoutingInfo to discover current routing
     * Step 2: InsertSubscriberData to modify forwarding/MSC address
     * Step 3: (Optional) Diameter UpdateLocation to re-register to attacker node
     *
     * This is the classic SS7 interception attack used by nation-state actors.
     *
     * GSMA category: Interception
     * MITRE: T1123 (Audio Capture), T1636 (Adversary-in-the-Middle)
     */
    public static AttackPattern interceptionSetup() {
        return AttackPattern.builder()
                .patternId("ATK-002")
                .name("Interception Setup")
                .description("Attacker modifies subscriber routing to redirect calls/SMS. " +
                        "SendRoutingInfo reveals current routing, InsertSubscriberData " +
                        "changes the forwarding target, and optionally a Diameter " +
                        "UpdateLocation re-registers the subscriber to the attacker's node. " +
                        "This enables call/SMS interception.")
                .severity(AttackPattern.Severity.CRITICAL)
                .maxWindow(Duration.ofMinutes(2))
                .requireSameSource(true)
                .mitreTechniques(Set.of("T1123", "T1636"))
                .addStep(1, SignalingOperation.MAP_SEND_ROUTING_INFO)
                .addStep(2, SignalingOperation.MAP_INSERT_SUBSCRIBER_DATA)
                .addStep(3, SignalingOperation.DIA_UPDATE_LOCATION_REQUEST, false)
                .build();
    }

    /**
     * ATTACK 3: Tracking with Session Correlation
     *
     * Cross-protocol attack: SS7 reconnaissance followed by GTP session
     * establishment. The attacker maps the subscriber via MAP, then
     * establishes a data session via GTP-C targeting the same IMSI.
     *
     * This cross-protocol pattern is invisible to single-interface monitors.
     *
     * GSMA category: Tracking + Session Hijacking
     */
    public static AttackPattern trackingWithSessionCorrelation() {
        return AttackPattern.builder()
                .patternId("ATK-003")
                .name("Tracking with Session Correlation")
                .description("Cross-protocol attack combining SS7 reconnaissance with " +
                        "GTP-C session establishment. MAP SendRoutingInfo reveals " +
                        "subscriber identity and routing, followed by GTP Create-Session " +
                        "targeting the same IMSI. This enables data interception " +
                        "following initial location discovery.")
                .severity(AttackPattern.Severity.CRITICAL)
                .maxWindow(Duration.ofMinutes(5))
                .requireSameSource(false) // Different protocols, likely different source nodes
                .mitreTechniques(Set.of("T1430", "T1565"))
                .addStep(1, SignalingOperation.MAP_SEND_ROUTING_INFO)
                .addStep(2, SignalingOperation.GTP_CREATE_SESSION_REQUEST)
                .build();
    }

    /**
     * ATTACK 4: IMSI Harvesting Sweep
     *
     * The attacker sends SendRoutingInfo for many MSISDNs in rapid succession,
     * mapping phone numbers to IMSIs. This is a precursor to targeted attacks.
     *
     * Detected not by a single pattern match but by volume: N SendRoutingInfo
     * requests from the same source within T seconds targeting different subscribers.
     *
     * Note: This pattern matches per-subscriber (2 SRI from same source for same target),
     * but the CorrelationEngine also performs source-level volume analysis.
     *
     * GSMA category: Reconnaissance / Enumeration
     */
    public static AttackPattern imsiHarvestingSweep() {
        return AttackPattern.builder()
                .patternId("ATK-004")
                .name("IMSI Harvesting (Repeated Query)")
                .description("Same subscriber queried via SendRoutingInfo multiple times " +
                        "in rapid succession, possibly with ProvideSubscriberInfo. " +
                        "Indicates persistent tracking or identity harvesting. " +
                        "Source-level sweep detection is handled separately by volume analysis.")
                .severity(AttackPattern.Severity.MEDIUM)
                .maxWindow(Duration.ofMinutes(10))
                .requireSameSource(true)
                .mitreTechniques(Set.of("T1592"))
                .addStep(1, SignalingOperation.MAP_SEND_ROUTING_INFO)
                .addStep(2, SignalingOperation.MAP_SEND_ROUTING_INFO)
                .build();
    }

    /**
     * ATTACK 5: Diameter Spoofing with SS7 Fallback
     *
     * Attacker attempts authentication on the Diameter S6a interface;
     * when rejected, falls back to SS7 MAP SendAuthenticationInfo.
     * This protocol downgrade exploits the trust boundary between
     * 4G (Diameter) and 2G/3G (SS7) networks.
     *
     * GSMA category: Protocol Downgrade / Authentication Bypass
     */
    public static AttackPattern diameterSpoofWithSs7Fallback() {
        return AttackPattern.builder()
                .patternId("ATK-005")
                .name("Diameter-to-SS7 Authentication Downgrade")
                .description("Attacker sends Diameter Authentication-Information-Request " +
                        "which is rejected, then falls back to SS7 MAP " +
                        "SendAuthenticationInfo for the same subscriber. " +
                        "This exploits the weaker authentication controls in " +
                        "legacy SS7 compared to Diameter.")
                .severity(AttackPattern.Severity.HIGH)
                .maxWindow(Duration.ofSeconds(120))
                .requireSameSource(false) // Cross-protocol, different source formats
                .mitreTechniques(Set.of("T1562"))
                .addStep(1, SignalingOperation.DIA_AUTH_INFO_REQUEST)
                .addStep(2, SignalingOperation.MAP_SEND_AUTH_INFO)
                .build();
    }

    /**
     * ATTACK 6: Subscriber Denial of Service
     *
     * Attacker cancels subscriber's location registration, causing DoS.
     * Step 1: CancelLocation purges subscriber from VLR/MME
     * Step 2: DeleteSubscriberData removes profile
     *
     * GSMA category: Denial of Service
     */
    public static AttackPattern subscriberDenialOfService() {
        return AttackPattern.builder()
                .patternId("ATK-006")
                .name("Subscriber Denial of Service")
                .description("Attacker cancels subscriber location registration and " +
                        "deletes subscriber data, causing service denial. " +
                        "The subscriber is disconnected from the network.")
                .severity(AttackPattern.Severity.HIGH)
                .maxWindow(Duration.ofSeconds(30))
                .requireSameSource(true)
                .mitreTechniques(Set.of("T1499"))
                .addStep(1, SignalingOperation.MAP_CANCEL_LOCATION)
                .addStep(2, SignalingOperation.MAP_DELETE_SUBSCRIBER_DATA)
                .build();
    }

    /**
     * ATTACK 7: Call Interception via Forwarding
     *
     * Attacker sets up unconditional call forwarding via supplementary services.
     * Step 1: RegisterSS to register forwarding to attacker number
     * Step 2: ActivateSS to activate the forwarding
     *
     * GSMA category: Interception
     */
    public static AttackPattern callInterceptionViaForwarding() {
        return AttackPattern.builder()
                .patternId("ATK-007")
                .name("Call Interception via Forwarding")
                .description("Attacker registers and activates call forwarding " +
                        "to redirect all calls to an interception point. " +
                        "RegisterSS sets the forwarding number, ActivateSS enables it.")
                .severity(AttackPattern.Severity.CRITICAL)
                .maxWindow(Duration.ofSeconds(60))
                .requireSameSource(true)
                .mitreTechniques(Set.of("T1123"))
                .addStep(1, SignalingOperation.MAP_REGISTER_SS)
                .addStep(2, SignalingOperation.MAP_ACTIVATE_SS)
                .build();
    }

    /**
     * ATTACK 8: Cross-Protocol Reconnaissance
     *
     * Attacker performs reconnaissance across both MAP and Diameter,
     * querying subscriber info via MAP then requesting authentication
     * vectors via Diameter for the same subscriber.
     *
     * GSMA category: Reconnaissance / Pre-attack
     */
    public static AttackPattern crossProtocolReconnaissance() {
        return AttackPattern.builder()
                .patternId("ATK-008")
                .name("Cross-Protocol Reconnaissance")
                .description("Attacker combines MAP routing queries with Diameter " +
                        "authentication requests targeting the same subscriber. " +
                        "This cross-protocol reconnaissance gathers both routing " +
                        "information and authentication material.")
                .severity(AttackPattern.Severity.HIGH)
                .maxWindow(Duration.ofMinutes(3))
                .requireSameSource(false)
                .mitreTechniques(Set.of("T1592", "T1589"))
                .addStep(1, SignalingOperation.MAP_SEND_ROUTING_INFO)
                .addStep(2, SignalingOperation.DIA_AUTH_INFO_REQUEST)
                .build();
    }
}
