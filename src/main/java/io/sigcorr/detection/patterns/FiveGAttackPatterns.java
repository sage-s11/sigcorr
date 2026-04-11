package io.sigcorr.detection.patterns;

import io.sigcorr.core.model.SignalingOperation;
import java.time.Duration;
import java.util.List;
import java.util.Set;

/**
 * 5G NAS / NGAP / PFCP attack patterns for SigCorr.
 *
 * These patterns detect attacks that exploit 5G-specific interfaces
 * (NAS-5GS, NGAP, PFCP) as well as cross-generation attacks that
 * chain 5G operations with legacy SS7/MAP and Diameter.
 *
 * Derived from published research:
 * - 3GPP TS 33.501 (5G Security Architecture)
 * - ENISA 5G Threat Landscape (2019, 2021)
 * - AdaptiveMobile "Simjacker" and 5G security reports
 * - Hu & Weng "Formal Analysis of 5G Authentication" (CCS 2019)
 * - Hussain et al. "5GReasoner: A Property-Directed Security and
 *   Privacy Analysis Framework for 5G Cellular Network Protocol" (CCS 2019)
 * - GSMA FS.40 (5G Security Considerations)
 *
 * Pattern IDs: ATK-023 through ATK-029
 * (ATK-001..ATK-022 are legacy SS7/Diameter/GTP patterns in AttackPatternCatalog)
 */
public class FiveGAttackPatterns {

    private FiveGAttackPatterns() {}

    /**
     * Returns all 7 5G attack patterns.
     */
    public static List<AttackPattern> all() {
        return List.of(
            nasNullCipherDowngrade(),
            nasRegistrationFlood(),
            nasForcedDeregistration(),
            nasAuthFailureHarvesting(),
            pfcpSessionHijack(),
            ngapRogueHandover(),
            crossGenerationDowngrade()
        );
    }

    // ──────────────────────────────────────────────────────────────
    //  ATK-023: NAS Null-Cipher Downgrade
    // ──────────────────────────────────────────────────────────────

    /**
     * ATTACK 23: NAS Null-Cipher Downgrade (5G Security Bypass)
     *
     * Attacker forces the UE to accept null ciphering (5G-EA0) or null
     * integrity (5G-IA0) through a manipulated SecurityModeCommand.
     * When the UE rejects (SecurityModeReject), it indicates either a
     * legitimate misconfiguration or active downgrade attempt.
     *
     * The SecurityModeCommand→SecurityModeReject sequence within a tight
     * window is abnormal in production 5G networks — legitimate SMC
     * exchanges should succeed. Repeated failures from the same gNB
     * strongly indicate a rogue or compromised base station.
     *
     * 3GPP reference: TS 33.501 §6.7.2 (NAS security mode control)
     * MITRE: T1557 (Adversary-in-the-Middle), FGT1557 (5G variant)
     * GSMA: FS.40 §5.2 (Cipher negotiation attacks)
     */
    public static AttackPattern nasNullCipherDowngrade() {
        return AttackPattern.builder()
            .patternId("ATK-023")
            .name("NAS Null-Cipher Downgrade")
            .description("5G NAS security mode attack: SecurityModeCommand proposes "
                + "null ciphering (5G-EA0) or null integrity (5G-IA0), followed by "
                + "SecurityModeReject from UE. Indicates rogue gNB or active downgrade "
                + "attempt. Legitimate SMC exchanges should not fail in production.")
            .severity(AttackPattern.Severity.HIGH)
            .maxWindow(Duration.ofSeconds(10))
            .mitreTechniques(Set.of("T1557", "FGT1557"))
            .requireSameSource(true)
            .addStep(1, SignalingOperation.NAS_5G_SECURITY_MODE_COMMAND)
            .addStep(2, SignalingOperation.NAS_5G_SECURITY_MODE_REJECT)
            .build();
    }

    // ──────────────────────────────────────────────────────────────
    //  ATK-024: NAS Registration Flood
    // ──────────────────────────────────────────────────────────────

    /**
     * ATTACK 24: NAS Registration Flood (AMF Resource Exhaustion)
     *
     * Rapid burst of 5G NAS RegistrationRequest messages targeting the
     * same AMF. In legitimate operation, a subscriber sends one
     * RegistrationRequest per attach/mobility event. Rapid repeated
     * registrations from the same subscriber indicate either:
     *   - A rogue device flooding the AMF
     *   - An IMSI catcher forcing repeated re-registrations
     *   - A DoS attack exhausting AMF connection resources
     *
     * This pattern detects per-subscriber floods (same SUPI seen in
     * two RegistrationRequests within a short window). Source-level
     * volume analysis for multi-subscriber floods is handled separately
     * by the CorrelationEngine.
     *
     * 3GPP reference: TS 24.501 §5.5.1 (Registration procedure)
     * MITRE: T1499 (Endpoint Denial of Service)
     */
    public static AttackPattern nasRegistrationFlood() {
        return AttackPattern.builder()
            .patternId("ATK-024")
            .name("NAS Registration Flood")
            .description("Rapid repeated 5G NAS RegistrationRequest for the same subscriber. "
                + "Legitimate operation produces one registration per attach event. "
                + "Repeated registrations within seconds indicate AMF resource exhaustion, "
                + "rogue device activity, or IMSI catcher forcing re-registration.")
            .severity(AttackPattern.Severity.HIGH)
            .maxWindow(Duration.ofSeconds(15))
            .mitreTechniques(Set.of("T1499"))
            .requireSameSource(true)
            .addStep(1, SignalingOperation.NAS_5G_REGISTRATION_REQUEST)
            .addStep(2, SignalingOperation.NAS_5G_REGISTRATION_REQUEST)
            .build();
    }

    // ──────────────────────────────────────────────────────────────
    //  ATK-025: Forced Deregistration (Network-Initiated)
    // ──────────────────────────────────────────────────────────────

    /**
     * ATTACK 25: Forced Deregistration (5G to Legacy Bidding-Down)
     *
     * Subscriber is forcibly deregistered from 5G via a spoofed
     * network-initiated DeregistrationRequest, then appears on the
     * legacy SS7/MAP network via UpdateLocation. This forces the
     * subscriber from a secure 5G connection to 2G/3G where
     * interception is trivially possible (A5/1 cracking, fake BTS).
     *
     * The cross-generation nature of this attack (5G NAS → SS7 MAP)
     * makes it invisible to single-protocol monitors. SigCorr's
     * IMSI↔MSISDN identity correlation across protocol boundaries
     * is required to detect this pattern.
     *
     * 3GPP reference: TS 24.501 §5.5.2.3 (Network-initiated deregistration)
     * MITRE: T1562.001 (Impair Defenses: Disable or Modify Tools)
     * FGT: FGT1600.501 (5G Bidding Down)
     * GSMA: FS.40 §5.4 (Inter-generation attack vectors)
     */
    public static AttackPattern nasForcedDeregistration() {
        return AttackPattern.builder()
            .patternId("ATK-025")
            .name("Forced Deregistration (Bidding-Down)")
            .description("Subscriber forcibly deregistered from 5G then appears on legacy "
                + "SS7/MAP via UpdateLocation. Forces subscriber from secure 5G to "
                + "vulnerable 2G/3G where interception is trivial. Cross-generation "
                + "attack invisible to single-protocol monitors.")
            .severity(AttackPattern.Severity.CRITICAL)
            .maxWindow(Duration.ofSeconds(120))
            .mitreTechniques(Set.of("T1562.001", "FGT1600.501"))
            .requireSameSource(false)  // Cross-protocol: 5G NAS and SS7 MAP have different source nodes
            .addStep(1, SignalingOperation.NAS_5G_DEREGISTRATION_REQUEST_NW)
            .addStep(2, SignalingOperation.MAP_UPDATE_LOCATION)
            .build();
    }

    // ──────────────────────────────────────────────────────────────
    //  ATK-026: NAS Authentication Failure Harvesting
    // ──────────────────────────────────────────────────────────────

    /**
     * ATTACK 26: NAS Authentication Failure Harvesting
     *
     * Repeated AuthenticationRequest→AuthenticationFailure sequences
     * for the same subscriber. In 5G-AKA, an AuthenticationFailure
     * with cause "MAC failure" or "SYNCH failure" leaks information
     * about the subscriber's authentication state.
     *
     * An attacker with access to the N1 interface (rogue gNB, MitM
     * position) can replay or manipulate AuthenticationRequest messages
     * to harvest AUTN/RAND pairs and observe failure responses,
     * potentially enabling key material extraction or subscriber
     * fingerprinting.
     *
     * A single AuthRequest→AuthFailure can be legitimate (e.g., SQN
     * resync). Two such sequences within a short window strongly
     * indicates active probing.
     *
     * 3GPP reference: TS 33.501 §6.1.3 (5G-AKA procedures)
     * MITRE: T1528 (Steal Application Access Token — adapted for auth vectors)
     */
    public static AttackPattern nasAuthFailureHarvesting() {
        return AttackPattern.builder()
            .patternId("ATK-026")
            .name("NAS Auth Failure Harvesting")
            .description("Repeated 5G NAS AuthenticationRequest followed by "
                + "AuthenticationFailure for the same subscriber. Indicates active "
                + "probing of authentication state, possibly harvesting AUTN/RAND "
                + "pairs for key extraction or subscriber fingerprinting. Single "
                + "failures can be legitimate (SQN resync); repeated failures are not.")
            .severity(AttackPattern.Severity.HIGH)
            .maxWindow(Duration.ofSeconds(30))
            .mitreTechniques(Set.of("T1528", "T1556"))
            .requireSameSource(true)
            .addStep(1, SignalingOperation.NAS_5G_AUTHENTICATION_REQUEST)
            .addStep(2, SignalingOperation.NAS_5G_AUTH_FAILURE)
            .build();
    }

    // ──────────────────────────────────────────────────────────────
    //  ATK-027: PFCP Session Hijack
    // ──────────────────────────────────────────────────────────────

    /**
     * ATTACK 27: PFCP Session Hijack (User Plane Redirection)
     *
     * Unauthorized PFCP session modification redirecting subscriber
     * data traffic. In the 5G SBA, the SMF controls the UPF via PFCP.
     * An attacker who gains access to the N4 interface can:
     *   - Establish a rogue PFCP session (SessionEstablishmentRequest)
     *   - Modify forwarding rules (SessionModificationRequest)
     *   - Redirect all user-plane traffic through their own UPF
     *
     * The establishment→modification sequence from an unexpected
     * PFCP node_id is the key indicator. Legitimate SMF→UPF
     * communication uses known node pairs.
     *
     * 3GPP reference: TS 29.244 (PFCP protocol)
     * MITRE: T1565 (Data Manipulation), FGT5012 (5G User Plane compromise)
     */
    public static AttackPattern pfcpSessionHijack() {
        return AttackPattern.builder()
            .patternId("ATK-027")
            .name("PFCP Session Hijack")
            .description("Unauthorized PFCP session establishment followed by modification, "
                + "redirecting subscriber data traffic through rogue UPF. Attacker gains "
                + "N4 interface access, establishes session, then modifies forwarding "
                + "rules. Legitimate PFCP uses known SMF↔UPF node pairs.")
            .severity(AttackPattern.Severity.CRITICAL)
            .maxWindow(Duration.ofSeconds(60))
            .mitreTechniques(Set.of("T1565", "FGT5012"))
            .requireSameSource(false)
            .addStep(1, SignalingOperation.PFCP_SESSION_ESTABLISHMENT_REQ)
            .addStep(2, SignalingOperation.PFCP_SESSION_MODIFICATION_REQ)
            .build();
    }

    // ──────────────────────────────────────────────────────────────
    //  ATK-028: NGAP Rogue Handover (gNB Hijack)
    // ──────────────────────────────────────────────────────────────

    /**
     * ATTACK 28: NGAP Rogue Handover (gNB Hijack)
     *
     * Suspicious NGAP handover to a rogue gNB followed by GTP tunnel
     * modification. The handover redirects the UE's radio connection,
     * and the subsequent GTP ModifyBearerRequest reroutes the data
     * tunnel — giving the attacker full MitM position.
     *
     * Detection key: HandoverRequired from a legitimate gNB to an
     * unknown/suspicious target, followed by GTP tunnel modification.
     * Cross-protocol (NGAP → GTPv2-C) correlation is required.
     *
     * 3GPP reference: TS 38.413 §8.4 (NGAP Handover procedures)
     * MITRE: T1557 (Adversary-in-the-Middle), FGT1599 (5G RAN compromise)
     */
    public static AttackPattern ngapRogueHandover() {
        return AttackPattern.builder()
            .patternId("ATK-028")
            .name("NGAP Rogue Handover")
            .description("Suspicious NGAP handover to rogue gNB followed by GTP tunnel "
                + "modification. Redirects UE radio connection and reroutes data tunnel, "
                + "giving attacker full MitM position. Cross-protocol detection required "
                + "(NGAP → GTPv2-C).")
            .severity(AttackPattern.Severity.CRITICAL)
            .maxWindow(Duration.ofSeconds(30))
            .mitreTechniques(Set.of("T1557", "FGT1599"))
            .requireSameSource(false)  // NGAP and GTP have different source entities
            .addStep(1, SignalingOperation.NGAP_HANDOVER_REQUIRED)
            .addStep(2, SignalingOperation.GTP_MODIFY_BEARER_REQUEST)
            .build();
    }

    // ──────────────────────────────────────────────────────────────
    //  ATK-029: Full Cross-Generation Downgrade Chain
    // ──────────────────────────────────────────────────────────────

    /**
     * ATTACK 29: Full Cross-Generation Downgrade Chain (5G → 4G → 2G)
     *
     * The most sophisticated cross-generation attack: a 3-protocol
     * downgrade spanning all generations:
     *   Step 1: 5G NAS DeregistrationRequest_NW — force subscriber off 5G
     *   Step 2: Diameter CancelLocationRequest — remove from 4G/MME
     *   Step 3: MAP SendRoutingInfo — attack on now-vulnerable 2G/3G
     *
     * Each step uses a different protocol interface, making this attack
     * completely invisible to any single-protocol monitor. Only
     * cross-protocol correlation with identity resolution (SUPI/IMSI
     * mapping) can detect the full chain.
     *
     * This is SigCorr's flagship cross-generation detection capability.
     *
     * 3GPP reference: TS 33.501 §5.2 (Interworking security)
     * MITRE: T1562.001, T1557, FGT1600.501
     * GSMA: FS.11 + FS.40 (cross-generation threat)
     */
    public static AttackPattern crossGenerationDowngrade() {
        return AttackPattern.builder()
            .patternId("ATK-029")
            .name("5G-to-Legacy Downgrade Chain")
            .description("Full 3-protocol downgrade chain: 5G NAS deregistration forces "
                + "subscriber off 5G, Diameter CancelLocation removes from 4G, "
                + "MAP SendRoutingInfo attacks on now-vulnerable 2G/3G. Each step uses "
                + "a different protocol — invisible to single-protocol monitors. "
                + "Requires cross-protocol SUPI/IMSI identity correlation to detect.")
            .severity(AttackPattern.Severity.CRITICAL)
            .maxWindow(Duration.ofSeconds(300))
            .mitreTechniques(Set.of("T1562.001", "T1557", "FGT1600.501"))
            .requireSameSource(false)  // Three different protocol sources
            .addStep(1, SignalingOperation.NAS_5G_DEREGISTRATION_REQUEST_NW)
            .addStep(2, SignalingOperation.DIA_CANCEL_LOCATION_REQUEST)
            .addStep(3, SignalingOperation.MAP_SEND_ROUTING_INFO)
            .build();
    }
}
