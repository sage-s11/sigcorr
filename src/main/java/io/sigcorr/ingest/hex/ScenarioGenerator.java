package io.sigcorr.ingest.hex;

import io.sigcorr.core.event.NetworkNode;
import io.sigcorr.core.event.SignalingEvent;
import io.sigcorr.core.identity.SubscriberIdentity;
import io.sigcorr.core.model.ProtocolInterface;
import io.sigcorr.core.model.SignalingOperation;

import java.time.Duration;
import java.time.Instant;
import java.util.*;

/**
 * Generates synthetic signaling event sequences for testing and validation.
 *
 * This is a critical component for two reasons:
 * 1. Testing: We can't run a live telecom core in a home lab, so we generate
 *    realistic event sequences that model known attack patterns.
 * 2. Validation: Security vendors use the same approach — synthetic scenario
 *    generation is the standard method for telecom security tool testing.
 *
 * Each scenario method generates a chronologically ordered list of SignalingEvents
 * representing a specific attack pattern, including both the attack events and
 * plausible background/legitimate traffic for realism.
 */
public class ScenarioGenerator {

    private static final String DEFAULT_FOREIGN_GT = "+491720000000";
    private static final String DEFAULT_HOME_GT = "+441234567890";
    private static final String DEFAULT_FOREIGN_DIA_HOST = "mme.foreign-operator.com";
    private static final String DEFAULT_FOREIGN_DIA_REALM = "foreign-operator.com";
    private static final String DEFAULT_HOME_DIA_HOST = "hss.home-network.com";
    private static final String DEFAULT_HOME_DIA_REALM = "home-network.com";
    private static final String DEFAULT_GTP_PEER = "10.99.0.1";

    private final Random random = new Random(42); // Deterministic for reproducible tests

    /**
     * Generate a silent location tracking attack sequence.
     * ATK-001: SRI → PSI targeting the same subscriber from the same foreign node.
     */
    public List<SignalingEvent> generateLocationTracking(String targetMsisdn, String targetImsi,
                                                         Instant baseTime) {
        List<SignalingEvent> events = new ArrayList<>();
        NetworkNode foreignNode = NetworkNode.fromGlobalTitle(DEFAULT_FOREIGN_GT);
        NetworkNode homeNode = NetworkNode.fromGlobalTitle(DEFAULT_HOME_GT);

        // Step 1: MAP SendRoutingInfo (MSISDN → IMSI + serving MSC)
        events.add(SignalingEvent.builder()
                .timestamp(baseTime)
                .protocolInterface(ProtocolInterface.SS7_MAP)
                .operation(SignalingOperation.MAP_SEND_ROUTING_INFO)
                .subscriber(SubscriberIdentity.fromMsisdn(targetMsisdn))
                .sourceNode(foreignNode)
                .destinationNode(homeNode)
                .direction(SignalingEvent.Direction.INBOUND)
                .parameters(Map.of(
                        "msisdn", targetMsisdn,
                        "messageType", "invoke",
                        "operationCode", "22"
                ))
                .build());

        // Step 1b: SRI Response (reveals IMSI)
        events.add(SignalingEvent.builder()
                .timestamp(baseTime.plusMillis(150))
                .protocolInterface(ProtocolInterface.SS7_MAP)
                .operation(SignalingOperation.MAP_SEND_ROUTING_INFO)
                .subscriber(SubscriberIdentity.fromBoth(targetImsi, targetMsisdn))
                .sourceNode(homeNode)
                .destinationNode(foreignNode)
                .direction(SignalingEvent.Direction.OUTBOUND)
                .parameters(Map.of(
                        "imsi", targetImsi,
                        "msisdn", targetMsisdn,
                        "messageType", "returnResult",
                        "operationCode", "22"
                ))
                .build());

        // Step 2: MAP ProvideSubscriberInfo (get location using IMSI)
        events.add(SignalingEvent.builder()
                .timestamp(baseTime.plusSeconds(3))
                .protocolInterface(ProtocolInterface.SS7_MAP)
                .operation(SignalingOperation.MAP_PROVIDE_SUBSCRIBER_INFO)
                .subscriber(SubscriberIdentity.fromImsi(targetImsi))
                .sourceNode(foreignNode)
                .destinationNode(homeNode)
                .direction(SignalingEvent.Direction.INBOUND)
                .parameters(Map.of(
                        "imsi", targetImsi,
                        "messageType", "invoke",
                        "operationCode", "71"
                ))
                .build());

        return events;
    }

    /**
     * Generate an interception setup attack sequence.
     * ATK-002: SRI → ISD → (optional) Diameter ULR.
     */
    public List<SignalingEvent> generateInterceptionSetup(String targetMsisdn, String targetImsi,
                                                          Instant baseTime) {
        List<SignalingEvent> events = new ArrayList<>();
        NetworkNode foreignNode = NetworkNode.fromGlobalTitle(DEFAULT_FOREIGN_GT);
        NetworkNode homeNode = NetworkNode.fromGlobalTitle(DEFAULT_HOME_GT);

        // Step 1: SRI
        events.add(SignalingEvent.builder()
                .timestamp(baseTime)
                .protocolInterface(ProtocolInterface.SS7_MAP)
                .operation(SignalingOperation.MAP_SEND_ROUTING_INFO)
                .subscriber(SubscriberIdentity.fromMsisdn(targetMsisdn))
                .sourceNode(foreignNode)
                .destinationNode(homeNode)
                .direction(SignalingEvent.Direction.INBOUND)
                .parameters(Map.of("msisdn", targetMsisdn, "messageType", "invoke", "operationCode", "22"))
                .build());

        // Step 2: InsertSubscriberData (modify forwarding to attacker MSC)
        events.add(SignalingEvent.builder()
                .timestamp(baseTime.plusSeconds(5))
                .protocolInterface(ProtocolInterface.SS7_MAP)
                .operation(SignalingOperation.MAP_INSERT_SUBSCRIBER_DATA)
                .subscriber(SubscriberIdentity.fromImsi(targetImsi))
                .sourceNode(foreignNode)
                .destinationNode(homeNode)
                .direction(SignalingEvent.Direction.INBOUND)
                .parameters(Map.of(
                        "imsi", targetImsi,
                        "msisdn", targetMsisdn,
                        "messageType", "invoke",
                        "operationCode", "7",
                        "forwardingMsc", DEFAULT_FOREIGN_GT
                ))
                .build());

        // Step 3: Diameter UpdateLocation (cross-protocol — re-register to attacker)
        events.add(SignalingEvent.builder()
                .timestamp(baseTime.plusSeconds(12))
                .protocolInterface(ProtocolInterface.DIAMETER_S6A)
                .operation(SignalingOperation.DIA_UPDATE_LOCATION_REQUEST)
                .subscriber(SubscriberIdentity.fromImsi(targetImsi))
                .sourceNode(NetworkNode.fromDiameterHost(DEFAULT_FOREIGN_DIA_HOST, DEFAULT_FOREIGN_DIA_REALM))
                .destinationNode(NetworkNode.fromDiameterHost(DEFAULT_HOME_DIA_HOST, DEFAULT_HOME_DIA_REALM))
                .direction(SignalingEvent.Direction.INBOUND)
                .parameters(Map.of(
                        "imsi", targetImsi,
                        "isRequest", "true",
                        "commandCode", "318",
                        "originHost", DEFAULT_FOREIGN_DIA_HOST,
                        "originRealm", DEFAULT_FOREIGN_DIA_REALM
                ))
                .build());

        return events;
    }

    /**
     * Generate a cross-protocol tracking + session attack.
     * ATK-003: MAP SRI → GTP-C Create-Session.
     */
    public List<SignalingEvent> generateTrackingWithSession(String targetMsisdn, String targetImsi,
                                                            Instant baseTime) {
        List<SignalingEvent> events = new ArrayList<>();
        NetworkNode foreignGt = NetworkNode.fromGlobalTitle(DEFAULT_FOREIGN_GT);
        NetworkNode homeGt = NetworkNode.fromGlobalTitle(DEFAULT_HOME_GT);
        NetworkNode gtpPeer = NetworkNode.fromGtpPeer(DEFAULT_GTP_PEER);

        // Step 1: MAP SRI
        events.add(SignalingEvent.builder()
                .timestamp(baseTime)
                .protocolInterface(ProtocolInterface.SS7_MAP)
                .operation(SignalingOperation.MAP_SEND_ROUTING_INFO)
                .subscriber(SubscriberIdentity.fromMsisdn(targetMsisdn))
                .sourceNode(foreignGt)
                .destinationNode(homeGt)
                .direction(SignalingEvent.Direction.INBOUND)
                .parameters(Map.of("msisdn", targetMsisdn, "messageType", "invoke", "operationCode", "22"))
                .build());

        // Step 2: GTP Create-Session (same IMSI, different protocol)
        events.add(SignalingEvent.builder()
                .timestamp(baseTime.plusSeconds(45))
                .protocolInterface(ProtocolInterface.GTPC_V2)
                .operation(SignalingOperation.GTP_CREATE_SESSION_REQUEST)
                .subscriber(SubscriberIdentity.fromBoth(targetImsi, targetMsisdn))
                .sourceNode(gtpPeer)
                .direction(SignalingEvent.Direction.INBOUND)
                .parameters(Map.of(
                        "imsi", targetImsi,
                        "msisdn", targetMsisdn,
                        "messageType", "32",
                        "apn", "internet.foreign.com",
                        "ratType", "6"
                ))
                .build());

        return events;
    }

    /**
     * Generate a Diameter-to-SS7 authentication downgrade attack.
     * ATK-005: Diameter AIR → MAP SendAuthInfo.
     */
    public List<SignalingEvent> generateAuthDowngrade(String targetImsi, Instant baseTime) {
        List<SignalingEvent> events = new ArrayList<>();

        // Step 1: Diameter Auth-Info Request
        events.add(SignalingEvent.builder()
                .timestamp(baseTime)
                .protocolInterface(ProtocolInterface.DIAMETER_S6A)
                .operation(SignalingOperation.DIA_AUTH_INFO_REQUEST)
                .subscriber(SubscriberIdentity.fromImsi(targetImsi))
                .sourceNode(NetworkNode.fromDiameterHost(DEFAULT_FOREIGN_DIA_HOST, DEFAULT_FOREIGN_DIA_REALM))
                .direction(SignalingEvent.Direction.INBOUND)
                .parameters(Map.of(
                        "imsi", targetImsi,
                        "isRequest", "true",
                        "commandCode", "316"
                ))
                .build());

        // Step 1b: Diameter Auth-Info Answer (rejected)
        events.add(SignalingEvent.builder()
                .timestamp(baseTime.plusMillis(200))
                .protocolInterface(ProtocolInterface.DIAMETER_S6A)
                .operation(SignalingOperation.DIA_AUTH_INFO_ANSWER)
                .subscriber(SubscriberIdentity.fromImsi(targetImsi))
                .direction(SignalingEvent.Direction.OUTBOUND)
                .parameters(Map.of(
                        "imsi", targetImsi,
                        "isRequest", "false",
                        "commandCode", "316",
                        "resultCode", "5012" // UNABLE_TO_COMPLY
                ))
                .build());

        // Step 2: SS7 MAP SendAuthenticationInfo (fallback to legacy)
        events.add(SignalingEvent.builder()
                .timestamp(baseTime.plusSeconds(8))
                .protocolInterface(ProtocolInterface.SS7_MAP)
                .operation(SignalingOperation.MAP_SEND_AUTH_INFO)
                .subscriber(SubscriberIdentity.fromImsi(targetImsi))
                .sourceNode(NetworkNode.fromGlobalTitle(DEFAULT_FOREIGN_GT))
                .direction(SignalingEvent.Direction.INBOUND)
                .parameters(Map.of(
                        "imsi", targetImsi,
                        "messageType", "invoke",
                        "operationCode", "56"
                ))
                .build());

        return events;
    }

    /**
     * Generate cross-protocol reconnaissance.
     * ATK-008: MAP SRI → Diameter AIR.
     */
    public List<SignalingEvent> generateCrossProtocolRecon(String targetMsisdn, String targetImsi,
                                                           Instant baseTime) {
        List<SignalingEvent> events = new ArrayList<>();

        // Step 1: MAP SRI request (MSISDN only)
        events.add(SignalingEvent.builder()
                .timestamp(baseTime)
                .protocolInterface(ProtocolInterface.SS7_MAP)
                .operation(SignalingOperation.MAP_SEND_ROUTING_INFO)
                .subscriber(SubscriberIdentity.fromMsisdn(targetMsisdn))
                .sourceNode(NetworkNode.fromGlobalTitle(DEFAULT_FOREIGN_GT))
                .direction(SignalingEvent.Direction.INBOUND)
                .parameters(Map.of("msisdn", targetMsisdn, "messageType", "invoke", "operationCode", "22"))
                .build());

        // Step 1b: SRI response reveals IMSI (links MSISDN↔IMSI)
        events.add(SignalingEvent.builder()
                .timestamp(baseTime.plusMillis(150))
                .protocolInterface(ProtocolInterface.SS7_MAP)
                .operation(SignalingOperation.MAP_SEND_ROUTING_INFO)
                .subscriber(SubscriberIdentity.fromBoth(targetImsi, targetMsisdn))
                .sourceNode(NetworkNode.fromGlobalTitle(DEFAULT_HOME_GT))
                .direction(SignalingEvent.Direction.OUTBOUND)
                .parameters(Map.of("imsi", targetImsi, "msisdn", targetMsisdn,
                        "messageType", "returnResult", "operationCode", "22"))
                .build());

        // Step 2: Diameter AIR (IMSI only — different protocol)
        events.add(SignalingEvent.builder()
                .timestamp(baseTime.plusSeconds(20))
                .protocolInterface(ProtocolInterface.DIAMETER_S6A)
                .operation(SignalingOperation.DIA_AUTH_INFO_REQUEST)
                .subscriber(SubscriberIdentity.fromImsi(targetImsi))
                .sourceNode(NetworkNode.fromDiameterHost(DEFAULT_FOREIGN_DIA_HOST, DEFAULT_FOREIGN_DIA_REALM))
                .direction(SignalingEvent.Direction.INBOUND)
                .parameters(Map.of(
                        "imsi", targetImsi,
                        "isRequest", "true",
                        "commandCode", "316"
                ))
                .build());

        return events;
    }

    /**
     * Generate subscriber DoS attack.
     * ATK-006: CancelLocation → DeleteSubscriberData.
     */
    public List<SignalingEvent> generateSubscriberDoS(String targetImsi, Instant baseTime) {
        List<SignalingEvent> events = new ArrayList<>();
        NetworkNode foreignNode = NetworkNode.fromGlobalTitle(DEFAULT_FOREIGN_GT);

        events.add(SignalingEvent.builder()
                .timestamp(baseTime)
                .protocolInterface(ProtocolInterface.SS7_MAP)
                .operation(SignalingOperation.MAP_CANCEL_LOCATION)
                .subscriber(SubscriberIdentity.fromImsi(targetImsi))
                .sourceNode(foreignNode)
                .direction(SignalingEvent.Direction.INBOUND)
                .parameters(Map.of("imsi", targetImsi, "messageType", "invoke", "operationCode", "3"))
                .build());

        events.add(SignalingEvent.builder()
                .timestamp(baseTime.plusSeconds(2))
                .protocolInterface(ProtocolInterface.SS7_MAP)
                .operation(SignalingOperation.MAP_DELETE_SUBSCRIBER_DATA)
                .subscriber(SubscriberIdentity.fromImsi(targetImsi))
                .sourceNode(foreignNode)
                .direction(SignalingEvent.Direction.INBOUND)
                .parameters(Map.of("imsi", targetImsi, "messageType", "invoke", "operationCode", "8"))
                .build());

        return events;
    }

    /**
     * Generate call interception via forwarding.
     * ATK-007: RegisterSS → ActivateSS.
     */
    public List<SignalingEvent> generateCallForwardingInterception(String targetMsisdn,
                                                                   Instant baseTime) {
        List<SignalingEvent> events = new ArrayList<>();
        NetworkNode foreignNode = NetworkNode.fromGlobalTitle(DEFAULT_FOREIGN_GT);

        events.add(SignalingEvent.builder()
                .timestamp(baseTime)
                .protocolInterface(ProtocolInterface.SS7_MAP)
                .operation(SignalingOperation.MAP_REGISTER_SS)
                .subscriber(SubscriberIdentity.fromMsisdn(targetMsisdn))
                .sourceNode(foreignNode)
                .direction(SignalingEvent.Direction.INBOUND)
                .parameters(Map.of("msisdn", targetMsisdn, "messageType", "invoke", "operationCode", "10"))
                .build());

        events.add(SignalingEvent.builder()
                .timestamp(baseTime.plusSeconds(1))
                .protocolInterface(ProtocolInterface.SS7_MAP)
                .operation(SignalingOperation.MAP_ACTIVATE_SS)
                .subscriber(SubscriberIdentity.fromMsisdn(targetMsisdn))
                .sourceNode(foreignNode)
                .direction(SignalingEvent.Direction.INBOUND)
                .parameters(Map.of("msisdn", targetMsisdn, "messageType", "invoke", "operationCode", "12"))
                .build());

        return events;
    }

    /**
     * Generate legitimate background traffic (not an attack).
     * Used to test that the engine doesn't produce false positives.
     */
    public List<SignalingEvent> generateLegitimateTraffic(int count, Instant baseTime) {
        List<SignalingEvent> events = new ArrayList<>();
        String[] legitimateOps = {"roaming-attach", "handover", "service-request"};

        for (int i = 0; i < count; i++) {
            String imsi = String.format("23410%010d", random.nextInt(1_000_000_000));
            String msisdn = String.format("4477%08d", random.nextInt(100_000_000));

            // Single operation — no pattern match possible
            SignalingOperation op = random.nextBoolean()
                    ? SignalingOperation.MAP_UPDATE_LOCATION
                    : SignalingOperation.DIA_UPDATE_LOCATION_REQUEST;

            ProtocolInterface iface = op.getProtocolInterface();

            events.add(SignalingEvent.builder()
                    .timestamp(baseTime.plusMillis(random.nextInt(300_000)))
                    .protocolInterface(iface)
                    .operation(op)
                    .subscriber(SubscriberIdentity.fromBoth(imsi, msisdn))
                    .sourceNode(iface.getFamily() == ProtocolInterface.ProtocolFamily.SS7
                            ? NetworkNode.fromGlobalTitle(DEFAULT_HOME_GT)
                            : NetworkNode.fromDiameterHost(DEFAULT_HOME_DIA_HOST, DEFAULT_HOME_DIA_REALM))
                    .direction(SignalingEvent.Direction.INTERNAL)
                    .parameters(Map.of("imsi", imsi, "msisdn", msisdn, "messageType", "invoke"))
                    .build());
        }

        events.sort(Comparator.comparing(SignalingEvent::getTimestamp));
        return events;
    }

    /**
     * Generate a mixed scenario: attacks hidden in legitimate traffic.
     */
    public MixedScenario generateMixedScenario(Instant baseTime) {
        List<SignalingEvent> allEvents = new ArrayList<>();
        List<String> expectedAttackIds = new ArrayList<>();

        // Background: 50 legitimate events
        allEvents.addAll(generateLegitimateTraffic(50, baseTime));

        // Attack 1: Location tracking at T+30s
        allEvents.addAll(generateLocationTracking("447712345678", "234101234567890",
                baseTime.plusSeconds(30)));
        expectedAttackIds.add("ATK-001");

        // Attack 2: Interception at T+120s
        allEvents.addAll(generateInterceptionSetup("447712345678", "234101234567890",
                baseTime.plusSeconds(120)));
        expectedAttackIds.add("ATK-002");

        // Attack 3: Cross-protocol recon on different subscriber at T+200s
        allEvents.addAll(generateCrossProtocolRecon("447798765432", "234109876543210",
                baseTime.plusSeconds(200)));
        expectedAttackIds.add("ATK-008");

        // More background
        allEvents.addAll(generateLegitimateTraffic(30, baseTime.plusSeconds(100)));

        // Sort everything chronologically
        allEvents.sort(Comparator.comparing(SignalingEvent::getTimestamp));

        return new MixedScenario(allEvents, expectedAttackIds);
    }

    /**
     * Container for a mixed scenario with expected results.
     */
    public record MixedScenario(
            List<SignalingEvent> events,
            List<String> expectedAttackPatternIds
    ) {}
}
