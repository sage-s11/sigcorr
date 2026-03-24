package io.sigcorr.detection;

import io.sigcorr.core.event.NetworkNode;
import io.sigcorr.core.event.SignalingEvent;
import io.sigcorr.core.identity.SubscriberIdentity;
import io.sigcorr.core.model.ProtocolInterface;
import io.sigcorr.core.model.SignalingOperation;
import io.sigcorr.detection.patterns.AttackPattern;
import io.sigcorr.detection.patterns.AttackPatternCatalog;
import io.sigcorr.detection.rules.PatternMatcher;
import io.sigcorr.detection.scoring.SecurityAlert;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.*;

import static org.assertj.core.api.Assertions.*;

@DisplayName("PatternMatcher")
class PatternMatcherTest {

    private PatternMatcher matcher;
    private static final Instant BASE = Instant.parse("2025-01-01T00:00:00Z");
    private static final String IMSI = "234101234567890";
    private static final String KEY = "IMSI:" + IMSI;

    @BeforeEach
    void setUp() {
        matcher = new PatternMatcher(AttackPatternCatalog.getAllPatterns());
    }

    private SignalingEvent event(Instant time, SignalingOperation op, NetworkNode source) {
        return SignalingEvent.builder()
                .timestamp(time)
                .protocolInterface(op.getProtocolInterface())
                .operation(op)
                .subscriber(SubscriberIdentity.fromImsi(IMSI))
                .sourceNode(source)
                .parameters(Map.of("imsi", IMSI, "messageType", "invoke"))
                .build();
    }

    @Test
    @DisplayName("Detect ATK-001: Silent Location Tracking (SRI → PSI)")
    void detectLocationTracking() {
        NetworkNode foreign = NetworkNode.fromGlobalTitle("+491720000000");
        var events = List.of(
                event(BASE, SignalingOperation.MAP_SEND_ROUTING_INFO, foreign),
                event(BASE.plusSeconds(5), SignalingOperation.MAP_PROVIDE_SUBSCRIBER_INFO, foreign)
        );

        var alerts = matcher.matchAll(KEY, events);
        assertThat(alerts).anyMatch(a -> a.getMatchedPattern().getPatternId().equals("ATK-001"));
    }

    @Test
    @DisplayName("Detect ATK-002: Interception Setup (SRI → ISD)")
    void detectInterceptionSetup() {
        NetworkNode foreign = NetworkNode.fromGlobalTitle("+491720000000");
        var events = List.of(
                event(BASE, SignalingOperation.MAP_SEND_ROUTING_INFO, foreign),
                event(BASE.plusSeconds(5), SignalingOperation.MAP_INSERT_SUBSCRIBER_DATA, foreign)
        );

        var alerts = matcher.matchAll(KEY, events);
        assertThat(alerts).anyMatch(a -> a.getMatchedPattern().getPatternId().equals("ATK-002"));
    }

    @Test
    @DisplayName("Detect ATK-003: Cross-Protocol Tracking + Session (MAP → GTP)")
    void detectCrossProtocolSession() {
        var events = List.of(
                event(BASE, SignalingOperation.MAP_SEND_ROUTING_INFO,
                        NetworkNode.fromGlobalTitle("+491720000000")),
                event(BASE.plusSeconds(30), SignalingOperation.GTP_CREATE_SESSION_REQUEST,
                        NetworkNode.fromGtpPeer("10.99.0.1"))
        );

        var alerts = matcher.matchAll(KEY, events);
        assertThat(alerts).anyMatch(a -> {
            var alert = a;
            return alert.getMatchedPattern().getPatternId().equals("ATK-003")
                    && alert.isCrossProtocol();
        });
    }

    @Test
    @DisplayName("Detect ATK-005: Diameter→SS7 Auth Downgrade")
    void detectAuthDowngrade() {
        var events = List.of(
                event(BASE, SignalingOperation.DIA_AUTH_INFO_REQUEST,
                        NetworkNode.fromDiameterHost("mme.foreign.com", "foreign.com")),
                event(BASE.plusSeconds(8), SignalingOperation.MAP_SEND_AUTH_INFO,
                        NetworkNode.fromGlobalTitle("+491720000000"))
        );

        var alerts = matcher.matchAll(KEY, events);
        assertThat(alerts).anyMatch(a -> {
            var alert = a;
            return alert.getMatchedPattern().getPatternId().equals("ATK-005")
                    && alert.isCrossProtocol();
        });
    }

    @Test
    @DisplayName("Detect ATK-006: Subscriber DoS (Cancel + Delete)")
    void detectSubscriberDoS() {
        NetworkNode foreign = NetworkNode.fromGlobalTitle("+491720000000");
        var events = List.of(
                event(BASE, SignalingOperation.MAP_CANCEL_LOCATION, foreign),
                event(BASE.plusSeconds(2), SignalingOperation.MAP_DELETE_SUBSCRIBER_DATA, foreign)
        );

        var alerts = matcher.matchAll(KEY, events);
        assertThat(alerts).anyMatch(a -> a.getMatchedPattern().getPatternId().equals("ATK-006"));
    }

    @Test
    @DisplayName("Detect ATK-007: Call Forwarding Interception")
    void detectCallForwarding() {
        NetworkNode foreign = NetworkNode.fromGlobalTitle("+491720000000");
        var events = List.of(
                event(BASE, SignalingOperation.MAP_REGISTER_SS, foreign),
                event(BASE.plusSeconds(1), SignalingOperation.MAP_ACTIVATE_SS, foreign)
        );

        var alerts = matcher.matchAll(KEY, events);
        assertThat(alerts).anyMatch(a -> a.getMatchedPattern().getPatternId().equals("ATK-007"));
    }

    @Test
    @DisplayName("Detect ATK-008: Cross-Protocol Recon (MAP → Diameter)")
    void detectCrossProtocolRecon() {
        var events = List.of(
                event(BASE, SignalingOperation.MAP_SEND_ROUTING_INFO,
                        NetworkNode.fromGlobalTitle("+491720000000")),
                event(BASE.plusSeconds(15), SignalingOperation.DIA_AUTH_INFO_REQUEST,
                        NetworkNode.fromDiameterHost("mme.foreign.com", "foreign.com"))
        );

        var alerts = matcher.matchAll(KEY, events);
        assertThat(alerts).anyMatch(a -> a.getMatchedPattern().getPatternId().equals("ATK-008"));
    }

    @Test
    @DisplayName("No alert for single event (needs sequence)")
    void noAlertForSingleEvent() {
        var events = List.of(
                event(BASE, SignalingOperation.MAP_SEND_ROUTING_INFO,
                        NetworkNode.fromGlobalTitle("+491720000000"))
        );

        var alerts = matcher.matchAll(KEY, events);
        assertThat(alerts).isEmpty();
    }

    @Test
    @DisplayName("No alert when events exceed time window")
    void noAlertOutsideWindow() {
        NetworkNode foreign = NetworkNode.fromGlobalTitle("+491720000000");
        var events = List.of(
                event(BASE, SignalingOperation.MAP_SEND_ROUTING_INFO, foreign),
                // 10 minutes later — outside ATK-001's 60s window
                event(BASE.plus(java.time.Duration.ofMinutes(10)), SignalingOperation.MAP_PROVIDE_SUBSCRIBER_INFO, foreign)
        );

        var alerts = matcher.matchAll(KEY, events);
        // ATK-001 should NOT match (60s window exceeded)
        assertThat(alerts).noneMatch(a -> a.getMatchedPattern().getPatternId().equals("ATK-001"));
    }

    @Test
    @DisplayName("Same-source constraint enforced")
    void sameSourceConstraint() {
        // ATK-001 requires same source — use different sources
        var events = List.of(
                event(BASE, SignalingOperation.MAP_SEND_ROUTING_INFO,
                        NetworkNode.fromGlobalTitle("+491720000000")),
                event(BASE.plusSeconds(5), SignalingOperation.MAP_PROVIDE_SUBSCRIBER_INFO,
                        NetworkNode.fromGlobalTitle("+861390000000")) // Different source!
        );

        var alerts = matcher.matchAll(KEY, events);
        assertThat(alerts).noneMatch(a -> a.getMatchedPattern().getPatternId().equals("ATK-001"));
    }

    @Test
    @DisplayName("Cross-protocol alerts marked correctly")
    void crossProtocolMarking() {
        var events = List.of(
                event(BASE, SignalingOperation.MAP_SEND_ROUTING_INFO,
                        NetworkNode.fromGlobalTitle("+491720000000")),
                event(BASE.plusSeconds(30), SignalingOperation.GTP_CREATE_SESSION_REQUEST,
                        NetworkNode.fromGtpPeer("10.99.0.1"))
        );

        var alerts = matcher.matchAll(KEY, events);
        var crossProtocol = alerts.stream().filter(SecurityAlert::isCrossProtocol).toList();
        assertThat(crossProtocol).isNotEmpty();
        assertThat(crossProtocol.get(0).getCrossInterfaceCount()).isGreaterThan(1);
    }

    @Test
    @DisplayName("Confidence score is between 0 and 1")
    void confidenceScoreRange() {
        NetworkNode foreign = NetworkNode.fromGlobalTitle("+491720000000");
        var events = List.of(
                event(BASE, SignalingOperation.MAP_SEND_ROUTING_INFO, foreign),
                event(BASE.plusSeconds(3), SignalingOperation.MAP_PROVIDE_SUBSCRIBER_INFO, foreign)
        );

        var alerts = matcher.matchAll(KEY, events);
        assertThat(alerts).allMatch(a -> a.getConfidenceScore() > 0.0 && a.getConfidenceScore() <= 1.0);
    }

    @Test
    @DisplayName("Pattern requires minimum 2 steps")
    void patternMinimumSteps() {
        assertThatThrownBy(() -> AttackPattern.builder()
                .patternId("TEST")
                .name("Test")
                .addStep(1, SignalingOperation.MAP_SEND_ROUTING_INFO)
                .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("at least 2 steps");
    }

    @Test
    @DisplayName("Empty event list produces no alerts")
    void emptyEvents() {
        assertThat(matcher.matchAll(KEY, List.of())).isEmpty();
        assertThat(matcher.matchAll(KEY, null)).isEmpty();
    }
}
