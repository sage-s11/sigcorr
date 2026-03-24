package io.sigcorr.integration;

import io.sigcorr.correlation.engine.CorrelationEngine;
import io.sigcorr.correlation.engine.EngineConfig;
import io.sigcorr.detection.patterns.AttackPattern;
import io.sigcorr.detection.scoring.SecurityAlert;
import io.sigcorr.ingest.hex.ScenarioGenerator;
import io.sigcorr.output.json.JsonOutputFormatter;
import org.junit.jupiter.api.*;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.*;

@DisplayName("Integration Tests — Full Pipeline")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class FullPipelineIntegrationTest {

    private CorrelationEngine engine;
    private ScenarioGenerator generator;
    private static final Instant BASE = Instant.parse("2025-03-15T10:00:00Z");

    @BeforeEach
    void setUp() {
        engine = CorrelationEngine.createDefault();
        generator = new ScenarioGenerator();
    }

    // ================================================================
    // Individual Attack Detection
    // ================================================================

    @Test
    @Order(1)
    @DisplayName("E2E: Detect silent location tracking (ATK-001)")
    void detectLocationTracking() {
        var events = generator.generateLocationTracking("447712345678", "234101234567890", BASE);
        var alerts = engine.processBatch(events);

        assertThat(alerts).isNotEmpty();
        assertThat(alerts).anyMatch(a -> a.getMatchedPattern().getPatternId().equals("ATK-001"));

        var atk001 = alerts.stream()
                .filter(a -> a.getMatchedPattern().getPatternId().equals("ATK-001"))
                .findFirst().orElseThrow();

        assertThat(atk001.getSeverity()).isEqualTo(AttackPattern.Severity.HIGH);
        assertThat(atk001.getMatchedEvents()).hasSizeGreaterThanOrEqualTo(2);
        assertThat(atk001.getConfidenceScore()).isGreaterThan(0.5);
        assertThat(atk001.isCrossProtocol()).isFalse(); // Both MAP
    }

    @Test
    @Order(2)
    @DisplayName("E2E: Detect interception setup (ATK-002) with Diameter cross-protocol")
    void detectInterceptionSetup() {
        var events = generator.generateInterceptionSetup("447798765432", "234109876543210", BASE);
        var alerts = engine.processBatch(events);

        assertThat(alerts).anyMatch(a -> a.getMatchedPattern().getPatternId().equals("ATK-002"));

        var atk002 = alerts.stream()
                .filter(a -> a.getMatchedPattern().getPatternId().equals("ATK-002"))
                .findFirst().orElseThrow();

        assertThat(atk002.getSeverity()).isEqualTo(AttackPattern.Severity.CRITICAL);
        assertThat(atk002.getMatchedEvents().size()).isGreaterThanOrEqualTo(2);
    }

    @Test
    @Order(3)
    @DisplayName("E2E: Detect SS7→GTP cross-protocol session attack (ATK-003)")
    void detectCrossProtocolSession() {
        var events = generator.generateTrackingWithSession("447755555555", "234105555555550", BASE);
        var alerts = engine.processBatch(events);

        assertThat(alerts).anyMatch(a -> a.getMatchedPattern().getPatternId().equals("ATK-003"));

        var atk003 = alerts.stream()
                .filter(a -> a.getMatchedPattern().getPatternId().equals("ATK-003"))
                .findFirst().orElseThrow();

        assertThat(atk003.isCrossProtocol()).isTrue(); // MAP + GTP
        assertThat(atk003.getCrossInterfaceCount()).isEqualTo(2);
    }

    @Test
    @Order(4)
    @DisplayName("E2E: Detect Diameter→SS7 auth downgrade (ATK-005)")
    void detectAuthDowngrade() {
        var events = generator.generateAuthDowngrade("234101111111110", BASE);
        var alerts = engine.processBatch(events);

        assertThat(alerts).anyMatch(a -> a.getMatchedPattern().getPatternId().equals("ATK-005"));

        var atk005 = alerts.stream()
                .filter(a -> a.getMatchedPattern().getPatternId().equals("ATK-005"))
                .findFirst().orElseThrow();

        assertThat(atk005.isCrossProtocol()).isTrue(); // Diameter + MAP
        assertThat(atk005.getSeverity()).isEqualTo(AttackPattern.Severity.HIGH);
    }

    @Test
    @Order(5)
    @DisplayName("E2E: Detect subscriber DoS (ATK-006)")
    void detectSubscriberDoS() {
        var events = generator.generateSubscriberDoS("234102222222220", BASE);
        var alerts = engine.processBatch(events);

        assertThat(alerts).anyMatch(a -> a.getMatchedPattern().getPatternId().equals("ATK-006"));
    }

    @Test
    @Order(6)
    @DisplayName("E2E: Detect call forwarding interception (ATK-007)")
    void detectCallForwarding() {
        var events = generator.generateCallForwardingInterception("447733333333", BASE);
        var alerts = engine.processBatch(events);

        assertThat(alerts).anyMatch(a -> a.getMatchedPattern().getPatternId().equals("ATK-007"));

        var atk007 = alerts.stream()
                .filter(a -> a.getMatchedPattern().getPatternId().equals("ATK-007"))
                .findFirst().orElseThrow();

        assertThat(atk007.getSeverity()).isEqualTo(AttackPattern.Severity.CRITICAL);
    }

    @Test
    @Order(7)
    @DisplayName("E2E: Detect cross-protocol recon (ATK-008)")
    void detectCrossProtocolRecon() {
        var events = generator.generateCrossProtocolRecon("447744444444", "234104444444440", BASE);
        var alerts = engine.processBatch(events);

        assertThat(alerts).anyMatch(a -> a.getMatchedPattern().getPatternId().equals("ATK-008"));

        var atk008 = alerts.stream()
                .filter(a -> a.getMatchedPattern().getPatternId().equals("ATK-008"))
                .findFirst().orElseThrow();

        assertThat(atk008.isCrossProtocol()).isTrue();
    }

    // ================================================================
    // False Positive Resistance
    // ================================================================

    @Test
    @Order(10)
    @DisplayName("E2E: Legitimate traffic produces ZERO alerts")
    void noFalsePositives() {
        var events = generator.generateLegitimateTraffic(100, BASE);
        var alerts = engine.processBatch(events);

        assertThat(alerts).isEmpty();
        assertThat(engine.getEventsProcessed()).isEqualTo(100);
    }

    @Test
    @Order(11)
    @DisplayName("E2E: Single events produce no alerts (need sequence)")
    void singleEventsNoAlerts() {
        var events = generator.generateLegitimateTraffic(200, BASE);
        var alerts = engine.processBatch(events);
        assertThat(alerts).isEmpty();
    }

    // ================================================================
    // Mixed Scenario (attacks hidden in legitimate traffic)
    // ================================================================

    @Test
    @Order(20)
    @DisplayName("E2E: Mixed scenario — find attacks in background noise")
    void mixedScenario() {
        var scenario = generator.generateMixedScenario(BASE);
        var alerts = engine.processBatch(scenario.events());

        // Should detect the injected attacks
        Set<String> detectedPatterns = alerts.stream()
                .map(a -> a.getMatchedPattern().getPatternId())
                .collect(Collectors.toSet());

        for (String expectedId : scenario.expectedAttackPatternIds()) {
            assertThat(detectedPatterns)
                    .as("Expected to detect pattern " + expectedId)
                    .contains(expectedId);
        }

        // No false positives from background traffic
        // (all alerts should be traceable to injected attack events)
        assertThat(alerts.size())
                .as("Alert count should be reasonable (not flooded with FPs)")
                .isLessThanOrEqualTo(scenario.expectedAttackPatternIds().size() * 3);
    }

    // ================================================================
    // Engine Statistics & Summary
    // ================================================================

    @Test
    @Order(30)
    @DisplayName("E2E: Engine tracks correct statistics")
    void engineStatistics() {
        var events1 = generator.generateLocationTracking("447712345678", "234101234567890", BASE);
        var events2 = generator.generateAuthDowngrade("234109999999990", BASE.plusSeconds(100));
        engine.processBatch(events1);
        engine.processBatch(events2);

        var summary = engine.getSummary();
        assertThat(summary.totalEvents()).isEqualTo(events1.size() + events2.size());
        assertThat(summary.totalAlerts()).isGreaterThan(0);
        assertThat(summary.eventsByInterface()).isNotEmpty();
        assertThat(summary.subscribersTracked()).isGreaterThan(0);
    }

    @Test
    @Order(31)
    @DisplayName("E2E: Identity resolver learns mappings from signaling")
    void identityResolution() {
        // Location tracking scenario has both MSISDN and IMSI for same subscriber
        var events = generator.generateLocationTracking("447712345678", "234101234567890", BASE);
        engine.processBatch(events);

        var resolver = engine.getIdentityResolver();
        assertThat(resolver.getMappingCount()).isGreaterThan(0);
        assertThat(resolver.lookupImsi("447712345678")).contains("234101234567890");
    }

    @Test
    @Order(32)
    @DisplayName("E2E: Cross-protocol alert filtering works")
    void crossProtocolFiltering() {
        // Inject both same-protocol and cross-protocol attacks
        engine.processBatch(generator.generateLocationTracking("447711111111", "234101111111110", BASE));
        engine.processBatch(generator.generateAuthDowngrade("234102222222220", BASE.plusSeconds(100)));

        var allAlerts = engine.getAlerts();
        var crossOnly = engine.getCrossProtocolAlerts();

        assertThat(crossOnly.size()).isLessThanOrEqualTo(allAlerts.size());
        assertThat(crossOnly).allMatch(SecurityAlert::isCrossProtocol);
    }

    @Test
    @Order(33)
    @DisplayName("E2E: Severity filtering works")
    void severityFiltering() {
        engine.processBatch(generator.generateLocationTracking("447711111111", "234101111111110", BASE));
        engine.processBatch(generator.generateInterceptionSetup("447722222222", "234102222222220",
                BASE.plusSeconds(100)));

        var critical = engine.getAlertsBySeverity(AttackPattern.Severity.CRITICAL);
        var high = engine.getAlertsBySeverity(AttackPattern.Severity.HIGH);

        assertThat(high.size()).isGreaterThanOrEqualTo(critical.size());
    }

    // ================================================================
    // JSON Output
    // ================================================================

    @Test
    @Order(40)
    @DisplayName("E2E: JSON report is valid and complete")
    void jsonReport() {
        engine.processBatch(generator.generateLocationTracking("447712345678", "234101234567890", BASE));
        engine.processBatch(generator.generateAuthDowngrade("234109999999990", BASE.plusSeconds(100)));

        JsonOutputFormatter formatter = new JsonOutputFormatter();
        String json = formatter.formatReport(engine);

        assertThat(json).isNotEmpty();
        assertThat(json).contains("summary");
        assertThat(json).contains("alerts");
        assertThat(json).contains("ATK-");
        assertThat(json).contains("confidence");

        // Verify it's valid JSON
        assertThatNoException().isThrownBy(() ->
                com.google.gson.JsonParser.parseString(json));
    }

    @Test
    @Order(41)
    @DisplayName("E2E: Individual alert JSON is valid")
    void alertJson() {
        engine.processBatch(generator.generateLocationTracking("447712345678", "234101234567890", BASE));

        JsonOutputFormatter formatter = new JsonOutputFormatter();
        for (SecurityAlert alert : engine.getAlerts()) {
            String json = formatter.formatAlert(alert);
            assertThat(json).isNotEmpty();
            assertThatNoException().isThrownBy(() ->
                    com.google.gson.JsonParser.parseString(json));
        }
    }

    // ================================================================
    // Engine Reset
    // ================================================================

    @Test
    @Order(50)
    @DisplayName("E2E: Engine reset clears all state")
    void engineReset() {
        engine.processBatch(generator.generateLocationTracking("447712345678", "234101234567890", BASE));
        assertThat(engine.getAlerts()).isNotEmpty();

        engine.reset();

        assertThat(engine.getAlerts()).isEmpty();
        assertThat(engine.getEventsProcessed()).isEqualTo(0);
        assertThat(engine.getTemporalWindow().getTotalEventCount()).isEqualTo(0);
        assertThat(engine.getIdentityResolver().getMappingCount()).isEqualTo(0);
    }

    // ================================================================
    // Alert Properties
    // ================================================================

    @Test
    @Order(60)
    @DisplayName("E2E: Alert attack duration is calculated correctly")
    void alertAttackDuration() {
        var events = generator.generateLocationTracking("447712345678", "234101234567890", BASE);
        var alerts = engine.processBatch(events);

        for (SecurityAlert alert : alerts) {
            assertThat(alert.getAttackDurationMillis()).isGreaterThanOrEqualTo(0);
        }
    }

    @Test
    @Order(61)
    @DisplayName("E2E: Alert toString is readable and informative")
    void alertToString() {
        engine.processBatch(generator.generateLocationTracking("447712345678", "234101234567890", BASE));

        for (SecurityAlert alert : engine.getAlerts()) {
            String str = alert.toString();
            assertThat(str).contains("ALERT");
            assertThat(str).contains(alert.getMatchedPattern().getPatternId());
            assertThat(str).contains("confidence");
        }
    }

    @Test
    @Order(62)
    @DisplayName("E2E: Analysis summary toString is formatted")
    void summaryToString() {
        engine.processBatch(generator.generateLocationTracking("447712345678", "234101234567890", BASE));
        String summary = engine.getSummary().toString();

        assertThat(summary).contains("SigCorr Analysis Summary");
        assertThat(summary).contains("Events processed");
        assertThat(summary).contains("Total alerts");
    }
}
