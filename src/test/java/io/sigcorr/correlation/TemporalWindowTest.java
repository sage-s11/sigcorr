package io.sigcorr.correlation;

import io.sigcorr.core.event.SignalingEvent;
import io.sigcorr.core.identity.SubscriberIdentity;
import io.sigcorr.core.model.ProtocolInterface;
import io.sigcorr.core.model.SignalingOperation;
import io.sigcorr.correlation.window.TemporalWindow;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.*;

@DisplayName("TemporalWindow")
class TemporalWindowTest {

    private TemporalWindow window;
    private static final Instant BASE = Instant.parse("2025-01-01T00:00:00Z");

    @BeforeEach
    void setUp() {
        window = new TemporalWindow(Duration.ofMinutes(5));
    }

    private SignalingEvent makeEvent(Instant time, SignalingOperation op, String imsi) {
        return SignalingEvent.builder()
                .timestamp(time)
                .protocolInterface(op.getProtocolInterface())
                .operation(op)
                .subscriber(SubscriberIdentity.fromImsi(imsi))
                .parameters(Map.of("imsi", imsi))
                .build();
    }

    @Test
    @DisplayName("Add and retrieve events for a subscriber")
    void addAndRetrieve() {
        var event = makeEvent(BASE, SignalingOperation.MAP_SEND_ROUTING_INFO, "234101234567890");
        window.addEvent("IMSI:234101234567890", event);
        assertThat(window.getAllEvents("IMSI:234101234567890")).hasSize(1);
        assertThat(window.getTotalEventCount()).isEqualTo(1);
        assertThat(window.getSubscriberCount()).isEqualTo(1);
    }

    @Test
    @DisplayName("Correlated events within window")
    void correlatedWithinWindow() {
        String key = "IMSI:234101234567890";
        var e1 = makeEvent(BASE, SignalingOperation.MAP_SEND_ROUTING_INFO, "234101234567890");
        var e2 = makeEvent(BASE.plusSeconds(10), SignalingOperation.MAP_PROVIDE_SUBSCRIBER_INFO, "234101234567890");
        var e3 = makeEvent(BASE.plusSeconds(20), SignalingOperation.MAP_INSERT_SUBSCRIBER_DATA, "234101234567890");

        window.addEvent(key, e1);
        window.addEvent(key, e2);
        window.addEvent(key, e3);

        List<SignalingEvent> correlated = window.getCorrelatedEvents(key, e2);
        assertThat(correlated).hasSize(2); // e1 and e3 (excludes e2 itself)
    }

    @Test
    @DisplayName("Events outside window are excluded")
    void eventsOutsideWindowExcluded() {
        String key = "IMSI:234101234567890";
        var e1 = makeEvent(BASE, SignalingOperation.MAP_SEND_ROUTING_INFO, "234101234567890");
        var e2 = makeEvent(BASE.plus(java.time.Duration.ofMinutes(10)), SignalingOperation.MAP_PROVIDE_SUBSCRIBER_INFO, "234101234567890");

        window.addEvent(key, e1);
        window.addEvent(key, e2);

        // e2 is 10 minutes after e1, window is 5 minutes
        List<SignalingEvent> correlated = window.getCorrelatedEvents(key, e1);
        assertThat(correlated).isEmpty();
    }

    @Test
    @DisplayName("Different subscribers are isolated")
    void subscriberIsolation() {
        var e1 = makeEvent(BASE, SignalingOperation.MAP_SEND_ROUTING_INFO, "234101234567890");
        var e2 = makeEvent(BASE.plusSeconds(5), SignalingOperation.MAP_SEND_ROUTING_INFO, "234109876543210");

        window.addEvent("IMSI:234101234567890", e1);
        window.addEvent("IMSI:234109876543210", e2);

        assertThat(window.getAllEvents("IMSI:234101234567890")).hasSize(1);
        assertThat(window.getAllEvents("IMSI:234109876543210")).hasSize(1);
        assertThat(window.getSubscriberCount()).isEqualTo(2);
    }

    @Test
    @DisplayName("Evict old events")
    void evictOldEvents() {
        String key = "IMSI:234101234567890";
        var old = makeEvent(BASE, SignalingOperation.MAP_SEND_ROUTING_INFO, "234101234567890");
        var recent = makeEvent(BASE.plus(java.time.Duration.ofMinutes(10)), SignalingOperation.MAP_PROVIDE_SUBSCRIBER_INFO, "234101234567890");

        window.addEvent(key, old);
        window.addEvent(key, recent);

        int evicted = window.evictBefore(BASE.plus(java.time.Duration.ofMinutes(5)));
        assertThat(evicted).isEqualTo(1);
        assertThat(window.getAllEvents(key)).hasSize(1);
        assertThat(window.getAllEvents(key).get(0).getOperation())
                .isEqualTo(SignalingOperation.MAP_PROVIDE_SUBSCRIBER_INFO);
    }

    @Test
    @DisplayName("Events in range query")
    void eventsInRange() {
        String key = "IMSI:234101234567890";
        for (int i = 0; i < 10; i++) {
            var e = makeEvent(BASE.plusSeconds(i * 30), SignalingOperation.MAP_SEND_ROUTING_INFO, "234101234567890");
            window.addEvent(key, e);
        }

        var range = window.getEventsInRange(key, BASE.plusSeconds(60), BASE.plusSeconds(180));
        assertThat(range).hasSize(5); // events at 60, 90, 120, 150 seconds
    }

    @Test
    @DisplayName("Reject zero duration window")
    void rejectZeroWindow() {
        assertThatThrownBy(() -> new TemporalWindow(Duration.ZERO))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("Reject negative duration window")
    void rejectNegativeWindow() {
        assertThatThrownBy(() -> new TemporalWindow(Duration.ofSeconds(-1)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("Active subscribers tracking")
    void activeSubscribers() {
        window.addEvent("IMSI:111", makeEvent(BASE, SignalingOperation.MAP_SEND_ROUTING_INFO, "23410111111111"));
        window.addEvent("IMSI:222", makeEvent(BASE, SignalingOperation.MAP_SEND_ROUTING_INFO, "23410222222222"));
        assertThat(window.getActiveSubscribers()).containsExactlyInAnyOrder("IMSI:111", "IMSI:222");
    }

    @Test
    @DisplayName("Clear removes everything")
    void clear() {
        window.addEvent("IMSI:111", makeEvent(BASE, SignalingOperation.MAP_SEND_ROUTING_INFO, "23410111111111"));
        window.clear();
        assertThat(window.getTotalEventCount()).isEqualTo(0);
        assertThat(window.getSubscriberCount()).isEqualTo(0);
    }
}
