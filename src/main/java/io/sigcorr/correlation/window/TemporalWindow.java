package io.sigcorr.correlation.window;

import io.sigcorr.core.event.SignalingEvent;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Temporal sliding window that groups signaling events by subscriber identity
 * within configurable time bounds.
 *
 * The core insight: attacks span multiple protocol interfaces but target the
 * same subscriber within a narrow time window. A location tracking attack
 * sends SendRoutingInfo (MAP), then ProvideSubscriberInfo (MAP), possibly
 * followed by a Diameter re-registration — all within seconds to minutes.
 *
 * The TemporalWindow maintains per-subscriber event lists and provides
 * efficient lookup for correlation.
 *
 * Thread-safe: uses ConcurrentHashMap for the subscriber→events mapping.
 */
public class TemporalWindow {

    private final Duration windowSize;
    private final Map<String, List<SignalingEvent>> subscriberEvents;

    /**
     * Create a temporal window with the given size.
     *
     * @param windowSize maximum time span between correlated events
     */
    public TemporalWindow(Duration windowSize) {
        this.windowSize = Objects.requireNonNull(windowSize);
        if (windowSize.isNegative() || windowSize.isZero()) {
            throw new IllegalArgumentException("Window size must be positive");
        }
        this.subscriberEvents = new ConcurrentHashMap<>();
    }

    /**
     * Add an event to the window, indexed by its subscriber correlation key.
     *
     * @param correlationKey the subscriber identifier (from IdentityResolver)
     * @param event          the signaling event
     */
    public void addEvent(String correlationKey, SignalingEvent event) {
        subscriberEvents.computeIfAbsent(correlationKey, k -> Collections.synchronizedList(new ArrayList<>()))
                .add(event);
    }

    /**
     * Get all events for a subscriber that fall within the window relative
     * to a reference event's timestamp.
     *
     * @param correlationKey subscriber identifier
     * @param reference      the event to use as the time anchor
     * @return events within [reference.time - windowSize, reference.time + windowSize]
     */
    public List<SignalingEvent> getCorrelatedEvents(String correlationKey, SignalingEvent reference) {
        List<SignalingEvent> events = subscriberEvents.get(correlationKey);
        if (events == null) return Collections.emptyList();

        Instant refTime = reference.getTimestamp();
        Instant windowStart = refTime.minus(windowSize);
        Instant windowEnd = refTime.plus(windowSize);

        synchronized (events) {
            return events.stream()
                    .filter(e -> !e.getEventId().equals(reference.getEventId()))
                    .filter(e -> !e.getTimestamp().isBefore(windowStart)
                            && !e.getTimestamp().isAfter(windowEnd))
                    .sorted(Comparator.comparing(SignalingEvent::getTimestamp))
                    .collect(Collectors.toList());
        }
    }

    /**
     * Get all events for a subscriber within a specific time range.
     */
    public List<SignalingEvent> getEventsInRange(String correlationKey, Instant start, Instant end) {
        List<SignalingEvent> events = subscriberEvents.get(correlationKey);
        if (events == null) return Collections.emptyList();

        synchronized (events) {
            return events.stream()
                    .filter(e -> !e.getTimestamp().isBefore(start) && !e.getTimestamp().isAfter(end))
                    .sorted(Comparator.comparing(SignalingEvent::getTimestamp))
                    .collect(Collectors.toList());
        }
    }

    /**
     * Get all events for a subscriber, ordered chronologically.
     */
    public List<SignalingEvent> getAllEvents(String correlationKey) {
        List<SignalingEvent> events = subscriberEvents.get(correlationKey);
        if (events == null) return Collections.emptyList();

        synchronized (events) {
            return events.stream()
                    .sorted(Comparator.comparing(SignalingEvent::getTimestamp))
                    .collect(Collectors.toList());
        }
    }

    /**
     * Evict events older than the window size relative to the given time.
     * Call periodically to prevent unbounded memory growth.
     */
    public int evictBefore(Instant cutoff) {
        int evicted = 0;
        for (Map.Entry<String, List<SignalingEvent>> entry : subscriberEvents.entrySet()) {
            List<SignalingEvent> events = entry.getValue();
            synchronized (events) {
                int sizeBefore = events.size();
                events.removeIf(e -> e.getTimestamp().isBefore(cutoff));
                evicted += sizeBefore - events.size();
            }
        }
        // Remove empty subscriber entries
        subscriberEvents.entrySet().removeIf(e -> e.getValue().isEmpty());
        return evicted;
    }

    /**
     * Get all subscriber correlation keys that have events in the window.
     */
    public Set<String> getActiveSubscribers() {
        return Collections.unmodifiableSet(subscriberEvents.keySet());
    }

    /**
     * Total number of events across all subscribers.
     */
    public int getTotalEventCount() {
        return subscriberEvents.values().stream()
                .mapToInt(List::size)
                .sum();
    }

    /**
     * Number of tracked subscribers.
     */
    public int getSubscriberCount() {
        return subscriberEvents.size();
    }

    public Duration getWindowSize() {
        return windowSize;
    }

    /**
     * Clear all events.
     */
    public void clear() {
        subscriberEvents.clear();
    }
}
