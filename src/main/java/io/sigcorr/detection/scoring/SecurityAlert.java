package io.sigcorr.detection.scoring;

import io.sigcorr.core.event.SignalingEvent;
import io.sigcorr.detection.patterns.AttackPattern;

import java.time.Instant;
import java.util.*;

/**
 * A security alert generated when a pattern match is confirmed.
 *
 * Contains the matched pattern, the sequence of events that triggered it,
 * the targeted subscriber, and confidence/severity scoring.
 */
public final class SecurityAlert {

    private final String alertId;
    private final Instant detectionTime;
    private final AttackPattern matchedPattern;
    private final List<SignalingEvent> matchedEvents;
    private final String subscriberKey;
    private final double confidenceScore;
    private final Map<String, String> metadata;

    public SecurityAlert(String alertId, Instant detectionTime, AttackPattern matchedPattern,
                          List<SignalingEvent> matchedEvents, String subscriberKey,
                          double confidenceScore, Map<String, String> metadata) {
        this.alertId = Objects.requireNonNull(alertId);
        this.detectionTime = Objects.requireNonNull(detectionTime);
        this.matchedPattern = Objects.requireNonNull(matchedPattern);
        this.matchedEvents = Collections.unmodifiableList(new ArrayList<>(matchedEvents));
        this.subscriberKey = Objects.requireNonNull(subscriberKey);
        this.confidenceScore = confidenceScore;
        this.metadata = metadata != null
                ? Collections.unmodifiableMap(new HashMap<>(metadata))
                : Collections.emptyMap();
    }

    public String getAlertId() { return alertId; }
    public Instant getDetectionTime() { return detectionTime; }
    public AttackPattern getMatchedPattern() { return matchedPattern; }
    public List<SignalingEvent> getMatchedEvents() { return matchedEvents; }
    public String getSubscriberKey() { return subscriberKey; }
    public double getConfidenceScore() { return confidenceScore; }
    public Map<String, String> getMetadata() { return metadata; }

    public AttackPattern.Severity getSeverity() {
        return matchedPattern.getSeverity();
    }

    /**
     * Time span between first and last matched event.
     */
    public long getAttackDurationMillis() {
        if (matchedEvents.size() < 2) return 0;
        Instant first = matchedEvents.get(0).getTimestamp();
        Instant last = matchedEvents.get(matchedEvents.size() - 1).getTimestamp();
        return last.toEpochMilli() - first.toEpochMilli();
    }

    /**
     * Number of distinct protocol interfaces involved in the attack.
     */
    public long getCrossInterfaceCount() {
        return matchedEvents.stream()
                .map(SignalingEvent::getProtocolInterface)
                .distinct()
                .count();
    }

    /**
     * Whether this alert involves events from multiple protocol families
     * (SS7 + Diameter, SS7 + GTP, etc.). These are the highest-value
     * detections — invisible to single-protocol monitors.
     */
    public boolean isCrossProtocol() {
        return getCrossInterfaceCount() > 1
                && matchedEvents.stream()
                .map(e -> e.getProtocolInterface().getFamily())
                .distinct()
                .count() > 1;
    }

    @Override
    public String toString() {
        return String.format("ALERT[%s] %s | %s | subscriber=%s | confidence=%.0f%% | " +
                        "events=%d | cross-protocol=%s | duration=%dms",
                matchedPattern.getSeverity().getDisplayName().toUpperCase(),
                matchedPattern.getPatternId(),
                matchedPattern.getName(),
                subscriberKey,
                confidenceScore * 100,
                matchedEvents.size(),
                isCrossProtocol(),
                getAttackDurationMillis());
    }
}
