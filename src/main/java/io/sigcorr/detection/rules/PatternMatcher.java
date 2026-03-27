package io.sigcorr.detection.rules;

import io.sigcorr.core.event.SignalingEvent;
import io.sigcorr.detection.patterns.AttackPattern;
import io.sigcorr.detection.scoring.SecurityAlert;
import io.sigcorr.detection.whitelist.Whitelist;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.*;

/**
 * Matches sequences of signaling events against attack pattern definitions.
 *
 * The matching algorithm is deliberately simple and auditable:
 * 1. For each attack pattern, check if the subscriber's event timeline
 *    contains the required operations in the correct order
 * 2. Verify temporal constraints (max window, inter-step delays)
 * 3. Verify source constraints (same source node if required)
 * 4. Check whitelist (trusted GT pairs, home network traffic)
 * 5. Calculate confidence score based on match completeness
 *
 * This is NOT a machine learning black box. Every detection can be traced
 * to a specific sequence of observed events matching a defined pattern.
 * This is essential for telecom security: operators need to understand
 * exactly why an alert was raised and present evidence to interconnect partners.
 */
public class PatternMatcher {

    private static final Logger log = LoggerFactory.getLogger(PatternMatcher.class);

    private final List<AttackPattern> patterns;
    private final Whitelist whitelist;

    public PatternMatcher(List<AttackPattern> patterns) {
        this(patterns, Whitelist.disabled());
    }

    public PatternMatcher(List<AttackPattern> patterns, Whitelist whitelist) {
        this.patterns = Objects.requireNonNull(patterns);
        this.whitelist = Objects.requireNonNull(whitelist);
    }

    /**
     * Match all patterns against a subscriber's event timeline.
     *
     * @param subscriberKey correlation key for the subscriber
     * @param events        chronologically ordered events for this subscriber
     * @return list of security alerts for all matched patterns
     */
    public List<SecurityAlert> matchAll(String subscriberKey, List<SignalingEvent> events) {
        if (events == null || events.size() < 2) return Collections.emptyList();

        List<SecurityAlert> alerts = new ArrayList<>();
        for (AttackPattern pattern : patterns) {
            Optional<SecurityAlert> alert = matchPattern(subscriberKey, events, pattern);
            alert.ifPresent(alerts::add);
        }
        return alerts;
    }

    /**
     * Match a single pattern against a subscriber's event timeline.
     */
    public Optional<SecurityAlert> matchPattern(String subscriberKey,
                                                  List<SignalingEvent> events,
                                                  AttackPattern pattern) {
        List<AttackPattern.PatternStep> steps = pattern.getSteps();

        // Find all possible matches using greedy sequential matching
        List<SignalingEvent> matchedEvents = findSequentialMatch(events, steps, pattern);

        if (matchedEvents == null) return Optional.empty();

        // Verify temporal constraints
        if (!verifyTemporalConstraints(matchedEvents, pattern)) {
            return Optional.empty();
        }

        // Verify source constraints
        if (pattern.isRequireSameSource() && !verifySameSource(matchedEvents)) {
            return Optional.empty();
        }

        // Check whitelist — if ALL events are from trusted sources, suppress alert
        if (whitelist.isEnabled() && allEventsTrusted(matchedEvents)) {
            log.debug("Suppressing alert for pattern {} — all events match whitelist", pattern.getPatternId());
            return Optional.empty();
        }

        // Calculate confidence
        double confidence = calculateConfidence(matchedEvents, steps, pattern);

        // Build alert
        Map<String, String> metadata = new HashMap<>();
        metadata.put("patternStepsTotal", String.valueOf(steps.size()));
        metadata.put("patternStepsMatched", String.valueOf(matchedEvents.size()));
        metadata.put("crossProtocol", String.valueOf(isCrossProtocol(matchedEvents)));
        
        // Add whitelist info if partially matched
        if (whitelist.isEnabled()) {
            long trustedCount = matchedEvents.stream()
                    .filter(whitelist::isTrusted)
                    .count();
            if (trustedCount > 0) {
                metadata.put("trustedEventsCount", String.valueOf(trustedCount));
                metadata.put("whitelistPartialMatch", "true");
            }
        }

        SecurityAlert alert = new SecurityAlert(
                UUID.randomUUID().toString(),
                Instant.now(),
                pattern,
                matchedEvents,
                subscriberKey,
                confidence,
                metadata
        );

        log.info("Pattern match: {}", alert);
        return Optional.of(alert);
    }

    /**
     * Check if all events in a sequence are from trusted sources.
     */
    private boolean allEventsTrusted(List<SignalingEvent> events) {
        return events.stream().allMatch(whitelist::isTrusted);
    }

    /**
     * Find events matching the pattern steps in sequential order.
     * Returns the matched events, or null if required steps are missing.
     */
    List<SignalingEvent> findSequentialMatch(List<SignalingEvent> events,
                                                    List<AttackPattern.PatternStep> steps,
                                                    AttackPattern pattern) {
        List<SignalingEvent> matched = new ArrayList<>();
        int eventIdx = 0;

        for (AttackPattern.PatternStep step : steps) {
            boolean found = false;

            while (eventIdx < events.size()) {
                SignalingEvent event = events.get(eventIdx);
                eventIdx++;

                if (event.getOperation() == step.getOperation()) {
                    // Check required parameters
                    if (matchesRequiredParams(event, step)) {
                        // Check inter-step timing
                        if (step.getMaxDelayFromPrevious() != null && !matched.isEmpty()) {
                            SignalingEvent prev = matched.get(matched.size() - 1);
                            long delayMs = event.getTimestamp().toEpochMilli()
                                    - prev.getTimestamp().toEpochMilli();
                            if (delayMs > step.getMaxDelayFromPrevious().toMillis()) {
                                continue; // Too slow, keep looking
                            }
                        }
                        matched.add(event);
                        found = true;
                        break;
                    }
                }
            }

            if (!found && step.isRequired()) {
                return null; // Required step not found
            }
        }

        // Must match at least the required steps (minimum 2 for a pattern)
        long requiredCount = steps.stream().filter(AttackPattern.PatternStep::isRequired).count();
        return matched.size() >= requiredCount ? matched : null;
    }

    /**
     * Verify that the matched events fall within the pattern's time window.
     */
    private boolean verifyTemporalConstraints(List<SignalingEvent> matched, AttackPattern pattern) {
        if (matched.size() < 2) return false;

        Instant first = matched.get(0).getTimestamp();
        Instant last = matched.get(matched.size() - 1).getTimestamp();
        Duration span = Duration.between(first, last);

        return !span.isNegative() && span.compareTo(pattern.getMaxWindow()) <= 0;
    }

    /**
     * Verify that all matched events originate from the same network node.
     */
    private boolean verifySameSource(List<SignalingEvent> matched) {
        if (matched.size() < 2) return true;

        // Events with unknown source don't violate the constraint
        var sources = matched.stream()
                .filter(e -> e.getSourceNode() != null)
                .map(e -> e.getSourceNode().getIdentifier())
                .distinct()
                .toList();

        return sources.size() <= 1;
    }

    /**
     * Check if an event matches a step's required parameter constraints.
     */
    private boolean matchesRequiredParams(SignalingEvent event, AttackPattern.PatternStep step) {
        for (Map.Entry<String, String> entry : step.getRequiredParameters().entrySet()) {
            String actual = event.getParameter(entry.getKey());
            if (actual == null || !actual.equals(entry.getValue())) {
                return false;
            }
        }
        return true;
    }

    /**
     * Calculate confidence score (0.0 to 1.0) based on match quality.
     *
     * Factors:
     * - Completeness: all steps matched vs only required steps
     * - Temporal tightness: shorter time span → higher confidence
     * - Source consistency: same source → higher confidence
     * - Cross-protocol: multi-protocol → higher confidence (harder to fake)
     */
    double calculateConfidence(List<SignalingEvent> matched,
                                       List<AttackPattern.PatternStep> steps,
                                       AttackPattern pattern) {
        double score = 0.0;

        // Base: required steps matched (0.5)
        long requiredCount = steps.stream().filter(AttackPattern.PatternStep::isRequired).count();
        long matchedRequired = matched.stream()
                .filter(e -> steps.stream()
                        .filter(AttackPattern.PatternStep::isRequired)
                        .anyMatch(s -> s.getOperation() == e.getOperation()))
                .count();
        score += 0.5 * (double) matchedRequired / requiredCount;

        // Completeness bonus: optional steps matched (0.15)
        long optionalCount = steps.size() - requiredCount;
        if (optionalCount > 0) {
            long matchedOptional = matched.size() - matchedRequired;
            score += 0.15 * (double) matchedOptional / optionalCount;
        } else {
            score += 0.15;
        }

        // Temporal tightness (0.15): closer events → higher confidence
        if (matched.size() >= 2) {
            long spanMs = matched.get(matched.size() - 1).getTimestamp().toEpochMilli()
                    - matched.get(0).getTimestamp().toEpochMilli();
            long windowMs = pattern.getMaxWindow().toMillis();
            double temporalRatio = 1.0 - (double) spanMs / windowMs;
            score += 0.15 * Math.max(0.0, temporalRatio);
        }

        // Source consistency (0.10)
        if (verifySameSource(matched)) {
            score += 0.10;
        }

        // Cross-protocol bonus (0.10): harder to produce false positives
        if (isCrossProtocol(matched)) {
            score += 0.10;
        }

        return Math.min(1.0, score);
    }

    private boolean isCrossProtocol(List<SignalingEvent> events) {
        return events.stream()
                .map(e -> e.getProtocolInterface().getFamily())
                .distinct()
                .count() > 1;
    }
}
