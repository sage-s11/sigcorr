package io.sigcorr.detection.patterns;

import io.sigcorr.core.model.SignalingOperation;

import java.time.Duration;
import java.util.*;

/**
 * Defines a multi-step attack pattern that spans one or more protocol interfaces.
 *
 * An AttackPattern is an ordered sequence of signaling operations (steps) that,
 * when observed targeting the same subscriber within a time window, indicate
 * a specific attack. Each step can specify constraints on the operation,
 * the protocol interface, and temporal ordering.
 *
 * Example: Silent Location Tracking
 *   Step 1: MAP SendRoutingInfo (get IMSI from MSISDN) — RECONNAISSANCE
 *   Step 2: MAP ProvideSubscriberInfo (get Cell-ID from IMSI) — TRACKING
 *   Constraint: Step 2 must follow Step 1 within 30 seconds
 *   Constraint: Both steps originate from same foreign node
 *
 * Patterns are defined in YAML configuration files and loaded at startup.
 * The pattern matching engine is intentionally simple (ordered sequence matching
 * with temporal constraints) to be auditable and explainable — not a black box.
 */
public class AttackPattern {

    private final String patternId;
    private final String name;
    private final String description;
    private final Severity severity;
    private final List<PatternStep> steps;
    private final Duration maxWindow;
    private final Set<String> mitreTechniques;
    private final boolean requireSameSource;

    private AttackPattern(Builder builder) {
        this.patternId = Objects.requireNonNull(builder.patternId);
        this.name = Objects.requireNonNull(builder.name);
        this.description = builder.description;
        this.severity = builder.severity != null ? builder.severity : Severity.MEDIUM;
        this.steps = Collections.unmodifiableList(new ArrayList<>(builder.steps));
        this.maxWindow = builder.maxWindow != null ? builder.maxWindow : Duration.ofMinutes(5);
        this.mitreTechniques = builder.mitreTechniques != null
                ? Collections.unmodifiableSet(new HashSet<>(builder.mitreTechniques))
                : Collections.emptySet();
        this.requireSameSource = builder.requireSameSource;

        if (steps.size() < 2) {
            throw new IllegalArgumentException("Attack pattern must have at least 2 steps");
        }
    }

    public String getPatternId() { return patternId; }
    public String getName() { return name; }
    public String getDescription() { return description; }
    public Severity getSeverity() { return severity; }
    public List<PatternStep> getSteps() { return steps; }
    public Duration getMaxWindow() { return maxWindow; }
    public Set<String> getMitreTechniques() { return mitreTechniques; }
    public boolean isRequireSameSource() { return requireSameSource; }

    @Override
    public String toString() {
        return String.format("AttackPattern[%s: %s (%d steps, %s)]",
                patternId, name, steps.size(), severity);
    }

    public static Builder builder() { return new Builder(); }

    /**
     * A single step in an attack pattern.
     */
    public static class PatternStep {
        private final int stepNumber;
        private final SignalingOperation operation;
        private final boolean required;
        private final Duration maxDelayFromPrevious;
        private final Map<String, String> requiredParameters;

        public PatternStep(int stepNumber, SignalingOperation operation, boolean required,
                           Duration maxDelayFromPrevious, Map<String, String> requiredParameters) {
            this.stepNumber = stepNumber;
            this.operation = Objects.requireNonNull(operation);
            this.required = required;
            this.maxDelayFromPrevious = maxDelayFromPrevious;
            this.requiredParameters = requiredParameters != null
                    ? Collections.unmodifiableMap(new HashMap<>(requiredParameters))
                    : Collections.emptyMap();
        }

        public PatternStep(int stepNumber, SignalingOperation operation) {
            this(stepNumber, operation, true, null, null);
        }

        public int getStepNumber() { return stepNumber; }
        public SignalingOperation getOperation() { return operation; }
        public boolean isRequired() { return required; }
        public Duration getMaxDelayFromPrevious() { return maxDelayFromPrevious; }
        public Map<String, String> getRequiredParameters() { return requiredParameters; }

        @Override
        public String toString() {
            return String.format("Step[%d: %s (%s)%s]",
                    stepNumber,
                    operation.getDisplayName(),
                    operation.getProtocolInterface().getDisplayName(),
                    required ? "" : " optional");
        }
    }

    /**
     * Severity levels for detected attacks.
     */
    public enum Severity {
        /** Information gathering, may be legitimate */
        LOW(1, "Low"),
        /** Suspicious activity, likely unauthorized */
        MEDIUM(2, "Medium"),
        /** Active attack in progress */
        HIGH(3, "High"),
        /** Interception or subscriber manipulation confirmed */
        CRITICAL(4, "Critical");

        private final int level;
        private final String displayName;

        Severity(int level, String displayName) {
            this.level = level;
            this.displayName = displayName;
        }

        public int getLevel() { return level; }
        public String getDisplayName() { return displayName; }
    }

    public static final class Builder {
        private String patternId;
        private String name;
        private String description;
        private Severity severity;
        private final List<PatternStep> steps = new ArrayList<>();
        private Duration maxWindow;
        private Set<String> mitreTechniques;
        private boolean requireSameSource = false;

        public Builder patternId(String id) { this.patternId = id; return this; }
        public Builder name(String name) { this.name = name; return this; }
        public Builder description(String desc) { this.description = desc; return this; }
        public Builder severity(Severity sev) { this.severity = sev; return this; }
        public Builder maxWindow(Duration d) { this.maxWindow = d; return this; }
        public Builder requireSameSource(boolean b) { this.requireSameSource = b; return this; }
        public Builder mitreTechniques(Set<String> t) { this.mitreTechniques = t; return this; }

        public Builder addStep(PatternStep step) {
            this.steps.add(step);
            return this;
        }

        public Builder addStep(int stepNum, SignalingOperation op) {
            return addStep(new PatternStep(stepNum, op));
        }

        public Builder addStep(int stepNum, SignalingOperation op, boolean required) {
            return addStep(new PatternStep(stepNum, op, required, null, null));
        }

        public AttackPattern build() {
            return new AttackPattern(this);
        }
    }
}
