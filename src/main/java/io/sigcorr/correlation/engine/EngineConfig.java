package io.sigcorr.correlation.engine;

import io.sigcorr.detection.patterns.AttackPattern;
import io.sigcorr.detection.whitelist.Whitelist;

import java.time.Duration;
import java.util.List;
import java.util.Set;

/**
 * Configuration for the CorrelationEngine.
 */
public class EngineConfig {

    private Duration correlationWindow;
    private long deduplicationWindowMs;
    private Set<String> homeNetworkIdentifiers;
    private List<AttackPattern> customPatterns;
    private Whitelist whitelist;

    private EngineConfig() {}

    public static EngineConfig defaults() {
        EngineConfig config = new EngineConfig();
        config.correlationWindow = Duration.ofMinutes(10);
        config.deduplicationWindowMs = 60_000L; // 1 minute dedup
        config.homeNetworkIdentifiers = Set.of();
        config.customPatterns = null; // Use built-in catalog
        config.whitelist = Whitelist.disabled();
        return config;
    }

    public Duration getCorrelationWindow() { return correlationWindow; }
    public long getDeduplicationWindowMs() { return deduplicationWindowMs; }
    public Set<String> getHomeNetworkIdentifiers() { return homeNetworkIdentifiers; }
    public List<AttackPattern> getCustomPatterns() { return customPatterns; }
    public Whitelist getWhitelist() { return whitelist; }

    public EngineConfig withCorrelationWindow(Duration d) {
        this.correlationWindow = d; return this;
    }

    public EngineConfig withDeduplicationWindowMs(long ms) {
        this.deduplicationWindowMs = ms; return this;
    }

    public EngineConfig withHomeNetworkIdentifiers(Set<String> ids) {
        this.homeNetworkIdentifiers = ids; return this;
    }

    public EngineConfig withCustomPatterns(List<AttackPattern> patterns) {
        this.customPatterns = patterns; return this;
    }

    public EngineConfig withWhitelist(Whitelist whitelist) {
        this.whitelist = whitelist; return this;
    }
}
