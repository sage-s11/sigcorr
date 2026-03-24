package io.sigcorr.core;

import io.sigcorr.core.identity.IdentityResolver;
import io.sigcorr.core.identity.SubscriberIdentity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.*;

@DisplayName("IdentityResolver")
class IdentityResolverTest {

    private IdentityResolver resolver;

    @BeforeEach
    void setUp() {
        resolver = new IdentityResolver();
    }

    @Test
    @DisplayName("Register and retrieve IMSI→MSISDN mapping")
    void registerAndRetrieve() {
        resolver.registerMapping("234101234567890", "447712345678");
        assertThat(resolver.lookupMsisdn("234101234567890")).contains("447712345678");
        assertThat(resolver.lookupImsi("447712345678")).contains("234101234567890");
        assertThat(resolver.getMappingCount()).isEqualTo(1);
    }

    @Test
    @DisplayName("Resolve MSISDN-only identity to full identity via learned mapping")
    void resolveEnrichment() {
        resolver.registerMapping("234101234567890", "447712345678");
        var resolved = resolver.resolveByMsisdn("447712345678");
        assertThat(resolved.hasImsi()).isTrue();
        assertThat(resolved.hasMsisdn()).isTrue();
        assertThat(resolved.getImsi()).contains("234101234567890");
    }

    @Test
    @DisplayName("Correlation key prefers IMSI over MSISDN")
    void correlationKeyPrefersImsi() {
        resolver.registerMapping("234101234567890", "447712345678");
        var msisdnOnly = SubscriberIdentity.fromMsisdn("447712345678");
        String key = resolver.getCorrelationKey(msisdnOnly);
        assertThat(key).isEqualTo("IMSI:234101234567890");
    }

    @Test
    @DisplayName("Unknown MSISDN falls back to MSISDN key")
    void unknownMsisdnFallback() {
        var unknown = SubscriberIdentity.fromMsisdn("447799999999");
        String key = resolver.getCorrelationKey(unknown);
        assertThat(key).isEqualTo("MSISDN:447799999999");
    }

    @Test
    @DisplayName("Multiple mappings tracked independently")
    void multipleMappings() {
        resolver.registerMapping("234101234567890", "447712345678");
        resolver.registerMapping("310260123456789", "12025551234");
        assertThat(resolver.getMappingCount()).isEqualTo(2);
        assertThat(resolver.lookupImsi("447712345678")).contains("234101234567890");
        assertThat(resolver.lookupImsi("12025551234")).contains("310260123456789");
    }

    @Test
    @DisplayName("Clear removes all mappings")
    void clearMappings() {
        resolver.registerMapping("234101234567890", "447712345678");
        resolver.clear();
        assertThat(resolver.getMappingCount()).isEqualTo(0);
        assertThat(resolver.lookupImsi("447712345678")).isEmpty();
    }

    @Test
    @DisplayName("Resolve by unknown IMSI returns IMSI-only identity")
    void resolveUnknownImsi() {
        var resolved = resolver.resolveByImsi("234109999999990");
        assertThat(resolved.hasImsi()).isTrue();
        assertThat(resolved.hasMsisdn()).isFalse();
    }
}
