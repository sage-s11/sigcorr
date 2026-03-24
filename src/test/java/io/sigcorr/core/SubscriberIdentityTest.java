package io.sigcorr.core;

import io.sigcorr.core.identity.SubscriberIdentity;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.*;

@DisplayName("SubscriberIdentity")
class SubscriberIdentityTest {

    @Test
    @DisplayName("Create from valid IMSI")
    void createFromValidImsi() {
        var id = SubscriberIdentity.fromImsi("234101234567890");
        assertThat(id.hasImsi()).isTrue();
        assertThat(id.hasMsisdn()).isFalse();
        assertThat(id.getImsi()).contains("234101234567890");
        assertThat(id.getCorrelationKey()).isEqualTo("IMSI:234101234567890");
    }

    @Test
    @DisplayName("Create from valid MSISDN")
    void createFromValidMsisdn() {
        var id = SubscriberIdentity.fromMsisdn("447712345678");
        assertThat(id.hasMsisdn()).isTrue();
        assertThat(id.hasImsi()).isFalse();
        assertThat(id.getMsisdn()).contains("447712345678");
        assertThat(id.getCorrelationKey()).isEqualTo("MSISDN:447712345678");
    }

    @Test
    @DisplayName("Create from both IMSI and MSISDN")
    void createFromBoth() {
        var id = SubscriberIdentity.fromBoth("234101234567890", "447712345678");
        assertThat(id.hasImsi()).isTrue();
        assertThat(id.hasMsisdn()).isTrue();
        assertThat(id.getCorrelationKey()).isEqualTo("IMSI:234101234567890");
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "1234", "12345678901234567", "abcdefghijklmno"})
    @DisplayName("Reject invalid IMSI")
    void rejectInvalidImsi(String imsi) {
        assertThatThrownBy(() -> SubscriberIdentity.fromImsi(imsi))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "123", "12345", "1234567890123456", "abcdefgh"})
    @DisplayName("Reject invalid MSISDN")
    void rejectInvalidMsisdn(String msisdn) {
        assertThatThrownBy(() -> SubscriberIdentity.fromMsisdn(msisdn))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("Reject null-null identity")
    void rejectNullNull() {
        assertThatThrownBy(() -> SubscriberIdentity.of(null, null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("Extract MCC from IMSI")
    void extractMcc() {
        var id = SubscriberIdentity.fromImsi("234101234567890");
        assertThat(id.getMcc()).contains("234"); // UK MCC
    }

    @Test
    @DisplayName("Extract 2-digit MNC from IMSI")
    void extractMnc2Digit() {
        var id = SubscriberIdentity.fromImsi("234101234567890");
        assertThat(id.getMnc(2)).contains("10"); // EE UK
    }

    @Test
    @DisplayName("Extract 3-digit MNC from IMSI")
    void extractMnc3Digit() {
        var id = SubscriberIdentity.fromImsi("310260123456789");
        assertThat(id.getMnc(3)).contains("260"); // T-Mobile US
    }

    @Test
    @DisplayName("Merge identities — IMSI only + MSISDN only")
    void mergeComplementary() {
        var imsiOnly = SubscriberIdentity.fromImsi("234101234567890");
        var msisdnOnly = SubscriberIdentity.fromMsisdn("447712345678");
        var merged = imsiOnly.merge(msisdnOnly);
        assertThat(merged.hasImsi()).isTrue();
        assertThat(merged.hasMsisdn()).isTrue();
        assertThat(merged.getImsi()).contains("234101234567890");
        assertThat(merged.getMsisdn()).contains("447712345678");
    }

    @Test
    @DisplayName("Merge identities — same IMSI is OK")
    void mergeSameImsi() {
        var a = SubscriberIdentity.fromImsi("234101234567890");
        var b = SubscriberIdentity.fromBoth("234101234567890", "447712345678");
        var merged = a.merge(b);
        assertThat(merged.getImsi()).contains("234101234567890");
        assertThat(merged.getMsisdn()).contains("447712345678");
    }

    @Test
    @DisplayName("Merge fails on IMSI conflict")
    void mergeImsiConflict() {
        var a = SubscriberIdentity.fromImsi("234101234567890");
        var b = SubscriberIdentity.fromImsi("234109876543210");
        assertThatThrownBy(() -> a.merge(b))
                .isInstanceOf(SubscriberIdentity.IdentityConflictException.class)
                .hasMessageContaining("IMSI conflict");
    }

    @Test
    @DisplayName("Merge fails on MSISDN conflict")
    void mergeMsisdnConflict() {
        var a = SubscriberIdentity.fromMsisdn("447712345678");
        var b = SubscriberIdentity.fromMsisdn("447798765432");
        assertThatThrownBy(() -> a.merge(b))
                .isInstanceOf(SubscriberIdentity.IdentityConflictException.class)
                .hasMessageContaining("MSISDN conflict");
    }

    @Test
    @DisplayName("couldMatch — same IMSI matches")
    void couldMatchSameImsi() {
        var a = SubscriberIdentity.fromImsi("234101234567890");
        var b = SubscriberIdentity.fromBoth("234101234567890", "447712345678");
        assertThat(a.couldMatch(b)).isTrue();
    }

    @Test
    @DisplayName("couldMatch — same MSISDN matches")
    void couldMatchSameMsisdn() {
        var a = SubscriberIdentity.fromMsisdn("447712345678");
        var b = SubscriberIdentity.fromMsisdn("447712345678");
        assertThat(a.couldMatch(b)).isTrue();
    }

    @Test
    @DisplayName("couldMatch — different identifiers cannot determine")
    void couldMatchNoOverlap() {
        var imsiOnly = SubscriberIdentity.fromImsi("234101234567890");
        var msisdnOnly = SubscriberIdentity.fromMsisdn("447712345678");
        assertThat(imsiOnly.couldMatch(msisdnOnly)).isFalse();
    }

    @Test
    @DisplayName("14-digit IMSI is valid")
    void fourteenDigitImsi() {
        assertThatNoException().isThrownBy(() ->
                SubscriberIdentity.fromImsi("23410123456789"));
    }

    @Test
    @DisplayName("Equality based on both fields")
    void equality() {
        var a = SubscriberIdentity.fromBoth("234101234567890", "447712345678");
        var b = SubscriberIdentity.fromBoth("234101234567890", "447712345678");
        assertThat(a).isEqualTo(b);
        assertThat(a.hashCode()).isEqualTo(b.hashCode());
    }

    @Test
    @DisplayName("toString is readable")
    void toStringReadable() {
        var id = SubscriberIdentity.fromBoth("234101234567890", "447712345678");
        assertThat(id.toString()).contains("IMSI=234101234567890");
        assertThat(id.toString()).contains("MSISDN=447712345678");
    }
}
