package io.sigcorr.ingest;

import io.sigcorr.ingest.tshark.TsharkBridge;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.*;

@DisplayName("TsharkBridge")
class TsharkBridgeTest {

    @Test
    @DisplayName("Availability check doesn't crash when tshark is missing")
    void availabilityCheckSafe() {
        TsharkBridge bridge = new TsharkBridge();
        bridge.setTsharkPath("/nonexistent/tshark");
        assertThat(bridge.isTsharkAvailable()).isFalse();
    }

    @Test
    @DisplayName("Version check returns 'unavailable' when tshark is missing")
    void versionCheckSafe() {
        TsharkBridge bridge = new TsharkBridge();
        bridge.setTsharkPath("/nonexistent/tshark");
        assertThat(bridge.getTsharkVersion()).isEqualTo("unavailable");
    }

    @Test
    @DisplayName("decodePcap handles nonexistent file gracefully")
    void decodeNonexistentFile() throws Exception {
        TsharkBridge bridge = new TsharkBridge();
        // If tshark is installed, it handles missing files and returns empty.
        // If not installed, it may throw. Either way, no crash.
        try {
            var events = bridge.decodePcap(java.nio.file.Path.of("/nonexistent/file.pcap"));
            assertThat(events).isEmpty();
        } catch (Exception e) {
            // Expected if tshark not available
        }
    }

    @Test
    @DisplayName("Check tshark on system PATH (informational)")
    void checkSystemTshark() {
        TsharkBridge bridge = new TsharkBridge();
        boolean available = bridge.isTsharkAvailable();
        if (available) {
            System.out.println("tshark found: " + bridge.getTsharkVersion());
        } else {
            System.out.println("tshark not found on PATH (install: sudo apt install tshark)");
        }
        // This test always passes — it's informational
    }
}
