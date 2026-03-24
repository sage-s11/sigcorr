package io.sigcorr.protocol.common;

import io.sigcorr.core.event.SignalingEvent;

import java.util.List;
import java.util.Optional;

/**
 * Interface for protocol-specific message decoders.
 *
 * Each decoder is responsible for:
 * 1. Detecting whether a raw byte sequence belongs to its protocol
 * 2. Parsing the message structure
 * 3. Extracting subscriber identity, operation type, and parameters
 * 4. Producing a normalized SignalingEvent
 *
 * Decoders are stateless — all context is in the raw bytes.
 */
public interface ProtocolDecoder {

    /**
     * Attempt to decode a raw message into a normalized SignalingEvent.
     *
     * @param rawBytes   the raw protocol message bytes
     * @param timestamp  capture timestamp (from pcap or trace file)
     * @return decoded event, or empty if this decoder can't handle the message
     */
    Optional<SignalingEvent> decode(byte[] rawBytes, java.time.Instant timestamp);

    /**
     * Decode multiple messages from a byte stream (e.g., a capture buffer).
     * Default implementation delegates to single-message decode.
     */
    default List<SignalingEvent> decodeStream(byte[] stream, java.time.Instant baseTimestamp) {
        Optional<SignalingEvent> event = decode(stream, baseTimestamp);
        return event.map(List::of).orElse(List.of());
    }

    /**
     * Check if this decoder can potentially handle the given bytes.
     * Quick heuristic check before attempting full decode.
     */
    boolean canDecode(byte[] rawBytes);

    /**
     * Human-readable name of this decoder.
     */
    String getDecoderName();
}
