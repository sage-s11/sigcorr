package io.sigcorr.core.event;

import io.sigcorr.core.identity.SubscriberIdentity;
import io.sigcorr.core.model.ProtocolInterface;
import io.sigcorr.core.model.SignalingOperation;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * A normalized signaling event — the universal representation of any
 * protocol-specific message (MAP, Diameter, GTP-C) after decoding.
 *
 * This is the central data structure of SigCorr. The correlation engine
 * operates entirely on SignalingEvents, not on raw protocol messages.
 * The normalization step (protocol decoder → SignalingEvent) is what
 * enables cross-protocol correlation.
 *
 * Immutable by design — events are facts that don't change after creation.
 *
 * Example event flow:
 *   Raw pcap → MAP decoder extracts SendRoutingInfo with MSISDN=447712345678
 *   → SignalingEvent {
 *       operation = MAP_SEND_ROUTING_INFO,
 *       subscriber = Subscriber[MSISDN=447712345678],
 *       sourceNode = "GT:1234567890",
 *       interface = SS7_MAP,
 *       timestamp = 2024-01-15T10:30:00Z,
 *       parameters = {msisdn: "447712345678", interrogationType: "basicCall"}
 *     }
 */
public final class SignalingEvent {

    private final String eventId;
    private final Instant timestamp;
    private final ProtocolInterface protocolInterface;
    private final SignalingOperation operation;
    private final SubscriberIdentity subscriber;
    private final NetworkNode sourceNode;
    private final NetworkNode destinationNode;
    private final Map<String, String> parameters;
    private final Direction direction;
    private final byte[] rawBytes;

    private SignalingEvent(Builder builder) {
        this.eventId = builder.eventId != null ? builder.eventId : UUID.randomUUID().toString();
        this.timestamp = Objects.requireNonNull(builder.timestamp, "timestamp is required");
        this.protocolInterface = Objects.requireNonNull(builder.protocolInterface, "protocolInterface is required");
        this.operation = Objects.requireNonNull(builder.operation, "operation is required");
        this.subscriber = Objects.requireNonNull(builder.subscriber, "subscriber is required");
        this.sourceNode = builder.sourceNode;
        this.destinationNode = builder.destinationNode;
        this.parameters = builder.parameters != null
                ? Collections.unmodifiableMap(builder.parameters)
                : Collections.emptyMap();
        this.direction = builder.direction != null ? builder.direction : Direction.UNKNOWN;
        this.rawBytes = builder.rawBytes;
    }

    // === Accessors ===

    public String getEventId() { return eventId; }
    public Instant getTimestamp() { return timestamp; }
    public ProtocolInterface getProtocolInterface() { return protocolInterface; }
    public SignalingOperation getOperation() { return operation; }
    public SubscriberIdentity getSubscriber() { return subscriber; }
    public NetworkNode getSourceNode() { return sourceNode; }
    public NetworkNode getDestinationNode() { return destinationNode; }
    public Map<String, String> getParameters() { return parameters; }
    public Direction getDirection() { return direction; }
    public byte[] getRawBytes() { return rawBytes != null ? rawBytes.clone() : null; }

    /**
     * Get a specific parameter value.
     */
    public String getParameter(String key) {
        return parameters.get(key);
    }

    /**
     * Check if this event is from the same subscriber as another event.
     */
    public boolean sameSubscriber(SignalingEvent other) {
        return this.subscriber.couldMatch(other.subscriber);
    }

    /**
     * Check if this event is within a time window of another event.
     */
    public boolean withinWindow(SignalingEvent other, long windowMillis) {
        long diff = Math.abs(this.timestamp.toEpochMilli() - other.timestamp.toEpochMilli());
        return diff <= windowMillis;
    }

    /**
     * Check if this event occurred after another event.
     */
    public boolean isAfter(SignalingEvent other) {
        return this.timestamp.isAfter(other.timestamp);
    }

    @Override
    public String toString() {
        return String.format("Event[%s %s %s @ %s from %s]",
                protocolInterface.getDisplayName(),
                operation.getDisplayName(),
                subscriber,
                timestamp,
                sourceNode != null ? sourceNode : "unknown");
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SignalingEvent that = (SignalingEvent) o;
        return Objects.equals(eventId, that.eventId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(eventId);
    }

    // === Builder ===

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private String eventId;
        private Instant timestamp;
        private ProtocolInterface protocolInterface;
        private SignalingOperation operation;
        private SubscriberIdentity subscriber;
        private NetworkNode sourceNode;
        private NetworkNode destinationNode;
        private Map<String, String> parameters;
        private Direction direction;
        private byte[] rawBytes;

        public Builder eventId(String eventId) { this.eventId = eventId; return this; }
        public Builder timestamp(Instant timestamp) { this.timestamp = timestamp; return this; }
        public Builder protocolInterface(ProtocolInterface pi) { this.protocolInterface = pi; return this; }
        public Builder operation(SignalingOperation op) { this.operation = op; return this; }
        public Builder subscriber(SubscriberIdentity sub) { this.subscriber = sub; return this; }
        public Builder sourceNode(NetworkNode node) { this.sourceNode = node; return this; }
        public Builder destinationNode(NetworkNode node) { this.destinationNode = node; return this; }
        public Builder parameters(Map<String, String> params) { this.parameters = params; return this; }
        public Builder direction(Direction dir) { this.direction = dir; return this; }
        public Builder rawBytes(byte[] raw) { this.rawBytes = raw; return this; }

        public SignalingEvent build() {
            return new SignalingEvent(this);
        }
    }

    /**
     * Direction of the signaling message relative to the home network.
     */
    public enum Direction {
        /** Incoming from foreign/roaming network */
        INBOUND,
        /** Outgoing to foreign/roaming network */
        OUTBOUND,
        /** Internal to home network */
        INTERNAL,
        /** Direction unknown */
        UNKNOWN
    }
}
