package io.sigcorr.protocol.diameter;

import io.sigcorr.core.event.NetworkNode;
import io.sigcorr.core.event.SignalingEvent;
import io.sigcorr.core.identity.SubscriberIdentity;
import io.sigcorr.core.model.ProtocolInterface;
import io.sigcorr.core.model.SignalingOperation;
import io.sigcorr.protocol.common.ProtocolDecoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

/**
 * Decoder for Diameter S6a/S6d messages (3GPP TS 29.272).
 *
 * Diameter messages have a fixed 20-byte header followed by AVPs (Attribute-Value Pairs).
 *
 * Header format (20 bytes):
 *   Version (1) | Message Length (3) | Flags (1) | Command Code (3) | Application-ID (4)
 *   Hop-by-Hop ID (4) | End-to-End ID (4)
 *
 * Flags: R(equest) P(roxiable) E(rror) T(retransmitted)
 *
 * AVP format:
 *   AVP Code (4) | Flags (1) | AVP Length (3) | [Vendor-ID (4)] | Data (padded to 4-byte boundary)
 *
 * Key AVPs for security analysis:
 *   1: User-Name (contains IMSI for S6a)
 *   264: Origin-Host
 *   296: Origin-Realm
 *   263: Session-Id
 *   268: Result-Code
 *   1400: Subscription-Data (grouped)
 *   1407: Visited-PLMN-Id
 */
public class DiameterDecoder implements ProtocolDecoder {

    private static final Logger log = LoggerFactory.getLogger(DiameterDecoder.class);

    // Diameter header
    private static final int HEADER_LENGTH = 20;
    private static final int DIAMETER_VERSION = 1;

    // Diameter flags
    private static final int FLAG_REQUEST = 0x80;

    // S6a Application ID (3GPP TS 29.272)
    private static final long APP_ID_S6A = 16777251L;

    // Common AVP codes
    private static final int AVP_USER_NAME = 1;           // IMSI in S6a
    private static final int AVP_SESSION_ID = 263;
    private static final int AVP_ORIGIN_HOST = 264;
    private static final int AVP_ORIGIN_REALM = 296;
    private static final int AVP_DESTINATION_HOST = 293;
    private static final int AVP_DESTINATION_REALM = 283;
    private static final int AVP_RESULT_CODE = 268;
    private static final int AVP_AUTH_SESSION_STATE = 277;

    // 3GPP-specific AVP codes (Vendor-ID 10415)
    private static final int AVP_VISITED_PLMN_ID = 1407;
    private static final int AVP_ULR_FLAGS = 1405;
    private static final int AVP_IDA_FLAGS = 1441;
    private static final int AVP_SUBSCRIPTION_DATA = 1400;

    // Vendor IDs
    private static final long VENDOR_3GPP = 10415L;

    @Override
    public String getDecoderName() {
        return "Diameter/S6a";
    }

    @Override
    public boolean canDecode(byte[] rawBytes) {
        if (rawBytes == null || rawBytes.length < HEADER_LENGTH) return false;
        // Check version byte
        return (rawBytes[0] & 0xFF) == DIAMETER_VERSION;
    }

    @Override
    public Optional<SignalingEvent> decode(byte[] rawBytes, Instant timestamp) {
        if (!canDecode(rawBytes)) return Optional.empty();

        try {
            return decodeDiameterMessage(rawBytes, timestamp);
        } catch (Exception e) {
            log.debug("Failed to decode Diameter message: {}", e.getMessage());
            return Optional.empty();
        }
    }

    private Optional<SignalingEvent> decodeDiameterMessage(byte[] bytes, Instant timestamp) {
        ByteBuffer buf = ByteBuffer.wrap(bytes);

        // Parse header
        int versionAndLength = buf.getInt();
        int version = (versionAndLength >> 24) & 0xFF;
        int messageLength = versionAndLength & 0x00FFFFFF;

        if (version != DIAMETER_VERSION) return Optional.empty();
        if (messageLength > bytes.length) {
            log.debug("Diameter message length {} exceeds available bytes {}", messageLength, bytes.length);
            messageLength = bytes.length; // Truncated capture
        }

        int flagsAndCommand = buf.getInt();
        int flags = (flagsAndCommand >> 24) & 0xFF;
        int commandCode = flagsAndCommand & 0x00FFFFFF;
        boolean isRequest = (flags & FLAG_REQUEST) != 0;

        long applicationId = buf.getInt() & 0xFFFFFFFFL;
        int hopByHopId = buf.getInt();
        int endToEndId = buf.getInt();

        // Parse AVPs
        Map<Integer, byte[]> avps = new LinkedHashMap<>();
        while (buf.position() < messageLength && buf.remaining() >= 8) {
            int avpCode = buf.getInt();
            int avpFlagsAndLength = buf.getInt();
            int avpFlags = (avpFlagsAndLength >> 24) & 0xFF;
            int avpLength = avpFlagsAndLength & 0x00FFFFFF;
            boolean hasVendor = (avpFlags & 0x80) != 0;

            int dataOffset = hasVendor ? 12 : 8; // header is 8 or 12 bytes
            int dataLength = avpLength - dataOffset;

            if (hasVendor && buf.remaining() >= 4) {
                long vendorId = buf.getInt() & 0xFFFFFFFFL;
                // Prefix vendor AVPs: vendorId * 100000 + avpCode
                if (vendorId == VENDOR_3GPP) {
                    avpCode = (int) (VENDOR_3GPP * 100000 + avpCode);
                }
            }

            if (dataLength > 0 && buf.remaining() >= dataLength) {
                byte[] data = new byte[dataLength];
                buf.get(data);
                avps.put(avpCode, data);
            }

            // Pad to 4-byte boundary
            int padded = (avpLength + 3) & ~3;
            int paddingBytes = padded - avpLength;
            if (paddingBytes > 0 && buf.remaining() >= paddingBytes) {
                buf.position(buf.position() + paddingBytes);
            }
        }

        // Determine operation
        SignalingOperation operation = SignalingOperation.fromDiameterCommand(commandCode, isRequest);
        if (operation == null) {
            log.debug("Unknown Diameter command code: {} (request={})", commandCode, isRequest);
            return Optional.empty();
        }

        // Extract subscriber identity (User-Name AVP contains IMSI in S6a)
        Map<String, String> params = new HashMap<>();
        params.put("commandCode", String.valueOf(commandCode));
        params.put("isRequest", String.valueOf(isRequest));
        params.put("applicationId", String.valueOf(applicationId));
        params.put("hopByHopId", String.valueOf(hopByHopId));
        params.put("endToEndId", String.valueOf(endToEndId));

        SubscriberIdentity subscriber = null;

        // User-Name AVP (1) = IMSI in S6a context
        byte[] userName = avps.get(AVP_USER_NAME);
        if (userName != null) {
            String imsi = new String(userName, StandardCharsets.UTF_8).trim();
            if (imsi.matches("\\d{14,15}")) {
                subscriber = SubscriberIdentity.fromImsi(imsi);
                params.put("imsi", imsi);
            }
        }

        if (subscriber == null) return Optional.empty();

        // Extract network node info
        NetworkNode sourceNode = null;
        byte[] originHost = avps.get(AVP_ORIGIN_HOST);
        byte[] originRealm = avps.get(AVP_ORIGIN_REALM);
        if (originHost != null) {
            String host = new String(originHost, StandardCharsets.UTF_8).trim();
            String realm = originRealm != null
                    ? new String(originRealm, StandardCharsets.UTF_8).trim() : null;
            sourceNode = NetworkNode.fromDiameterHost(host, realm);
            params.put("originHost", host);
            if (realm != null) params.put("originRealm", realm);
        }

        // Extract destination
        NetworkNode destNode = null;
        byte[] destHost = avps.get(AVP_DESTINATION_HOST);
        byte[] destRealm = avps.get(AVP_DESTINATION_REALM);
        if (destHost != null) {
            String host = new String(destHost, StandardCharsets.UTF_8).trim();
            String realm = destRealm != null
                    ? new String(destRealm, StandardCharsets.UTF_8).trim() : null;
            destNode = NetworkNode.fromDiameterHost(host, realm);
            params.put("destinationHost", host);
            if (realm != null) params.put("destinationRealm", realm);
        }

        // Session ID
        byte[] sessionId = avps.get(AVP_SESSION_ID);
        if (sessionId != null) {
            params.put("sessionId", new String(sessionId, StandardCharsets.UTF_8).trim());
        }

        // Visited PLMN ID (3GPP AVP 1407)
        int visitedPlmnAvpCode = (int) (VENDOR_3GPP * 100000 + AVP_VISITED_PLMN_ID);
        byte[] visitedPlmn = avps.get(visitedPlmnAvpCode);
        if (visitedPlmn != null && visitedPlmn.length >= 3) {
            String plmn = decodePlmnId(visitedPlmn);
            if (plmn != null) params.put("visitedPlmn", plmn);
        }

        // Result code (for answers)
        byte[] resultCode = avps.get(AVP_RESULT_CODE);
        if (resultCode != null && resultCode.length == 4) {
            int code = ByteBuffer.wrap(resultCode).getInt();
            params.put("resultCode", String.valueOf(code));
        }

        return Optional.of(SignalingEvent.builder()
                .timestamp(timestamp)
                .protocolInterface(ProtocolInterface.DIAMETER_S6A)
                .operation(operation)
                .subscriber(subscriber)
                .sourceNode(sourceNode)
                .destinationNode(destNode)
                .parameters(params)
                .direction(isRequest ? SignalingEvent.Direction.INBOUND : SignalingEvent.Direction.OUTBOUND)
                .rawBytes(bytes)
                .build());
    }

    /**
     * Decode PLMN-ID (3 bytes BCD-encoded: MCC + MNC).
     * Byte 0: MCC digit 2 | MCC digit 1
     * Byte 1: MNC digit 3 | MCC digit 3
     * Byte 2: MNC digit 2 | MNC digit 1
     */
    public static String decodePlmnId(byte[] bytes) {
        if (bytes.length < 3) return null;
        int mcc1 = bytes[0] & 0x0F;
        int mcc2 = (bytes[0] >> 4) & 0x0F;
        int mcc3 = bytes[1] & 0x0F;
        int mnc3 = (bytes[1] >> 4) & 0x0F;
        int mnc1 = bytes[2] & 0x0F;
        int mnc2 = (bytes[2] >> 4) & 0x0F;

        String mcc = "" + mcc1 + mcc2 + mcc3;
        String mnc = mnc3 == 0x0F ? ("" + mnc1 + mnc2) : ("" + mnc1 + mnc2 + mnc3);
        return mcc + mnc;
    }
}
