package io.sigcorr.protocol.gtpc;

import io.sigcorr.core.event.NetworkNode;
import io.sigcorr.core.event.SignalingEvent;
import io.sigcorr.core.identity.SubscriberIdentity;
import io.sigcorr.core.model.ProtocolInterface;
import io.sigcorr.core.model.SignalingOperation;
import io.sigcorr.protocol.common.ProtocolDecoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.*;

/**
 * Decoder for GTPv2-C (GTP Control Plane version 2) messages (3GPP TS 29.274).
 *
 * GTPv2-C is used for session/bearer management in 4G/LTE networks, carrying
 * messages between SGW, PGW, and MME.
 *
 * Header format (variable, 8 or 12 bytes):
 *   Version (3 bits) | P | T | Spare (3 bits) | Message Type (1 byte)
 *   Message Length (2 bytes) | [TEID (4 bytes if T=1)]
 *   Sequence Number (3 bytes) | Spare (1 byte)
 *
 * IE (Information Element) format:
 *   IE Type (1 byte) | IE Length (2 bytes) | Spare (4 bits) | Instance (4 bits) | Data
 *
 * Key IEs for security analysis:
 *   1: IMSI
 *   2: Cause
 *   3: Recovery
 *   71: APN (Access Point Name)
 *   76: MSISDN
 *   82: RAT Type
 *   86: User Location Information (ULI)
 *   87: F-TEID (Fully Qualified TEID)
 *   93: Bearer Context
 */
public class GtpcDecoder implements ProtocolDecoder {

    private static final Logger log = LoggerFactory.getLogger(GtpcDecoder.class);

    // GTPv2-C header
    private static final int GTPV2_VERSION = 2;
    private static final int MIN_HEADER_LENGTH = 8;

    // IE Types
    private static final int IE_IMSI = 1;
    private static final int IE_CAUSE = 2;
    private static final int IE_APN = 71;
    private static final int IE_MSISDN = 76;
    private static final int IE_RAT_TYPE = 82;
    private static final int IE_SERVING_NETWORK = 83;
    private static final int IE_ULI = 86;
    private static final int IE_FTEID = 87;
    private static final int IE_BEARER_CONTEXT = 93;
    private static final int IE_PDN_TYPE = 99;

    @Override
    public String getDecoderName() {
        return "GTPv2-C";
    }

    @Override
    public boolean canDecode(byte[] rawBytes) {
        if (rawBytes == null || rawBytes.length < MIN_HEADER_LENGTH) return false;
        int version = (rawBytes[0] >> 5) & 0x07;
        return version == GTPV2_VERSION;
    }

    @Override
    public Optional<SignalingEvent> decode(byte[] rawBytes, Instant timestamp) {
        if (!canDecode(rawBytes)) return Optional.empty();

        try {
            return decodeGtpcMessage(rawBytes, timestamp);
        } catch (Exception e) {
            log.debug("Failed to decode GTPv2-C message: {}", e.getMessage());
            return Optional.empty();
        }
    }

    private Optional<SignalingEvent> decodeGtpcMessage(byte[] bytes, Instant timestamp) {
        ByteBuffer buf = ByteBuffer.wrap(bytes);

        // Parse header
        int firstByte = buf.get() & 0xFF;
        int version = (firstByte >> 5) & 0x07;
        boolean hasPiggyback = (firstByte & 0x10) != 0;
        boolean hasTeid = (firstByte & 0x08) != 0;

        int messageType = buf.get() & 0xFF;
        int messageLength = buf.getShort() & 0xFFFF;

        long teid = 0;
        if (hasTeid) {
            teid = buf.getInt() & 0xFFFFFFFFL;
        }

        int sequenceNumber = 0;
        if (buf.remaining() >= 4) {
            sequenceNumber = ((buf.get() & 0xFF) << 16) | ((buf.get() & 0xFF) << 8) | (buf.get() & 0xFF);
            buf.get(); // spare
        }

        // Determine operation
        SignalingOperation operation = SignalingOperation.fromGtpMessageType(messageType);
        if (operation == null) {
            log.debug("Unknown GTPv2-C message type: {}", messageType);
            return Optional.empty();
        }

        // Parse IEs
        Map<Integer, byte[]> ies = new LinkedHashMap<>();
        int headerSize = hasTeid ? 12 : 8;
        int ieEnd = Math.min(headerSize + messageLength, bytes.length);

        while (buf.position() < ieEnd && buf.remaining() >= 4) {
            int ieType = buf.get() & 0xFF;
            int ieLength = buf.getShort() & 0xFFFF;
            int ieSpareInstance = buf.get() & 0xFF;
            int instance = ieSpareInstance & 0x0F;

            if (ieLength > 0 && buf.remaining() >= ieLength) {
                byte[] ieData = new byte[ieLength];
                buf.get(ieData);
                // Key by type*16 + instance to handle multiple IEs of same type
                ies.put(ieType * 16 + instance, ieData);
            } else {
                break;
            }
        }

        // Extract subscriber identity
        Map<String, String> params = new HashMap<>();
        params.put("messageType", String.valueOf(messageType));
        params.put("sequenceNumber", String.valueOf(sequenceNumber));
        if (hasTeid) params.put("teid", String.valueOf(teid));

        SubscriberIdentity subscriber = null;

        // IMSI IE (type 1)
        byte[] imsiIe = ies.get(IE_IMSI * 16);
        if (imsiIe != null) {
            String imsi = decodeTbcdImsi(imsiIe);
            if (imsi != null) {
                subscriber = SubscriberIdentity.fromImsi(imsi);
                params.put("imsi", imsi);
            }
        }

        // MSISDN IE (type 76)
        byte[] msisdnIe = ies.get(IE_MSISDN * 16);
        if (msisdnIe != null) {
            String msisdn = decodeTbcdMsisdn(msisdnIe);
            if (msisdn != null) {
                params.put("msisdn", msisdn);
                if (subscriber != null && subscriber.hasImsi()) {
                    subscriber = SubscriberIdentity.of(subscriber.getImsi().orElse(null), msisdn);
                } else if (subscriber == null) {
                    subscriber = SubscriberIdentity.fromMsisdn(msisdn);
                }
            }
        }

        if (subscriber == null) return Optional.empty();

        // APN IE
        byte[] apnIe = ies.get(IE_APN * 16);
        if (apnIe != null) {
            String apn = decodeApn(apnIe);
            if (apn != null) params.put("apn", apn);
        }

        // RAT Type IE
        byte[] ratIe = ies.get(IE_RAT_TYPE * 16);
        if (ratIe != null && ratIe.length >= 1) {
            params.put("ratType", String.valueOf(ratIe[0] & 0xFF));
        }

        // Serving Network IE (PLMN)
        byte[] servingNetIe = ies.get(IE_SERVING_NETWORK * 16);
        if (servingNetIe != null && servingNetIe.length >= 3) {
            String plmn = decodePlmnFromIe(servingNetIe);
            if (plmn != null) params.put("servingPlmn", plmn);
        }

        // F-TEID IE — extract peer IP
        NetworkNode sourceNode = null;
        byte[] fteidIe = ies.get(IE_FTEID * 16);
        if (fteidIe != null && fteidIe.length >= 5) {
            String ip = extractFteidIp(fteidIe);
            if (ip != null) {
                sourceNode = NetworkNode.fromGtpPeer(ip);
                params.put("fteidIp", ip);
            }
        }

        // ULI IE — User Location Information
        byte[] uliIe = ies.get(IE_ULI * 16);
        if (uliIe != null) {
            String uliInfo = parseUliBasic(uliIe);
            if (uliInfo != null) params.put("uli", uliInfo);
        }

        return Optional.of(SignalingEvent.builder()
                .timestamp(timestamp)
                .protocolInterface(ProtocolInterface.GTPC_V2)
                .operation(operation)
                .subscriber(subscriber)
                .sourceNode(sourceNode)
                .parameters(params)
                .direction(SignalingEvent.Direction.INBOUND)
                .rawBytes(bytes)
                .build());
    }

    /**
     * Decode IMSI from GTPv2-C TBCD encoding.
     */
    public static String decodeTbcdImsi(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            int low = b & 0x0F;
            int high = (b >> 4) & 0x0F;
            if (low <= 9) sb.append((char) ('0' + low));
            else if (low == 0x0F) break;
            if (high <= 9) sb.append((char) ('0' + high));
            else if (high == 0x0F) break;
        }
        String result = sb.toString();
        return (result.length() >= 14 && result.length() <= 15) ? result : null;
    }

    /**
     * Decode MSISDN from GTPv2-C TBCD encoding.
     */
    public static String decodeTbcdMsisdn(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            int low = b & 0x0F;
            int high = (b >> 4) & 0x0F;
            if (low <= 9) sb.append((char) ('0' + low));
            else if (low == 0x0F) break;
            if (high <= 9) sb.append((char) ('0' + high));
            else if (high == 0x0F) break;
        }
        String result = sb.toString();
        return (result.length() >= 7 && result.length() <= 15) ? result : null;
    }

    /**
     * Decode APN from label-length encoded format.
     */
    public static String decodeApn(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        int i = 0;
        while (i < bytes.length) {
            int labelLen = bytes[i] & 0xFF;
            i++;
            if (labelLen == 0 || i + labelLen > bytes.length) break;
            if (sb.length() > 0) sb.append('.');
            for (int j = 0; j < labelLen; j++) {
                sb.append((char) (bytes[i + j] & 0xFF));
            }
            i += labelLen;
        }
        return sb.length() > 0 ? sb.toString() : null;
    }

    /**
     * Extract IPv4 address from F-TEID IE.
     */
    public static String extractFteidIp(byte[] bytes) {
        if (bytes.length < 5) return null;
        int flags = bytes[0] & 0xFF;
        boolean hasV4 = (flags & 0x80) != 0;
        // Skip TEID (4 bytes after flags)
        if (hasV4 && bytes.length >= 9) {
            return String.format("%d.%d.%d.%d",
                    bytes[5] & 0xFF, bytes[6] & 0xFF,
                    bytes[7] & 0xFF, bytes[8] & 0xFF);
        }
        return null;
    }

    /**
     * Decode PLMN from Serving Network IE.
     */
    public static String decodePlmnFromIe(byte[] bytes) {
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

    /**
     * Basic ULI parsing — extract TAI/ECGI if present.
     */
    public static String parseUliBasic(byte[] bytes) {
        if (bytes.length < 1) return null;
        int flags = bytes[0] & 0xFF;
        // Bit flags indicate which location elements are present
        List<String> parts = new ArrayList<>();
        if ((flags & 0x01) != 0) parts.add("CGI");
        if ((flags & 0x02) != 0) parts.add("SAI");
        if ((flags & 0x04) != 0) parts.add("RAI");
        if ((flags & 0x08) != 0) parts.add("TAI");
        if ((flags & 0x10) != 0) parts.add("ECGI");
        if ((flags & 0x20) != 0) parts.add("LAI");
        return String.join("+", parts);
    }
}
