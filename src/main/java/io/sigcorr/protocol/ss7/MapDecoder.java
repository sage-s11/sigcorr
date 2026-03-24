package io.sigcorr.protocol.ss7;

import io.sigcorr.core.event.NetworkNode;
import io.sigcorr.core.event.SignalingEvent;
import io.sigcorr.core.identity.SubscriberIdentity;
import io.sigcorr.core.model.ProtocolInterface;
import io.sigcorr.core.model.SignalingOperation;
import io.sigcorr.protocol.common.ProtocolDecoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.*;

/**
 * Decoder for SS7 MAP (Mobile Application Part) messages.
 *
 * MAP messages are ASN.1 BER (Basic Encoding Rules) encoded, carried over
 * TCAP (Transaction Capabilities Application Part) over SCCP over MTP3.
 *
 * For pcap-based analysis, we expect either:
 * - Raw TCAP/MAP payloads (extracted from M3UA/SCTP captures)
 * - Hex-encoded MAP operation payloads (from trace files)
 *
 * BER encoding structure:
 *   Tag (1+ bytes) | Length (1+ bytes) | Value (Length bytes)
 *
 * MAP operations are identified by their operation code (local value)
 * within the TCAP Invoke component.
 *
 * Key MAP messages for security analysis:
 * - SendRoutingInfo (opcode 22): MSISDN → IMSI + routing info
 * - ProvideSubscriberInfo (opcode 71): IMSI → location (Cell-ID)
 * - InsertSubscriberData (opcode 7): modify subscriber profile
 * - UpdateLocation (opcode 2): re-register subscriber to new VLR
 * - SendAuthenticationInfo (opcode 56): get auth vectors
 */
public class MapDecoder implements ProtocolDecoder {

    private static final Logger log = LoggerFactory.getLogger(MapDecoder.class);

    // BER tag constants
    private static final int TAG_SEQUENCE = 0x30;
    private static final int TAG_INTEGER = 0x02;
    private static final int TAG_OCTET_STRING = 0x04;
    private static final int TAG_CONTEXT_0 = 0xA0;
    private static final int TAG_CONTEXT_1 = 0xA1;
    private static final int TAG_CONTEXT_2 = 0xA2;

    // TCAP message types
    private static final int TCAP_BEGIN = 0x62;
    private static final int TCAP_CONTINUE = 0x65;
    private static final int TCAP_END = 0x64;
    private static final int TCAP_ABORT = 0x67;

    // TCAP component types
    private static final int COMPONENT_INVOKE = 0xA1;
    private static final int COMPONENT_RETURN_RESULT = 0xA2;
    private static final int COMPONENT_RETURN_ERROR = 0xA3;

    @Override
    public String getDecoderName() {
        return "SS7/MAP";
    }

    @Override
    public boolean canDecode(byte[] rawBytes) {
        if (rawBytes == null || rawBytes.length < 4) return false;
        int firstByte = rawBytes[0] & 0xFF;
        // TCAP message types
        return firstByte == TCAP_BEGIN || firstByte == TCAP_CONTINUE
                || firstByte == TCAP_END || firstByte == TCAP_ABORT;
    }

    @Override
    public Optional<SignalingEvent> decode(byte[] rawBytes, Instant timestamp) {
        if (!canDecode(rawBytes)) return Optional.empty();

        try {
            return decodeTcapMessage(rawBytes, timestamp);
        } catch (Exception e) {
            log.debug("Failed to decode MAP message: {}", e.getMessage());
            return Optional.empty();
        }
    }

    /**
     * Decode a TCAP-wrapped MAP message.
     */
    private Optional<SignalingEvent> decodeTcapMessage(byte[] bytes, Instant timestamp) {
        int offset = 0;
        int tcapTag = bytes[offset] & 0xFF;
        offset++;

        int tcapLength = decodeLength(bytes, offset);
        offset += lengthOfLength(bytes, offset);

        // Parse TCAP components — we need the Invoke or ReturnResult
        // Skip transaction IDs, look for component portion
        String originGT = null;
        String destGT = null;

        while (offset < bytes.length) {
            int tag = bytes[offset] & 0xFF;
            offset++;
            int len = decodeLength(bytes, offset);
            offset += lengthOfLength(bytes, offset);

            if (tag == 0x6C) { // Component portion
                return decodeComponentPortion(bytes, offset, offset + len, timestamp,
                        originGT, destGT);
            } else {
                // Skip other TCAP elements (transaction IDs, dialogue portion)
                if (tag == 0x48 || tag == 0x49) {
                    // Transaction ID — could extract for correlation
                }
                offset += len;
            }
        }

        return Optional.empty();
    }

    /**
     * Decode the TCAP component portion containing MAP operation(s).
     */
    private Optional<SignalingEvent> decodeComponentPortion(byte[] bytes, int start, int end,
                                                            Instant timestamp, String originGT, String destGT) {
        int offset = start;

        while (offset < end && offset < bytes.length) {
            int componentTag = bytes[offset] & 0xFF;
            offset++;
            int componentLen = decodeLength(bytes, offset);
            offset += lengthOfLength(bytes, offset);

            if (componentTag == COMPONENT_INVOKE) {
                return decodeInvoke(bytes, offset, offset + componentLen, timestamp, originGT, destGT);
            } else if (componentTag == COMPONENT_RETURN_RESULT) {
                return decodeReturnResult(bytes, offset, offset + componentLen, timestamp, originGT, destGT);
            }

            offset += componentLen;
        }

        return Optional.empty();
    }

    /**
     * Decode a TCAP Invoke component → MAP operation request.
     */
    private Optional<SignalingEvent> decodeInvoke(byte[] bytes, int start, int end,
                                                  Instant timestamp, String originGT, String destGT) {
        int offset = start;
        int invokeId = -1;
        int operationCode = -1;
        byte[] argumentBytes = null;

        while (offset < end && offset < bytes.length) {
            int tag = bytes[offset] & 0xFF;
            offset++;
            int len = decodeLength(bytes, offset);
            offset += lengthOfLength(bytes, offset);

            if (tag == TAG_INTEGER && invokeId == -1) {
                // First INTEGER is Invoke ID
                invokeId = decodeInteger(bytes, offset, len);
            } else if (tag == TAG_INTEGER) {
                // Second INTEGER is operation code (local value)
                operationCode = decodeInteger(bytes, offset, len);
            } else if (tag == TAG_SEQUENCE || (tag & 0xA0) == 0xA0) {
                // Argument (SEQUENCE or context-tagged)
                argumentBytes = Arrays.copyOfRange(bytes, offset, Math.min(offset + len, bytes.length));
            }

            offset += len;
        }

        if (operationCode == -1) return Optional.empty();

        SignalingOperation operation = SignalingOperation.fromMapOpcode(operationCode);
        if (operation == null) {
            log.debug("Unknown MAP operation code: {}", operationCode);
            return Optional.empty();
        }

        // Extract subscriber identity from argument
        Map<String, String> params = new HashMap<>();
        params.put("operationCode", String.valueOf(operationCode));
        params.put("invokeId", String.valueOf(invokeId));
        params.put("messageType", "invoke");

        SubscriberIdentity subscriber = extractSubscriberFromArgument(operation, argumentBytes, params);
        if (subscriber == null) return Optional.empty();

        SignalingEvent.Builder builder = SignalingEvent.builder()
                .timestamp(timestamp)
                .protocolInterface(ProtocolInterface.SS7_MAP)
                .operation(operation)
                .subscriber(subscriber)
                .parameters(params)
                .direction(SignalingEvent.Direction.INBOUND)
                .rawBytes(Arrays.copyOfRange(bytes, start, Math.min(end, bytes.length)));

        if (originGT != null) builder.sourceNode(NetworkNode.fromGlobalTitle(originGT));
        if (destGT != null) builder.destinationNode(NetworkNode.fromGlobalTitle(destGT));

        return Optional.of(builder.build());
    }

    /**
     * Decode a TCAP ReturnResult component → MAP operation response.
     */
    private Optional<SignalingEvent> decodeReturnResult(byte[] bytes, int start, int end,
                                                        Instant timestamp, String originGT, String destGT) {
        int offset = start;
        int invokeId = -1;
        int operationCode = -1;
        byte[] resultBytes = null;

        while (offset < end && offset < bytes.length) {
            int tag = bytes[offset] & 0xFF;
            offset++;
            int len = decodeLength(bytes, offset);
            offset += lengthOfLength(bytes, offset);

            if (tag == TAG_INTEGER && invokeId == -1) {
                invokeId = decodeInteger(bytes, offset, len);
            } else if (tag == TAG_SEQUENCE) {
                // ReturnResult contains SEQUENCE { operationCode, result }
                int innerOffset = offset;
                if (innerOffset < offset + len) {
                    int innerTag = bytes[innerOffset] & 0xFF;
                    innerOffset++;
                    int innerLen = decodeLength(bytes, innerOffset);
                    innerOffset += lengthOfLength(bytes, innerOffset);
                    if (innerTag == TAG_INTEGER) {
                        operationCode = decodeInteger(bytes, innerOffset, innerLen);
                    }
                    innerOffset += innerLen;
                    if (innerOffset < offset + len) {
                        resultBytes = Arrays.copyOfRange(bytes, innerOffset, Math.min(offset + len, bytes.length));
                    }
                }
            }

            offset += len;
        }

        if (operationCode == -1) return Optional.empty();

        SignalingOperation operation = SignalingOperation.fromMapOpcode(operationCode);
        if (operation == null) return Optional.empty();

        Map<String, String> params = new HashMap<>();
        params.put("operationCode", String.valueOf(operationCode));
        params.put("invokeId", String.valueOf(invokeId));
        params.put("messageType", "returnResult");

        SubscriberIdentity subscriber = extractSubscriberFromResult(operation, resultBytes, params);
        if (subscriber == null) return Optional.empty();

        return Optional.of(SignalingEvent.builder()
                .timestamp(timestamp)
                .protocolInterface(ProtocolInterface.SS7_MAP)
                .operation(operation)
                .subscriber(subscriber)
                .parameters(params)
                .direction(SignalingEvent.Direction.OUTBOUND)
                .rawBytes(Arrays.copyOfRange(bytes, start, Math.min(end, bytes.length)))
                .build());
    }

    /**
     * Extract subscriber identity from MAP operation arguments.
     * Different operations carry identity in different places.
     */
    private SubscriberIdentity extractSubscriberFromArgument(SignalingOperation op,
                                                             byte[] argBytes, Map<String, String> params) {
        if (argBytes == null || argBytes.length == 0) return null;

        switch (op) {
            case MAP_SEND_ROUTING_INFO:
            case MAP_SEND_ROUTING_INFO_GPRS:
                // Argument contains MSISDN as ISDN-AddressString
                String msisdn = extractAddressString(argBytes, 0);
                if (msisdn != null) {
                    params.put("msisdn", msisdn);
                    return SubscriberIdentity.fromMsisdn(msisdn);
                }
                break;

            case MAP_PROVIDE_SUBSCRIBER_INFO:
            case MAP_INSERT_SUBSCRIBER_DATA:
            case MAP_DELETE_SUBSCRIBER_DATA:
            case MAP_SEND_AUTH_INFO:
                // Argument contains IMSI
                String imsi = extractImsi(argBytes, 0);
                if (imsi != null) {
                    params.put("imsi", imsi);
                    return SubscriberIdentity.fromImsi(imsi);
                }
                break;

            case MAP_UPDATE_LOCATION:
                // Contains IMSI + new VLR address
                imsi = extractImsi(argBytes, 0);
                if (imsi != null) {
                    params.put("imsi", imsi);
                    return SubscriberIdentity.fromImsi(imsi);
                }
                break;

            case MAP_REGISTER_SS:
            case MAP_ACTIVATE_SS:
                // Contains MSISDN for supplementary service registration
                msisdn = extractAddressString(argBytes, 0);
                if (msisdn != null) {
                    params.put("msisdn", msisdn);
                    return SubscriberIdentity.fromMsisdn(msisdn);
                }
                break;

            default:
                break;
        }

        // Fallback: try to find any IMSI or MSISDN in the argument
        return extractAnyIdentity(argBytes);
    }

    /**
     * Extract subscriber identity from MAP operation results.
     */
    private SubscriberIdentity extractSubscriberFromResult(SignalingOperation op,
                                                           byte[] resultBytes, Map<String, String> params) {
        if (resultBytes == null || resultBytes.length == 0) return null;

        switch (op) {
            case MAP_SEND_ROUTING_INFO:
                // Result contains IMSI (the mapping we want to learn!)
                String imsi = extractImsi(resultBytes, 0);
                if (imsi != null) {
                    params.put("imsi", imsi);
                    return SubscriberIdentity.fromImsi(imsi);
                }
                break;
            default:
                break;
        }

        return extractAnyIdentity(resultBytes);
    }

    // === BER Utility Methods ===

    /**
     * Extract IMSI from BER-encoded TBCD (Telephony BCD) string.
     * IMSI is encoded as OCTET STRING with BCD nibble swapping.
     */
    public String extractImsi(byte[] bytes, int searchStart) {
        for (int i = searchStart; i < bytes.length - 2; i++) {
            int tag = bytes[i] & 0xFF;
            if (tag == TAG_OCTET_STRING) {
                int len = bytes[i + 1] & 0xFF;
                if (len >= 3 && len <= 8 && i + 2 + len <= bytes.length) {
                    String decoded = decodeTBCD(bytes, i + 2, len);
                    if (decoded != null && decoded.length() >= 14 && decoded.length() <= 15
                            && decoded.chars().allMatch(Character::isDigit)) {
                        return decoded;
                    }
                }
            }
        }
        return null;
    }

    /**
     * Extract ISDN-AddressString (MSISDN/GT) from BER.
     * Format: OCTET STRING { nature+numbering plan, BCD digits... }
     */
    public String extractAddressString(byte[] bytes, int searchStart) {
        for (int i = searchStart; i < bytes.length - 2; i++) {
            int tag = bytes[i] & 0xFF;
            if (tag == TAG_OCTET_STRING) {
                int len = bytes[i + 1] & 0xFF;
                if (len >= 4 && len <= 9 && i + 2 + len <= bytes.length) {
                    // First byte: numbering plan + nature of address
                    // Remaining bytes: BCD-encoded digits
                    String decoded = decodeTBCD(bytes, i + 3, len - 1);
                    if (decoded != null && decoded.length() >= 7 && decoded.length() <= 15
                            && decoded.chars().allMatch(Character::isDigit)) {
                        return decoded;
                    }
                }
            }
        }
        return null;
    }

    /**
     * Attempt to find any subscriber identity in raw bytes.
     */
    private SubscriberIdentity extractAnyIdentity(byte[] bytes) {
        String imsi = extractImsi(bytes, 0);
        if (imsi != null) return SubscriberIdentity.fromImsi(imsi);

        String msisdn = extractAddressString(bytes, 0);
        if (msisdn != null) return SubscriberIdentity.fromMsisdn(msisdn);

        return null;
    }

    /**
     * Decode TBCD (Telephony BCD) encoded bytes to digit string.
     * TBCD swaps nibbles: byte 0x21 = digits "12"
     */
    public static String decodeTBCD(byte[] bytes, int offset, int length) {
        StringBuilder sb = new StringBuilder(length * 2);
        for (int i = 0; i < length && offset + i < bytes.length; i++) {
            int b = bytes[offset + i] & 0xFF;
            int lowNibble = b & 0x0F;
            int highNibble = (b >> 4) & 0x0F;

            if (lowNibble <= 9) sb.append((char) ('0' + lowNibble));
            else if (lowNibble == 0x0F) break; // filler
            else return null; // invalid

            if (highNibble <= 9) sb.append((char) ('0' + highNibble));
            else if (highNibble == 0x0F) break; // filler (last digit odd)
            else return null; // invalid
        }
        return sb.length() > 0 ? sb.toString() : null;
    }

    /**
     * Decode BER length field.
     */
    public static int decodeLength(byte[] bytes, int offset) {
        if (offset >= bytes.length) return 0;
        int firstByte = bytes[offset] & 0xFF;
        if (firstByte < 0x80) return firstByte;
        int numOctets = firstByte & 0x7F;
        int length = 0;
        for (int i = 0; i < numOctets && offset + 1 + i < bytes.length; i++) {
            length = (length << 8) | (bytes[offset + 1 + i] & 0xFF);
        }
        return length;
    }

    /**
     * Number of bytes used by the length field.
     */
    public static int lengthOfLength(byte[] bytes, int offset) {
        if (offset >= bytes.length) return 1;
        int firstByte = bytes[offset] & 0xFF;
        if (firstByte < 0x80) return 1;
        return 1 + (firstByte & 0x7F);
    }

    /**
     * Decode BER INTEGER value.
     */
    public static int decodeInteger(byte[] bytes, int offset, int length) {
        int value = 0;
        for (int i = 0; i < length && offset + i < bytes.length; i++) {
            value = (value << 8) | (bytes[offset + i] & 0xFF);
        }
        return value;
    }
}
