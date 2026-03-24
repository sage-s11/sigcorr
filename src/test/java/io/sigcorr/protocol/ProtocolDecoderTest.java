package io.sigcorr.protocol;

import io.sigcorr.protocol.diameter.DiameterDecoder;
import io.sigcorr.protocol.gtpc.GtpcDecoder;
import io.sigcorr.protocol.ss7.MapDecoder;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.*;

@DisplayName("Protocol Decoders")
class ProtocolDecoderTest {

    @Nested
    @DisplayName("MAP Decoder — BER Utilities")
    class MapDecoderTests {

        private final MapDecoder decoder = new MapDecoder();

        @Test
        @DisplayName("Decode TBCD: normal even-length")
        void decodeTbcdNormal() {
            // TBCD for "214365" → bytes 0x12, 0x34, 0x56
            byte[] bytes = {0x12, 0x34, 0x56};
            assertThat(MapDecoder.decodeTBCD(bytes, 0, 3)).isEqualTo("214365");
        }

        @Test
        @DisplayName("Decode TBCD: odd-length with 0xF filler")
        void decodeTbcdOddLength() {
            // TBCD for "21436" → bytes 0x12, 0x34, 0xF6
            byte[] bytes = {0x12, 0x34, (byte) 0xF6};
            assertThat(MapDecoder.decodeTBCD(bytes, 0, 3)).isEqualTo("21436");
        }

        @Test
        @DisplayName("Decode TBCD: IMSI-like sequence")
        void decodeTbcdImsi() {
            // IMSI 234101234567890 → TBCD: 32 14 01 32 54 76 98 F0
            byte[] bytes = {0x32, 0x14, 0x10, 0x32, 0x54, 0x76, (byte) 0x98, (byte) 0xF0};
            String result = MapDecoder.decodeTBCD(bytes, 0, 8);
            assertThat(result).isEqualTo("234101234567890");
        }

        @Test
        @DisplayName("Decode BER length: short form")
        void berLengthShort() {
            byte[] bytes = {0x30}; // length = 48
            assertThat(MapDecoder.decodeLength(bytes, 0)).isEqualTo(48);
            assertThat(MapDecoder.lengthOfLength(bytes, 0)).isEqualTo(1);
        }

        @Test
        @DisplayName("Decode BER length: long form (1 byte)")
        void berLengthLong1() {
            byte[] bytes = {(byte) 0x81, (byte) 0x80}; // length = 128
            assertThat(MapDecoder.decodeLength(bytes, 0)).isEqualTo(128);
            assertThat(MapDecoder.lengthOfLength(bytes, 0)).isEqualTo(2);
        }

        @Test
        @DisplayName("Decode BER length: long form (2 bytes)")
        void berLengthLong2() {
            byte[] bytes = {(byte) 0x82, 0x01, 0x00}; // length = 256
            assertThat(MapDecoder.decodeLength(bytes, 0)).isEqualTo(256);
            assertThat(MapDecoder.lengthOfLength(bytes, 0)).isEqualTo(3);
        }

        @Test
        @DisplayName("Decode BER integer")
        void berInteger() {
            byte[] bytes = {0x00, 0x16}; // 22 = SRI opcode
            assertThat(MapDecoder.decodeInteger(bytes, 0, 2)).isEqualTo(22);
        }

        @Test
        @DisplayName("canDecode rejects non-TCAP")
        void canDecodeRejectsNonTcap() {
            assertThat(decoder.canDecode(null)).isFalse();
            assertThat(decoder.canDecode(new byte[]{})).isFalse();
            assertThat(decoder.canDecode(new byte[]{0x01, 0x02, 0x03, 0x04})).isFalse();
        }

        @Test
        @DisplayName("canDecode accepts TCAP Begin")
        void canDecodeAcceptsTcapBegin() {
            assertThat(decoder.canDecode(new byte[]{0x62, 0x10, 0x00, 0x00})).isTrue();
        }

        @Test
        @DisplayName("canDecode accepts TCAP End")
        void canDecodeAcceptsTcapEnd() {
            assertThat(decoder.canDecode(new byte[]{0x64, 0x10, 0x00, 0x00})).isTrue();
        }

        @Test
        @DisplayName("Decoder name is correct")
        void decoderName() {
            assertThat(decoder.getDecoderName()).isEqualTo("SS7/MAP");
        }

        @Test
        @DisplayName("Extract IMSI from BER octet string")
        void extractImsiFromBer() {
            // OCTET STRING tag (0x04), length 8, TBCD IMSI 234101234567890
            byte[] bytes = {0x04, 0x08, 0x32, 0x14, 0x10, 0x32, 0x54, 0x76, (byte) 0x98, (byte) 0xF0};
            String imsi = decoder.extractImsi(bytes, 0);
            assertThat(imsi).isEqualTo("234101234567890");
        }
    }

    @Nested
    @DisplayName("Diameter Decoder")
    class DiameterDecoderTests {

        private final DiameterDecoder decoder = new DiameterDecoder();

        @Test
        @DisplayName("canDecode accepts Diameter v1")
        void canDecodeAcceptsDiameter() {
            byte[] header = new byte[20];
            header[0] = 0x01; // Version 1
            assertThat(decoder.canDecode(header)).isTrue();
        }

        @Test
        @DisplayName("canDecode rejects non-Diameter")
        void canDecodeRejects() {
            assertThat(decoder.canDecode(null)).isFalse();
            assertThat(decoder.canDecode(new byte[10])).isFalse();
            byte[] wrongVersion = new byte[20];
            wrongVersion[0] = 0x02;
            assertThat(decoder.canDecode(wrongVersion)).isFalse();
        }

        @Test
        @DisplayName("Decoder name is correct")
        void decoderName() {
            assertThat(decoder.getDecoderName()).isEqualTo("Diameter/S6a");
        }

        @Test
        @DisplayName("Decode PLMN-ID: 3-digit MNC")
        void decodePlmn3Digit() {
            // MCC=234, MNC=100 → bytes: 0x42, 0x03, 0x01
            byte[] plmn = {0x42, 0x03, 0x01};
            assertThat(DiameterDecoder.decodePlmnId(plmn)).isNotNull();
        }

        @Test
        @DisplayName("Decode PLMN-ID: 2-digit MNC with filler")
        void decodePlmn2Digit() {
            // MCC=310, MNC=26 → bytes: 0x13, 0xF0, 0x62
            byte[] plmn = {0x13, (byte) 0xF0, 0x62};
            String result = DiameterDecoder.decodePlmnId(plmn);
            assertThat(result).isNotNull();
        }

        @Test
        @DisplayName("Decode complete Diameter AIR message")
        void decodeCompleteAir() {
            // Build a synthetic Diameter AIR (cmd=316, R flag set, app=16777251)
            byte[] msg = buildDiameterMessage(316, true, 16777251L, "234101234567890",
                    "mme.test.com", "test.com");
            var result = decoder.decode(msg, Instant.now());
            assertThat(result).isPresent();
            assertThat(result.get().getOperation())
                    .isEqualTo(io.sigcorr.core.model.SignalingOperation.DIA_AUTH_INFO_REQUEST);
            assertThat(result.get().getSubscriber().getImsi()).contains("234101234567890");
        }

        @Test
        @DisplayName("Decode complete Diameter ULR message")
        void decodeCompleteUlr() {
            byte[] msg = buildDiameterMessage(318, true, 16777251L, "234101234567890",
                    "mme.test.com", "test.com");
            var result = decoder.decode(msg, Instant.now());
            assertThat(result).isPresent();
            assertThat(result.get().getOperation())
                    .isEqualTo(io.sigcorr.core.model.SignalingOperation.DIA_UPDATE_LOCATION_REQUEST);
        }

        /**
         * Build a synthetic Diameter message for testing.
         */
        private byte[] buildDiameterMessage(int commandCode, boolean isRequest, long appId,
                                            String imsi, String originHost, String originRealm) {
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            try {
                // We'll build AVPs first, then prepend header
                java.io.ByteArrayOutputStream avpBuf = new java.io.ByteArrayOutputStream();

                // AVP: User-Name (code=1) — contains IMSI
                writeAvp(avpBuf, 1, imsi.getBytes(java.nio.charset.StandardCharsets.UTF_8), false);

                // AVP: Origin-Host (code=264)
                writeAvp(avpBuf, 264, originHost.getBytes(java.nio.charset.StandardCharsets.UTF_8), false);

                // AVP: Origin-Realm (code=296)
                writeAvp(avpBuf, 296, originRealm.getBytes(java.nio.charset.StandardCharsets.UTF_8), false);

                byte[] avpBytes = avpBuf.toByteArray();
                int totalLength = 20 + avpBytes.length;

                // Header
                java.nio.ByteBuffer header = java.nio.ByteBuffer.allocate(20);
                header.putInt((0x01 << 24) | (totalLength & 0x00FFFFFF)); // version + length
                int flags = isRequest ? 0xC0 : 0x40; // R+P flags
                header.putInt((flags << 24) | (commandCode & 0x00FFFFFF));
                header.putInt((int) appId);
                header.putInt(0x12345678); // hop-by-hop
                header.putInt(0x87654321); // end-to-end

                out.write(header.array());
                out.write(avpBytes);

            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            return out.toByteArray();
        }

        private void writeAvp(java.io.ByteArrayOutputStream out, int code, byte[] data, boolean hasVendor) {
            java.nio.ByteBuffer avp = java.nio.ByteBuffer.allocate(8 + data.length + (4 - data.length % 4) % 4);
            avp.putInt(code);
            int avpFlags = 0x40; // Mandatory bit
            int avpLength = 8 + data.length;
            avp.putInt((avpFlags << 24) | (avpLength & 0x00FFFFFF));
            avp.put(data);
            // Padding
            int pad = (4 - data.length % 4) % 4;
            for (int i = 0; i < pad; i++) avp.put((byte) 0);
            out.write(avp.array(), 0, avp.position());
        }
    }

    @Nested
    @DisplayName("GTPv2-C Decoder")
    class GtpcDecoderTests {

        private final GtpcDecoder decoder = new GtpcDecoder();

        @Test
        @DisplayName("canDecode accepts GTPv2")
        void canDecodeAcceptsGtpv2() {
            byte[] header = new byte[8];
            header[0] = 0x48; // Version=2, T=1
            assertThat(decoder.canDecode(header)).isTrue();
        }

        @Test
        @DisplayName("canDecode rejects non-GTP")
        void canDecodeRejects() {
            assertThat(decoder.canDecode(null)).isFalse();
            assertThat(decoder.canDecode(new byte[3])).isFalse();
            // GTPv1
            byte[] v1 = new byte[8];
            v1[0] = 0x32;
            assertThat(decoder.canDecode(v1)).isFalse();
        }

        @Test
        @DisplayName("Decoder name is correct")
        void decoderName() {
            assertThat(decoder.getDecoderName()).isEqualTo("GTPv2-C");
        }

        @Test
        @DisplayName("Decode TBCD IMSI")
        void decodeTbcdImsi() {
            // 234101234567890 → 32 14 01 32 54 76 98 F0
            byte[] tbcd = {0x32, 0x14, 0x10, 0x32, 0x54, 0x76, (byte) 0x98, (byte) 0xF0};
            assertThat(GtpcDecoder.decodeTbcdImsi(tbcd)).isEqualTo("234101234567890");
        }

        @Test
        @DisplayName("Decode TBCD MSISDN")
        void decodeTbcdMsisdn() {
            // 447712345678 → 44 77 21 43 65 87
            byte[] tbcd = {0x44, 0x77, 0x21, 0x43, 0x65, (byte) 0x87};
            String result = GtpcDecoder.decodeTbcdMsisdn(tbcd);
            assertThat(result).isNotNull();
            assertThat(result).matches("\\d{7,15}");
        }

        @Test
        @DisplayName("Decode APN label-length encoding")
        void decodeApn() {
            // "internet.example.com" → 8 internet 7 example 3 com
            byte[] apn = {8, 'i', 'n', 't', 'e', 'r', 'n', 'e', 't',
                    7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                    3, 'c', 'o', 'm'};
            assertThat(GtpcDecoder.decodeApn(apn)).isEqualTo("internet.example.com");
        }

        @Test
        @DisplayName("Decode F-TEID IPv4")
        void decodeFteidIpv4() {
            // Flags: V4=1, TEID=0x12345678, IP=192.168.1.1
            byte[] fteid = {(byte) 0x80, 0x12, 0x34, 0x56, 0x78,
                    (byte) 192, (byte) 168, 1, 1};
            assertThat(GtpcDecoder.extractFteidIp(fteid)).isEqualTo("192.168.1.1");
        }

        @Test
        @DisplayName("Decode Serving Network PLMN")
        void decodeServingNetwork() {
            byte[] plmn = {0x42, 0x03, 0x01}; // Some PLMN
            assertThat(GtpcDecoder.decodePlmnFromIe(plmn)).isNotNull();
        }

        @Test
        @DisplayName("Parse ULI flags")
        void parseUliFlags() {
            byte[] uli = {0x18}; // TAI + ECGI
            assertThat(GtpcDecoder.parseUliBasic(uli)).isEqualTo("TAI+ECGI");
        }

        @Test
        @DisplayName("Decode complete Create-Session-Request")
        void decodeCreateSession() {
            byte[] msg = buildGtpCreateSession("234101234567890", "447712345678");
            var result = decoder.decode(msg, Instant.now());
            assertThat(result).isPresent();
            assertThat(result.get().getOperation())
                    .isEqualTo(io.sigcorr.core.model.SignalingOperation.GTP_CREATE_SESSION_REQUEST);
            assertThat(result.get().getSubscriber().getImsi()).contains("234101234567890");
        }

        private byte[] buildGtpCreateSession(String imsi, String msisdn) {
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            java.io.ByteArrayOutputStream ies = new java.io.ByteArrayOutputStream();
            try {
                // IMSI IE (type=1)
                byte[] imsiTbcd = encodeTbcd(imsi);
                writeIe(ies, 1, imsiTbcd);

                // MSISDN IE (type=76)
                byte[] msisdnTbcd = encodeTbcd(msisdn);
                writeIe(ies, 76, msisdnTbcd);

                byte[] ieBytes = ies.toByteArray();

                // Header: version=2, T=1, msg type=32 (Create Session)
                java.nio.ByteBuffer hdr = java.nio.ByteBuffer.allocate(12);
                hdr.put((byte) 0x48); // V=2, P=0, T=1
                hdr.put((byte) 32);   // Message type
                hdr.putShort((short) (ieBytes.length + 4)); // Length (includes seq+spare)
                hdr.putInt(0x00000001); // TEID
                hdr.put((byte) 0); hdr.put((byte) 0); hdr.put((byte) 1); // Sequence
                hdr.put((byte) 0); // Spare

                out.write(hdr.array());
                out.write(ieBytes);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            return out.toByteArray();
        }

        private void writeIe(java.io.ByteArrayOutputStream out, int type, byte[] data) throws Exception {
            java.nio.ByteBuffer ie = java.nio.ByteBuffer.allocate(4 + data.length);
            ie.put((byte) type);
            ie.putShort((short) data.length);
            ie.put((byte) 0); // spare + instance
            ie.put(data);
            out.write(ie.array());
        }

        private byte[] encodeTbcd(String digits) {
            int len = (digits.length() + 1) / 2;
            byte[] result = new byte[len];
            for (int i = 0; i < digits.length(); i += 2) {
                int low = digits.charAt(i) - '0';
                int high = (i + 1 < digits.length()) ? digits.charAt(i + 1) - '0' : 0x0F;
                result[i / 2] = (byte) ((high << 4) | low);
            }
            return result;
        }
    }
}
