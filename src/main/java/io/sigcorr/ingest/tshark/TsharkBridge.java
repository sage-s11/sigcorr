package io.sigcorr.ingest.tshark;

import com.google.gson.*;
import io.sigcorr.core.event.NetworkNode;
import io.sigcorr.core.event.SignalingEvent;
import io.sigcorr.core.identity.SubscriberIdentity;
import io.sigcorr.core.model.ProtocolInterface;
import io.sigcorr.core.model.SignalingOperation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.file.Path;
import java.time.Instant;
import java.util.*;

/**
 * Bridge between tshark (Wireshark CLI) and SigCorr's normalized event model.
 *
 * Instead of reimplementing protocol dissectors for SS7/MAP, Diameter, and GTPv2-C
 * (which Wireshark already does perfectly), we use tshark to decode pcap files into
 * structured JSON, then parse that JSON into SignalingEvents.
 *
 * Pipeline:
 *   capture.pcap → tshark -T json → JSON stdout → TsharkBridge parser → List<SignalingEvent>
 *
 * tshark field mappings:
 *   SS7/MAP:  gsm_map.opcode, gsm_map.imsi, gsm_map.msisdn, sccp.calling_party_address.gt
 *   Diameter: diameter.cmd.code, diameter.flags.request, diameter.User-Name,
 *             diameter.Origin-Host, diameter.Origin-Realm
 *   GTPv2-C: gtpv2.message_type, gtpv2.imsi, gtpv2.msisdn, gtpv2.apn
 */
public class TsharkBridge {

    private static final Logger log = LoggerFactory.getLogger(TsharkBridge.class);

    private String tsharkPath = "tshark";

    /**
     * Check if tshark is available on the system PATH.
     */
    public boolean isTsharkAvailable() {
        try {
            Process p = new ProcessBuilder(tsharkPath, "--version")
                    .redirectErrorStream(true).start();
            p.getInputStream().readAllBytes();
            return p.waitFor() == 0;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Get tshark version string.
     */
    public String getTsharkVersion() {
        try {
            Process p = new ProcessBuilder(tsharkPath, "--version")
                    .redirectErrorStream(true).start();
            String output = new String(p.getInputStream().readAllBytes());
            p.waitFor();
            return output.lines().findFirst().orElse("unknown");
        } catch (Exception e) {
            return "unavailable";
        }
    }

    /**
     * Decode a pcap file into normalized SignalingEvents.
     *
     * Runs tshark with protocol-specific field extraction, parses the JSON output,
     * and maps each decoded packet to a SignalingEvent.
     *
     * @param pcapFile path to the pcap/pcapng file
     * @return list of decoded events, chronologically ordered
     */
    public List<SignalingEvent> decodePcap(Path pcapFile) throws IOException, InterruptedException {
        List<SignalingEvent> allEvents = new ArrayList<>();

        // Run three tshark passes: MAP, Diameter, GTPv2-C
        // Each pass uses different display filters and field extractions
        allEvents.addAll(decodeMapEvents(pcapFile));
        allEvents.addAll(decodeDiameterEvents(pcapFile));
        allEvents.addAll(decodeGtpcEvents(pcapFile));

        // Sort chronologically
        allEvents.sort(Comparator.comparing(SignalingEvent::getTimestamp));

        log.info("Decoded {} total events from {}", allEvents.size(), pcapFile.getFileName());
        return allEvents;
    }

    /**
     * Decode SS7/MAP events from pcap.
     */
    private List<SignalingEvent> decodeMapEvents(Path pcapFile) throws IOException, InterruptedException {
        // tshark fields for MAP
        String[] fields = {
                "-e", "frame.time_epoch",
                "-e", "gsm_old.opCode",
                "-e", "gsm_map.imsi",
                "-e", "gsm_map.msisdn",
                "-e", "gsm_old.localValue",
                "-e", "e164.called_party_number.digits",
                "-e", "e212.imsi",
                "-e", "sccp.calling.digits",
                "-e", "sccp.called.digits",
                "-e", "gsm_map.ch.msisdn",
        };

        String filter = "gsm_map || camel";
        List<JsonObject> packets = runTshark(pcapFile, filter, fields);
        List<SignalingEvent> events = new ArrayList<>();

        for (JsonObject pkt : packets) {
            try {
                SignalingEvent event = parseMapPacket(pkt);
                if (event != null) events.add(event);
            } catch (Exception e) {
                log.debug("Failed to parse MAP packet: {}", e.getMessage());
            }
        }

        log.debug("Decoded {} MAP events", events.size());
        return events;
    }

    /**
     * Decode Diameter events from pcap.
     */
    private List<SignalingEvent> decodeDiameterEvents(Path pcapFile) throws IOException, InterruptedException {
        String[] fields = {
                "-e", "frame.time_epoch",
                "-e", "diameter.cmd.code",
                "-e", "diameter.flags.request",
                "-e", "diameter.User-Name",
                "-e", "diameter.Origin-Host",
                "-e", "diameter.Origin-Realm",
                "-e", "diameter.Destination-Host",
                "-e", "diameter.Destination-Realm",
                "-e", "diameter.Session-Id",
                "-e", "diameter.Result-Code",
                "-e", "diameter.applicationId",
                "-e", "e212.imsi",
        };

        String filter = "diameter";
        List<JsonObject> packets = runTshark(pcapFile, filter, fields);
        List<SignalingEvent> events = new ArrayList<>();

        for (JsonObject pkt : packets) {
            try {
                SignalingEvent event = parseDiameterPacket(pkt);
                if (event != null) events.add(event);
            } catch (Exception e) {
                log.debug("Failed to parse Diameter packet: {}", e.getMessage());
            }
        }

        log.debug("Decoded {} Diameter events", events.size());
        return events;
    }

    /**
     * Decode GTPv2-C events from pcap.
     */
    private List<SignalingEvent> decodeGtpcEvents(Path pcapFile) throws IOException, InterruptedException {
        String[] fields = {
                "-e", "frame.time_epoch",
                "-e", "gtpv2.message_type",
                "-e", "e164.msisdn",
                "-e", "gtpv2.apn",
                "-e", "gtpv2.rat_type",
                "-e", "gtpv2.f_teid_ipv4",
                "-e", "e212.imsi",
                "-e", "ip.src",
                "-e", "ip.dst",
        };

        String filter = "gtpv2";
        List<JsonObject> packets = runTshark(pcapFile, filter, fields);
        List<SignalingEvent> events = new ArrayList<>();

        for (JsonObject pkt : packets) {
            try {
                SignalingEvent event = parseGtpcPacket(pkt);
                if (event != null) events.add(event);
            } catch (Exception e) {
                log.debug("Failed to parse GTPv2-C packet: {}", e.getMessage());
            }
        }

        log.debug("Decoded {} GTPv2-C events", events.size());
        return events;
    }

    // ════════════════════════════════════════════════════════════════
    //  tshark execution
    // ════════════════════════════════════════════════════════════════

    /**
     * Run tshark and parse JSON output.
     */
    private List<JsonObject> runTshark(Path pcapFile, String displayFilter, String[] fields)
            throws IOException, InterruptedException {

        List<String> cmd = new ArrayList<>();
        cmd.add(tsharkPath);
        cmd.add("-r");
        cmd.add(pcapFile.toAbsolutePath().toString());
        cmd.add("-Y");
        cmd.add(displayFilter);
        cmd.add("-T");
        cmd.add("ek");  // Elasticsearch bulk JSON — one JSON object per line, easier to parse
        cmd.add("-l");   // Flush after each packet
        Collections.addAll(cmd, fields);

        log.debug("Running: {}", String.join(" ", cmd));

        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(false);
        Process process = pb.start();

        List<JsonObject> packets = new ArrayList<>();
        Gson gson = new Gson();

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("{\"index\"")) continue; // Skip EK index lines

                try {
                    JsonObject obj = gson.fromJson(line, JsonObject.class);
                    if (obj != null && obj.has("layers")) {
                        packets.add(obj.getAsJsonObject("layers"));
                    }
                } catch (JsonSyntaxException e) {
                    log.debug("Skipping non-JSON line: {}", line.substring(0, Math.min(80, line.length())));
                }
            }
        }

        // Drain stderr
        String stderr = new String(process.getErrorStream().readAllBytes());
        int exitCode = process.waitFor();

        if (exitCode != 0 && !stderr.isBlank()) {
            log.warn("tshark exited with code {} for filter '{}': {}", exitCode, displayFilter,
                    stderr.lines().findFirst().orElse(""));
        }

        return packets;
    }

    // ════════════════════════════════════════════════════════════════
    //  Packet → SignalingEvent mapping
    // ════════════════════════════════════════════════════════════════

    private SignalingEvent parseMapPacket(JsonObject layers) {
        Instant timestamp = extractTimestamp(layers);
        if (timestamp == null) return null;

        // Get MAP operation code
        int opcode = extractInt(layers, "gsm_old_localValue", "gsm_old_opCode");
        if (opcode < 0) return null;

        SignalingOperation operation = SignalingOperation.fromMapOpcode(opcode);
        if (operation == null) {
            log.debug("Unknown MAP opcode: {}", opcode);
            return null;
        }

        // Extract subscriber identity
        String imsi = extractString(layers, "e212_imsi", "gsm_map_ch_imsi", "gsm_map_sm_imsi", "e212_imsi");
        String msisdn = extractString(layers, "gsm_map_msisdn", "e164_msisdn", "gsm_map_sm_msisdn", "e164_called_party_number_digits");

        SubscriberIdentity subscriber = buildIdentity(imsi, msisdn);

        // Network nodes from SCCP addresses
        String callingGt = extractString(layers, "sccp_calling_digits");
        String calledGt = extractString(layers, "sccp_called_digits");

        // Fallback: use SCCP GT as subscriber when no IMSI/MSISDN
        if (subscriber == null) {
            String attackerGt = null;
            if (callingGt != null && callingGt.startsWith("49")) {
                attackerGt = callingGt;
            } else if (calledGt != null && calledGt.startsWith("49")) {
                attackerGt = calledGt;
            } else {
                attackerGt = callingGt != null ? callingGt : calledGt;
            }
            if (attackerGt != null) {
                subscriber = SubscriberIdentity.fromMsisdn(attackerGt);
            }
        }
        if (subscriber == null) {
            log.debug("Skipping MAP event with no subscriber identity");
            return null;
        }

        Map<String, String> params = new HashMap<>();
        params.put("operationCode", String.valueOf(opcode));
        if (imsi != null) params.put("imsi", imsi);
        if (msisdn != null) params.put("msisdn", msisdn);

        var builder = SignalingEvent.builder()
                .timestamp(timestamp)
                .protocolInterface(ProtocolInterface.SS7_MAP)
                .operation(operation)
                .subscriber(subscriber)
                .parameters(params)
                .direction(SignalingEvent.Direction.INBOUND);

        if (callingGt != null) builder.sourceNode(NetworkNode.fromGlobalTitle(callingGt));
        if (calledGt != null) builder.destinationNode(NetworkNode.fromGlobalTitle(calledGt));

        return builder.build();
    }

    private SignalingEvent parseDiameterPacket(JsonObject layers) {
        Instant timestamp = extractTimestamp(layers);
        if (timestamp == null) return null;

        int commandCode = extractInt(layers, "diameter_cmd_code");
        if (commandCode < 0) return null;

        String requestFlag = extractString(layers, "diameter_flags_request");
        boolean isRequest = "1".equals(requestFlag);

        SignalingOperation operation = SignalingOperation.fromDiameterCommand(commandCode, isRequest);
        if (operation == null) return null;

        // IMSI from User-Name AVP or e212
        String imsi = extractString(layers, "diameter_User-Name", "e212_imsi");
        if (imsi != null) imsi = imsi.replaceAll("[^0-9]", ""); // Clean non-digits

        SubscriberIdentity subscriber = buildIdentity(imsi, null);

        Map<String, String> params = new HashMap<>();
        params.put("commandCode", String.valueOf(commandCode));
        params.put("isRequest", String.valueOf(isRequest));
        if (imsi != null) params.put("imsi", imsi);

        String originHost = extractString(layers, "diameter_Origin-Host");
        String originRealm = extractString(layers, "diameter_Origin-Realm");
        String destHost = extractString(layers, "diameter_Destination-Host");
        String destRealm = extractString(layers, "diameter_Destination-Realm");
        String sessionId = extractString(layers, "diameter_Session-Id");
        String resultCode = extractString(layers, "diameter_Result-Code");

        if (originHost != null) params.put("originHost", originHost);
        if (originRealm != null) params.put("originRealm", originRealm);
        if (sessionId != null) params.put("sessionId", sessionId);
        if (resultCode != null) params.put("resultCode", resultCode);

        var builder = SignalingEvent.builder()
                .timestamp(timestamp)
                .protocolInterface(ProtocolInterface.DIAMETER_S6A)
                .operation(operation)
                .subscriber(subscriber)
                .parameters(params)
                .direction(isRequest ? SignalingEvent.Direction.INBOUND : SignalingEvent.Direction.OUTBOUND);

        if (originHost != null) builder.sourceNode(NetworkNode.fromDiameterHost(originHost, originRealm));
        if (destHost != null) builder.destinationNode(NetworkNode.fromDiameterHost(destHost, destRealm));

        return builder.build();
    }

    private SignalingEvent parseGtpcPacket(JsonObject layers) {
        Instant timestamp = extractTimestamp(layers);
        if (timestamp == null) return null;

        int messageType = extractInt(layers, "gtpv2_message_type");
        if (messageType < 0) return null;

        SignalingOperation operation = SignalingOperation.fromGtpMessageType(messageType);
        if (operation == null) return null;

        String imsi = extractString(layers, "e212_imsi");
        String msisdn = extractString(layers, "e164_msisdn");

        SubscriberIdentity subscriber = buildIdentity(imsi, msisdn);

        Map<String, String> params = new HashMap<>();
        params.put("messageType", String.valueOf(messageType));
        if (imsi != null) params.put("imsi", imsi);
        if (msisdn != null) params.put("msisdn", msisdn);

        String apn = extractString(layers, "gtpv2_apn");
        String ratType = extractString(layers, "gtpv2_rat_type");
        String fteidIp = extractString(layers, "gtpv2_f_teid_ipv4");
        String srcIp = extractString(layers, "ip_src");

        if (apn != null) params.put("apn", apn);
        if (ratType != null) params.put("ratType", ratType);

        var builder = SignalingEvent.builder()
                .timestamp(timestamp)
                .protocolInterface(ProtocolInterface.GTPC_V2)
                .operation(operation)
                .subscriber(subscriber)
                .parameters(params)
                .direction(SignalingEvent.Direction.INBOUND);

        if (fteidIp != null) builder.sourceNode(NetworkNode.fromGtpPeer(fteidIp));
        else if (srcIp != null) builder.sourceNode(NetworkNode.fromGtpPeer(srcIp));

        return builder.build();
    }

    // ════════════════════════════════════════════════════════════════
    //  JSON field extraction helpers
    // ════════════════════════════════════════════════════════════════

    /**
     * Extract timestamp from frame.time_epoch field.
     * tshark EK format uses field names with dots replaced by underscores.
     */
    private Instant extractTimestamp(JsonObject layers) {
        String epoch = extractString(layers, "frame_time_epoch");
        if (epoch == null) return null;
        try {
            // frame.time_epoch is seconds with microsecond precision
            double secs = Double.parseDouble(epoch);
            long epochMillis = (long) (secs * 1000);
            return Instant.ofEpochMilli(epochMillis);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /**
     * Try multiple field names and return the first non-null value.
     * tshark EK format replaces dots with underscores in field names.
     */
    private String extractString(JsonObject layers, String... fieldNames) {
        for (String field : fieldNames) {
            // Try exact name
            JsonElement el = layers.get(field);
            if (el == null) {
                // Try with dots replaced by underscores (EK format)
                el = layers.get(field.replace(".", "_").replace("-", "_"));
            }
            if (el == null) continue;

            if (el.isJsonArray()) {
                JsonArray arr = el.getAsJsonArray();
                if (!arr.isEmpty()) return arr.get(0).getAsString();
            } else if (el.isJsonPrimitive()) {
                String val = el.getAsString().trim();
                if (!val.isEmpty()) return val;
            }
        }
        return null;
    }

    /**
     * Extract an integer field, trying multiple names.
     */
    private int extractInt(JsonObject layers, String... fieldNames) {
        String val = extractString(layers, fieldNames);
        if (val == null) return -1;
        try {
            return Integer.parseInt(val.trim());
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    /**
     * Build a SubscriberIdentity from whatever identifiers are available.
     */
    private SubscriberIdentity buildIdentity(String imsi, String msisdn) {
        // Clean up
        if (imsi != null) {
            imsi = imsi.replaceAll("[^0-9]", "");
            if (imsi.length() < 14 || imsi.length() > 15) imsi = null;
        }
        if (msisdn != null) {
            msisdn = msisdn.replaceAll("[^0-9]", "");
            if (msisdn.length() < 7 || msisdn.length() > 15) msisdn = null;
        }

        try {
            if (imsi != null && msisdn != null) return SubscriberIdentity.fromBoth(imsi, msisdn);
            if (imsi != null) return SubscriberIdentity.fromImsi(imsi);
            if (msisdn != null) return SubscriberIdentity.fromMsisdn(msisdn);
        } catch (IllegalArgumentException e) {
            log.debug("Invalid identity: imsi={}, msisdn={}: {}", imsi, msisdn, e.getMessage());
        }
        return null;
    }

    public void setTsharkPath(String path) { this.tsharkPath = path; }
}
