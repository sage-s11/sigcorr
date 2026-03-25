package io.sigcorr.evidence;

import io.sigcorr.core.event.SignalingEvent;
import io.sigcorr.detection.scoring.SecurityAlert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.file.*;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Exports evidence pcap files containing only the packets involved in detected attacks.
 * 
 * Uses tshark/editcap to extract specific packets from the original pcap.
 */
public class EvidenceExporter {
    
    private static final Logger log = LoggerFactory.getLogger(EvidenceExporter.class);
    
    private final Path evidenceDirectory;
    private final String tsharkPath;
    private final String editcapPath;
    
    public EvidenceExporter(Path evidenceDirectory) {
        this.evidenceDirectory = evidenceDirectory;
        this.tsharkPath = "tshark";
        this.editcapPath = "editcap";
        
        // Create evidence directory if it doesn't exist
        try {
            Files.createDirectories(evidenceDirectory);
        } catch (IOException e) {
            log.error("Failed to create evidence directory: {}", e.getMessage());
        }
    }
    
    /**
     * Export evidence pcap for a security alert.
     * 
     * @param alert The security alert to export evidence for
     * @param sourcePcap Original pcap file
     * @param allEvents All events from the pcap (to find packet numbers)
     * @return Path to the exported evidence pcap, or null if export failed
     */
    public Path exportEvidence(SecurityAlert alert, Path sourcePcap, List<SignalingEvent> allEvents) {
        try {
            // Generate evidence filename
            String filename = generateEvidenceFilename(alert);
            Path outputPath = evidenceDirectory.resolve(filename);
            
            // Get packet numbers for the alert's events
            Set<Integer> packetNumbers = getPacketNumbers(alert, allEvents);
            
            if (packetNumbers.isEmpty()) {
                log.warn("No packet numbers found for alert {}", alert.getMatchedPattern().getPatternId());
                return null;
            }
            
            // Export using editcap (simpler than tshark for packet extraction)
            boolean success = exportPackets(sourcePcap, outputPath, packetNumbers);
            
            if (success) {
                log.info("Exported evidence to: {}", outputPath);
                return outputPath;
            } else {
                log.error("Failed to export evidence for alert {}", alert.getMatchedPattern().getPatternId());
                return null;
            }
            
        } catch (Exception e) {
            log.error("Error exporting evidence: {}", e.getMessage(), e);
            return null;
        }
    }
    
    /**
     * Generate evidence filename based on alert details.
     */
    private String generateEvidenceFilename(SecurityAlert alert) {
        String timestamp = DateTimeFormatter.ISO_INSTANT
                .format(alert.getDetectionTime())
                .replaceAll("[:\\-]", "")
                .replace(".", "_");
        
        String subscriber = alert.getSubscriberKey()
                .replaceAll("[^a-zA-Z0-9]", "_");
        
        return String.format("%s_%s_%s_evidence.pcap",
                alert.getMatchedPattern().getPatternId(),
                timestamp,
                subscriber);
    }
    
    /**
     * Get packet numbers for events in the alert.
     * Uses the matched events from the alert and finds their positions in allEvents.
     */
    private Set<Integer> getPacketNumbers(SecurityAlert alert, List<SignalingEvent> allEvents) {
        Set<Integer> packetNumbers = new HashSet<>();
        
        // Get the matched events from the alert
        List<SignalingEvent> matchedEvents = alert.getMatchedEvents();
        
        // Find their positions in allEvents
        for (SignalingEvent matchedEvent : matchedEvents) {
            for (int i = 0; i < allEvents.size(); i++) {
                SignalingEvent event = allEvents.get(i);
                
                // Match by timestamp and operation
                if (event.getTimestamp().equals(matchedEvent.getTimestamp()) &&
                    event.getOperation().equals(matchedEvent.getOperation())) {
                    
                    // Packet number is index + 1 (pcaps are 1-indexed)
                    packetNumbers.add(i + 1);
                    break;
                }
            }
        }
        
        return packetNumbers;
    }
    
    /**
     * Export specific packets from source pcap using editcap.
     */
    private boolean exportPackets(Path sourcePcap, Path outputPcap, Set<Integer> packetNumbers) {
        try {
            // Build packet range string for editcap
            // editcap supports ranges like "1-5,10,15-20"
            String packetRange = buildPacketRange(packetNumbers);
            
            // Use editcap to extract packets
            // editcap -r input.pcap output.pcap 1-5,10,15-20
            List<String> cmd = Arrays.asList(
                    editcapPath,
                    "-r",  // Keep specified packets
                    sourcePcap.toAbsolutePath().toString(),
                    outputPcap.toAbsolutePath().toString(),
                    packetRange
            );
            
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(true);
            Process process = pb.start();
            
            // Read output
            String output = new String(process.getInputStream().readAllBytes());
            int exitCode = process.waitFor();
            
            if (exitCode != 0) {
                log.error("editcap failed with code {}: {}", exitCode, output);
                return false;
            }
            
            return true;
            
        } catch (IOException | InterruptedException e) {
            log.error("Failed to run editcap: {}", e.getMessage());
            return false;
        }
    }
    
    /**
     * Build packet range string from set of packet numbers.
     * Optimizes consecutive packets into ranges.
     */
    private String buildPacketRange(Set<Integer> packetNumbers) {
        List<Integer> sorted = new ArrayList<>(packetNumbers);
        Collections.sort(sorted);
        
        StringBuilder range = new StringBuilder();
        int rangeStart = -1;
        int prev = -1;
        
        for (int pkt : sorted) {
            if (rangeStart == -1) {
                rangeStart = pkt;
            } else if (pkt != prev + 1) {
                // End of consecutive range
                if (rangeStart == prev) {
                    range.append(rangeStart).append(",");
                } else {
                    range.append(rangeStart).append("-").append(prev).append(",");
                }
                rangeStart = pkt;
            }
            prev = pkt;
        }
        
        // Add final range
        if (rangeStart != -1) {
            if (rangeStart == prev) {
                range.append(rangeStart);
            } else {
                range.append(rangeStart).append("-").append(prev);
            }
        }
        
        return range.toString();
    }
    
    /**
     * Check if editcap is available.
     */
    public boolean isEditcapAvailable() {
        try {
            Process p = new ProcessBuilder(editcapPath, "-h")
                    .redirectErrorStream(true).start();
            p.getInputStream().readAllBytes();
            return p.waitFor() == 0;
        } catch (Exception e) {
            return false;
        }
    }
}
