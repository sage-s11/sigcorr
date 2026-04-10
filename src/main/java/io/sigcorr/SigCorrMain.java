package io.sigcorr;

import io.sigcorr.correlation.engine.CorrelationEngine;
import io.sigcorr.detection.patterns.AttackPatternCatalog;
import io.sigcorr.detection.scoring.SecurityAlert;
import io.sigcorr.ingest.hex.ScenarioGenerator;
import io.sigcorr.ingest.tshark.TsharkBridge;
import io.sigcorr.config.SigCorrConfig;
import io.sigcorr.evidence.EvidenceExporter;
import io.sigcorr.output.json.JsonOutputFormatter;
import io.sigcorr.output.csv.CsvOutputFormatter;
import io.sigcorr.core.event.SignalingEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.stream.Stream;

public class SigCorrMain {

    private static final Logger log = LoggerFactory.getLogger(SigCorrMain.class);
    private static final String VERSION = "0.1.0";

    private static boolean verbose = false;
    private static boolean quiet = false;
    private static boolean jsonOutput = false;
    private static boolean csvOutput = false;
    private static boolean exportEvidence = false;

    private static final String BANNER = """

              _____ _        ____              \s
             / ____(_)      / ___|___  _ __ _ __\s
             \\___ \\| | __ _| |   / _ \\| '__| '__|
              ___) | |/ _` | |__| (_) | |  | | \s
             |____/|_|\\__, |\\____\\___/|_|  |_| \s
                       |___/                    \s
             Passive Cross-Interface Signaling Security Correlator v%s
            """.formatted(VERSION);

    public static void main(String[] args) {
        var remaining = parseGlobalFlags(args);
        if (remaining.isEmpty()) { printUsage(); return; }
        configureLogging();
        String command = remaining.get(0).toLowerCase();
        switch (command) {
            case "demo" -> runDemo();
            case "analyze" -> {
                if (remaining.size() < 2) { System.err.println("Usage: sigcorr analyze <pcap-file-or-directory>"); System.exit(1); }
                String target = remaining.get(1);
                Path targetPath = Path.of(target);
                if (Files.isDirectory(targetPath)) {
                    runBatchAnalyze(targetPath);
                } else {
                    runAnalyze(target);
                }
            }
            case "patterns" -> listPatterns();
            case "version" -> System.out.println("sigcorr v" + VERSION);
            case "help", "-h", "--help" -> printUsage();
            default -> { System.err.println("Unknown command: " + command); printUsage(); System.exit(1); }
        }
    }

    private static List<String> parseGlobalFlags(String[] args) {
        var remaining = new java.util.ArrayList<String>();
        for (String arg : args) {
            switch (arg) {
                case "--verbose", "-v" -> verbose = true;
                case "--quiet", "-q" -> quiet = true;
                case "--json" -> { jsonOutput = true; csvOutput = false; }
                case "--csv" -> { csvOutput = true; jsonOutput = false; }
                case "--format" -> {} // handled with next arg below
                case "--export-evidence" -> exportEvidence = true;
                default -> {
                    // Handle --format json / --format csv
                    if (!remaining.isEmpty() && remaining.get(remaining.size() - 1).equals("--format")) {
                        remaining.remove(remaining.size() - 1);
                        switch (arg.toLowerCase()) {
                            case "json" -> { jsonOutput = true; csvOutput = false; }
                            case "csv" -> { csvOutput = true; jsonOutput = false; }
                            case "console", "text" -> { jsonOutput = false; csvOutput = false; }
                            default -> System.err.println("Unknown format: " + arg + " (use json, csv, or console)");
                        }
                    } else {
                        remaining.add(arg);
                    }
                }
            }
        }
        return remaining;
    }

    private static void configureLogging() {
        ch.qos.logback.classic.Logger root =
                (ch.qos.logback.classic.Logger) LoggerFactory.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
        if (verbose) root.setLevel(ch.qos.logback.classic.Level.DEBUG);
        else if (quiet) root.setLevel(ch.qos.logback.classic.Level.ERROR);
    }

    // ════════════════════════════════════════════════════════════════
    //  ANALYZE — real pcap analysis via tshark bridge
    // ════════════════════════════════════════════════════════════════

    private static void runAnalyze(String pcapPath) {
        Path path = Path.of(pcapPath);
        if (!Files.exists(path)) { System.err.println("File not found: " + pcapPath); System.exit(1); }
        
        // Load configuration
        SigCorrConfig config;
        try {
            config = SigCorrConfig.loadDefault();
            if (verbose) System.out.println("Loaded configuration from sigcorr-config.yaml");
        } catch (IOException e) {
            if (verbose) System.out.println("No config file found, using defaults");
            config = SigCorrConfig.createDefault();
        }
        
        if (!quiet) { System.out.println(BANNER); System.out.println("Analyzing: " + path.toAbsolutePath() + "\n"); }

        TsharkBridge bridge = new TsharkBridge();
        if (!bridge.isTsharkAvailable()) {
            System.err.println("ERROR: tshark not found on PATH");
            System.err.println("Install: sudo apt install tshark");
            System.exit(1);
        }
        if (verbose) System.out.println("tshark: " + bridge.getTsharkVersion() + "\n");

        try {
            if (!quiet) System.out.println("Decoding pcap via tshark...");
            List<SignalingEvent> events = bridge.decodePcap(path);

            if (events.isEmpty()) {
                System.out.println("No SS7/Diameter/GTP signaling events found in " + pcapPath);
                return;
            }
            if (!quiet) System.out.printf("Decoded %d signaling events%n%n", events.size());

            // Build engine config with whitelist
            io.sigcorr.detection.whitelist.Whitelist whitelist = io.sigcorr.detection.whitelist.Whitelist.fromConfig(
                    config.isWhitelistEnabled(),
                    config.getTrustedGtPairs(),
                    config.getHomeNetworkPrefixes()
            );
            
            if (verbose && whitelist.isEnabled()) {
                System.out.printf("Whitelist enabled: %d trusted entries, home prefixes: %s%n", 
                        whitelist.getTrustedPairCount(), config.getHomeNetworkPrefixes());
            }
            
            io.sigcorr.correlation.engine.EngineConfig engineConfig = io.sigcorr.correlation.engine.EngineConfig.defaults()
                    .withWhitelist(whitelist)
                    .withCorrelationWindow(java.time.Duration.ofSeconds(config.getCorrelationWindowSeconds()));
            
            CorrelationEngine engine = new CorrelationEngine(engineConfig);
            engine.processBatch(events);

            // Export evidence if requested or auto-export enabled
            List<SecurityAlert> alerts = engine.getAlerts();
            boolean shouldExport = exportEvidence || config.isAutoExportEnabled();
            if (shouldExport && !alerts.isEmpty()) {
                exportEvidencePcaps(alerts, path, events, config);
            }


            if (jsonOutput) {
                System.out.println(new JsonOutputFormatter().formatReport(engine));
            } else if (csvOutput) {
                System.out.print(new CsvOutputFormatter().formatReport(engine));
            } else {
                printResults(engine);
            }
        } catch (IOException | InterruptedException e) {
            System.err.println("Failed to analyze pcap: " + e.getMessage());
            if (verbose) e.printStackTrace();
            System.exit(1);
        }
    }

    // ════════════════════════════════════════════════════════════════
    //  BATCH ANALYZE — process all pcaps in a directory
    // ════════════════════════════════════════════════════════════════

    private static void runBatchAnalyze(Path directory) {
        if (!quiet) {
            System.out.println(BANNER);
            System.out.println("Batch analyzing: " + directory.toAbsolutePath() + "\n");
        }

        List<Path> pcapFiles;
        try (Stream<Path> stream = Files.list(directory)) {
            pcapFiles = stream
                    .filter(p -> {
                        String name = p.getFileName().toString().toLowerCase();
                        return name.endsWith(".pcap") || name.endsWith(".pcapng") || name.endsWith(".cap");
                    })
                    .sorted()
                    .toList();
        } catch (IOException e) {
            System.err.println("Failed to list directory: " + e.getMessage());
            System.exit(1);
            return;
        }

        if (pcapFiles.isEmpty()) {
            System.out.println("No pcap files found in " + directory);
            return;
        }

        if (!quiet) System.out.printf("Found %d pcap file(s)%n%n", pcapFiles.size());

        // Load configuration once
        SigCorrConfig config;
        try {
            config = SigCorrConfig.loadDefault();
        } catch (IOException e) {
            config = SigCorrConfig.createDefault();
        }

        TsharkBridge bridge = new TsharkBridge();
        if (!bridge.isTsharkAvailable()) {
            System.err.println("ERROR: tshark not found on PATH");
            System.exit(1);
        }

        // Build shared engine config
        io.sigcorr.detection.whitelist.Whitelist whitelist = io.sigcorr.detection.whitelist.Whitelist.fromConfig(
                config.isWhitelistEnabled(),
                config.getTrustedGtPairs(),
                config.getHomeNetworkPrefixes()
        );
        io.sigcorr.correlation.engine.EngineConfig engineConfig = io.sigcorr.correlation.engine.EngineConfig.defaults()
                .withWhitelist(whitelist)
                .withCorrelationWindow(java.time.Duration.ofSeconds(config.getCorrelationWindowSeconds()));

        // Single engine across all files for cross-file correlation
        CorrelationEngine engine = new CorrelationEngine(engineConfig);

        int totalFiles = 0;
        int totalEvents = 0;
        int filesWithAlerts = 0;

        for (Path pcapFile : pcapFiles) {
            totalFiles++;
            if (!quiet) System.out.printf("── [%d/%d] %s%n", totalFiles, pcapFiles.size(), pcapFile.getFileName());

            try {
                List<SignalingEvent> events = bridge.decodePcap(pcapFile);
                totalEvents += events.size();

                if (events.isEmpty()) {
                    if (!quiet) System.out.println("   No signaling events found\n");
                    continue;
                }

                int alertsBefore = engine.getAlerts().size();
                engine.processBatch(events);
                int newAlerts = engine.getAlerts().size() - alertsBefore;

                if (newAlerts > 0) filesWithAlerts++;
                if (!quiet) System.out.printf("   %d events, %d new alert(s)%n%n", events.size(), newAlerts);

                // Export evidence per file
                boolean shouldExport = exportEvidence || config.isAutoExportEnabled();
                if (shouldExport && newAlerts > 0) {
                    List<SecurityAlert> recentAlerts = engine.getAlerts().subList(
                            engine.getAlerts().size() - newAlerts, engine.getAlerts().size());
                    exportEvidencePcaps(recentAlerts, pcapFile, events, config);
                }

            } catch (IOException | InterruptedException e) {
                System.err.printf("   ERROR: %s%n%n", e.getMessage());
            }
        }

        // Print combined results
        if (!quiet) {
            System.out.println("═══════════════════════════════════════════════");
            System.out.printf("  Batch Summary: %d files, %d events, %d files with alerts%n",
                    totalFiles, totalEvents, filesWithAlerts);
            System.out.println("═══════════════════════════════════════════════\n");
        }

        if (jsonOutput) {
            System.out.println(new JsonOutputFormatter().formatReport(engine));
        } else if (csvOutput) {
            System.out.print(new CsvOutputFormatter().formatReport(engine));
        } else {
            printResults(engine);
        }
    }

    /**
     * Export evidence pcap files for detected alerts
     */
    private static void exportEvidencePcaps(List<SecurityAlert> alerts, Path sourcePcap, 
                                            List<SignalingEvent> events, SigCorrConfig config) {
        Path evidenceDir = Path.of(config.getEvidenceDirectory());
        EvidenceExporter exporter = new EvidenceExporter(evidenceDir);
        
        if (!exporter.isEditcapAvailable()) {
            System.err.println("WARNING: editcap not found - cannot export evidence pcaps");
            return;
        }
        
        System.out.println("\n─────────────────────────────────────────────────────────");
        System.out.println("Exporting Evidence PCAPs");
        System.out.println("─────────────────────────────────────────────────────────");
        
        for (SecurityAlert alert : alerts) {
            Path evidencePath = exporter.exportEvidence(alert, sourcePcap, events);
            if (evidencePath != null) {
                System.out.printf("  ✓ %s → %s%n", alert.getMatchedPattern().getPatternId(), evidencePath.getFileName());
            }
        }
        System.out.println();
    }

    private static void printResults(CorrelationEngine engine) {
        System.out.println(engine.getSummary());
        var alerts = engine.getAlerts();
        if (alerts.isEmpty()) { System.out.println("No attack patterns detected."); return; }

        System.out.println("Detected Attacks:");
        System.out.println("─────────────────────────────────────────────────────────");
        for (SecurityAlert alert : alerts) {
            System.out.println("  " + alert);
            if (verbose) {
                for (var ev : alert.getMatchedEvents()) {
                    System.out.printf("      %s %s %s %s%n", ev.getTimestamp(),
                            ev.getProtocolInterface().getDisplayName(),
                            ev.getOperation().getDisplayName(),
                            ev.getSourceNode() != null ? ev.getSourceNode() : "");
                }
                System.out.println();
            }
        }
        var cp = engine.getCrossProtocolAlerts();
        if (!cp.isEmpty()) {
            System.out.println("\nCross-Protocol Detections:");
            System.out.println("─────────────────────────────────────────────────────────");
            for (var a : cp) {
                System.out.printf("  %s: %s | Interfaces: %s | Confidence: %.0f%%%n",
                        a.getMatchedPattern().getPatternId(), a.getMatchedPattern().getName(),
                        a.getMatchedEvents().stream().map(e -> e.getProtocolInterface().getDisplayName()).distinct().toList(),
                        a.getConfidenceScore() * 100);
            }
        }
    }

    // ════════════════════════════════════════════════════════════════
    //  DEMO — synthetic attack scenarios
    // ════════════════════════════════════════════════════════════════

    private static void runDemo() {
        if (!quiet) System.out.println(BANNER);
        System.out.println("Running SigCorr Demo — Synthetic Attack Scenario Analysis");
        System.out.println("══════════════════════════════════════════════════════════\n");

        CorrelationEngine engine = CorrelationEngine.createDefault();
        ScenarioGenerator gen = new ScenarioGenerator();
        Instant t = Instant.parse("2025-03-15T10:00:00Z");

        record S(String name, String target, String attack, List<SignalingEvent> events) {}
        var scenarios = List.of(
                new S("Silent Location Tracking", "MSISDN 447712345678", "SRI → PSI",
                        gen.generateLocationTracking("447712345678", "234101234567890", t)),
                new S("Interception Setup (SS7+Diameter)", "MSISDN 447798765432", "SRI → ISD → ULR",
                        gen.generateInterceptionSetup("447798765432", "234109876543210", t.plusSeconds(300))),
                new S("SS7→GTP Session Attack", "MSISDN 447755555555", "MAP SRI → GTP CreateSession",
                        gen.generateTrackingWithSession("447755555555", "234105555555550", t.plusSeconds(600))),
                new S("Diameter→SS7 Auth Downgrade", "IMSI 234101111111110", "DIA AIR → MAP SendAuthInfo",
                        gen.generateAuthDowngrade("234101111111110", t.plusSeconds(900))),
                new S("Subscriber DoS", "IMSI 234102222222220", "CancelLocation → DeleteData",
                        gen.generateSubscriberDoS("234102222222220", t.plusSeconds(1200))),
                new S("Call Forwarding Interception", "MSISDN 447733333333", "RegisterSS → ActivateSS",
                        gen.generateCallForwardingInterception("447733333333", t.plusSeconds(1500))),
                new S("Cross-Protocol Recon", "MSISDN 447744444444", "MAP SRI → DIA AIR",
                        gen.generateCrossProtocolRecon("447744444444", "234104444444440", t.plusSeconds(1800)))
        );

        int n = 1;
        for (var s : scenarios) {
            System.out.printf("▶ Scenario %d: %s%n  Target: %s | Attack: %s%n", n++, s.name(), s.target(), s.attack());
            var alerts = engine.processBatch(s.events());
            System.out.printf("  Events: %d | Alerts: %d%n", s.events().size(), alerts.size());
            for (var a : alerts) System.out.println("  🚨 " + a);
            System.out.println();
        }

        System.out.println("▶ Scenario 8: Legitimate Traffic (50 events)");
        var legit = gen.generateLegitimateTraffic(50, t.plusSeconds(2100));
        var fp = engine.processBatch(legit);
        System.out.printf("  Events: %d | Alerts: %d%n", legit.size(), fp.size());
        System.out.println(fp.isEmpty() ? "  ✅ No false positives" : "  ⚠  FALSE POSITIVES");
        System.out.println();

        System.out.println(engine.getSummary());
        printResults(engine);

        if (jsonOutput) System.out.println(new JsonOutputFormatter().formatReport(engine));
        if (csvOutput) System.out.print(new CsvOutputFormatter().formatReport(engine));
    }

    // ════════════════════════════════════════════════════════════════
    //  PATTERNS — list detection catalog
    // ════════════════════════════════════════════════════════════════

    private static void listPatterns() {
        if (!quiet) System.out.println(BANNER);
        System.out.println("Detection Pattern Catalog");
        System.out.println("═════════════════════════════════════════════════\n");
        var patterns = AttackPatternCatalog.getAllPatterns();
        for (var p : patterns) {
            System.out.printf("  %s [%s] %s%n", p.getPatternId(), p.getSeverity().getDisplayName().toUpperCase(), p.getName());
            System.out.printf("    Steps: %d | Window: %ds | Same-source: %s%n",
                    p.getSteps().size(), p.getMaxWindow().toSeconds(), p.isRequireSameSource());
            for (var step : p.getSteps()) {
                System.out.printf("      %d. %s (%s)%s%n", step.getStepNumber(),
                        step.getOperation().getDisplayName(), step.getOperation().getProtocolInterface().getDisplayName(),
                        step.isRequired() ? "" : " [optional]");
            }
            if (!p.getMitreTechniques().isEmpty()) System.out.printf("    MITRE: %s%n", p.getMitreTechniques());
            System.out.println("    " + p.getDescription() + "\n");
        }
        System.out.printf("Total: %d patterns%n", patterns.size());
    }

    private static void printUsage() {
        System.out.println(BANNER);
        System.out.println("""
                Usage: sigcorr <command> [options]
                
                Commands:
                  demo                  Run synthetic attack scenario demo
                  analyze <pcap>        Analyze a pcap file (requires tshark)
                  analyze <directory>   Batch analyze all pcap files in a directory
                  patterns              List all detection patterns
                  version               Show version
                  help                  Show this help
                
                Options:
                  --verbose, -v         Debug output with event details
                  --quiet, -q           Suppress banner and info messages
                  --json                Output results as JSON
                  --csv                 Output results as CSV
                  --format <fmt>        Output format: json, csv, or console
                  --export-evidence     Export evidence pcaps for detected alerts
                
                Configuration:
                  Config file: ./sigcorr-config.yaml (optional)
                  Evidence output: ./evidence/ (configurable)
                
                Examples:
                  sigcorr analyze capture.pcap
                  sigcorr analyze capture.pcap --json
                  sigcorr analyze ./captures/ --format csv
                  sigcorr analyze capture.pcap --export-evidence
                """);
    }
}
