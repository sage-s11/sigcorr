#!/bin/bash
set -e

echo "Integrating Config + Evidence Export features..."

# Backup original
cp src/main/java/io/sigcorr/SigCorrMain.java \
   src/main/java/io/sigcorr/SigCorrMain.java.backup

# Add imports at the top (after existing imports)
sed -i '/import io.sigcorr.ingest.tshark.TsharkBridge;/a\
import io.sigcorr.config.SigCorrConfig;\
import io.sigcorr.evidence.EvidenceExporter;' \
  src/main/java/io/sigcorr/SigCorrMain.java

# Add exportEvidence flag
sed -i '/private static boolean jsonOutput = false;/a\    private static boolean exportEvidence = false;' \
  src/main/java/io/sigcorr/SigCorrMain.java

# Add flag parsing
sed -i '/case "--json" -> jsonOutput = true;/a\                case "--export-evidence" -> exportEvidence = true;' \
  src/main/java/io/sigcorr/SigCorrMain.java

# Add config loading and evidence export to runAnalyze
# This is complex - let's use a Python script instead

python3 << 'EOPYTHON'
import re

with open('src/main/java/io/sigcorr/SigCorrMain.java', 'r') as f:
    content = f.read()

# Add config loading after path validation
config_load = '''
        // Load configuration
        SigCorrConfig config;
        try {
            config = SigCorrConfig.loadDefault();
            if (verbose) System.out.println("Loaded configuration from sigcorr-config.yaml");
        } catch (IOException e) {
            if (verbose) System.out.println("No config file found, using defaults");
            config = SigCorrConfig.createDefault();
        }
        '''

content = content.replace(
    'if (!quiet) { System.out.println(BANNER);',
    config_load + '\n        if (!quiet) { System.out.println(BANNER);'
)

# Add evidence export method before printResults
evidence_method = '''
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
        
        System.out.println("\\n─────────────────────────────────────────────────────────");
        System.out.println("Exporting Evidence PCAPs");
        System.out.println("─────────────────────────────────────────────────────────");
        
        for (SecurityAlert alert : alerts) {
            Path evidencePath = exporter.exportEvidence(alert, sourcePcap, events);
            if (evidencePath != null) {
                System.out.printf("  ✓ %s → %s%n", alert.getPatternId(), evidencePath.getFileName());
            }
        }
        System.out.println();
    }

'''

content = content.replace(
    '    private static void printResults(CorrelationEngine engine) {',
    evidence_method + '    private static void printResults(CorrelationEngine engine) {'
)

# Add call to export evidence in runAnalyze
export_call = '''
            
            // Export evidence if requested or auto-export is enabled
            boolean shouldExport = exportEvidence || config.isAutoExportEnabled();
            if (shouldExport && !alerts.isEmpty()) {
                exportEvidencePcaps(alerts, path, events, config);
            }
            '''

content = content.replace(
    'if (!quiet) System.out.println(engine.getSummary());',
    'if (!quiet) System.out.println(engine.getSummary());' + export_call
)

# Update usage
content = content.replace(
    '  --json                Output results as JSON',
    '''  --json                Output results as JSON
                  --export-evidence     Export evidence pcaps for detected alerts
                
                Configuration:
                  Config file: ./sigcorr-config.yaml (optional)
                  Evidence output: ./evidence/ (configurable)'''
)

with open('src/main/java/io/sigcorr/SigCorrMain.java', 'w') as f:
    f.write(content)

print("✓ Integration complete")
EOPYTHON

echo "Building..."
mvn clean package -DskipTests

echo "✓ Done! Test with:"
echo "  java -jar target/sigcorr-0.1.0.jar analyze test-pcaps/ss7_location_tracking.pcap --export-evidence"
