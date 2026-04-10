package io.sigcorr.output.csv;

import io.sigcorr.correlation.engine.CorrelationEngine;
import io.sigcorr.detection.scoring.SecurityAlert;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Serializes analysis results to CSV format.
 * Compatible with Excel, pandas, and SIEM import.
 */
public class CsvOutputFormatter {

    private static final String HEADER = String.join(",",
            "alert_id",
            "detection_time",
            "pattern_id",
            "pattern_name",
            "severity",
            "subscriber",
            "confidence",
            "cross_protocol",
            "duration_ms",
            "event_count",
            "interfaces",
            "mitre_techniques",
            "description"
    );

    public String formatAlerts(List<SecurityAlert> alerts) {
        StringBuilder sb = new StringBuilder();
        sb.append(HEADER).append("\n");
        for (SecurityAlert alert : alerts) {
            sb.append(formatRow(alert)).append("\n");
        }
        return sb.toString();
    }

    public String formatReport(CorrelationEngine engine) {
        return formatAlerts(engine.getAlerts());
    }

    private String formatRow(SecurityAlert alert) {
        String interfaces = alert.getMatchedEvents().stream()
                .map(e -> e.getProtocolInterface().getDisplayName())
                .distinct()
                .collect(Collectors.joining(";"));

        String mitre = String.join(";", alert.getMatchedPattern().getMitreTechniques());

        return String.join(",",
                quote(alert.getAlertId()),
                quote(alert.getDetectionTime().toString()),
                quote(alert.getMatchedPattern().getPatternId()),
                quote(alert.getMatchedPattern().getName()),
                quote(alert.getSeverity().getDisplayName()),
                quote(alert.getSubscriberKey()),
                String.format("%.1f", alert.getConfidenceScore() * 100),
                String.valueOf(alert.isCrossProtocol()),
                String.valueOf(alert.getAttackDurationMillis()),
                String.valueOf(alert.getMatchedEvents().size()),
                quote(interfaces),
                quote(mitre),
                quote(alert.getMatchedPattern().getDescription())
        );
    }

    private static String quote(String value) {
        if (value == null) return "\"\"";
        return "\"" + value.replace("\"", "\"\"") + "\"";
    }
}
