package io.sigcorr.output.json;

import com.google.gson.*;
import io.sigcorr.correlation.engine.CorrelationEngine;
import io.sigcorr.core.event.SignalingEvent;
import io.sigcorr.detection.scoring.SecurityAlert;

import java.time.Instant;
import java.util.List;

/**
 * Serializes analysis results to JSON format.
 */
public class JsonOutputFormatter {

    private final Gson gson;

    public JsonOutputFormatter() {
        this.gson = new GsonBuilder()
                .setPrettyPrinting()
                .registerTypeAdapter(Instant.class,
                        (JsonSerializer<Instant>) (src, type, ctx) -> new JsonPrimitive(src.toString()))
                .create();
    }

    /**
     * Format a single alert as JSON.
     */
    public String formatAlert(SecurityAlert alert) {
        JsonObject obj = new JsonObject();
        obj.addProperty("alertId", alert.getAlertId());
        obj.addProperty("detectionTime", alert.getDetectionTime().toString());
        obj.addProperty("patternId", alert.getMatchedPattern().getPatternId());
        obj.addProperty("patternName", alert.getMatchedPattern().getName());
        obj.addProperty("severity", alert.getSeverity().getDisplayName());
        obj.addProperty("subscriberKey", alert.getSubscriberKey());
        obj.addProperty("confidence", String.format("%.1f%%", alert.getConfidenceScore() * 100));
        obj.addProperty("crossProtocol", alert.isCrossProtocol());
        obj.addProperty("attackDurationMs", alert.getAttackDurationMillis());

        JsonArray events = new JsonArray();
        for (SignalingEvent event : alert.getMatchedEvents()) {
            JsonObject eventObj = new JsonObject();
            eventObj.addProperty("timestamp", event.getTimestamp().toString());
            eventObj.addProperty("interface", event.getProtocolInterface().getDisplayName());
            eventObj.addProperty("operation", event.getOperation().getDisplayName());
            eventObj.addProperty("category", event.getOperation().getCategory().name());
            if (event.getSourceNode() != null) {
                eventObj.addProperty("sourceNode", event.getSourceNode().toString());
            }
            JsonObject params = new JsonObject();
            event.getParameters().forEach(params::addProperty);
            eventObj.add("parameters", params);
            events.add(eventObj);
        }
        obj.add("matchedEvents", events);

        if (!alert.getMatchedPattern().getMitreTechniques().isEmpty()) {
            JsonArray mitre = new JsonArray();
            alert.getMatchedPattern().getMitreTechniques().forEach(mitre::add);
            obj.add("mitreTechniques", mitre);
        }

        obj.addProperty("description", alert.getMatchedPattern().getDescription());

        return gson.toJson(obj);
    }

    /**
     * Format all alerts as a JSON array.
     */
    public String formatAlerts(List<SecurityAlert> alerts) {
        JsonArray array = new JsonArray();
        for (SecurityAlert alert : alerts) {
            array.add(JsonParser.parseString(formatAlert(alert)));
        }
        return gson.toJson(array);
    }

    /**
     * Format complete analysis report including summary and alerts.
     */
    public String formatReport(CorrelationEngine engine) {
        JsonObject report = new JsonObject();

        // Summary
        var summary = engine.getSummary();
        JsonObject summaryObj = new JsonObject();
        summaryObj.addProperty("totalEvents", summary.totalEvents());
        summaryObj.addProperty("droppedEvents", summary.droppedEvents());
        summaryObj.addProperty("subscribersTracked", summary.subscribersTracked());
        summaryObj.addProperty("identityMappings", summary.identityMappings());
        summaryObj.addProperty("totalAlerts", summary.totalAlerts());
        summaryObj.addProperty("crossProtocolAlerts", summary.crossProtocolAlerts());
        summaryObj.addProperty("criticalAlerts", summary.criticalAlerts());
        summaryObj.addProperty("highAlerts", summary.highAlerts());

        JsonObject ifaceBreakdown = new JsonObject();
        summary.eventsByInterface().forEach(ifaceBreakdown::addProperty);
        summaryObj.add("eventsByInterface", ifaceBreakdown);

        report.add("summary", summaryObj);

        // Alerts
        JsonArray alertsArray = new JsonArray();
        for (SecurityAlert alert : engine.getAlerts()) {
            alertsArray.add(JsonParser.parseString(formatAlert(alert)));
        }
        report.add("alerts", alertsArray);

        return gson.toJson(report);
    }
}
