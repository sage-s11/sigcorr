package io.sigcorr.config;

import java.io.*;
import java.nio.file.*;
import java.util.*;

/**
 * Configuration loader for SigCorr.
 * Reads sigcorr-config.yaml and provides typed access to settings.
 */
public class SigCorrConfig {
    
    private final Map<String, Object> config;
    
    private SigCorrConfig(Map<String, Object> config) {
        this.config = config;
    }
    
    /**
     * Load configuration from default location (./sigcorr-config.yaml)
     */
    public static SigCorrConfig loadDefault() throws IOException {
        return load(Paths.get("sigcorr-config.yaml"));
    }
    
    /**
     * Load configuration from specified path
     */
    public static SigCorrConfig load(Path configPath) throws IOException {
        if (!Files.exists(configPath)) {
            // Return default config if file doesn't exist
            return createDefault();
        }
        
        Map<String, Object> config = parseYaml(Files.readString(configPath));
        return new SigCorrConfig(config);
    }
    
    /**
     * Create default configuration (used when no config file exists)
     */
    public static SigCorrConfig createDefault() {
        Map<String, Object> config = new HashMap<>();
        
        // Severity thresholds
        Map<String, Integer> severity = new HashMap<>();
        severity.put("critical_threshold", 95);
        severity.put("high_threshold", 75);
        severity.put("medium_threshold", 50);
        config.put("severity", severity);
        
        // Evidence export
        Map<String, Object> evidence = new HashMap<>();
        evidence.put("auto_export", true);
        evidence.put("output_directory", "./evidence");
        evidence.put("include_context_packets", 2);
        config.put("evidence", evidence);
        
        // Output
        Map<String, Boolean> output = new HashMap<>();
        output.put("json", true);
        output.put("console", true);
        output.put("syslog", false);
        config.put("output", output);
        
        // Correlation
        Map<String, Integer> correlation = new HashMap<>();
        correlation.put("time_window_seconds", 300);
        config.put("correlation", correlation);
        
        return new SigCorrConfig(config);
    }
    
    // Getters
    public int getCriticalThreshold() {
        return getInt("severity.critical_threshold", 95);
    }
    
    public int getHighThreshold() {
        return getInt("severity.high_threshold", 75);
    }
    
    public int getMediumThreshold() {
        return getInt("severity.medium_threshold", 50);
    }
    
    public boolean isAutoExportEnabled() {
        return getBoolean("evidence.auto_export", true);
    }
    
    public String getEvidenceDirectory() {
        return getString("evidence.output_directory", "./evidence");
    }
    
    public int getContextPackets() {
        return getInt("evidence.include_context_packets", 2);
    }
    
    public boolean isJsonOutputEnabled() {
        return getBoolean("output.json", true);
    }
    
    public boolean isConsoleOutputEnabled() {
        return getBoolean("output.console", true);
    }
    
    public int getCorrelationWindowSeconds() {
        return getInt("correlation.time_window_seconds", 300);
    }
    
    // Helper methods
    private int getInt(String path, int defaultValue) {
        Object value = getNestedValue(path);
        if (value instanceof Number) {
            return ((Number) value).intValue();
        }
        return defaultValue;
    }
    
    private boolean getBoolean(String path, boolean defaultValue) {
        Object value = getNestedValue(path);
        if (value instanceof Boolean) {
            return (Boolean) value;
        }
        return defaultValue;
    }
    
    private String getString(String path, String defaultValue) {
        Object value = getNestedValue(path);
        if (value instanceof String) {
            return (String) value;
        }
        return defaultValue;
    }
    
    @SuppressWarnings("unchecked")
    private Object getNestedValue(String path) {
        String[] parts = path.split("\\.");
        Map<String, Object> current = config;
        
        for (int i = 0; i < parts.length - 1; i++) {
            Object next = current.get(parts[i]);
            if (!(next instanceof Map)) {
                return null;
            }
            current = (Map<String, Object>) next;
        }
        
        return current.get(parts[parts.length - 1]);
    }
    
    /**
     * Simple YAML parser (handles basic key-value pairs and nested maps)
     * For production, use a proper YAML library like SnakeYAML
     */
    private static Map<String, Object> parseYaml(String yaml) {
        Map<String, Object> root = new HashMap<>();
        Map<String, Object> currentSection = null;
        
        for (String line : yaml.split("\n")) {
            line = line.trim();
            
            // Skip comments and empty lines
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            
            // Section header (no leading spaces in original, has colon)
            if (!line.startsWith(" ") && line.contains(":") && !line.contains("  ")) {
                String key = line.substring(0, line.indexOf(":")).trim();
                currentSection = new HashMap<>();
                root.put(key, currentSection);
            }
            // Key-value pair within section
            else if (line.contains(":") && currentSection != null) {
                String[] parts = line.split(":", 2);
                String key = parts[0].trim();
                String value = parts[1].trim();
                
                // Parse value type
                Object parsedValue;
                if (value.equals("true") || value.equals("false")) {
                    parsedValue = Boolean.parseBoolean(value);
                } else if (value.matches("-?\\d+")) {
                    parsedValue = Integer.parseInt(value);
                } else if (value.startsWith("\"") || value.startsWith("'")) {
                    parsedValue = value.substring(1, value.length() - 1);
                } else {
                    parsedValue = value;
                }
                
                currentSection.put(key, parsedValue);
            }
        }
        
        return root;
    }
}
