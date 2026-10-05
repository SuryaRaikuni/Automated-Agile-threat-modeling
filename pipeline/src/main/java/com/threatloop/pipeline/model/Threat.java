package com.threatloop.pipeline.model;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public record Threat(
    String id,
    StrideCategory category,
    Severity severity,
    String title,
    String description,
    String mitigation,
    String affectedElementId,
    String runId,
    String status
) {
    public static Threat of(StrideCategory category, Severity severity, String title, String description, String mitigation, String affectedElementId, String runId) {
        String input = category.name() + ":" + affectedElementId + ":" + title;
        String generatedId = generateSha256(input);
        return new Threat(generatedId, category, severity, title, description, mitigation, affectedElementId, runId, "OPEN");
    }
    
    public Threat withStatus(String newStatus) {
        return new Threat(id, category, severity, title, description, mitigation, affectedElementId, runId, newStatus);
    }
    
    private static String generateSha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder(2 * hash.length);
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not found", e);
        }
    }
}
