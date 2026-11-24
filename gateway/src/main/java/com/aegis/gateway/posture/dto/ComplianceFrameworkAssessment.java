package com.aegis.gateway.posture.dto;

import java.util.Map;

/**
 * Compliance evaluation against a specific cybersecurity regulatory standard.
 */
public record ComplianceFrameworkAssessment(
    String frameworkName,
    String standardVersion,
    double scorePercentage,
    String status,
    int totalControls,
    int compliantControls,
    int nonCompliantControls,
    Map<String, String> controlAuditMap
) {}
