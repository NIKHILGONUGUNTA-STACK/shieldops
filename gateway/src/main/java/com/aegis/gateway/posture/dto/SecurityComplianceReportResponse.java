package com.aegis.gateway.posture.dto;

import java.time.Instant;
import java.util.List;

/**
 * Executive Security & Regulatory Compliance Dossier.
 */
public record SecurityComplianceReportResponse(
    String reportId,
    Instant generatedAt,
    double overallScorePercent,
    String certificationReadiness,
    int totalAssessedEndpoints,
    List<ComplianceFrameworkAssessment> frameworks,
    String executiveSummary,
    List<String> keyStrengths,
    List<String> recommendedRemediations
) {}
