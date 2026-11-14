package com.aegis.gateway.detection.campaign;

import java.util.List;

/**
 * Deterministic, explainable risk assessment for an exfiltration campaign.
 * Evaluates kill-chain progression, attack severity, resource breadth, domain diversity, and evidence quality.
 */
public record CampaignRiskAssessment(
    double overallScore,
    String riskCategory,
    double stageProgressionFactor,
    double attackSeverityFactor,
    double resourceBreadthFactor,
    double domainDiversityFactor,
    double evidenceCompletenessFactor,
    String rationale,
    List<String> keyRiskIndicators
) {
    /**
     * Deterministically calculates campaign risk score on a calibrated scale (0.0 - 100.0).
     */
    public static CampaignRiskAssessment calculate(
            int distinctStagesCount,
            String highestSeverity,
            int resourceCount,
            int sensitiveDomainCount,
            CampaignEvidenceCompleteness completeness,
            boolean hasUnauthorizedAccess,
            boolean hasRestrictedFieldLeak) {

        // 1. Stage Progression Factor (Max 35 points)
        // Up to 6 distinct stages: +6 points per stage, +5 bonus if >= 3 stages
        double stageScore = Math.min(30.0, distinctStagesCount * 5.0);
        if (distinctStagesCount >= 3) {
            stageScore += 5.0;
        }

        // 2. Attack Severity Factor (Max 25 points)
        double severityScore = switch (highestSeverity != null ? highestSeverity.toUpperCase() : "MEDIUM") {
            case "CRITICAL" -> 25.0;
            case "HIGH" -> 18.0;
            case "MEDIUM" -> 10.0;
            default -> 5.0;
        };
        if (hasRestrictedFieldLeak) {
            severityScore = Math.min(25.0, severityScore + 5.0);
        }

        // 3. Resource Breadth Factor (Max 15 points)
        double resourceScore = Math.min(15.0, resourceCount * 2.5);

        // 4. Domain Diversity Factor (Max 15 points)
        // Multiple entity boundaries (Customer + Account + Transfer)
        double domainScore = Math.min(15.0, sensitiveDomainCount * 5.0);

        // 5. Evidence Completeness Factor (Max 10 points)
        double completenessScore = switch (completeness) {
            case COMPLETE -> 10.0;
            case DEGRADED -> 6.0;
            case INCOMPLETE -> 3.0;
        };

        double rawTotal = stageScore + severityScore + resourceScore + domainScore + completenessScore;
        double overallScore = Math.min(100.0, Math.round(rawTotal * 10.0) / 10.0);

        String category = categorize(overallScore);

        List<String> indicators = new java.util.ArrayList<>();
        if (distinctStagesCount >= 2) {
            indicators.add(String.format("Multi-stage progression observed across %d kill-chain stages", distinctStagesCount));
        }
        if (hasUnauthorizedAccess) {
            indicators.add("Confirmed unauthorized resource access (HTTP 200 on cross-owner data)");
        }
        if (hasRestrictedFieldLeak) {
            indicators.add("Exposure of RESTRICTED cryptographic or credential secrets");
        }
        if (sensitiveDomainCount >= 2) {
            indicators.add(String.format("Cross-domain harvesting across %d sensitive service boundaries", sensitiveDomainCount));
        }
        if (resourceCount >= 5) {
            indicators.add(String.format("High-volume entity enumeration (%d distinct resources)", resourceCount));
        }
        if (completeness != CampaignEvidenceCompleteness.COMPLETE) {
            indicators.add(String.format("Evidence state is %s: %s", completeness.name(), completeness.getDescription()));
        }

        String rationale = String.format(
            "Campaign risk evaluated at %.1f/100 [%s]. Progressed through %d stage(s) with %s severity, touching %d resource(s) across %d domain(s). Evidence state: %s.",
            overallScore, category, distinctStagesCount, highestSeverity, resourceCount, sensitiveDomainCount, completeness.name()
        );

        return new CampaignRiskAssessment(
            overallScore,
            category,
            stageScore,
            severityScore,
            resourceScore,
            domainScore,
            completenessScore,
            rationale,
            indicators
        );
    }

    private static String categorize(double score) {
        if (score >= 80.0) return "CRITICAL";
        if (score >= 60.0) return "HIGH";
        if (score >= 35.0) return "MEDIUM";
        return "LOW";
    }
}

