package com.aegis.gateway.adversary;

import java.time.Instant;
import java.util.List;

public record CandidatePolicy(
    String id,
    String ruleId,
    String targetMethod,
    String targetPathPattern,
    List<String> requiredPredecessors,
    String description,
    double confidenceScore,
    int shadowEvaluationsCount,
    int shadowFalsePositives,
    double shadowFpr,
    String status,
    Instant createdAt,
    Instant promotedAt,
    String synthesizedFromCampaignId
) {
    public CandidatePolicy withShadowResult(int evaluations, int falsePositives) {
        double fpr = evaluations > 0 ? (double) falsePositives / evaluations : 0.0;
        String newStatus = (fpr == 0.0 && evaluations >= 5) ? "SAFE_FOR_PROMOTION" : "EVALUATING";
        return new CandidatePolicy(
            id, ruleId, targetMethod, targetPathPattern, requiredPredecessors, description,
            confidenceScore, evaluations, falsePositives, fpr, newStatus, createdAt, promotedAt, synthesizedFromCampaignId
        );
    }

    public CandidatePolicy withPromoted(Instant when) {
        return new CandidatePolicy(
            id, ruleId, targetMethod, targetPathPattern, requiredPredecessors, description,
            confidenceScore, shadowEvaluationsCount, shadowFalsePositives, shadowFpr, "PROMOTED", createdAt, when, synthesizedFromCampaignId
        );
    }
}
