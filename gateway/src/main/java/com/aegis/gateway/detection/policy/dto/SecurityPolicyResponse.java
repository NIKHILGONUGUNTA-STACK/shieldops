package com.aegis.gateway.detection.policy.dto;

import com.aegis.gateway.detection.policy.PolicyAction;
import com.aegis.gateway.detection.policy.PolicyCategory;
import com.aegis.gateway.detection.policy.SecurityPolicy;

import java.time.Instant;

public record SecurityPolicyResponse(
    String id,
    String name,
    String version,
    PolicyCategory category,
    PolicyAction recommendedAction,
    String description,
    boolean enabled,
    double riskThreshold,
    String conditionExplanation,
    Instant effectiveFrom,
    Instant updatedAt
) {
    public static SecurityPolicyResponse from(SecurityPolicy p) {
        return new SecurityPolicyResponse(
            p.id(),
            p.name(),
            p.version(),
            p.category(),
            p.recommendedAction(),
            p.description(),
            p.enabled(),
            p.riskThreshold(),
            p.conditionExplanation(),
            p.effectiveFrom(),
            p.updatedAt()
        );
    }
}
