package com.aegis.gateway.detection.leakage;

/**
 * Metadata and operational parameters for a Data Leakage detection rule.
 */
public record DataLeakageRuleInfoResponse(
    String ruleId,
    String ruleVersion,
    String name,
    String description,
    String threatCategory,
    String defaultSeverity,
    boolean enabled,
    String triggerConditionExplanation
) {}

