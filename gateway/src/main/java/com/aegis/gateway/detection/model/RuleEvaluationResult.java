package com.aegis.gateway.detection.model;

import java.util.Optional;

public record RuleEvaluationResult(
    String ruleId,
    String ruleVersion,
    boolean triggered,
    String targetEntityType,
    String targetEntityValue,
    Optional<DetectionEvidence> evidence,
    String summary
) {
    public static RuleEvaluationResult notTriggered(String ruleId, String ruleVersion) {
        return new RuleEvaluationResult(
            ruleId, ruleVersion, false, null, null, Optional.empty(), "Rule criteria not met"
        );
    }

    public static RuleEvaluationResult triggered(
            String ruleId,
            String ruleVersion,
            String targetEntityType,
            String targetEntityValue,
            DetectionEvidence evidence,
            String summary) {
        return new RuleEvaluationResult(
            ruleId, ruleVersion, true, targetEntityType, targetEntityValue, Optional.of(evidence), summary
        );
    }
}
