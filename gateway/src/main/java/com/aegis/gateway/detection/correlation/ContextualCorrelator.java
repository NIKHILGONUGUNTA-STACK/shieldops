package com.aegis.gateway.detection.correlation;

import com.aegis.gateway.detection.model.DetectionEvidence;
import com.aegis.gateway.detection.model.RuleEvaluationResult;
import com.aegis.gateway.detection.model.SecurityIncident;

import java.util.List;

/**
 * Strategy interface for correlating incoming detection evidence with active security incidents.
 */
public interface ContextualCorrelator {

    /**
     * Checks if this correlator supports the given rule or threat category.
     */
    boolean supports(String ruleId);

    /**
     * Evaluates whether the new rule evaluation result correlates with an active incident
     * and its associated past evidence records.
     */
    CorrelationResult evaluateCorrelation(
        RuleEvaluationResult newResult,
        SecurityIncident activeIncident,
        List<DetectionEvidence> pastEvidences
    );
}
