package com.aegis.gateway.detection.rules;

import com.aegis.gateway.detection.model.RuleEvaluationResult;
import com.aegis.gateway.telemetry.ApiEvent;

public interface DetectionRule {
    String getRuleId();
    String getRuleVersion();
    boolean isEnabled();
    RuleEvaluationResult evaluate(ApiEvent event);
}
