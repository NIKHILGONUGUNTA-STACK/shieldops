package com.aegis.gateway.workflow;

import java.util.List;
import java.util.Set;

/**
 * Result of evaluating a request against deterministic workflow rules.
 */
public record WorkflowCheckResult(
        boolean allowed,
        String ruleId,
        String targetEndpoint,
        List<String> missingPrerequisites,
        Set<String> completedSteps,
        String reason
) {
    public static WorkflowCheckResult allow(String targetEndpoint, Set<String> completedSteps) {
        return new WorkflowCheckResult(true, null, targetEndpoint, List.of(), completedSteps, null);
    }

    public static WorkflowCheckResult block(
            String ruleId,
            String targetEndpoint,
            List<String> missingPrerequisites,
            Set<String> completedSteps,
            String reason) {
        return new WorkflowCheckResult(false, ruleId, targetEndpoint, missingPrerequisites, completedSteps, reason);
    }
}
