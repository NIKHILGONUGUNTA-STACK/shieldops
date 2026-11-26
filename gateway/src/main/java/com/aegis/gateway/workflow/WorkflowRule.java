package com.aegis.gateway.workflow;

import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Represents a deterministic workflow invariant rule enforcing prerequisite business steps.
 */
public class WorkflowRule {
    private String id;
    private String targetMethod;
    private String targetPathPattern;
    private List<String> requiredPredecessors;
    private String description;
    private boolean enabled = true;

    private transient Pattern compiledPattern;

    public WorkflowRule() {}

    public WorkflowRule(
            String id,
            String targetMethod,
            String targetPathPattern,
            List<String> requiredPredecessors,
            String description) {
        this.id = id;
        this.targetMethod = targetMethod.toUpperCase();
        this.targetPathPattern = targetPathPattern;
        this.requiredPredecessors = requiredPredecessors;
        this.description = description;
        this.enabled = true;
    }

    public boolean matches(String method, String path) {
        if (!enabled || !targetMethod.equalsIgnoreCase(method)) {
            return false;
        }
        if (compiledPattern == null) {
            compiledPattern = Pattern.compile(targetPathPattern);
        }
        return compiledPattern.matcher(path).matches();
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getTargetMethod() {
        return targetMethod;
    }

    public void setTargetMethod(String targetMethod) {
        this.targetMethod = targetMethod != null ? targetMethod.toUpperCase() : null;
    }

    public String getTargetPathPattern() {
        return targetPathPattern;
    }

    public void setTargetPathPattern(String targetPathPattern) {
        this.targetPathPattern = targetPathPattern;
        this.compiledPattern = null;
    }

    public List<String> getRequiredPredecessors() {
        return requiredPredecessors;
    }

    public void setRequiredPredecessors(List<String> requiredPredecessors) {
        this.requiredPredecessors = requiredPredecessors;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        WorkflowRule that = (WorkflowRule) o;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
